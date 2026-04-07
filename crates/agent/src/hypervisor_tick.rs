use std::path::Path;

use tracing::{info, warn};

use crate::{config, AgentState};

/// Periodic hypervisor audit. Runs innerwarden-hypervisor's full_audit(),
/// caches environment classification, emits incidents when trust degrades,
/// and feeds the cross-layer correlation engine.
pub(crate) async fn process_hypervisor_tick(
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    use innerwarden_core::incident::Incident;

    // Run the full hypervisor audit (blocking I/O — spawn_blocking).
    let report = match tokio::task::spawn_blocking(innerwarden_hypervisor::full_audit).await {
        Ok(report) => report,
        Err(e) => {
            warn!(error = %e, "hypervisor tick: audit task panicked");
            return;
        }
    };

    // Cache environment for other modules (firmware_tick uses this).
    let prev_env = state
        .hypervisor_environment
        .replace(report.environment.clone());

    // Feed correlation engine with hypervisor events.
    for check in &report.checks {
        if check.status == innerwarden_hypervisor::CheckStatus::Critical
            || check.status == innerwarden_hypervisor::CheckStatus::Warning
        {
            let kind = format!("hypervisor.{}", check.id.to_lowercase().replace('-', "_"));
            let event = crate::correlation_engine::CorrelationEngine::hypervisor_event(
                &kind,
                serde_json::json!({
                    "check_id": check.id,
                    "name": check.name,
                    "status": format!("{:?}", check.status),
                    "confidence": check.confidence,
                    "detail": check.detail,
                }),
            );
            state.correlation_engine.observe(event);
        }
    }

    let host = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");

    let mut incidents = Vec::new();

    // Detect environment change (stealth hypervisor install / Blue Pill).
    if let Some(ref prev) = prev_env {
        let changed = match (prev, &report.environment) {
            (
                innerwarden_hypervisor::Environment::BareMetal,
                innerwarden_hypervisor::Environment::VirtualMachine { .. }
                | innerwarden_hypervisor::Environment::UnknownHypervisor,
            ) => Some("bare_metal_to_vm"),
            (
                innerwarden_hypervisor::Environment::VirtualMachine { .. },
                innerwarden_hypervisor::Environment::UnknownHypervisor,
            ) => Some("vm_to_unknown_hypervisor"),
            _ => None,
        };

        if let Some(drift_type) = changed {
            let incident_id = format!("hypervisor:env_drift:{drift_type}");
            incidents.push(Incident {
                ts: chrono::Utc::now(),
                host: host.clone(),
                incident_id,
                severity: innerwarden_core::event::Severity::Critical,
                title: "Hypervisor environment changed unexpectedly".into(),
                summary: format!(
                    "Environment changed from {:?} to {:?}. Possible Blue Pill or stealth hypervisor installation.",
                    prev, report.environment
                ),
                evidence: serde_json::json!({
                    "previous": format!("{:?}", prev),
                    "current": format!("{:?}", report.environment),
                    "trust_score": report.trust_score,
                    "vm_verdict": {
                        "is_vm": report.vm_verdict.is_vm,
                        "score": report.vm_verdict.score,
                        "brand": report.vm_verdict.brand,
                        "evidence_count": report.vm_verdict.evidence_count,
                    },
                }),
                recommended_checks: vec![
                    "Investigate unexpected hypervisor presence".into(),
                    "Check for Blue Pill rootkit".into(),
                    "Run innerwarden-hypervisor for full report".into(),
                ],
                tags: vec!["hypervisor".to_string(), "ring-minus-1".to_string(), "blue-pill".to_string()],
                entities: vec![],
            });

            // Feed critical correlation event for env drift.
            let event = crate::correlation_engine::CorrelationEngine::hypervisor_event(
                "hypervisor.environment_drift",
                serde_json::json!({
                    "drift_type": drift_type,
                    "previous": format!("{:?}", prev),
                    "current": format!("{:?}", report.environment),
                }),
            );
            state.correlation_engine.observe(event);
        }
    }

    // Trust score degradation.
    if report.trust_score < cfg.hypervisor.trust_score_threshold {
        // Cooldown: one incident per 24h.
        if let Some(last) = state.last_hypervisor_incident_at {
            let hours_since = (chrono::Utc::now() - last).num_hours();
            if hours_since < 24 {
                tracing::debug!(
                    hours_since,
                    "hypervisor: trust_degraded cooldown active, skipping"
                );
                // Still write env drift incidents above, but skip trust degradation.
                if incidents.is_empty() {
                    return;
                }
                // Write only drift incidents.
                write_incidents(data_dir, &today.to_string(), &incidents);
                notify_telegram(state, &incidents, report.trust_score);
                return;
            }
        }

        let incident_id = format!(
            "hypervisor:trust_degraded:{}",
            (report.trust_score * 100.0) as u32
        );

        if state
            .suppressed_incident_ids
            .iter()
            .any(|pat| incident_id.contains(pat))
        {
            tracing::debug!(incident_id, "hypervisor: incident suppressed by user");
        } else {
            let severity = if report.trust_score < 0.3 {
                innerwarden_core::event::Severity::Critical
            } else if report.trust_score < 0.6 {
                innerwarden_core::event::Severity::High
            } else {
                innerwarden_core::event::Severity::Medium
            };

            let critical_checks: Vec<String> = report
                .checks
                .iter()
                .filter(|c| c.status == innerwarden_hypervisor::CheckStatus::Critical)
                .map(|c| format!("[{}] {}", c.id, c.name))
                .collect();

            state.last_hypervisor_incident_at = Some(chrono::Utc::now());

            incidents.push(Incident {
                ts: chrono::Utc::now(),
                host: host.clone(),
                incident_id,
                severity,
                title: format!(
                    "Hypervisor trust score degraded to {:.0}%",
                    report.trust_score * 100.0
                ),
                summary: format!(
                    "Trust score {:.0}% (threshold: {:.0}%). Environment: {:?}. Critical checks: {}",
                    report.trust_score * 100.0,
                    cfg.hypervisor.trust_score_threshold * 100.0,
                    report.environment,
                    if critical_checks.is_empty() {
                        "none".to_string()
                    } else {
                        critical_checks.join(", ")
                    },
                ),
                evidence: serde_json::json!({
                    "trust_score": report.trust_score,
                    "threshold": cfg.hypervisor.trust_score_threshold,
                    "environment": format!("{:?}", report.environment),
                    "vm_verdict": {
                        "is_vm": report.vm_verdict.is_vm,
                        "score": report.vm_verdict.score,
                        "brand": report.vm_verdict.brand,
                    },
                    "checks": report.checks.iter()
                        .filter(|c| c.status != innerwarden_hypervisor::CheckStatus::Unavailable)
                        .map(|c| serde_json::json!({
                            "id": c.id,
                            "name": c.name,
                            "status": format!("{:?}", c.status),
                            "confidence": c.confidence,
                        }))
                        .collect::<Vec<_>>(),
                }),
                recommended_checks: vec![
                    "Review hypervisor audit: innerwarden-hypervisor".into(),
                    "Check for unauthorized hypervisor modifications".into(),
                ],
                tags: vec!["hypervisor".to_string(), "ring-minus-1".to_string()],
                entities: vec![],
            });
        }
    }

    if incidents.is_empty() {
        let secure = report
            .checks
            .iter()
            .filter(|c| c.status == innerwarden_hypervisor::CheckStatus::Secure)
            .count();
        tracing::debug!(
            trust_score = format!("{:.0}%", report.trust_score * 100.0),
            environment = ?report.environment,
            secure_checks = secure,
            "hypervisor tick: all clear"
        );
        return;
    }

    write_incidents(data_dir, &today.to_string(), &incidents);
    notify_telegram(state, &incidents, report.trust_score);

    info!(
        count = incidents.len(),
        trust_score = format!("{:.0}%", report.trust_score * 100.0),
        environment = ?report.environment,
        "hypervisor tick: emitted incidents"
    );
}

fn write_incidents(
    data_dir: &Path,
    today: &str,
    incidents: &[innerwarden_core::incident::Incident],
) {
    use std::io::Write;
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            for inc in incidents {
                if let Ok(line) = serde_json::to_string(inc) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        Err(e) => warn!(error = %e, "hypervisor tick: failed to write incidents"),
    }
}

fn notify_telegram(
    state: &AgentState,
    incidents: &[innerwarden_core::incident::Incident],
    trust_score: f64,
) {
    if let Some(ref tg) = state.telegram_client {
        for inc in incidents {
            let sev = match inc.severity {
                innerwarden_core::event::Severity::Critical => "🔴 CRITICAL",
                innerwarden_core::event::Severity::High => "🟠 HIGH",
                _ => "🟡 MEDIUM",
            };
            let msg = format!(
                "🖥️ <b>Hypervisor Alert</b>\n\n\
                 {sev}\n\
                 <b>{}</b>\n\
                 {}\n\n\
                 Trust Score: {:.0}%",
                inc.title,
                inc.summary,
                trust_score * 100.0,
            );
            let tg = tg.clone();
            tokio::spawn(async move {
                let _ = tg.send_raw_html(&msg).await;
            });
        }
    }
}

/// Check if the cached hypervisor environment indicates a VM.
/// Used by firmware_tick to decide severity downgrade.
pub(crate) fn is_virtual_machine(state: &AgentState) -> bool {
    matches!(
        &state.hypervisor_environment,
        Some(innerwarden_hypervisor::Environment::VirtualMachine { .. })
            | Some(innerwarden_hypervisor::Environment::UnknownHypervisor)
    )
}
