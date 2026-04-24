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
        let changed = detect_environment_drift(prev, &report.environment);

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
        if should_skip_hypervisor_cooldown(state.last_hypervisor_incident_at, chrono::Utc::now()) {
            let hours_since = state
                .last_hypervisor_incident_at
                .map(|last| (chrono::Utc::now() - last).num_hours())
                .unwrap_or_default();
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
            let severity = classify_hypervisor_trust_severity(report.trust_score);

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
    state: &mut AgentState,
    incidents: &[innerwarden_core::incident::Incident],
    trust_score: f64,
) {
    if let Some(ref tg) = state.telegram_client {
        for inc in incidents {
            let ctx = crate::notification_gate::NotificationContext::from_firmware_or_hypervisor(
                inc,
                "hypervisor",
            );
            let gate_counter = state.telemetry.gate_suppressed_counter();
            let verdict =
                crate::notification_gate::should_notify_with_counter(&ctx, gate_counter.as_ref());
            match verdict {
                crate::notification_gate::NotificationVerdict::SendNow => {
                    let sev = format_hypervisor_severity(&inc.severity);
                    let msg = format!(
                        "\u{1f5a5}\u{fe0f} <b>Hypervisor Alert</b>\n\n\
                         {sev}\n\
                         <b>{}</b>\n\
                         {}\n\n\
                         Trust Score: {:.0}%",
                        inc.title,
                        inc.summary,
                        trust_score * 100.0,
                    );
                    let tg = tg.clone();
                    // Spec 036 PR-5: register the alert in the agent's
                    // TaskGroup so SIGTERM drain waits for it. Same
                    // design as PR-2's telegram-polling and PR-4's
                    // honeypot listener. Body does NOT observe
                    // `token.cancelled()` — dropping a hypervisor
                    // alert mid-send loses the notification silently,
                    // which is worse than letting a short HTTP call
                    // complete within the shutdown deadline.
                    state.task_group.spawn_or_log(
                        "hypervisor-alert",
                        Box::pin(async move {
                            let _ = tg.send_alert_html(&msg).await;
                        }),
                    );
                }
                crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                    *state
                        .telegram_deferred
                        .entry("hypervisor".to_string())
                        .or_insert(0) += 1;
                }
                crate::notification_gate::NotificationVerdict::Drop => {}
            }
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

fn detect_environment_drift(
    previous: &innerwarden_hypervisor::Environment,
    current: &innerwarden_hypervisor::Environment,
) -> Option<&'static str> {
    match (previous, current) {
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
    }
}

fn should_skip_hypervisor_cooldown(
    last_incident_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    last_incident_at
        .map(|last| (now - last).num_hours() < 24)
        .unwrap_or(false)
}

fn classify_hypervisor_trust_severity(score: f64) -> innerwarden_core::event::Severity {
    if score < 0.3 {
        innerwarden_core::event::Severity::Critical
    } else if score < 0.6 {
        innerwarden_core::event::Severity::High
    } else {
        innerwarden_core::event::Severity::Medium
    }
}

fn format_hypervisor_severity(severity: &innerwarden_core::event::Severity) -> &'static str {
    match severity {
        innerwarden_core::event::Severity::Critical => "\u{1f534} CRITICAL",
        innerwarden_core::event::Severity::High => "\u{1f7e0} HIGH",
        _ => "\u{1f7e1} MEDIUM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use innerwarden_core::event::Severity;

    #[test]
    fn detect_environment_drift_flags_bare_metal_to_vm_transition() {
        // Ensures Blue-Pill style environment flips are captured as critical drift events.
        let drift = detect_environment_drift(
            &innerwarden_hypervisor::Environment::BareMetal,
            &innerwarden_hypervisor::Environment::UnknownHypervisor,
        );
        assert_eq!(drift, Some("bare_metal_to_vm"));
    }

    #[test]
    fn detect_environment_drift_flags_vm_to_unknown_transition() {
        // Covers downgrade path when known VM metadata disappears into unknown hypervisor state.
        let drift = detect_environment_drift(
            &innerwarden_hypervisor::Environment::VirtualMachine {
                hypervisor: "kvm".to_string(),
            },
            &innerwarden_hypervisor::Environment::UnknownHypervisor,
        );
        assert_eq!(drift, Some("vm_to_unknown_hypervisor"));
    }

    #[test]
    fn detect_environment_drift_ignores_stable_environment() {
        // Verifies steady-state environments do not emit false-positive drift types.
        let drift = detect_environment_drift(
            &innerwarden_hypervisor::Environment::BareMetal,
            &innerwarden_hypervisor::Environment::BareMetal,
        );
        assert_eq!(drift, None);
    }

    #[test]
    fn should_skip_hypervisor_cooldown_only_within_24h_window() {
        // Guards cooldown behavior so repeated trust incidents are suppressed for one day.
        let now = Utc::now();
        assert!(should_skip_hypervisor_cooldown(
            Some(now - Duration::hours(2)),
            now
        ));
        assert!(!should_skip_hypervisor_cooldown(
            Some(now - Duration::hours(25)),
            now
        ));
    }

    #[test]
    fn classify_hypervisor_trust_severity_uses_score_bands() {
        // Ensures trust-score thresholds map to stable severity levels used by alerting.
        assert!(matches!(
            classify_hypervisor_trust_severity(0.2),
            Severity::Critical
        ));
        assert!(matches!(
            classify_hypervisor_trust_severity(0.5),
            Severity::High
        ));
        assert!(matches!(
            classify_hypervisor_trust_severity(0.8),
            Severity::Medium
        ));
    }

    #[test]
    fn format_hypervisor_severity_produces_expected_labels() {
        // Checks Telegram label formatting so severity badges remain operator-friendly.
        assert_eq!(
            format_hypervisor_severity(&Severity::Critical),
            "\u{1f534} CRITICAL"
        );
        assert_eq!(
            format_hypervisor_severity(&Severity::High),
            "\u{1f7e0} HIGH"
        );
        assert_eq!(
            format_hypervisor_severity(&Severity::Medium),
            "\u{1f7e1} MEDIUM"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Spec 036 PR-5 migration anchors — notify_telegram (hypervisor)
    // ─────────────────────────────────────────────────────────────────
    //
    // Mirrors the firmware_tick anchors. The migration at line ~265
    // inside `notify_telegram` wires the hypervisor alert through
    // `state.task_group.spawn_or_log("hypervisor-alert", ...)`.
    // Verdict logic is shared with firmware (both use
    // `NotificationContext::from_firmware_or_hypervisor`), so the
    // SendNow path requires severity=Critical AND a compromise tag
    // (rootkit / firmware_tampering / msr_write / spi_flash).

    fn make_hypervisor_incident(
        title: &str,
        severity: Severity,
        tags: Vec<&str>,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("hypervisor:test:{title}").replace(' ', "_"),
            severity,
            title: title.to_string(),
            summary: "fixture".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: tags.into_iter().map(String::from).collect(),
            entities: vec![],
        }
    }

    fn make_test_telegram_client() -> std::sync::Arc<crate::telegram::TelegramClient> {
        std::sync::Arc::new(
            crate::telegram::TelegramClient::new(
                "test-bot-token",
                "test-chat-id",
                None, // dashboard_url
            )
            .expect("TelegramClient::new builds a stub client"),
        )
    }

    #[tokio::test]
    async fn notify_telegram_registers_hypervisor_alert_in_task_group_on_send_now() {
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(make_test_telegram_client());

        // Critical + rootkit tag → evaluates to SendNow.
        let incident =
            make_hypervisor_incident("Ring-0 hook detected", Severity::Critical, vec!["rootkit"]);

        notify_telegram(&mut state, std::slice::from_ref(&incident), 0.4);

        assert_eq!(
            state.task_group.len(),
            1,
            "SendNow verdict MUST register a 'hypervisor-alert' task in the TaskGroup"
        );

        // Drain so the fire-and-forget HTTP call does not leak.
        let report = state.task_group.shutdown(Duration::from_millis(100)).await;
        assert_eq!(report.total, 1);
    }

    #[tokio::test]
    async fn notify_telegram_defers_and_does_not_spawn_on_non_compromise_critical() {
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(make_test_telegram_client());

        // Critical but no compromise tag → DailyBriefingOnly.
        let incident = make_hypervisor_incident(
            "VM exit timing anomaly",
            Severity::Critical,
            vec!["hypervisor"],
        );

        notify_telegram(&mut state, std::slice::from_ref(&incident), 0.6);

        assert_eq!(
            state.task_group.len(),
            0,
            "DailyBriefingOnly MUST NOT spawn; incident is deferred"
        );
        assert_eq!(
            state
                .telegram_deferred
                .get("hypervisor")
                .copied()
                .unwrap_or(0),
            1,
            "deferred counter must increment for the daily digest"
        );

        let report = state.task_group.shutdown(Duration::from_millis(50)).await;
        assert_eq!(report.total, 0);
    }

    #[tokio::test]
    async fn notify_telegram_is_noop_when_telegram_client_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = None;

        let incident = make_hypervisor_incident(
            "Should never reach the gate",
            Severity::Critical,
            vec!["rootkit"],
        );

        notify_telegram(&mut state, std::slice::from_ref(&incident), 0.2);

        assert_eq!(state.task_group.len(), 0);
        assert!(
            state.telegram_deferred.is_empty(),
            "deferred counter must NOT increment when Telegram is disabled"
        );
    }
}
