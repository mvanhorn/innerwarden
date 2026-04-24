use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::{config, AgentState};

/// Load suppressed incident IDs from file (one pattern per line).
/// Users can add patterns via `innerwarden suppress <pattern>`.
pub(crate) fn load_suppressed_ids(data_dir: &Path) -> HashSet<String> {
    let path = data_dir.join("suppressed-incidents.txt");
    match std::fs::read_to_string(&path) {
        Ok(content) => parse_suppressed_ids(&content),
        Err(_) => HashSet::new(),
    }
}

/// Detect if running inside a virtual machine.
/// Uses cached hypervisor environment when available (from hypervisor_tick),
/// falls back to basic detection if hypervisor audit hasn't run yet.
fn is_virtual_machine(state: &AgentState) -> bool {
    if state.hypervisor_environment.is_some() {
        return crate::hypervisor_tick::is_virtual_machine(state);
    }
    // Fallback: basic detection before first hypervisor tick.
    Path::new("/sys/hypervisor/type").exists()
        || std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .map(|s| {
                let l = s.to_lowercase();
                l.contains("virtual")
                    || l.contains("kvm")
                    || l.contains("qemu")
                    || l.contains("vmware")
            })
            .unwrap_or(false)
        || std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.contains("hypervisor"))
            .unwrap_or(false)
}

/// Periodic firmware audit. Runs innerwarden-smm's full_audit(), compares
/// against baseline, and emits incidents when trust degrades or threats correlate.
pub(crate) async fn process_firmware_tick(
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    use innerwarden_core::incident::Incident;
    use std::io::Write;

    // Run the full firmware audit (blocking I/O — spawn_blocking).
    let data_dir_owned = data_dir.to_path_buf();
    let report = match tokio::task::spawn_blocking(move || {
        // Override baseline path to use agent's data_dir.
        let baseline_path = data_dir_owned.join("firmware_baseline.json");
        if !baseline_path.exists() {
            // Auto-capture baseline on first run.
            let baseline = innerwarden_smm::baseline::FirmwareBaseline::capture();
            if let Err(e) = baseline.save(&baseline_path) {
                tracing::warn!(error = %e, "firmware: failed to save initial baseline");
            } else {
                tracing::info!("firmware: initial baseline captured");
            }
        }
        innerwarden_smm::full_audit()
    })
    .await
    {
        Ok(report) => report,
        Err(e) => {
            warn!(error = %e, "firmware tick: audit task panicked");
            return;
        }
    };

    let host = std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");

    let mut incidents = Vec::new();

    // Check trust score degradation.
    if report.trust_score < cfg.firmware.trust_score_threshold {
        let incident_id = format!(
            "firmware:trust_degraded:{}",
            (report.trust_score * 100.0) as u32
        );

        // --- Cooldown: don't emit same firmware incident more than once per 24h ---
        if let Some(last) = state.last_firmware_incident_at {
            let hours_since = (chrono::Utc::now() - last).num_hours();
            if hours_since < 24 {
                tracing::debug!(
                    hours_since,
                    "firmware: trust_degraded cooldown active, skipping"
                );
                return;
            }
        }

        // --- Suppression: check if user suppressed this incident type ---
        if state
            .suppressed_incident_ids
            .iter()
            .any(|pat| incident_id.contains(pat))
        {
            tracing::debug!(incident_id, "firmware: incident suppressed by user");
            return;
        }

        // --- VM detection: reduce severity on VMs where firmware is inaccessible ---
        let on_vm = is_virtual_machine(state);
        let severity = classify_firmware_trust_severity(report.trust_score, on_vm);

        // On VMs with Info severity, skip generating an incident entirely
        if should_skip_vm_trust_incident(on_vm, &severity) {
            tracing::debug!(
                trust_score = format!("{:.0}%", report.trust_score * 100.0),
                "firmware: VM detected, skipping trust_degraded incident"
            );
            return;
        }
        let critical_checks: Vec<String> = report
            .checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Critical)
            .map(|c| format!("[{}] {}", c.id, c.name))
            .collect();

        // Update cooldown timestamp
        state.last_firmware_incident_at = Some(chrono::Utc::now());

        incidents.push(Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: incident_id.clone(),
            severity,
            title: format!(
                "Firmware trust score degraded to {:.0}%",
                report.trust_score * 100.0
            ),
            summary: format!(
                "Trust score {:.0}% (threshold: {:.0}%). Critical checks: {}",
                report.trust_score * 100.0,
                cfg.firmware.trust_score_threshold * 100.0,
                if critical_checks.is_empty() {
                    "none".to_string()
                } else {
                    critical_checks.join(", ")
                },
            ),
            evidence: serde_json::json!({
                "trust_score": report.trust_score,
                "threshold": cfg.firmware.trust_score_threshold,
                "checks": report.checks.iter()
                    .filter(|c| c.status != innerwarden_smm::CheckStatus::Unavailable)
                    .map(|c| serde_json::json!({
                        "id": c.id,
                        "name": c.name,
                        "status": format!("{:?}", c.status),
                        "confidence": c.confidence,
                    }))
                    .collect::<Vec<_>>(),
            }),
            recommended_checks: vec![
                "Review firmware audit: innerwarden-smm".into(),
                "Check for unauthorized firmware modifications".into(),
            ],
            tags: vec!["firmware".to_string(), "ring-minus-2".to_string()],
            entities: vec![],
        });
    }

    // Emit incidents for correlated threats.
    for threat in &report.correlated_threats {
        incidents.push(Incident {
            ts: chrono::Utc::now(),
            host: host.clone(),
            incident_id: format!("firmware:corr:{}", threat.id),
            severity: classify_correlated_threat_severity(threat.confidence),
            title: threat.name.clone(),
            summary: threat.detail.clone(),
            evidence: serde_json::json!({
                "correlation_id": threat.id,
                "confidence": threat.confidence,
                "evidence": threat.evidence,
            }),
            recommended_checks: vec!["Run innerwarden-smm for full report".into()],
            tags: vec![
                "firmware".to_string(),
                "correlated".to_string(),
                "ring-minus-2".to_string(),
            ],
            entities: vec![],
        });
    }

    if incidents.is_empty() {
        let secure = report
            .checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Secure)
            .count();
        tracing::debug!(
            trust_score = format!("{:.0}%", report.trust_score * 100.0),
            secure_checks = secure,
            "firmware tick: all clear"
        );
        return;
    }

    // Write incidents to JSONL.
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            for inc in &incidents {
                if let Ok(line) = serde_json::to_string(inc) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        Err(e) => warn!(error = %e, "firmware tick: failed to write incidents"),
    }

    info!(
        count = incidents.len(),
        trust_score = format!("{:.0}%", report.trust_score * 100.0),
        "firmware tick: emitted incidents"
    );

    // Telegram notification for firmware incidents (gated).
    if let Some(ref tg) = state.telegram_client {
        for inc in &incidents {
            let ctx = crate::notification_gate::NotificationContext::from_firmware_or_hypervisor(
                inc, "firmware",
            );
            let gate_counter = state.telemetry.gate_suppressed_counter();
            let verdict =
                crate::notification_gate::should_notify_with_counter(&ctx, gate_counter.as_ref());
            match verdict {
                crate::notification_gate::NotificationVerdict::SendNow => {
                    let sev = match inc.severity {
                        innerwarden_core::event::Severity::Critical => "\u{1f534} CRITICAL",
                        innerwarden_core::event::Severity::High => "\u{1f7e0} HIGH",
                        _ => "\u{1f7e1} MEDIUM",
                    };
                    let msg = format!(
                        "\u{1f527} <b>Firmware Alert</b>\n\n\
                         {sev}\n\
                         <b>{}</b>\n\
                         {}\n\n\
                         Trust Score: {:.0}%",
                        inc.title,
                        inc.summary,
                        report.trust_score * 100.0,
                    );
                    let tg = tg.clone();
                    try_spawn_firmware_alert(
                        &state.task_group,
                        Box::pin(async move {
                            let _ = tg.send_alert_html(&msg).await;
                        }),
                    );
                }
                crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                    *state
                        .telegram_deferred
                        .entry("firmware".to_string())
                        .or_insert(0) += 1;
                }
                crate::notification_gate::NotificationVerdict::Drop => {}
            }
        }
    }
}

fn parse_suppressed_ids(content: &str) -> HashSet<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn classify_firmware_trust_severity(score: f64, on_vm: bool) -> innerwarden_core::event::Severity {
    if on_vm {
        innerwarden_core::event::Severity::Info
    } else if score < 0.3 {
        innerwarden_core::event::Severity::Critical
    } else if score < 0.6 {
        innerwarden_core::event::Severity::High
    } else {
        innerwarden_core::event::Severity::Medium
    }
}

fn should_skip_vm_trust_incident(
    on_vm: bool,
    severity: &innerwarden_core::event::Severity,
) -> bool {
    on_vm && matches!(severity, innerwarden_core::event::Severity::Info)
}

fn classify_correlated_threat_severity(confidence: f64) -> innerwarden_core::event::Severity {
    if confidence >= 0.9 {
        innerwarden_core::event::Severity::Critical
    } else if confidence >= 0.7 {
        innerwarden_core::event::Severity::High
    } else {
        innerwarden_core::event::Severity::Medium
    }
}

/// Register a firmware alert task on the agent's TaskGroup.
///
/// Spec 036 PR-2: the alert is a single HTTP call (transactional) and
/// deliberately does NOT observe `token.cancelled()` — dropping an
/// alert mid-send loses the notification silently, which is worse
/// than letting a short call complete within the shutdown deadline.
/// The operator's knob is the deadline.
///
/// If the TaskGroup is already shut down, `spawn` returns
/// `Err(TaskGroupError::Closed)`; we surface that via `tracing::warn!`
/// so the operator sees the dropped alert. No silent drop — the
/// primitive's explicit error is what lets us log here.
///
/// Accepts a type-erased boxed future on purpose: generic
/// `impl Future` caused per-call-site monomorphization that split
/// line-coverage reporting (the production monomorphization inside
/// `process_firmware_tick` was treated as distinct from the tests'
/// monomorphization and flagged as uncovered). The `Pin<Box<dyn …>>`
/// boundary collapses every caller into a single monomorphization
/// so the helper body is covered exactly once — see PR #274 for the
/// codecov-driven diagnosis.
type BoxedAlertFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

fn try_spawn_firmware_alert(task_group: &crate::task_group::TaskGroup, alert: BoxedAlertFuture) {
    if let Err(e) = task_group.spawn("firmware-alert", alert) {
        tracing::warn!(
            error = %e,
            "firmware-alert spawn rejected: TaskGroup closed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    #[test]
    fn parse_suppressed_ids_ignores_comments_and_blanks() {
        // Ensures suppression file parsing keeps only valid incident-id patterns.
        let parsed = parse_suppressed_ids("# comment\n\nfirmware:trust_degraded\n  hypervisor  \n");
        assert!(parsed.contains("firmware:trust_degraded"));
        assert!(parsed.contains("hypervisor"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn classify_firmware_trust_severity_downgrades_to_info_on_vm() {
        // Covers VM branch where firmware telemetry is less reliable and should not escalate.
        assert!(matches!(
            classify_firmware_trust_severity(0.1, true),
            Severity::Info
        ));
    }

    #[test]
    fn classify_firmware_trust_severity_uses_score_bands_on_bare_metal() {
        // Verifies trust-score thresholds map to stable severity levels off-VM.
        assert!(matches!(
            classify_firmware_trust_severity(0.2, false),
            Severity::Critical
        ));
        assert!(matches!(
            classify_firmware_trust_severity(0.5, false),
            Severity::High
        ));
        assert!(matches!(
            classify_firmware_trust_severity(0.8, false),
            Severity::Medium
        ));
    }

    #[test]
    fn should_skip_vm_trust_incident_only_for_vm_info_cases() {
        // Guards skip logic so only VM + Info combinations suppress trust incidents.
        assert!(should_skip_vm_trust_incident(true, &Severity::Info));
        assert!(!should_skip_vm_trust_incident(false, &Severity::Info));
        assert!(!should_skip_vm_trust_incident(true, &Severity::High));
    }

    #[test]
    fn classify_correlated_threat_severity_follows_confidence_thresholds() {
        // Confirms correlated threat confidence translates to deterministic severity bands.
        assert!(matches!(
            classify_correlated_threat_severity(0.95),
            Severity::Critical
        ));
        assert!(matches!(
            classify_correlated_threat_severity(0.75),
            Severity::High
        ));
        assert!(matches!(
            classify_correlated_threat_severity(0.50),
            Severity::Medium
        ));
    }

    // ─────────────────────────────────────────────────────────────────
    // Spec 036 PR-2 migration anchors — try_spawn_firmware_alert
    // ─────────────────────────────────────────────────────────────────
    //
    // The migration in `process_firmware_tick` now goes through
    // `try_spawn_firmware_alert`. These tests drive that helper
    // directly so both the Ok and Err branches are line-covered —
    // previously the Err branch (the `tracing::warn!` for a closed
    // TaskGroup) was unreachable from any fixture and codecov flagged
    // it as uncovered. Driving the helper avoids fixturing a full
    // firmware audit run and still anchors the real invariants:
    //
    //   - Ok path: alert future is registered in the TaskGroup and
    //     runs to completion under `shutdown()`.
    //   - Err path: a closed TaskGroup drops the alert with a
    //     visible `warn!` — NEVER silently.

    #[tokio::test]
    async fn try_spawn_firmware_alert_registers_and_drains_the_alert() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let tg = crate::task_group::TaskGroup::new();
        let sent = Arc::new(AtomicBool::new(false));
        let sent_c = sent.clone();

        // Stand-in for `tg.send_alert_html(&msg).await`. The helper
        // takes a type-erased boxed future so callers (test + prod)
        // share one monomorphization — see the helper's doc comment.
        try_spawn_firmware_alert(
            &tg,
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(15)).await;
                sent_c.store(true, Ordering::SeqCst);
            }),
        );

        assert_eq!(tg.len(), 1, "alert must be tracked in the group");

        let report = tg.shutdown(Duration::from_secs(1)).await;
        assert_eq!(report.total, 1);
        assert_eq!(
            report.joined, 1,
            "alert must complete within deadline, not be abandoned"
        );
        assert_eq!(report.timed_out, 0);
        assert!(
            sent.load(Ordering::SeqCst),
            "alert body must have run — if this fails the helper dropped the future"
        );
    }

    #[tokio::test]
    async fn try_spawn_firmware_alert_warns_and_drops_when_group_closed() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let tg = crate::task_group::TaskGroup::new();
        let _ = tg.shutdown(Duration::from_millis(50)).await;

        // The alert future would set this to true — it must NOT run
        // because the group is closed. Operator-visible evidence that
        // the Err branch dropped the future intentionally (not by
        // accident).
        let ran = Arc::new(AtomicBool::new(false));
        let ran_c = ran.clone();

        // The helper returns `()` for both branches — the Err side
        // logs `tracing::warn!` and returns, NEVER panics, NEVER
        // silently spawns. This call exercises exactly that line.
        try_spawn_firmware_alert(
            &tg,
            Box::pin(async move {
                ran_c.store(true, Ordering::SeqCst);
            }),
        );

        // Group must not have a tracked task — the spawn returned Err
        // and the future was dropped.
        assert_eq!(
            tg.len(),
            0,
            "closed group must reject spawn, future must be dropped"
        );
        assert!(
            !ran.load(Ordering::SeqCst),
            "alert body must NOT have run — the future was dropped, not executed"
        );
    }
}
