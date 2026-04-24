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
    notify_telegram(state, &incidents, report.trust_score);
}

/// Dispatch Telegram notifications for a batch of firmware incidents
/// according to the shared notification gate. Extracted from the
/// inline loop in `process_firmware_tick` so the SendNow → spawn
/// path is unit-testable without fixturing a full `innerwarden_smm`
/// audit run — see spec 036 PR-5 and the `notify_telegram_*` tests
/// below.
fn notify_telegram(
    state: &mut AgentState,
    incidents: &[innerwarden_core::incident::Incident],
    trust_score: f64,
) {
    let Some(tg) = state.telegram_client.clone() else {
        return;
    };
    for inc in incidents {
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
                    trust_score * 100.0,
                );
                let tg = tg.clone();
                // Spec 036 PR-5: register the alert in the agent's
                // TaskGroup so SIGTERM drain waits for it. Same
                // design as PR-2's telegram-polling and PR-4's
                // honeypot listener. Body does NOT observe
                // `token.cancelled()` — dropping a firmware alert
                // mid-send loses the notification silently, which is
                // worse than letting a short HTTP call complete
                // within the shutdown deadline.
                state.task_group.spawn_or_log(
                    "firmware-alert",
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
    // Spec 036 PR-5 migration anchors — notify_telegram
    // ─────────────────────────────────────────────────────────────────
    //
    // The migration in `process_firmware_tick` now goes through
    // `notify_telegram`. These tests drive that helper directly so
    // the SendNow → `state.task_group.spawn_or_log(...)` path is
    // line-covered without fixturing a full `innerwarden_smm`
    // audit run.
    //
    // Verdict steering from `notification_gate::evaluate_verdict`:
    //   - SendNow: severity=Critical AND tag is one of
    //       {"rootkit", "firmware_tampering", "msr_write",
    //        "spi_flash"} (the "is_compromise" path).
    //   - DailyBriefingOnly: any other (default path for
    //     firmware/hypervisor contexts, which set
    //     is_active_intrusion=false and is_contained=false).
    //   - Drop: not reachable for firmware-tick contexts.
    //
    // The Ok-path test also exercises PR-2's `spawn_or_log` primitive
    // through its real caller — the same coverage-risk line that
    // blocked PR-2 is now landed via this direct test on the
    // extracted helper.

    fn make_firmware_incident(
        title: &str,
        severity: innerwarden_core::event::Severity,
        tags: Vec<&str>,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("firmware:test:{title}").replace(' ', "_"),
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
        // Invalid bot token → Telegram API responds with 401 quickly
        // if the spawned future ever gets polled. The tests assert
        // registration (tg.len()) and then call shutdown with a
        // short deadline, so whether the HTTP call completes or
        // gets abandoned is irrelevant to the assertion.
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
    async fn notify_telegram_registers_firmware_alert_in_task_group_on_send_now() {
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(make_test_telegram_client());

        // Critical + rootkit tag → evaluates to SendNow via
        // `is_compromise` rule in notification_gate.
        let incident = make_firmware_incident(
            "Rootkit signature detected",
            innerwarden_core::event::Severity::Critical,
            vec!["rootkit"],
        );

        // Invoke the migrated helper. Internally calls
        // `state.task_group.spawn_or_log("firmware-alert", ...)`.
        notify_telegram(&mut state, std::slice::from_ref(&incident), 0.3);

        assert_eq!(
            state.task_group.len(),
            1,
            "SendNow verdict MUST register a 'firmware-alert' task in the TaskGroup"
        );

        // Drain the group so the fire-and-forget HTTP call is
        // either completed or cleanly abandoned — don't leak a
        // runtime task across test boundaries.
        let report = state.task_group.shutdown(Duration::from_millis(100)).await;
        assert_eq!(report.total, 1);
        // Not asserted: joined vs timed_out. The HTTP call hitting
        // api.telegram.org with a junk token may or may not complete
        // within 100 ms; either outcome is valid for the contract
        // under test (which is "spawn registered").
    }

    #[tokio::test]
    async fn notify_telegram_defers_and_does_not_spawn_on_non_compromise_critical() {
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(make_test_telegram_client());

        // Critical severity but NO compromise tag → default rule:
        // DailyBriefingOnly. Guards against a refactor that
        // accidentally widened the SendNow predicate.
        let incident = make_firmware_incident(
            "Trust score degraded",
            innerwarden_core::event::Severity::Critical,
            vec!["firmware"], // not in the compromise tag set
        );

        notify_telegram(&mut state, std::slice::from_ref(&incident), 0.5);

        assert_eq!(
            state.task_group.len(),
            0,
            "DailyBriefingOnly MUST NOT spawn a task; incident is deferred to the daily digest"
        );
        assert_eq!(
            state
                .telegram_deferred
                .get("firmware")
                .copied()
                .unwrap_or(0),
            1,
            "deferred counter must increment so the daily digest picks up this incident"
        );

        // Shutdown is a no-op on an empty group but keeps the test
        // symmetric with the SendNow variant.
        let report = state.task_group.shutdown(Duration::from_millis(50)).await;
        assert_eq!(report.total, 0);
    }

    #[tokio::test]
    async fn notify_telegram_is_noop_when_telegram_client_absent() {
        // Guards the early-return: when the agent is configured
        // without a Telegram client, the helper must not touch
        // state flags or spawn anything.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = None;

        let incident = make_firmware_incident(
            "Should never reach the gate",
            innerwarden_core::event::Severity::Critical,
            vec!["rootkit"],
        );

        notify_telegram(&mut state, std::slice::from_ref(&incident), 0.1);

        assert_eq!(state.task_group.len(), 0);
        assert!(
            state.telegram_deferred.is_empty(),
            "deferred counter must NOT increment when Telegram is disabled"
        );
    }
}
