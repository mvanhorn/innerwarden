use std::io::Write;
use std::path::Path;

use tracing::{info, warn};

use innerwarden_killchain::tracker::PidTracker;

use crate::correlation_engine;

/// `comm` values whose events the kill chain tracker must ignore. These are
/// the platform's own thread names — the agent, sensor, and watchdog. Without
/// this list, routine agent activity (outbound threat-feed fetches +
/// credential file reads) trivially matches DATA_EXFIL against the agent
/// itself.
///
/// Linux `comm` is truncated to 15 characters (`TASK_COMM_LEN = 16` including
/// NUL), so the binary names below are already in their truncated form as
/// they appear in kernel events.
pub const KILLCHAIN_SELF_EXCLUDED_COMMS: &[&str] = &[
    "tokio-rt-worker", // tokio async runtime worker pool (15 chars)
    "innerwarden-age", // innerwarden-agent (truncated)
    "innerwarden-sen", // innerwarden-sensor (truncated)
    "innerwarden-wat", // innerwarden-watchdog (truncated)
];

/// Process a batch of sensor events through the kill chain tracker.
/// Returns incidents (JSON values) for any detected chains.
/// Also feeds the correlation engine with kill chain events.
pub(crate) fn process_events(
    tracker: &mut PidTracker,
    events: &[innerwarden_core::event::Event],
    correlation_engine: &mut correlation_engine::CorrelationEngine,
) -> Vec<serde_json::Value> {
    let mut all_incidents = Vec::new();

    for event in events {
        // Convert core Event to JSON for the killchain tracker.
        let json = event_to_tracker_json(event);
        let incidents = tracker.process_event(&json);

        for inc in &incidents {
            // Feed kill chain detections into the correlation engine.
            let pattern = inc
                .get("evidence")
                .and_then(|e| e.get("pattern"))
                .and_then(|p| p.as_str())
                .unwrap_or("unknown");

            let severity_str = inc
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("medium");

            let kind = format!("killchain.{}", pattern);
            let mut corr_event = correlation_engine::CorrelationEngine::killchain_event(
                &kind,
                serde_json::json!({
                    "pattern": pattern,
                    "severity": severity_str,
                    "pid": inc.get("evidence").and_then(|e| e.get("pid")),
                }),
            );
            // Phase 014-C: carry incident_id so link_correlated_incidents can
            // create CorrelatedWith edges if this kill chain pattern is part
            // of a larger multi-stage cross-layer attack chain.
            if let Some(iid) = inc.get("incident_id").and_then(|v| v.as_str()) {
                corr_event.incident_id = iid.to_string();
            }
            correlation_engine.observe(corr_event);
        }

        all_incidents.extend(incidents);
    }

    all_incidents
}

/// Write kill chain incidents to the daily JSONL file.
pub(crate) fn write_incidents(data_dir: &Path, incidents: &[serde_json::Value]) {
    if incidents.is_empty() {
        return;
    }

    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
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
            info!(count = incidents.len(), "killchain: emitted incidents");
        }
        Err(e) => warn!(error = %e, "killchain: failed to write incidents"),
    }
}

/// Notify via Telegram for critical kill chain detections.
/// Gated through the centralized notification gate.
pub(crate) fn notify_telegram(
    telegram_client: &Option<std::sync::Arc<crate::telegram::TelegramClient>>,
    incidents: &[serde_json::Value],
    burst_tracker: &crate::notification_gate::BurstTracker,
    deferred: &mut std::collections::HashMap<String, u32>,
) {
    let Some(tg) = telegram_client else { return };

    // Known service processes that legitimately do socket+dup (web gateways, proxies).
    const KILLCHAIN_COMM_ALLOWLIST: &[&str] = &[
        "ruby",
        "python",
        "python3",
        "node",
        "java",
        "beam.smp", // runtimes
        "nginx",
        "haproxy",
        "envoy",
        "caddy", // proxies
        "postgres",
        "mysqld",
        "redis-server", // databases
        "openclaw",
        "innerwarden", // our own
    ];

    for inc in incidents {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("medium");
        if severity != "critical" {
            continue;
        }

        // Skip known service processes (socket+dup is normal for them)
        let comm = inc
            .get("evidence")
            .and_then(|e| e.get("comm"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if KILLCHAIN_COMM_ALLOWLIST.iter().any(|a| comm.starts_with(a)) {
            continue;
        }

        // Gate through notification policy.
        let ctx = crate::notification_gate::NotificationContext::from_killchain_json(inc);
        let verdict = crate::notification_gate::should_notify(&ctx);

        match verdict {
            crate::notification_gate::NotificationVerdict::SendNow => {
                let title = inc
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Kill chain detected");
                let summary = inc.get("summary").and_then(|s| s.as_str()).unwrap_or("");
                let pattern = inc
                    .get("evidence")
                    .and_then(|e| e.get("pattern"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("unknown");

                let msg = format!(
                    "\u{26d3}\u{fe0f} <b>Kill Chain Alert</b>\n\n\
                     \u{1f534} CRITICAL\n\
                     <b>{title}</b>\n\
                     Pattern: {pattern}\n\
                     {summary}",
                );
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_alert_html(&msg).await;
                });
            }
            crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                *deferred.entry(ctx.detector.clone()).or_insert(0) += 1;
                if ctx.is_contained {
                    if let Some(count) = burst_tracker.record_contained() {
                        let msg = crate::notification_gate::format_burst_summary(count);
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let _ = tg.send_alert_html(&msg).await;
                        });
                    }
                }
                info!(
                    detector = %ctx.detector,
                    "killchain notification deferred to daily briefing"
                );
            }
            crate::notification_gate::NotificationVerdict::Drop => {}
        }
    }
}

/// Convert an innerwarden_core::Event to the JSON format expected by PidTracker.
fn event_to_tracker_json(event: &innerwarden_core::event::Event) -> serde_json::Value {
    serde_json::json!({
        "kind": event.kind,
        "source": event.source,
        "host": event.host,
        "ts": event.ts.to_rfc3339(),
        "details": event.details,
    })
}

/// Periodic maintenance: clean up stale PIDs from the tracker.
pub(crate) fn cleanup_stale(tracker: &mut PidTracker) {
    tracker.cleanup_stale();
}

/// Get tracker stats for telemetry/logging.
pub(crate) fn stats(tracker: &PidTracker) -> (usize, usize, usize) {
    tracker.stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    // event_to_tracker_json preserves key fields
    #[test]
    fn event_to_tracker_json_has_required_fields() {
        let event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "myhost".into(),
            kind: "syscall.execve".into(),
            source: "ebpf".into(),
            details: serde_json::json!({"pid": 1234, "comm": "bash"}),
            severity: innerwarden_core::event::Severity::Medium,
            summary: String::new(),
            tags: vec![],
            entities: vec![],
        };
        let json = event_to_tracker_json(&event);
        assert_eq!(json["kind"], "syscall.execve");
        assert_eq!(json["source"], "ebpf");
        assert_eq!(json["host"], "myhost");
        assert!(json["ts"].as_str().is_some());
        assert_eq!(json["details"]["pid"], 1234);
        assert_eq!(json["details"]["comm"], "bash");
    }

    // event_to_tracker_json handles empty details
    #[test]
    fn event_to_tracker_json_empty_details() {
        let event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            kind: "file.read".into(),
            source: "audit".into(),
            details: serde_json::json!({}),
            severity: innerwarden_core::event::Severity::Low,
            summary: String::new(),
            tags: vec![],
            entities: vec![],
        };
        let json = event_to_tracker_json(&event);
        assert_eq!(json["kind"], "file.read");
        assert!(json["details"].is_object());
    }

    // Self-exclusion: the platform's own thread names are all present and
    // each fits in Linux's 15-char comm limit.
    #[test]
    fn self_excluded_comms_cover_platform_threads_and_respect_comm_len() {
        const COMM_LEN: usize = 15;
        for name in KILLCHAIN_SELF_EXCLUDED_COMMS {
            assert!(
                name.len() <= COMM_LEN,
                "'{name}' exceeds {COMM_LEN}-char comm limit — kernel would truncate it and the match would never fire"
            );
        }
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"tokio-rt-worker"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-age"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-sen"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-wat"));
    }

    // Wiring: a tracker built with the self-exclusion list ignores events
    // attributed to the agent's tokio worker pool.
    #[test]
    fn tracker_configured_with_self_exclusions_drops_tokio_rt_worker() {
        let mut tracker = PidTracker::new()
            .with_excluded_comms(KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied());

        let connect = serde_json::json!({
            "kind": "network.outbound_connect",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 1234,
                "uid": 0,
                "comm": "tokio-rt-worker",
                "dst_ip": "1.1.1.1",
                "dst_port": 443
            }
        });
        let read = serde_json::json!({
            "kind": "file.read_access",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 1234,
                "uid": 0,
                "comm": "tokio-rt-worker",
                "filename": "/root/.ssh/id_rsa"
            }
        });

        assert!(tracker.process_event(&connect).is_empty());
        assert!(tracker.process_event(&read).is_empty());
        assert_eq!(tracker.stats(), (0, 0, 0));
    }

    // KILLCHAIN_COMM_ALLOWLIST prevents notification for known service processes
    #[test]
    fn comm_allowlist_blocks_known_services() {
        let allowlist: &[&str] = &[
            "ruby",
            "python",
            "python3",
            "node",
            "java",
            "beam.smp",
            "nginx",
            "haproxy",
            "envoy",
            "caddy",
            "postgres",
            "mysqld",
            "redis-server",
            "openclaw",
            "innerwarden",
        ];
        // Known services should be in the list
        assert!(allowlist.iter().any(|a| "nginx".starts_with(a)));
        assert!(allowlist.iter().any(|a| "python3".starts_with(a)));
        assert!(allowlist.iter().any(|a| "innerwarden-agent".starts_with(a)));
        // Unknown attacker binaries should NOT match
        assert!(!allowlist.iter().any(|a| "nc".starts_with(a)));
        assert!(!allowlist.iter().any(|a| "bash".starts_with(a)));
    }
}
