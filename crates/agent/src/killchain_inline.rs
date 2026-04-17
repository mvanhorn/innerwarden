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

/// Write kill chain incidents to the daily JSONL file **and** the unified
/// SQLite store (when available). The JSONL path is retained for legacy
/// consumers; SQLite is the source of truth for dashboard queries, attacker
/// intel, and monthly reports, so missing sqlite writes make kill chain
/// detections invisible to the rest of the agent.
pub(crate) fn write_incidents(
    data_dir: &Path,
    sqlite_store: Option<&innerwarden_store::Store>,
    incidents: &[serde_json::Value],
) {
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

    if let Some(store) = sqlite_store {
        let mut persisted = 0usize;
        for inc in incidents {
            match serde_json::from_value::<innerwarden_core::incident::Incident>(inc.clone()) {
                Ok(parsed) => {
                    if let Err(e) = store.insert_incident(&parsed) {
                        warn!(error = %e, "killchain: sqlite insert_incident failed");
                    } else {
                        persisted += 1;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "killchain: incident JSON did not match Incident schema");
                }
            }
        }
        if persisted > 0 {
            info!(persisted, "killchain: incidents persisted to sqlite");
        }
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
        let mut tracker =
            PidTracker::new().with_excluded_comms(KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied());

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

    // write_incidents must persist a conforming incident to the sqlite store
    // when one is provided, *and* to the JSONL file (unchanged legacy path).
    #[test]
    fn write_incidents_persists_to_sqlite_when_store_provided() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");

        let incident = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "testhost",
            "incident_id": "kill_chain:detected:DATA_EXFIL:999:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "Kill chain detected: DATA_EXFIL (PID 999, attacker)",
            "summary": "PID 999 (attacker) completed DATA_EXFIL pattern.",
            "evidence": [{"pattern": "DATA_EXFIL"}],
            "recommended_checks": [],
            "tags": ["kill_chain", "detected", "data_exfil"],
            "entities": []
        });

        write_incidents(tmp.path(), Some(&store), &[incident]);

        assert_eq!(store.incidents_count().unwrap(), 1);
        let found = store
            .get_incident("kill_chain:detected:DATA_EXFIL:999:2026-04-16T15:52Z")
            .unwrap();
        assert!(found.is_some(), "incident must be queryable by incident_id");

        let jsonl = std::fs::read_to_string(tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        )))
        .expect("jsonl written");
        assert!(jsonl.contains("DATA_EXFIL"));
    }

    // write_incidents without a store must still write JSONL and not panic.
    #[test]
    fn write_incidents_without_store_still_writes_jsonl() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let incident = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "testhost",
            "incident_id": "kill_chain:detected:REVERSE_SHELL:42:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "t",
            "summary": "s",
            "evidence": [],
            "recommended_checks": [],
            "tags": [],
            "entities": []
        });
        write_incidents(tmp.path(), None, &[incident]);
        let jsonl = std::fs::read_to_string(tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        )))
        .expect("jsonl written");
        assert!(jsonl.contains("REVERSE_SHELL"));
    }

    // A malformed incident (missing required fields) must not corrupt sqlite
    // and must be skipped with a warning — the rest of the batch still writes.
    #[test]
    fn write_incidents_skips_malformed_and_persists_valid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");

        let bad = serde_json::json!({"not_an_incident": true});
        let good = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "h",
            "incident_id": "kill_chain:detected:DATA_EXFIL:1:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "t",
            "summary": "s",
            "evidence": [],
            "recommended_checks": [],
            "tags": [],
            "entities": []
        });

        write_incidents(tmp.path(), Some(&store), &[bad, good]);

        assert_eq!(store.incidents_count().unwrap(), 1);
    }

    // An empty incident slice must be a cheap no-op — no JSONL file created,
    // no sqlite write attempted.
    #[test]
    fn write_incidents_empty_is_noop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");
        write_incidents(tmp.path(), Some(&store), &[]);
        assert_eq!(store.incidents_count().unwrap(), 0);

        let expected_jsonl = tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        ));
        assert!(
            !expected_jsonl.exists(),
            "no JSONL file should be created for empty input"
        );
    }

    // ─── Spec 024 contract tests ───────────────────────────────────────
    //
    // PidTracker::process_event contract:
    //   - Events whose `details.comm` matches `KILLCHAIN_SELF_EXCLUDED_COMMS`
    //     MUST NOT mutate tracker state. Self-exclusion is the whole reason
    //     the platform stopped DATA_EXFIL'ing itself in PR #124.
    //   - Events unrelated to kill-chain bits (e.g. a cold exec that is not
    //     in any known pattern) MUST NOT emit an incident.
    //   - When an event DOES advance a pattern, process_event returns a
    //     non-empty Vec. The specific contents are the PidTracker's own
    //     business; the agent contract is only about presence/absence.

    #[test]
    fn contract_excluded_comm_never_mutates_state() {
        let mut tracker =
            PidTracker::new().with_excluded_comms(KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied());
        let (pids_before, _, _) = tracker.stats();

        for comm in KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied() {
            let ev = serde_json::json!({
                "kind": "network.outbound_connect",
                "ts": chrono::Utc::now().to_rfc3339(),
                "host": "h",
                "details": {
                    "pid": 1111,
                    "uid": 0,
                    "comm": comm,
                    "dst_ip": "1.1.1.1",
                    "dst_port": 443
                }
            });
            let incidents = tracker.process_event(&ev);
            assert!(
                incidents.is_empty(),
                "self-excluded comm '{comm}' must never emit incidents"
            );
        }
        let (pids_after, _, _) = tracker.stats();
        assert_eq!(
            pids_before, pids_after,
            "self-excluded comms must not mutate tracker state"
        );
    }

    #[test]
    fn contract_innocent_event_emits_no_incidents() {
        // A noop event must produce a Vec with zero incidents. We assert
        // on length (Vec API) rather than identity so the storage layer is
        // free to change.
        let mut tracker = PidTracker::new();
        let ev = serde_json::json!({
            "kind": "file.read_access",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 9999,
                "uid": 1000,
                "comm": "user-shell",
                "filename": "/home/user/.bashrc"
            }
        });
        let out: Vec<serde_json::Value> = tracker.process_event(&ev);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn contract_returns_vec_not_option() {
        // Signature check: if someone ever changes process_event to return
        // Option<Incident> (which it *has* looked like in the past), scenario
        // and replay pipelines that iterate will silently lose batches.
        let mut tracker = PidTracker::new();
        let out: Vec<serde_json::Value> = tracker.process_event(&serde_json::json!({
            "kind": "noop",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {"pid": 1, "comm": "init"}
        }));
        // Vec is iterable by reference and by value. Both compile ⇒ contract holds.
        let _ = out.iter().count();
        let _ = out.into_iter().count();
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
