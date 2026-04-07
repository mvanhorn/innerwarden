//! Kill chain detector — processes lsm.exec_blocked events and creates enriched incidents.

use serde_json::{json, Value};

use crate::patterns;
use crate::tracker::PidTracker;

/// Process an `lsm.exec_blocked` event and produce an enriched incident if applicable.
///
/// Returns `Some(incident)` when the event represents a kernel LSM block triggered by
/// the kill chain eBPF program, or `None` if the event is irrelevant.
pub fn process_lsm_blocked(event: &Value, tracker: &PidTracker) -> Option<Value> {
    // 1. Check event kind == "lsm.exec_blocked"
    let kind = event.get("kind")?.as_str()?;
    if kind != "lsm.exec_blocked" {
        return None;
    }

    // 2. Check filename contains "KILL_CHAIN_BLOCKED" (kernel marker)
    let details = event.get("details")?;
    let filename = details.get("filename")?.as_str()?;
    if !filename.contains("KILL_CHAIN_BLOCKED") {
        return None;
    }

    // 3. Extract pid, uid, comm, filename from event details
    let pid = details.get("pid")?.as_u64()? as u32;
    let uid = details.get("uid")?.as_u64()? as u32;
    let comm = details.get("comm")?.as_str().unwrap_or("unknown");
    let ts = event
        .get("ts")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let host = event
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // 4. Look up PidChainState from tracker (if available)
    match tracker.get_state(pid) {
        Some(state) => {
            // 5. State found: build enriched incident with timeline, C2 IP, chain flags, pattern name
            let pattern_name = patterns::best_match(state.flags)
                .unwrap_or("unknown")
                .to_uppercase();
            let chain_bits: Vec<String> = patterns::flag_names(state.flags)
                .iter()
                .map(|s| s.to_uppercase())
                .collect();
            let chain_flags_hex = format!("0x{:02x}", state.flags);

            let c2_ip = state
                .last_connect_ip
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let c2_port = state.last_connect_port.unwrap_or(0);

            let timeline: Vec<Value> = state
                .events
                .iter()
                .map(|ev| {
                    json!({
                        "ts": ev.ts.to_rfc3339(),
                        "syscall": ev.syscall,
                        "details": ev.details,
                        "flag_set": ev.flag_set,
                    })
                })
                .collect();

            let incident_id = format!("kill_chain:blocked:{}:{}:{}", pattern_name, pid, ts);

            let title = format!(
                "Kill chain BLOCKED: {} (PID {}, {})",
                pattern_name, pid, comm
            );

            let summary = format!(
                "Kernel LSM blocked execve() for PID {} ({}) after detecting {} pattern. \
                 The process was denied execution of {}.",
                pid, comm, pattern_name, filename
            );

            let mut recommended_checks =
                vec![format!("Investigate process tree: pstree -p {}", pid)];
            if c2_ip != "unknown" {
                recommended_checks.push(format!("Block C2 IP: innerwarden block {}", c2_ip));
            }
            recommended_checks.push("Check for lateral movement from this host".to_string());
            recommended_checks.push(format!("Review user account uid={} for compromise", uid));

            let mut entities = Vec::new();
            if c2_ip != "unknown" {
                entities.push(json!({"type": "ip", "value": c2_ip}));
            }

            let mut tags = vec![
                "kill_chain".to_string(),
                "lsm_blocked".to_string(),
                pattern_name.to_lowercase(),
                "ebpf".to_string(),
            ];
            // Deduplicate tags
            tags.dedup();

            Some(json!({
                "ts": ts,
                "host": host,
                "incident_id": incident_id,
                "severity": "critical",
                "title": title,
                "summary": summary,
                "evidence": [{
                    "kind": "kill_chain_blocked",
                    "pattern": pattern_name,
                    "pid": pid,
                    "uid": uid,
                    "comm": comm,
                    "filename": filename,
                    "chain_flags": chain_flags_hex,
                    "chain_bits": chain_bits,
                    "c2_ip": c2_ip,
                    "c2_port": c2_port,
                    "timeline": timeline,
                }],
                "recommended_checks": recommended_checks,
                "tags": tags,
                "entities": entities,
            }))
        }
        None => {
            // 6. State NOT found: build basic incident with just the event data
            let incident_id = format!("kill_chain:blocked:UNKNOWN:{}:{}", pid, ts);

            let title = format!("Kill chain BLOCKED: UNKNOWN (PID {}, {})", pid, comm);

            let summary = format!(
                "Kernel LSM blocked execve() for PID {} ({}) but no chain state was found in \
                 the tracker. The process was denied execution of {}.",
                pid, comm, filename
            );

            Some(json!({
                "ts": ts,
                "host": host,
                "incident_id": incident_id,
                "severity": "critical",
                "title": title,
                "summary": summary,
                "evidence": [{
                    "kind": "kill_chain_blocked",
                    "pattern": "UNKNOWN",
                    "pid": pid,
                    "uid": uid,
                    "comm": comm,
                    "filename": filename,
                    "chain_flags": "0x00",
                    "chain_bits": [],
                    "c2_ip": null,
                    "c2_port": null,
                    "timeline": [],
                }],
                "recommended_checks": [
                    format!("Investigate process tree: pstree -p {}", pid),
                    "Check for lateral movement from this host".to_string(),
                    format!("Review user account uid={} for compromise", uid),
                ],
                "tags": ["kill_chain", "lsm_blocked", "ebpf"],
                "entities": [],
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    use crate::types::{ChainEvent, PidChainState};

    /// Helper to build a tracker with a single PID's chain state.
    fn tracker_with_state(state: PidChainState) -> PidTracker {
        let mut tracker = PidTracker::new();
        tracker.insert_state(state);
        tracker
    }

    /// Helper to build a standard lsm.exec_blocked event.
    fn lsm_blocked_event(pid: u32, uid: u32, comm: &str, filename: &str) -> Value {
        json!({
            "kind": "lsm.exec_blocked",
            "ts": "2026-03-26T12:00:00Z",
            "host": "node-1",
            "details": {
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "filename": filename,
            }
        })
    }

    #[test]
    fn test_lsm_blocked_with_tracker_data_produces_full_incident() {
        let now = Utc::now();
        let mut state = PidChainState::new(1234, 1000, "python3".into(), "node-1".into(), now);
        state.flags = patterns::PATTERN_REVERSE_SHELL;
        state.last_connect_ip = Some("185.234.1.1".into());
        state.last_connect_port = Some(4444);
        state.events.push(ChainEvent {
            ts: now,
            syscall: "connect".into(),
            details: json!({"fd": 3, "addr": "185.234.1.1:4444"}),
            flag_set: patterns::CHAIN_SOCKET,
        });

        let tracker = tracker_with_state(state);
        let event = lsm_blocked_event(1234, 1000, "python3", "/bin/sh KILL_CHAIN_BLOCKED");
        let incident = process_lsm_blocked(&event, &tracker);

        assert!(incident.is_some());
        let inc = incident.unwrap();
        assert_eq!(inc["severity"], "critical");
        assert!(inc["title"].as_str().unwrap().contains("REVERSE_SHELL"));
        assert!(inc["title"].as_str().unwrap().contains("1234"));
        assert!(inc["title"].as_str().unwrap().contains("python3"));

        let evidence = &inc["evidence"][0];
        assert_eq!(evidence["pattern"], "REVERSE_SHELL");
        assert_eq!(evidence["pid"], 1234);
        assert_eq!(evidence["c2_ip"], "185.234.1.1");
        assert_eq!(evidence["c2_port"], 4444);
        assert!(evidence["chain_bits"].as_array().unwrap().len() > 0);
        assert!(evidence["timeline"].as_array().unwrap().len() > 0);

        // Check entities contain the C2 IP
        let entities = inc["entities"].as_array().unwrap();
        assert_eq!(entities[0]["type"], "ip");
        assert_eq!(entities[0]["value"], "185.234.1.1");
    }

    #[test]
    fn test_lsm_blocked_without_tracker_data_produces_basic_incident() {
        let tracker = PidTracker::new();
        let event = lsm_blocked_event(5678, 1001, "bash", "/usr/bin/curl KILL_CHAIN_BLOCKED");
        let incident = process_lsm_blocked(&event, &tracker);

        assert!(incident.is_some());
        let inc = incident.unwrap();
        assert_eq!(inc["severity"], "critical");
        assert!(inc["title"].as_str().unwrap().contains("UNKNOWN"));
        assert!(inc["title"].as_str().unwrap().contains("5678"));

        let evidence = &inc["evidence"][0];
        assert_eq!(evidence["pattern"], "UNKNOWN");
        assert_eq!(evidence["pid"], 5678);
        assert!(evidence["c2_ip"].is_null());
        assert!(evidence["timeline"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_non_lsm_event_returns_none() {
        let tracker = PidTracker::new();
        let event = json!({
            "kind": "syscall.connect",
            "ts": "2026-03-26T12:00:00Z",
            "host": "node-1",
            "details": {
                "pid": 1234,
                "uid": 1000,
                "comm": "python3",
                "filename": "KILL_CHAIN_BLOCKED",
            }
        });
        assert!(process_lsm_blocked(&event, &tracker).is_none());
    }

    #[test]
    fn test_lsm_event_without_kill_chain_marker_returns_none() {
        let tracker = PidTracker::new();
        let event = json!({
            "kind": "lsm.exec_blocked",
            "ts": "2026-03-26T12:00:00Z",
            "host": "node-1",
            "details": {
                "pid": 1234,
                "uid": 1000,
                "comm": "python3",
                "filename": "/bin/sh",
            }
        });
        assert!(process_lsm_blocked(&event, &tracker).is_none());
    }
}
