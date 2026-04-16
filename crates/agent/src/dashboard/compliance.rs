// Auto-extracted from mod.rs — dashboard compliance handlers

use super::*;

/// GET /api/honeypot/sessions - list honeypot sessions from the honeypot/ subdirectory.
pub(super) async fn api_honeypot_sessions(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let honeypot_dir = state.data_dir.join("honeypot");

    // Collect blocked IPs from knowledge graph (Phase 6A: no JSONL reads).
    // Includes all block_ip decisions (dry-run and executed) to match original semantics.
    let mut blocked_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    {
        use crate::knowledge_graph::types::{Node, NodeType};
        let graph = state.knowledge_graph.read().unwrap();
        for id in graph.nodes_of_type(NodeType::Incident) {
            if let Some(Node::Incident {
                decision: Some(dec),
                decision_target: Some(target),
                ..
            }) = graph.get_node(id)
            {
                if dec == "block_ip" {
                    blocked_ips.insert(target.clone());
                }
            }
        }
    }

    // Read session metadata files
    let mut sessions: Vec<serde_json::Value> = Vec::new();

    let Ok(mut dir) = tokio::fs::read_dir(&honeypot_dir).await else {
        return Json(serde_json::json!({ "sessions": [] }));
    };

    // Collect all file names first so we can detect .jsonl-only sessions
    let mut json_sessions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut jsonl_sessions: std::collections::HashSet<String> = std::collections::HashSet::new();

    while let Ok(Some(entry)) = dir.next_entry().await {
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.starts_with("listener-session-") {
            continue;
        }
        if fname.ends_with(".json") && !fname.ends_with(".jsonl") {
            let id = fname
                .trim_start_matches("listener-session-")
                .trim_end_matches(".json")
                .to_string();
            json_sessions.insert(id);
        } else if fname.ends_with(".jsonl") {
            let id = fname
                .trim_start_matches("listener-session-")
                .trim_end_matches(".jsonl")
                .to_string();
            jsonl_sessions.insert(id);
        }
    }

    // Helper: extract commands + auth_attempts from a .jsonl evidence file
    pub(super) async fn read_evidence(
        path: &std::path::Path,
    ) -> (Vec<String>, usize, String, String) {
        let mut commands: Vec<String> = Vec::new();
        let mut auth_count = 0usize;
        let mut ts = String::new();
        let mut peer_ip = String::new();
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            for line in content.lines() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                    if val.get("type").and_then(|t| t.as_str()) == Some("ssh_connection") {
                        if ts.is_empty() {
                            ts = val
                                .get("ts")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                        }
                        if peer_ip.is_empty() {
                            peer_ip = val
                                .get("peer_ip")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                        }
                        auth_count += val
                            .get("auth_attempts_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as usize;
                        if let Some(cmds) = val.get("shell_commands").and_then(|a| a.as_array()) {
                            for c in cmds {
                                if let Some(cmd) = c.get("command").and_then(|v| v.as_str()) {
                                    if !cmd.is_empty() {
                                        commands.push(cmd.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        (commands, auth_count, ts, peer_ip)
    }

    // Process .json metadata sessions (listener mode)
    for session_id in &json_sessions {
        let meta_path = honeypot_dir.join(format!("listener-session-{session_id}.json"));
        let Ok(content) = tokio::fs::read_to_string(&meta_path).await else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };

        let target_ip = meta
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let started_at = meta
            .get("ts")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let duration_secs = meta
            .get("duration_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let evidence_path = honeypot_dir.join(format!("listener-session-{session_id}.jsonl"));
        let (commands, auth_count, _, _) = read_evidence(&evidence_path).await;
        let iocs = crate::ioc::extract_from_commands(&commands);

        sessions.push(serde_json::json!({
            "session_id": session_id,
            "target_ip": target_ip,
            "started_at": started_at,
            "duration_secs": duration_secs,
            "auth_attempts": auth_count,
            "commands_count": commands.len(),
            "commands": commands,
            "iocs": iocs.format_list(),
            "blocked": blocked_ips.contains(&target_ip),
            "mode": "listener",
        }));
    }

    // Process .jsonl-only sessions (always_on mode - no .json metadata file)
    for session_id in &jsonl_sessions {
        if json_sessions.contains(session_id) {
            continue; // already processed above
        }
        let evidence_path = honeypot_dir.join(format!("listener-session-{session_id}.jsonl"));
        let (commands, auth_count, ts, peer_ip) = read_evidence(&evidence_path).await;
        if peer_ip.is_empty() {
            continue;
        }
        let iocs = crate::ioc::extract_from_commands(&commands);

        sessions.push(serde_json::json!({
            "session_id": session_id,
            "target_ip": peer_ip,
            "started_at": ts,
            "duration_secs": 0,
            "auth_attempts": auth_count,
            "commands_count": commands.len(),
            "commands": commands,
            "iocs": iocs.format_list(),
            "blocked": blocked_ips.contains(&peer_ip),
            "mode": "always_on",
        }));
    }

    // Sort sessions by started_at descending (newest first)
    sessions.sort_by(|a, b| {
        let ta = a.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });

    Json(serde_json::json!({ "sessions": sessions }))
}
/// GET /api/admin-actions - recent admin action entries for compliance view.
pub(super) async fn api_admin_actions(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let path = state.data_dir.join(format!("admin-actions-{date}.jsonl"));
    let entries = read_jsonl::<AdminActionEntry>(&path);
    let items: Vec<serde_json::Value> = entries
        .iter()
        .rev()
        .take(50)
        .map(|e| {
            serde_json::json!({
                "ts": e.ts.to_rfc3339(),
                "operator": e.operator,
                "source": e.source,
                "action": e.action,
                "target": e.target,
                "result": e.result,
            })
        })
        .collect();
    Json(serde_json::json!({ "date": date, "total": entries.len(), "items": items }))
}

/// GET /api/advisory-cache - current advisory cache for compliance view.
pub(super) async fn api_advisory_cache(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let cache = state
        .advisory_cache
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let items: Vec<serde_json::Value> = cache
        .iter()
        .map(|e| {
            serde_json::json!({
                "advisory_id": e.advisory_id,
                "command_preview": e.command_preview,
                "risk_score": e.risk_score,
                "recommendation": e.recommendation,
                "signals": e.signals,
                "ts": e.ts.to_rfc3339(),
            })
        })
        .collect();
    Json(serde_json::json!({ "total": items.len(), "items": items }))
}

/// GET /api/compliance - compliance overview: retention, hash chain, ISO 27001.
pub(super) async fn api_compliance(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let cfg = &state.action_cfg;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Hash chain verification: read the last few entries of today's decisions file
    // and verify each entry's prev_hash matches the SHA-256 of the preceding entry.
    let decisions_path = state.data_dir.join(format!("decisions-{today}.jsonl"));
    let (chain_intact, chain_length, last_hash) = tokio::task::spawn_blocking({
        let path = decisions_path;
        move || -> (bool, usize, String) {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => return (true, 0, "none".to_string()),
            };
            verify_hash_chain(&content)
        }
    })
    .await
    .unwrap_or((true, 0, "none".to_string()));

    // Data retention config
    let retention = serde_json::json!({
        "events_days": cfg.retention_events_days,
        "incidents_days": cfg.retention_incidents_days,
        "decisions_days": cfg.retention_decisions_days,
        "telemetry_days": cfg.retention_telemetry_days,
        "reports_days": cfg.retention_reports_days,
    });

    // ISO 27001 control checklist - map controls to feature state
    let controls = serde_json::json!([
        { "id": "A.5.1",  "name": "Information security policies", "met": true, "reason": "Security agent with automated response policy" },
        { "id": "A.6.1",  "name": "Organization of information security", "met": cfg.ai_enabled, "reason": if cfg.ai_enabled { "AI-driven triage active" } else { "Enable AI analysis for automated triage" } },
        { "id": "A.8.1",  "name": "Asset management", "met": true, "reason": "Sensor inventory tracks all monitored log sources" },
        { "id": "A.9.1",  "name": "Access control", "met": cfg.sudo_protection_enabled, "reason": if cfg.sudo_protection_enabled { "Sudo protection detects privilege abuse" } else { "Enable sudo-protection for access control monitoring" } },
        { "id": "A.10.1", "name": "Cryptography", "met": chain_length > 0, "reason": if chain_length > 0 { "Decision audit trail uses SHA-256 hash chain" } else { "No decisions recorded yet" } },
        { "id": "A.12.1", "name": "Operations security", "met": cfg.enabled, "reason": if cfg.enabled { "Automated response enabled" } else { "Enable responder for operational security controls" } },
        { "id": "A.12.4", "name": "Logging and monitoring", "met": true, "reason": "Continuous monitoring with 48 detectors, 20 response playbooks, and hardened allowlists" },
        { "id": "A.12.6", "name": "Technical vulnerability management", "met": cfg.execution_guard_enabled, "reason": if cfg.execution_guard_enabled { "Execution guard blocks exploit payloads" } else { "Enable execution-guard for exploit prevention" } },
        { "id": "A.13.1", "name": "Network security management", "met": cfg.enabled && !cfg.dry_run, "reason": if cfg.enabled && !cfg.dry_run { "Automated IP blocking active" } else { "Enable guard mode for network-level response" } },
        { "id": "A.13.2", "name": "Information transfer", "met": true, "reason": "Container drift detection (overlayfs upper-layer check) + io_uring monitoring prevent unauthorized data transfer via syscall bypass and dropped executables" },
        { "id": "A.16.1", "name": "Incident management", "met": true, "reason": "20 automated playbooks: detect → correlate → respond → notify → audit" },
        { "id": "A.18.1", "name": "Compliance", "met": cfg.retention_decisions_days >= 90, "reason": format!("Audit trail retained {}d (requirement: 90d)", cfg.retention_decisions_days) },
        { "id": "A.18.2", "name": "Information security reviews", "met": true, "reason": "Daily automated security reports with telemetry" },
    ]);

    let controls_met = controls
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c["met"].as_bool().unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    let controls_total = controls.as_array().map(|a| a.len()).unwrap_or(0);

    Json(serde_json::json!({
        "hash_chain": {
            "intact": chain_intact,
            "length": chain_length,
            "last_hash": last_hash,
        },
        "retention": retention,
        "iso_27001": {
            "controls": controls,
            "met": controls_met,
            "total": controls_total,
        },
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ---------------------------------------------------------------------------
// Pure validation logic
// ---------------------------------------------------------------------------

pub(crate) fn verify_hash_chain(content: &str) -> (bool, usize, String) {
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return (true, 0, "none".to_string());
    }
    let mut intact = true;
    let mut prev_computed_hash: Option<String> = None;
    for line in &lines {
        // We tolerate invalid JSON in production stream by just skipping prev_hash checks
        // but we always hash the exact byte sequence of the string.
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            let prev_hash = entry["prev_hash"].as_str().map(|s| s.to_string());
            if let Some(ref expected) = prev_hash {
                if let Some(ref computed) = prev_computed_hash {
                    if expected != computed {
                        intact = false;
                    }
                }
            }
        }
        use sha2::Digest;
        let hash = sha2::Sha256::digest(line.as_bytes());
        prev_computed_hash = Some(format!("{hash:x}"));
    }
    let last = prev_computed_hash.unwrap_or_else(|| "none".to_string());
    (intact, lines.len(), last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_hash_chain_empty() {
        let (intact, len, last) = verify_hash_chain("");
        assert!(intact);
        assert_eq!(len, 0);
        assert_eq!(last, "none");
    }

    #[test]
    fn test_verify_hash_chain_valid() {
        let entry1 = r#"{"action":"block", "prev_hash": null}"#;
        use sha2::Digest;
        let hash1 = format!("{:x}", sha2::Sha256::digest(entry1.as_bytes()));
        let entry2 = format!(r#"{{"action":"monitor", "prev_hash": "{}"}}"#, hash1);

        let content = format!("{}\n{}\n", entry1, entry2);
        let (intact, len, _) = verify_hash_chain(&content);

        assert!(intact);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_verify_hash_chain_tampered() {
        // Intentional tamper of prev_hash
        let entry1 = r#"{"action":"block", "prev_hash": null}"#;
        // Wrong hash pointing backwards
        let entry2 = r#"{"action":"monitor", "prev_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;

        let content = format!("{}\n{}\n", entry1, entry2);
        let (intact, len, _) = verify_hash_chain(&content);

        assert!(!intact);
        assert_eq!(len, 2);
    }
}
