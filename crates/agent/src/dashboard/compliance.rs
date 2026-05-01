// Auto-extracted from mod.rs — dashboard compliance handlers

use super::*;

/// GET /api/honeypot/sessions - list honeypot sessions from the honeypot/ subdirectory.
pub(super) async fn api_honeypot_sessions(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let honeypot_dir = state.data_dir.join("honeypot");

    // Collect blocked IPs from knowledge graph (Phase 6A: no JSONL reads).
    // Includes all block_ip decisions (dry-run and executed) to match
    // original semantics. Runs on the blocking pool because the KG read
    // lock can be contended with the slow_loop write path; holding it
    // here on an async worker would stall sibling dashboard requests
    // (`RECURRING_BUGS.md` "Dashboard handlers block tokio worker
    // threads"). The rest of this handler uses `tokio::fs::*` so there
    // are no other blocking sinks to wrap.
    let kg = std::sync::Arc::clone(&state.knowledge_graph);
    let blocked_ips: std::collections::HashSet<String> = tokio::task::spawn_blocking(move || {
        use crate::knowledge_graph::types::{Node, NodeType};
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let graph = kg.read().unwrap();
        for id in graph.nodes_of_type(NodeType::Incident) {
            if let Some(Node::Incident {
                decision: Some(dec),
                decision_target: Some(target),
                ..
            }) = graph.get_node(id)
            {
                if dec == "block_ip" {
                    set.insert(target.clone());
                }
            }
        }
        set
    })
    .await
    .unwrap_or_default();

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

    // Read today's JSONL, verify its chain, and — when a sqlite store is
    // attached — verify the SQLite chain and cross-check each JSONL line
    // against the `decisions.data` column. The cross-check is pure
    // visibility: operators see drift between the two persistence layers
    // without the endpoint failing hard. Reconciliation is a separate PR.
    let decisions_path = state.data_dir.join(format!("decisions-{today}.jsonl"));
    let store_handle = state.sqlite_store.clone();
    let chain_report = tokio::task::spawn_blocking({
        let path = decisions_path;
        move || -> serde_json::Value {
            let jsonl_content = std::fs::read_to_string(&path).unwrap_or_default();
            let (intact, length, last_hash) = verify_hash_chain(&jsonl_content);
            let jsonl = serde_json::json!({
                "intact": intact,
                "length": length,
                "last_hash": last_hash,
            });
            let (sqlite, cross_check) = match store_handle {
                Some(store) => (
                    sqlite_chain_status(&store),
                    cross_check_jsonl_vs_sqlite(&jsonl_content, &store),
                ),
                None => (
                    serde_json::json!({ "available": false }),
                    serde_json::json!({ "available": false }),
                ),
            };
            serde_json::json!({
                "jsonl": jsonl,
                "sqlite": sqlite,
                "cross_check": cross_check,
            })
        }
    })
    .await
    .unwrap_or_else(|_| serde_json::json!({}));

    // Back-compat: flatten the JSONL fields at the top of `hash_chain` so
    // existing dashboard JS that reads `intact`, `length`, and `last_hash`
    // from the old shape keeps working. New fields (`sqlite`, `cross_check`)
    // sit alongside.
    let chain_intact = chain_report["jsonl"]["intact"].as_bool().unwrap_or(true);
    let chain_length = chain_report["jsonl"]["length"].as_u64().unwrap_or(0) as usize;
    let last_hash = chain_report["jsonl"]["last_hash"]
        .as_str()
        .unwrap_or("none")
        .to_string();

    // Data retention config
    let retention = serde_json::json!({
        "events_days": cfg.retention_events_days,
        "incidents_days": cfg.retention_incidents_days,
        "decisions_days": cfg.retention_decisions_days,
        "telemetry_days": cfg.retention_telemetry_days,
        "reports_days": cfg.retention_reports_days,
    });

    let controls = map_iso27001_controls(cfg, chain_length);

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
            "jsonl": chain_report["jsonl"],
            "sqlite": chain_report["sqlite"],
            "cross_check": chain_report["cross_check"],
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

pub(super) fn map_iso27001_controls(
    cfg: &DashboardActionConfig,
    chain_length: usize,
) -> serde_json::Value {
    serde_json::json!([
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
    ])
}

/// Report SQLite-side chain status via `Store::verify_hash_chain`. Distinct
/// from the JSONL chain — the two use different hash formulas by design
/// (JSONL: SHA-256(line); SQLite: SHA-256(prev_hash || data)) so the
/// byte-value of `last_hash` cannot be compared across the two sides.
/// Each side is self-consistent; content correspondence lives in the
/// cross-check helper.
pub(super) fn sqlite_chain_status(store: &innerwarden_store::Store) -> serde_json::Value {
    match store.verify_hash_chain() {
        Ok(r) => {
            let last_hash = store
                .last_decision_hash()
                .ok()
                .flatten()
                .unwrap_or_else(|| "none".to_string());
            // 2026-05-01: surface documented chain breaks alongside
            // the verifier result. Operator viewing the compliance
            // tab should see "audit chain has 2 documented breaks
            // (rows 9876-14577 + 15693-15695)" with reasons, instead
            // of having to ssh in and query sqlite directly. The
            // breaks list is bounded (one row per recovery sweep,
            // expected < 100 lifetime) so loading inline is fine.
            let breaks: Vec<serde_json::Value> = store
                .list_chain_breaks()
                .unwrap_or_default()
                .into_iter()
                .map(|b| {
                    serde_json::json!({
                        "id": b.id,
                        "rowid_start": b.rowid_start,
                        "rowid_end": b.rowid_end,
                        "rows_documented": b.rowid_end - b.rowid_start + 1,
                        "registered_at": b.registered_at,
                        "operator": b.operator,
                        "reason": b.reason,
                    })
                })
                .collect();
            serde_json::json!({
                "available": true,
                "intact": r.intact,
                "length": r.verified,
                "broken_at": r.broken_at,
                "last_hash": last_hash,
                "documented_breaks": r.documented_breaks,
                "breaks": breaks,
            })
        }
        Err(e) => serde_json::json!({
            "available": true,
            "intact": false,
            "length": 0,
            "broken_at": null,
            "last_hash": "none",
            "error": e.to_string(),
        }),
    }
}

/// Cross-check: every line in today's JSONL must appear as a `data` row in
/// SQLite. Reported as `(checked, matched, divergent, status)`. We use
/// set-membership rather than positional order so pre-dual-write
/// historical rows (only in JSONL, missing in SQLite) surface as `divergent`
/// without needing a date filter on the SQLite side. A SQLite row with no
/// JSONL counterpart is expected (prior-day history) and is not counted.
pub(super) fn cross_check_jsonl_vs_sqlite(
    jsonl_content: &str,
    store: &innerwarden_store::Store,
) -> serde_json::Value {
    let jsonl_lines: Vec<&str> = jsonl_content.lines().filter(|l| !l.is_empty()).collect();
    let sqlite_rows = match store.decisions_since(0, i64::MAX as usize) {
        Ok(rows) => rows,
        Err(e) => {
            return serde_json::json!({
                "available": true,
                "checked": jsonl_lines.len(),
                "matched": 0,
                "divergent": jsonl_lines.len(),
                "status": "error",
                "error": e.to_string(),
            });
        }
    };
    let sqlite_set: std::collections::HashSet<String> =
        sqlite_rows.into_iter().map(|(_, data)| data).collect();
    let matched = jsonl_lines
        .iter()
        .filter(|line| sqlite_set.contains(**line))
        .count();
    let checked = jsonl_lines.len();
    let divergent = checked.saturating_sub(matched);
    let status = if checked == 0 {
        "empty"
    } else if divergent == 0 {
        "ok"
    } else {
        "drift"
    };
    serde_json::json!({
        "available": true,
        "checked": checked,
        "matched": matched,
        "divergent": divergent,
        "status": status,
    })
}

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

    #[test]
    fn test_iso_27001_mapping_enabled() {
        let mut cfg = DashboardActionConfig::default();
        cfg.ai_enabled = true;
        cfg.sudo_protection_enabled = true;
        cfg.execution_guard_enabled = true;
        cfg.enabled = true;
        cfg.dry_run = false;
        cfg.retention_decisions_days = 90;

        let controls = map_iso27001_controls(&cfg, 5);
        let arr = controls.as_array().unwrap();

        let ai_control = arr.iter().find(|c| c["id"] == "A.6.1").unwrap();
        assert_eq!(ai_control["met"].as_bool(), Some(true));

        let crypto_control = arr.iter().find(|c| c["id"] == "A.10.1").unwrap();
        assert_eq!(crypto_control["met"].as_bool(), Some(true));

        let network_control = arr.iter().find(|c| c["id"] == "A.13.1").unwrap();
        assert_eq!(network_control["met"].as_bool(), Some(true));

        let compliance_control = arr.iter().find(|c| c["id"] == "A.18.1").unwrap();
        assert_eq!(compliance_control["met"].as_bool(), Some(true));
    }

    #[test]
    fn test_iso_27001_mapping_disabled() {
        let mut cfg = DashboardActionConfig::default();
        cfg.enabled = false;
        cfg.dry_run = true;
        cfg.retention_decisions_days = 30;

        let controls = map_iso27001_controls(&cfg, 0); // No hash blocks yet
        let arr = controls.as_array().unwrap();

        let crypto_control = arr.iter().find(|c| c["id"] == "A.10.1").unwrap();
        assert_eq!(crypto_control["met"].as_bool(), Some(false));

        let network_control = arr.iter().find(|c| c["id"] == "A.13.1").unwrap();
        assert_eq!(network_control["met"].as_bool(), Some(false));

        let compliance_control = arr.iter().find(|c| c["id"] == "A.18.1").unwrap();
        assert_eq!(compliance_control["met"].as_bool(), Some(false));
    }

    #[test]
    fn test_verify_hash_chain_single() {
        // Single-entry chain should be valid and report length one.
        let entry1 = r#"{"action":"block", "prev_hash": null}"#;
        // With 1 entry, chain is always intact since there is no missing preceding hash
        let (intact, len, _) = verify_hash_chain(entry1);
        assert!(intact);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_verify_hash_chain_single_entry_last_hash_present() {
        // Single entry should still produce a concrete hash value.
        let entry = r#"{"action":"monitor", "prev_hash": null}"#;
        let (intact, len, last) = verify_hash_chain(entry);
        assert!(intact);
        assert_eq!(len, 1);
        assert_ne!(last, "none");
    }

    #[test]
    fn test_verify_hash_chain_empty_returns_none_hash() {
        // Empty chain should return none as sentinel hash value.
        let (intact, len, last) = verify_hash_chain("");
        assert!(intact);
        assert_eq!(len, 0);
        assert_eq!(last, "none");
    }

    // ── SQLite ↔ JSONL cross-check anchors ───────────────────────────
    //
    // Three invariants the compliance endpoint now surfaces:
    //   1. SQLite chain self-consistency (`sqlite_chain_status` intact).
    //   2. JSONL line ↔ SQLite `data` column content correspondence
    //      (`cross_check_jsonl_vs_sqlite` matched == checked).
    //   3. Divergence does not panic — it reports `status = "drift"` so
    //      operators see it without the endpoint failing hard.

    fn seed_dual_write(
        dir: &std::path::Path,
    ) -> (std::sync::Arc<innerwarden_store::Store>, Vec<String>) {
        use std::sync::Arc;
        let store = Arc::new(innerwarden_store::Store::open(dir).expect("store"));
        let mut writer =
            crate::decisions::DecisionWriter::with_store(dir, Some(store.clone())).expect("writer");
        for i in 0..3 {
            writer
                .write(&crate::decisions::DecisionEntry {
                    ts: chrono::Utc::now(),
                    incident_id: format!("inc-cross-{i}"),
                    host: "h".into(),
                    ai_provider: "test".into(),
                    action_type: "block_ip".into(),
                    target_ip: Some("203.0.113.7".into()),
                    target_user: None,
                    skill_id: Some("block-ip-ufw".into()),
                    confidence: 0.9,
                    auto_executed: true,
                    dry_run: false,
                    reason: "synthetic".into(),
                    estimated_threat: "high".into(),
                    execution_result: "ok".into(),
                    prev_hash: None,
                })
                .expect("write");
        }
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let jsonl =
            std::fs::read_to_string(dir.join(format!("decisions-{today}.jsonl"))).expect("jsonl");
        let lines = jsonl
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        (store, lines)
    }

    #[test]
    fn sqlite_chain_status_reports_intact_length_and_last_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, lines) = seed_dual_write(dir.path());

        let status = sqlite_chain_status(&store);
        assert_eq!(status["available"], serde_json::Value::Bool(true));
        assert_eq!(status["intact"], serde_json::Value::Bool(true));
        assert_eq!(status["length"].as_u64(), Some(lines.len() as u64));
        assert_ne!(status["last_hash"].as_str(), Some("none"));
    }

    #[test]
    fn cross_check_reports_ok_when_every_jsonl_line_exists_in_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, lines) = seed_dual_write(dir.path());
        let jsonl_content = lines.join("\n");

        let result = cross_check_jsonl_vs_sqlite(&jsonl_content, &store);
        assert_eq!(result["status"], serde_json::Value::String("ok".into()));
        assert_eq!(result["checked"].as_u64(), Some(lines.len() as u64));
        assert_eq!(result["matched"].as_u64(), Some(lines.len() as u64));
        assert_eq!(result["divergent"].as_u64(), Some(0));
    }

    #[test]
    fn cross_check_reports_drift_when_jsonl_has_an_unmirrored_line() {
        // Simulates the exact gap PR-1 closed: a line written only to the
        // JSONL audit trail, never mirrored to SQLite (the pre-PR
        // `append_chained` path). After this PR, operators see it.
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, mut lines) = seed_dual_write(dir.path());
        lines.push(r#"{"ts":"2026-04-24T00:00:00Z","incident_id":"inc-jsonl-only","host":"h","ai_provider":"test","action_type":"block_ip","target_ip":"198.51.100.1","skill_id":"block-ip-ufw","confidence":0.9,"auto_executed":true,"dry_run":false,"reason":"pre-mirror","estimated_threat":"high","execution_result":"ok","prev_hash":null}"#.to_string());
        let jsonl_content = lines.join("\n");

        let result = cross_check_jsonl_vs_sqlite(&jsonl_content, &store);
        assert_eq!(
            result["status"],
            serde_json::Value::String("drift".into()),
            "JSONL line with no SQLite counterpart must surface as drift"
        );
        assert_eq!(result["divergent"].as_u64(), Some(1));
        assert_eq!(result["matched"].as_u64(), Some((lines.len() - 1) as u64));
    }

    #[test]
    fn cross_check_reports_empty_when_no_jsonl_today() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, _lines) = seed_dual_write(dir.path());

        let result = cross_check_jsonl_vs_sqlite("", &store);
        assert_eq!(result["status"], serde_json::Value::String("empty".into()));
        assert_eq!(result["checked"].as_u64(), Some(0));
        assert_eq!(result["divergent"].as_u64(), Some(0));
    }

    // ── api_honeypot_sessions (Finding 4 anchor) ─────────────────────
    //
    // The handler wraps the KG read in spawn_blocking. Verify the full
    // async path returns a well-formed JSON object even when no
    // honeypot directory exists (the early-return path).

    #[tokio::test]
    async fn api_honeypot_sessions_returns_empty_when_dir_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Don't create the honeypot/ subdir → handler short-circuits.
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let Json(payload) = api_honeypot_sessions(State(state)).await;
        let sessions = payload["sessions"].as_array().expect("sessions array");
        assert!(sessions.is_empty(), "no honeypot dir → empty sessions");
    }

    #[tokio::test]
    async fn api_honeypot_sessions_runs_blocked_ip_collection_on_blocking_pool() {
        // Anchors the spawn_blocking wrapper around the graph read.
        // Even with an empty graph, the handler must complete (proves
        // the spawn_blocking awaits without panicking and the blocked_ips
        // set is empty as expected).
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("honeypot")).unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let Json(payload) = api_honeypot_sessions(State(state)).await;
        let sessions = payload["sessions"].as_array().expect("sessions array");
        // No session JSON files → no entries.
        assert!(sessions.is_empty());
    }
}
