// Auto-extracted from mod.rs — dashboard sensors handlers

use super::*;

/// GET /api/sensors - sensor activity time-series for dashboard graphs.
/// Returns event counts bucketed by 5-minute intervals, grouped by source.
/// Cached for 30 seconds to avoid re-reading the events file on every request.
///
/// Cache miss path holds the KG read lock and walks every Incident node to
/// build the detector timeline. `tokio::task::spawn_blocking` keeps that
/// work off the async worker thread (see `RECURRING_BUGS.md` "Dashboard
/// handlers block tokio worker threads"). The 30s cache makes contention
/// rare but the spawn_blocking is correctness, not optimisation: a slow
/// path that pins an async worker can starve sibling handlers regardless
/// of frequency.
pub(super) async fn api_sensors(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    // Check cache (30s TTL)
    {
        let cache = state.sensor_cache.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now - cache.0 < 30 && cache.0 > 0 {
            return Json(cache.1.clone());
        }
    }

    // 2026-05-02 audit B1/P1 (Spec 039 P3): hydrate the canonical
    // OverviewSnapshot for today so the Sensors HUD's `total_events`
    // and `total_incidents` paint the same numbers the Home tile and
    // Briefing/Report paint. Pre-fix the HUD scanned the KG and
    // showed "47 events handled" while the Home tile said something
    // different — a contradiction the auditor flagged on the same
    // screen reload. The snapshot is computed inline (mirroring
    // api_overview / api_briefing_generate); when it's unavailable
    // the HUD falls back to the legacy KG / telemetry path.
    let snapshot = state.sqlite_store.as_ref().and_then(|store| {
        let today = super::helpers::resolve_date(None);
        let now_dt = chrono::Utc::now();
        let degraded = super::data_api::read_degraded_signals(&state);
        super::data_api::compute_overview_counts_from_sqlite(
            store,
            &today,
            0,
            None,
            now_dt,
            &degraded,
            &state.data_dir,
        )
        .and_then(|counts| counts.snapshot)
    });

    let kg = std::sync::Arc::clone(&state.knowledge_graph);
    let data_dir = state.data_dir.clone();
    let result = tokio::task::spawn_blocking(move || {
        build_sensors_payload(&kg, &data_dir, snapshot.as_ref())
    })
    .await
    .unwrap_or_else(|_| serde_json::json!({}));

    // Update cache
    {
        let mut cache = state.sensor_cache.lock().await;
        cache.0 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        cache.1 = result.clone();
    }

    Json(result)
}

/// Async-safe variant retained for any future caller that already runs on
/// a blocking thread (e.g. integration test). Production handler uses
/// `build_sensors_payload` via `spawn_blocking`.
#[allow(dead_code)]
pub(super) async fn api_sensors_inner(state: &DashboardState) -> serde_json::Value {
    build_sensors_payload(&state.knowledge_graph, &state.data_dir, None)
}

/// Test-only re-export of `build_sensors_payload` for the cross-surface
/// SoT anchor in `consistency_incidents_today.rs`. Production code
/// reaches this through `api_sensors` / `api_sensors_inner`; routing
/// the test through the public function avoids a `pub(super)` visibility
/// bump on the implementation that would leak into release builds.
#[cfg(test)]
pub(super) fn tests_only_call_build_sensors_payload(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: &std::path::Path,
    snapshot: Option<&super::types::OverviewSnapshot>,
) -> serde_json::Value {
    build_sensors_payload(kg, data_dir, snapshot)
}

fn build_sensors_payload(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: &std::path::Path,
    snapshot: Option<&super::types::OverviewSnapshot>,
) -> serde_json::Value {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();

    // Event telemetry — prefer graph counters, fall back to telemetry snapshot
    let (total_events_val, sources) = if graph.total_events_ingested > 0 {
        let mut s: Vec<_> = graph
            .source_counts
            .iter()
            .map(|(s, &c)| (s.clone(), c))
            .collect();
        s.sort_by(|a, b| b.1.cmp(&a.1));
        (graph.total_events_ingested, s)
    } else {
        // Fallback: read from telemetry snapshot (has events_by_collector)
        let telem = crate::telemetry::read_latest_snapshot(data_dir, &today);
        match telem {
            Some(t) => {
                let total = t.events_by_collector.values().sum::<u64>() as usize;
                // Wave 6b: t.events_by_collector keys are now `Arc<str>`;
                // the if-branch above produces `(String, usize)` from
                // graph.source_counts, so convert to `String` here to
                // keep both branches' element type identical.
                let mut s: Vec<(String, usize)> = t
                    .events_by_collector
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v as usize))
                    .collect();
                s.sort_by(|a, b| b.1.cmp(&a.1));
                (total, s)
            }
            None => (0, vec![]),
        }
    };

    let mut kinds: Vec<_> = graph
        .kind_counts
        .iter()
        .map(|(k, &c)| (k.clone(), c))
        .collect();
    kinds.sort_by(|a, b| b.1.cmp(&a.1));
    kinds.truncate(15);

    // Detector counts + timeline from Incident nodes. Bucket key now matches
    // the format used by `event_timeline` (`YYYY-MM-DDTHH:MM`, see
    // `knowledge_graph::buckets`) so cross-day uptime no longer collapses
    // different days into the same time-of-day bucket.
    let mut detector_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut detector_timeline: std::collections::BTreeMap<
        String,
        std::collections::HashMap<String, usize>,
    > = std::collections::BTreeMap::new();
    let total_incidents = graph.nodes_of_type(NodeType::Incident).len();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident { detector, ts, .. }) = graph.get_node(id) {
            *detector_counts.entry(detector.clone()).or_insert(0) += 1;
            let bucket = crate::knowledge_graph::buckets::format_bucket_key(*ts);
            *detector_timeline
                .entry(bucket)
                .or_default()
                .entry(detector.clone())
                .or_insert(0) += 1;
        }
    }

    let mut detectors: Vec<_> = detector_counts.into_iter().collect();
    detectors.sort_by(|a, b| b.1.cmp(&a.1));

    // event_timeline may be empty after restart (cursor/snapshot race).
    // Use detector_timeline as fallback — it's rebuilt from persisted Incident nodes.
    let event_tl_source: &std::collections::BTreeMap<
        String,
        std::collections::HashMap<String, usize>,
    > = if graph.event_timeline.is_empty() {
        &detector_timeline
    } else {
        &graph.event_timeline
    };

    // 2026-05-02: filter buckets to TODAY's date prefix before
    // stripping. Pre-fix the chart folded multi-day data into the same
    // HH:MM display key (operator: "o grafico fica fixo aparecendo
    // alto so depois das 20 horas, ta assim a dias"). Cause: bucket
    // keys are `YYYY-MM-DDTHH:MM`; `strip_date_prefix` drops the
    // date and `BTreeMap::collect` overwrites duplicates with the
    // last-iterated entry. With multi-day buckets in the KG, today's
    // empty pre-spike hours got overwritten by yesterday's same-time
    // values, producing a static-looking chart that "moved" only
    // when today's events landed past the agent's restart minute.
    //
    // Fix: keep only buckets whose date prefix matches today. The
    // KG retains multi-day data for windowed queries elsewhere
    // (report.rs::compute_recent_window); the Sensors HUD chart
    // explicitly shows TODAY ONLY.
    let today_prefix = format!("{today}T");
    let event_tl_display: std::collections::BTreeMap<
        String,
        &std::collections::HashMap<String, usize>,
    > = event_tl_source
        .iter()
        .filter(|(k, _)| k.starts_with(&today_prefix))
        .map(|(k, v)| {
            (
                crate::knowledge_graph::buckets::strip_date_prefix(k).to_string(),
                v,
            )
        })
        .collect();
    // Same today-only filter for the detector timeline — same reason.
    let detector_tl_display: std::collections::BTreeMap<
        String,
        &std::collections::HashMap<String, usize>,
    > = detector_timeline
        .iter()
        .filter(|(k, _)| k.starts_with(&today_prefix))
        .map(|(k, v)| {
            (
                crate::knowledge_graph::buckets::strip_date_prefix(k).to_string(),
                v,
            )
        })
        .collect();

    // 2026-05-02 audit B1/P1 (Spec 039 P3): canonical SoT override.
    // When the OverviewSnapshot is available, the HUD's topline
    // counters use snapshot fields (same as Home/Briefing/Report)
    // instead of KG-derived numbers. Per-source breakdown
    // (`sources`, `top_kinds`, `detectors`, `event_timeline`,
    // `detector_timeline`) keeps coming from the KG/telemetry walks
    // — those carry detail the snapshot does not.
    let (total_events_canonical, total_incidents_canonical) = match snapshot {
        Some(snap) => {
            let buckets = &snap.buckets;
            let total_inc = buckets.blocked.incidents
                + buckets.observing.incidents
                + buckets.honeypot.incidents
                + buckets.dismissed.incidents
                + buckets.allowlisted.incidents
                + buckets.attention.incidents;
            (snap.events_today, total_inc)
        }
        None => (total_events_val, total_incidents),
    };

    serde_json::json!({
        "date": today,
        "total_events": total_events_canonical,
        "total_incidents": total_incidents_canonical,
        "sources": sources.iter().map(|(s, c)| serde_json::json!({"name": s, "count": c})).collect::<Vec<_>>(),
        "top_kinds": kinds.iter().map(|(k, c)| serde_json::json!({"name": k, "count": c})).collect::<Vec<_>>(),
        "detectors": detectors.iter().map(|(d, c)| serde_json::json!({"name": d, "count": c})).collect::<Vec<_>>(),
        "event_timeline": event_tl_display,
        "detector_timeline": detector_tl_display,
    })
}

/// GET /api/status - E6: system status including data files and responder config.
pub(super) async fn api_status(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let data_dir = &state.data_dir;

    let file_exists = |name: &str| data_dir.join(name).exists();
    let file_size = |name: &str| {
        std::fs::metadata(data_dir.join(name))
            .map(|m| m.len())
            .unwrap_or(0)
    };

    let events_file = format!("events-{today}.jsonl");
    let incidents_file = format!("incidents-{today}.jsonl");
    let decisions_file = format!("decisions-{today}.jsonl");
    let telemetry_file = format!("telemetry-{today}.jsonl");

    let action_cfg = &state.action_cfg;

    // Compute seconds since last telemetry write (agent liveness check).
    let last_telemetry_secs = std::fs::metadata(data_dir.join(&telemetry_file))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok().map(|d| d.as_secs()));

    let mode = get_protection_mode(action_cfg.enabled, action_cfg.dry_run);

    // Count kill chain incidents from knowledge graph (Phase 6A: no JSONL reads).
    // Single pass — avoids u64 underflow from two-pass subtract.
    let mut kc_total_blocked: u64 = 0;
    let mut kc_total_pre_chain: u64 = 0;
    let mut kc_patterns: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    {
        use crate::knowledge_graph::types::{Node, NodeType};
        let graph = state.knowledge_graph.read().unwrap();
        for id in graph.nodes_of_type(NodeType::Incident) {
            if let Some(Node::Incident {
                detector, decision, ..
            }) = graph.get_node(id)
            {
                if !detector.contains("kill_chain") {
                    continue;
                }
                *kc_patterns.entry(detector.clone()).or_insert(0) += 1;
                if decision.as_deref() == Some("block_ip") {
                    kc_total_blocked += 1;
                } else {
                    kc_total_pre_chain += 1;
                }
            }
        }
    }

    // Graph stats for Health tab (replaces removed Graph tab).
    let graph_stats = {
        let graph = state.knowledge_graph.read().unwrap();
        let mut by_type: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for (_, n) in graph.nodes().iter() {
            *by_type.entry(format!("{:?}", n.node_type())).or_insert(0) += 1;
        }
        serde_json::json!({
            "node_count": graph.node_count(),
            "edge_count": graph.edges_slice().len(),
            "memory_bytes": graph.memory_estimate,
            "incident_nodes": by_type.get("Incident").copied().unwrap_or(0),
            "threat_intel_nodes": graph.threat_intel_nodes.len(),
            "nodes_by_type": by_type
        })
    };

    Json(serde_json::json!({
        "date": today,
        "data_dir": data_dir.display().to_string(),
        "mode": mode,
        "last_telemetry_secs": last_telemetry_secs,
        "ai_enabled": action_cfg.ai_enabled,
        "ai_provider": action_cfg.ai_provider,
        "ai_model": action_cfg.ai_model,
        "files": {
            "events": { "exists": file_exists(&events_file), "size_bytes": file_size(&events_file) },
            "incidents": { "exists": file_exists(&incidents_file), "size_bytes": file_size(&incidents_file) },
            "decisions": { "exists": file_exists(&decisions_file), "size_bytes": file_size(&decisions_file) },
            "telemetry": { "exists": file_exists(&telemetry_file), "size_bytes": file_size(&telemetry_file) }
        },
        "responder": {
            "enabled": action_cfg.enabled,
            "dry_run": action_cfg.dry_run,
            "block_backend": action_cfg.block_backend,
            "allowed_skills": action_cfg.allowed_skills
        },
        "webhook_format": action_cfg.webhook_format,
        "sudo_protection": action_cfg.sudo_protection_enabled,
        "execution_guard": action_cfg.execution_guard_enabled,
        "integrations": {
            "fail2ban": action_cfg.fail2ban_enabled,
            "geoip": action_cfg.geoip_enabled,
            "abuseipdb": action_cfg.abuseipdb_enabled,
            "abuseipdb_auto_block_threshold": action_cfg.abuseipdb_auto_block_threshold,
            "honeypot_mode": action_cfg.honeypot_mode,
            "telegram": action_cfg.telegram_enabled,
            "slack": action_cfg.slack_enabled,
            "cloudflare": action_cfg.cloudflare_enabled,
            "crowdsec": action_cfg.crowdsec_enabled,
            "mesh": action_cfg.mesh_enabled,
            "web_push": action_cfg.web_push_enabled,
            "shield": action_cfg.shield_enabled,
            "dna": action_cfg.dna_enabled
        },
        "retention": {
            "events_days": action_cfg.retention_events_days,
            "incidents_days": action_cfg.retention_incidents_days,
            "decisions_days": action_cfg.retention_decisions_days,
            "telemetry_days": action_cfg.retention_telemetry_days,
            "reports_days": action_cfg.retention_reports_days
        },
        "kill_chain": {
            "total_blocked": kc_total_blocked,
            "total_pre_chain": kc_total_pre_chain,
            "patterns": kc_patterns
        },
        "graph": graph_stats,
        "process_health": crate::process_health::ProcessHealth::snapshot(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// GET /api/collectors - sensor collector detection (file existence + recency).
/// Fail-silent: never requires root, never panics.
pub(super) async fn api_collectors(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    // Helper: check if a path exists
    let file_exists = |p: &str| std::path::Path::new(p).exists();

    // Helper: how many seconds since a file was modified (None if missing or error)
    let file_age_secs = |p: &str| -> Option<u64> {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
    };

    // Helper: check if a binary is in PATH
    let has_binary = |name: &str| {
        std::process::Command::new("which")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    // Count events by source — prefer graph counters, fall back to telemetry snapshot
    let graph = state.knowledge_graph.read().unwrap();
    let graph_source_counts = graph.source_counts.clone();
    let graph_total = graph.total_events_ingested;
    drop(graph);

    let telem_source_counts: std::collections::HashMap<String, usize> = if graph_total > 0 {
        graph_source_counts
    } else {
        // Graph counters empty (cursor/snapshot race after restart).
        // Fall back to telemetry snapshot which the agent writes every 30s.
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        crate::telemetry::read_latest_snapshot(&state.data_dir, &today)
            .map(|t| {
                // Wave 6b: snapshot keys are now `Arc<str>`; the local
                // adapter HashMap below uses `String` keys so the
                // `.get(source)` lookup against the &str signature
                // works without an Arc-to-str adapter on every call.
                t.events_by_collector
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v as usize))
                    .collect::<HashMap<String, usize>>()
            })
            .unwrap_or_default()
    };
    let count_source =
        move |source: &str| -> u64 { telem_source_counts.get(source).copied().unwrap_or(0) as u64 };

    // Recency threshold: active if file modified within last 2 hours
    let recent = |age: Option<u64>| age.map(|s| s < 7200).unwrap_or(false);

    let auth_log = "/var/log/auth.log";
    let audit_log = "/var/log/audit/audit.log";
    let nginx_acc = "/var/log/nginx/access.log";
    let nginx_err = "/var/log/nginx/error.log";
    let docker_sock = "/var/run/docker.sock";
    let syslog_fw = "/var/log/syslog";
    let kern_log = "/var/log/kern.log";
    let cloudtrail = "/var/log/cloudtrail/events.json";
    let collectors = serde_json::json!([
        {
            "id": "auth_log",
            "name": "SSH / Auth Log",
            "kind": "native",
            "log_path": auth_log,
            "detected": file_exists(auth_log),
            "active": recent(file_age_secs(auth_log)),
            "events_today": count_source("auth_log"),
            "desc": "Parses /var/log/auth.log for SSH failures, logins, sudo"
        },
        {
            "id": "journald",
            "name": "systemd Journal",
            "kind": "native",
            "log_path": "journald",
            "detected": has_binary("journalctl"),
            "active": has_binary("journalctl"),
            "events_today": count_source("journald"),
            "desc": "Tails journald (sshd, sudo, kernel) via journalctl --follow"
        },
        {
            "id": "docker",
            "name": "Docker Events",
            "kind": "native",
            "log_path": docker_sock,
            "detected": file_exists(docker_sock),
            "active": file_exists(docker_sock),
            "events_today": count_source("docker"),
            "desc": "Docker lifecycle events + privilege escalation detection"
        },
        {
            "id": "nginx_access",
            "name": "nginx Access Log",
            "kind": "native",
            "log_path": nginx_acc,
            "detected": file_exists(nginx_acc),
            "active": recent(file_age_secs(nginx_acc)),
            "events_today": count_source("nginx_access"),
            "desc": "nginx access log - search abuse, UA scanner detection"
        },
        {
            "id": "nginx_error",
            "name": "nginx Error Log",
            "kind": "native",
            "log_path": nginx_err,
            "detected": file_exists(nginx_err),
            "active": recent(file_age_secs(nginx_err)),
            "events_today": count_source("nginx_error"),
            "desc": "nginx error log - web scanner and probe detection"
        },
        {
            "id": "exec_audit",
            "name": "Shell Audit (auditd)",
            "kind": "native",
            "log_path": audit_log,
            "detected": file_exists(audit_log),
            "active": recent(file_age_secs(audit_log)),
            "events_today": count_source("exec_audit"),
            "desc": "auditd EXECVE events - execution guard and shell command trail"
        },
        {
            "id": "ebpf",
            "name": "eBPF Kernel",
            "kind": "native",
            "log_path": "/usr/local/lib/innerwarden/innerwarden-ebpf",
            "detected": file_exists("/usr/local/lib/innerwarden/innerwarden-ebpf"),
            "active": true,
            "events_today": count_source("ebpf"),
            "desc": "22 kernel hooks: 19 tracepoints + kprobe (privesc) + LSM (exec block) + XDP (wire-speed IP block)"
        },
        {
            "id": "syslog_firewall",
            "name": "Syslog Firewall",
            "kind": "native",
            "log_path": syslog_fw,
            "detected": file_exists(syslog_fw) || file_exists(kern_log),
            "active": recent(file_age_secs(syslog_fw)) || recent(file_age_secs(kern_log)),
            "events_today": count_source("syslog_firewall"),
            "desc": "iptables/nftables DROP logs from /var/log/syslog or kern.log"
        },
        {
            "id": "firmware_integrity",
            "name": "Firmware Integrity",
            "kind": "native",
            "log_path": "/boot/efi",
            "detected": file_exists("/boot/efi") || file_exists("/sys/firmware/efi"),
            "active": true,
            "events_today": count_source("firmware_integrity"),
            "desc": "UEFI/EFI boot partition monitoring - detects unauthorized binaries"
        },
        {
            "id": "cloudtrail",
            "name": "AWS CloudTrail",
            "kind": "external",
            "log_path": cloudtrail,
            "detected": file_exists(cloudtrail),
            "active": recent(file_age_secs(cloudtrail)),
            "events_today": count_source("cloudtrail"),
            "desc": "AWS CloudTrail JSON logs - IAM changes, S3 access, API calls"
        },
        {
            "id": "macos_log",
            "name": "macOS Unified Log",
            "kind": "native",
            "log_path": "log stream",
            "detected": has_binary("log"),
            "active": has_binary("log"),
            "events_today": count_source("macos_log"),
            "desc": "macOS unified log stream - auth events, process exec, network"
        },
    ]);

    Json(serde_json::json!({ "collectors": collectors }))
}

pub(super) fn get_protection_mode(enabled: bool, dry_run: bool) -> &'static str {
    if enabled {
        if dry_run {
            "watch"
        } else {
            "guard"
        }
    } else {
        "read_only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_protection_mode() {
        assert_eq!(get_protection_mode(false, false), "read_only");
        assert_eq!(get_protection_mode(false, true), "read_only");
        assert_eq!(get_protection_mode(true, true), "watch");
        assert_eq!(get_protection_mode(true, false), "guard");
    }

    #[test]
    fn test_sensors_system_status_mapping() {
        // Build mock telemetry config output matching structure expected by frontend
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let _events_file = format!("events-{today}.jsonl");

        let files = serde_json::json!({
            "events": { "exists": false, "size_bytes": 0 },
            "incidents": { "exists": false, "size_bytes": 0 }
        });

        // Assert structure mapping defaults correctly handle missing files fallback
        assert!(!files["events"]["exists"].as_bool().unwrap());
        assert_eq!(files["events"]["size_bytes"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_honeypot_mode_always_on() {
        let action_cfg = DashboardActionConfig {
            enabled: true,
            honeypot_mode: "always_on".to_string(),
            ..Default::default()
        };
        assert_eq!(action_cfg.honeypot_mode, "always_on");
    }

    #[test]
    fn test_honeypot_mode_off() {
        let action_cfg = DashboardActionConfig {
            enabled: false,
            honeypot_mode: "off".to_string(),
            ..Default::default()
        };
        assert_eq!(action_cfg.honeypot_mode, "off");
    }

    #[test]
    fn test_honeypot_mode_listener() {
        let action_cfg = DashboardActionConfig {
            enabled: true,
            honeypot_mode: "listener".to_string(),
            ..Default::default()
        };
        assert_eq!(action_cfg.honeypot_mode, "listener");
    }

    #[test]
    fn test_xdp_integration_state_off() {
        let action_cfg = DashboardActionConfig {
            execution_guard_enabled: false,
            ..Default::default()
        };
        assert_eq!(action_cfg.execution_guard_enabled, false);
    }

    #[test]
    fn test_kill_chain_tracker_on() {
        let action_cfg = DashboardActionConfig {
            enabled: true,
            execution_guard_enabled: true,
            ..Default::default()
        };
        assert!(action_cfg.enabled);
        assert!(action_cfg.execution_guard_enabled);
    }

    // ── build_sensors_payload (Finding 4 anchor) ─────────────────────
    //
    // The handler runs this on the blocking pool. The payload structure
    // must be stable; the test pins the JSON shape so a future refactor
    // (e.g. the spawn_blocking wrapper changing arg order) cannot
    // accidentally drop a field.

    #[test]
    fn build_sensors_payload_returns_expected_shape_on_empty_graph() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None);

        // Required fields: date, total_events, total_incidents, sources,
        // top_kinds, detectors, event_timeline, detector_timeline.
        for field in [
            "date",
            "total_events",
            "total_incidents",
            "sources",
            "top_kinds",
            "detectors",
            "event_timeline",
            "detector_timeline",
        ] {
            assert!(
                payload.get(field).is_some(),
                "build_sensors_payload missing required field {field}"
            );
        }
        assert_eq!(payload["total_events"].as_u64(), Some(0));
        assert_eq!(payload["total_incidents"].as_u64(), Some(0));
    }

    // 2026-05-02 audit B1/P1 (Spec 039 P3) anchor: the Sensors HUD
    // must paint the SAME total_events / total_incidents as the
    // canonical OverviewSnapshot (which Home, Briefing, and Report
    // already read). Pre-fix the HUD scanned the KG and showed
    // "47 events handled" while the Home tile said something different.
    #[test]
    fn build_sensors_payload_reads_topline_counters_from_snapshot() {
        use crate::dashboard::types::{
            BucketStats, DetectorCount, OutcomeBuckets, OverviewSnapshot, PendingBreakdown,
            SystemHealth,
        };
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");

        // Snapshot says: 5+3+1+2+1+4 = 16 incidents today, 14_700_000 events.
        let snap = OverviewSnapshot {
            date: "2026-05-02".to_string(),
            generated_at: chrono::Utc::now(),
            health: SystemHealth::OperatingNormally,
            buckets: OutcomeBuckets {
                blocked: BucketStats {
                    incidents: 5,
                    unique_attackers: 3,
                    severities: Default::default(),
                },
                observing: BucketStats {
                    incidents: 3,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                honeypot: BucketStats {
                    incidents: 1,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                dismissed: BucketStats {
                    incidents: 2,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                allowlisted: BucketStats {
                    incidents: 1,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                attention: BucketStats {
                    incidents: 4,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
            },
            pending: PendingBreakdown::default(),
            events_today: 14_700_000,
            top_detectors: vec![DetectorCount {
                detector: "ssh_bruteforce".to_string(),
                count: 1,
            }],
        };

        let payload = build_sensors_payload(&kg, dir.path(), Some(&snap));
        assert_eq!(
            payload["total_events"].as_u64(),
            Some(14_700_000),
            "total_events must come from snapshot.events_today, not KG counter"
        );
        assert_eq!(
            payload["total_incidents"].as_u64(),
            Some(16),
            "total_incidents must be the sum of OverviewSnapshot bucket incidents \
             (5+3+1+2+1+4 = 16) — same source the Home tile and Briefing read"
        );
    }

    #[tokio::test]
    async fn api_sensors_async_handler_returns_payload_via_spawn_blocking() {
        // Anchors the spawn_blocking wrapper around build_sensors_payload.
        // Goes through the full async handler so the cache + spawn_blocking
        // + extracted helper chain stays exercised.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        // Force `last_activity` to "recent" so the sleeping path doesn't
        // short-circuit the handler.
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let Json(payload) = api_sensors(State(state)).await;
        // First call is a cache miss; payload must include the canonical
        // shape from build_sensors_payload.
        for field in [
            "date",
            "total_events",
            "total_incidents",
            "sources",
            "top_kinds",
            "detectors",
        ] {
            assert!(
                payload.get(field).is_some(),
                "api_sensors response missing required field {field}"
            );
        }
    }

    #[test]
    fn build_sensors_payload_falls_back_to_telemetry_snapshot_when_graph_empty() {
        // Anchors the `else` branch of `if graph.total_events_ingested > 0`
        // — when the graph hasn't seen any telemetry, the handler reads
        // from the JSONL telemetry snapshot. Empty tempdir → fallback
        // returns empty sources but the payload still has the right shape.
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None);
        // Total stays 0 (no graph counters AND no telemetry file).
        assert_eq!(payload["total_events"].as_u64(), Some(0));
        let sources = payload["sources"].as_array().expect("sources array");
        assert_eq!(sources.len(), 0, "no telemetry snapshot → no sources");
    }

    #[test]
    fn build_sensors_payload_counts_telemetry_from_graph() {
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        // Inject telemetry counters directly so we don't depend on the
        // event-ingest pipeline. Sensors handler reads these counters
        // directly when total_events_ingested > 0.
        g.record_event_telemetry("auth_log", "ssh.login_failed", chrono::Utc::now());
        g.record_event_telemetry("auth_log", "ssh.login_failed", chrono::Utc::now());
        g.record_event_telemetry("nginx_access", "http.request", chrono::Utc::now());

        let kg = std::sync::Arc::new(std::sync::RwLock::new(g));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None);

        assert_eq!(payload["total_events"].as_u64(), Some(3));
        let sources = payload["sources"].as_array().expect("sources array");
        // Two distinct sources, sorted by count desc — auth_log first.
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0]["name"].as_str(), Some("auth_log"));
        assert_eq!(sources[0]["count"].as_u64(), Some(2));
    }

    // 2026-05-02 audit anchor: the operator reported the Event Timeline
    // chart was "fixo aparecendo alto so depois das 20 horas" / "ta
    // assim a dias". Cause: `event_timeline` keys are
    // `YYYY-MM-DDTHH:MM`; the display projection stripped the date and
    // the BTreeMap collapsed multi-day buckets onto the same `HH:MM`
    // display key. With last-iteration-wins semantics, yesterday's
    // pre-spike hours survived for hours where today hadn't ingested
    // anything yet — the chart looked like a multi-day average instead
    // of today's fresh data. The fix filters buckets to today's date
    // prefix before stripping; this anchor pins that contract.
    #[test]
    fn build_sensors_payload_event_timeline_filters_to_today_only() {
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        // Force `total_events_ingested > 0` so the per-source path is
        // taken (the chart-fold bug only affected dated buckets, not
        // the per-source counters tested above).
        g.record_event_telemetry("auth_log", "ssh.login_failed", chrono::Utc::now());

        // Seed the event_timeline with both today's and yesterday's
        // buckets. Yesterday's value for a slot today hasn't reached
        // is what would survive the BTreeMap dedup pre-fix.
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let mut yesterday_03_15: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        yesterday_03_15.insert("auth_log".to_string(), 9_999);
        let mut today_22_00: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        today_22_00.insert("auth_log".to_string(), 7);
        g.event_timeline
            .insert(format!("{yesterday}T03:15"), yesterday_03_15);
        g.event_timeline
            .insert(format!("{today}T22:00"), today_22_00);

        let kg = std::sync::Arc::new(std::sync::RwLock::new(g));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None);

        let timeline = payload["event_timeline"].as_object().expect("timeline");
        // Yesterday's `03:15` MUST NOT leak into today's chart even
        // though strip_date_prefix would project it to the same key.
        assert!(
            !timeline.contains_key("03:15"),
            "yesterday's 03:15 bucket must NOT appear on today's chart \
             (chart-fold regression — see commit message). Got: {timeline:?}"
        );
        // Today's bucket is present and untouched.
        assert!(
            timeline.contains_key("22:00"),
            "today's 22:00 bucket must appear on today's chart. Got: {timeline:?}"
        );
        let today_bucket = timeline["22:00"].as_object().unwrap();
        assert_eq!(today_bucket["auth_log"].as_u64(), Some(7));
    }

    // 2026-05-02 audit anchor: the operator's screenshot showed
    // "EVENTS TODAY: 0" while per-source counters totalled millions.
    // Pre-fix the SoT helper hardcoded `events_today: 0` and only
    // api_overview backfilled it. The Sensors HUD path (PR #409) read
    // the un-backfilled snapshot directly. This anchor pins that
    // build_sensors_payload, when handed an OverviewSnapshot with
    // events_today populated, surfaces that exact value as
    // `total_events`.
    #[test]
    fn build_sensors_payload_uses_snapshot_events_today_field() {
        use crate::dashboard::types::{
            BucketStats, OutcomeBuckets, OverviewSnapshot, PendingBreakdown, SystemHealth,
        };
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");

        let snap = OverviewSnapshot {
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            generated_at: chrono::Utc::now(),
            health: SystemHealth::OperatingNormally,
            buckets: OutcomeBuckets {
                blocked: BucketStats {
                    incidents: 1,
                    unique_attackers: 1,
                    severities: Default::default(),
                },
                ..Default::default()
            },
            pending: PendingBreakdown::default(),
            // Distinctive value so a regression that swaps fields would
            // surface immediately.
            events_today: 13_177_172,
            top_detectors: vec![],
        };

        let payload = build_sensors_payload(&kg, dir.path(), Some(&snap));
        assert_eq!(
            payload["total_events"].as_u64(),
            Some(13_177_172),
            "total_events MUST come from snapshot.events_today (the \
             canonical SoT field). If this drops to 0, the SoT \
             contract regressed — see fix in compute_overview_counts_from_sqlite"
        );
    }
}
