// Auto-extracted from mod.rs — dashboard sensors handlers

use super::*;

/// GET /api/sensors - sensor activity time-series for dashboard graphs.
/// Returns event counts bucketed by 5-minute intervals, grouped by source.
/// Cached for 30 seconds to avoid re-reading the events file on every request.
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

    let result = api_sensors_inner(&state).await;

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

pub(super) async fn api_sensors_inner(state: &DashboardState) -> serde_json::Value {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

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
        let telem = crate::telemetry::read_latest_snapshot(&state.data_dir, &today);
        match telem {
            Some(t) => {
                let total = t.events_by_collector.values().sum::<u64>() as usize;
                let mut s: Vec<_> = t
                    .events_by_collector
                    .into_iter()
                    .map(|(k, v)| (k, v as usize))
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

    // Detector counts from Incident nodes
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
            let ts_str = ts.format("%H:%M").to_string();
            if ts_str.len() >= 5 {
                let hour = &ts_str[0..2];
                let min: usize = ts_str[3..5].parse().unwrap_or(0);
                let bucket = format!("{}:{:02}", hour, (min / 5) * 5);
                *detector_timeline
                    .entry(bucket)
                    .or_default()
                    .entry(detector.clone())
                    .or_insert(0) += 1;
            }
        }
    }

    let mut detectors: Vec<_> = detector_counts.into_iter().collect();
    detectors.sort_by(|a, b| b.1.cmp(&a.1));

    // event_timeline may be empty after restart (cursor/snapshot race).
    // Use detector_timeline as fallback — it's rebuilt from persisted Incident nodes.
    let event_tl = if graph.event_timeline.is_empty() {
        &detector_timeline
    } else {
        &graph.event_timeline
    };

    serde_json::json!({
        "date": today,
        "total_events": total_events_val,
        "total_incidents": total_incidents,
        "sources": sources.iter().map(|(s, c)| serde_json::json!({"name": s, "count": c})).collect::<Vec<_>>(),
        "top_kinds": kinds.iter().map(|(k, c)| serde_json::json!({"name": k, "count": c})).collect::<Vec<_>>(),
        "detectors": detectors.iter().map(|(d, c)| serde_json::json!({"name": d, "count": c})).collect::<Vec<_>>(),
        "event_timeline": event_tl,
        "detector_timeline": detector_timeline,
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

    let mode = if action_cfg.enabled {
        if action_cfg.dry_run {
            "watch"
        } else {
            "guard"
        }
    } else {
        "read_only"
    };

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
                t.events_by_collector
                    .into_iter()
                    .map(|(k, v)| (k, v as usize))
                    .collect()
            })
            .unwrap_or_default()
    };
    let count_source = move |source: &str| -> u64 {
        telem_source_counts.get(source).copied().unwrap_or(0) as u64
    };

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
