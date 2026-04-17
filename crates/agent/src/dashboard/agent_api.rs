// Auto-extracted from mod.rs — dashboard agent_api handlers

use super::*;

// ---------------------------------------------------------------------------

pub(super) fn parse_disabled_detectors(content: &str) -> std::collections::HashSet<&'static str> {
    let mut disabled = std::collections::HashSet::new();
    if content.is_empty() {
        return disabled;
    }

    let table: toml::Table = match content.parse() {
        Ok(t) => t,
        Err(_) => return disabled,
    };

    let detectors_table = match table.get("detectors").and_then(|d| d.as_table()) {
        Some(t) => t,
        None => return disabled,
    };

    let all_names: &[&str] = &[
        "ssh_bruteforce",
        "credential_stuffing",
        "distributed_ssh",
        "credential_harvest",
        "suspicious_login",
        "port_scan",
        "web_scan",
        "user_agent_scanner",
        "search_abuse",
        "crypto_miner",
        "outbound_anomaly",
        "ransomware",
        "execution_guard",
        "reverse_shell",
        "process_tree",
        "docker_anomaly",
        "fileless",
        "integrity_alert",
        "log_tampering",
        "rootkit",
        "process_injection",
        "web_shell",
        "ssh_key_injection",
        "kernel_module_load",
        "crontab_persistence",
        "systemd_persistence",
        "user_creation",
        "container_escape",
        "privesc",
        "sudo_abuse",
        "c2_callback",
        "dns_tunneling",
        "data_exfiltration",
        "lateral_movement",
        "sensitive_write",
        "packet_flood",
        "data_exfil_ebpf",
    ];

    for &name in all_names {
        if let Some(det_config) = detectors_table.get(name).and_then(|d| d.as_table()) {
            if let Some(enabled) = det_config.get("enabled").and_then(|e| e.as_bool()) {
                if !enabled {
                    disabled.insert(name);
                }
            }
        }
    }

    disabled
}

/// Read sensor config.toml to find detectors with `enabled = false`.
/// Returns a set of detector names that are explicitly disabled.
/// Falls back to empty set if config can't be read or parsed.
fn read_disabled_detectors_from_config() -> std::collections::HashSet<&'static str> {
    let paths = [
        "/etc/innerwarden/config.toml",
        "/etc/innerwarden/sensor.toml",
    ];

    let content = paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();

    parse_disabled_detectors(&content)
}

// ---------------------------------------------------------------------------
// Agent API - security context for AI agents (OpenClaw, n8n, etc.)
// ---------------------------------------------------------------------------

/// GET /api/agent/security-context - threat overview for AI agents (Phase 6A: graph-only)
pub(super) async fn api_agent_security_context(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let date = resolve_date(None);

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    let total_incidents = incident_nodes.len();
    let mut high_or_critical = 0usize;
    let mut blocks_today = 0usize;
    let mut detector_counts = std::collections::HashMap::<String, usize>::new();

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            severity,
            decision,
            auto_executed,
            ..
        }) = graph.get_node(id)
        {
            let sev = severity.to_lowercase();
            if sev == "high" || sev == "critical" {
                high_or_critical += 1;
            }
            *detector_counts.entry(detector.clone()).or_default() += 1;

            if let Some(dec) = decision {
                if dec == "block_ip" && *auto_executed {
                    blocks_today += 1;
                }
            }
        }
    }

    let mut top: Vec<_> = detector_counts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    let top_threats: Vec<String> = top.iter().take(5).map(|(k, _)| k.clone()).collect();

    let threat_level = security_context_level(total_incidents);

    let recommendation = match threat_level {
        "critical" => "server under active attack - avoid risky operations",
        "high" => "elevated threat level - proceed with caution",
        _ => "safe to proceed",
    };

    Json(serde_json::json!({
        "threat_level": threat_level,
        "active_incidents_today": total_incidents,
        "high_or_critical_today": high_or_critical,
        "recent_blocks_today": blocks_today,
        "top_threats": top_threats,
        "recommendation": recommendation,
        "date": date,
    }))
}

/// Query params for check-ip
#[derive(serde::Deserialize)]
pub(super) struct CheckIpQuery {
    ip: String,
}

/// GET /api/agent/check-ip?ip=X - check if an IP is known threat (Phase 6A: graph-only)
pub(super) async fn api_agent_check_ip(
    State(state): State<DashboardState>,
    Query(query): Query<CheckIpQuery>,
) -> Json<serde_json::Value> {
    let ip = query.ip.trim();

    use crate::knowledge_graph::types::{Node, Relation};
    let graph = state.knowledge_graph.read().unwrap();

    // Find the IP node
    let ip_node_id = graph.find_by_ip(ip);

    let mut incident_count = 0usize;
    let mut blocked = false;
    let mut last_seen: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut detectors = std::collections::HashSet::new();

    if let Some(ip_id) = ip_node_id {
        // Use incoming edges on the IP node — O(k) instead of scanning all incidents
        for edge in graph.incoming_edges(ip_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            if let Some(Node::Incident {
                detector,
                ts,
                decision,
                auto_executed,
                ..
            }) = graph.get_node(edge.from)
            {
                incident_count += 1;
                detectors.insert(detector.clone());
                match &last_seen {
                    Some(prev) if prev >= ts => {}
                    _ => last_seen = Some(*ts),
                }
                if let Some(dec) = decision {
                    if dec == "block_ip" && *auto_executed {
                        blocked = true;
                    }
                }
            }
        }
    }

    let recommendation = check_ip_recommendation(blocked, incident_count);

    Json(serde_json::json!({
        "ip": ip,
        "known_threat": incident_count > 0 || blocked,
        "incident_count": incident_count,
        "blocked": blocked,
        "last_seen": last_seen.map(|ts| ts.to_rfc3339()),
        "detectors": detectors.into_iter().collect::<Vec<_>>(),
        "recommendation": recommendation,
    }))
}

pub(super) fn security_context_level(total_incidents: usize) -> &'static str {
    if total_incidents == 0 {
        "calm"
    } else if total_incidents <= 5 {
        "elevated"
    } else {
        "high"
    }
}

pub(super) fn check_ip_recommendation(blocked: bool, incident_count: usize) -> &'static str {
    if blocked {
        "avoid"
    } else if incident_count > 0 {
        "caution"
    } else {
        "no threat data"
    }
}

/// Request body for check-command
#[derive(serde::Deserialize)]
pub(super) struct CheckCommandRequest {
    command: String,
    #[serde(default)]
    agent_name: Option<String>,
}

/// Analyze a command for dangerous patterns (pure function, no state).
/// Returns a JSON object with risk_score, severity, signals, recommendation, explanation.
/// Run agent-guard unified command analysis and optionally emit a snitch alert.
pub(super) fn run_analysis(
    state: &DashboardState,
    command: &str,
    agent_name: Option<&str>,
) -> serde_json::Value {
    let analysis = innerwarden_agent_guard::mcp::analyze_command(command, Some(&state.rule_engine));

    // Emit snitch alert if deny or review.
    if analysis.recommendation == "deny" || analysis.recommendation == "review" {
        let alert = AgentGuardAlert {
            ts: Utc::now(),
            agent_name: agent_name.unwrap_or("unknown").to_string(),
            command: if command.len() > 200 {
                format!("{}...", &command[..200])
            } else {
                command.to_string()
            },
            risk_score: analysis.risk_score,
            severity: analysis.severity.clone(),
            recommendation: analysis.recommendation.clone(),
            signals: analysis.signals.iter().map(|s| s.signal.clone()).collect(),
            atr_rule_ids: analysis
                .atr_matches
                .iter()
                .map(|m| m.rule_id.clone())
                .collect(),
            explanation: analysis.explanation.clone(),
        };
        let _ = state.agent_alert_tx.try_send(alert);
    }

    // Serialize to the same JSON shape as the old analyze_command for backward compat.
    serde_json::json!({
        "command": analysis.command,
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "signals": analysis.signals,
        "recommendation": analysis.recommendation,
        "explanation": analysis.explanation,
    })
}

/// POST /api/agent/check-command - analyze a command for dangerous patterns
pub(super) async fn api_agent_check_command(
    State(state): State<DashboardState>,
    Json(body): Json<CheckCommandRequest>,
) -> Json<serde_json::Value> {
    Json(run_analysis(
        &state,
        &body.command,
        body.agent_name.as_deref(),
    ))
}

/// POST /api/advisor/check-command - analyze + cache advisory for deny/review results
pub(super) async fn api_advisor_check_command(
    State(state): State<DashboardState>,
    Json(body): Json<CheckCommandRequest>,
) -> Json<serde_json::Value> {
    let mut result = run_analysis(&state, &body.command, body.agent_name.as_deref());

    // If deny or review, cache the advisory for correlation with real incidents
    let recommendation = result
        .get("recommendation")
        .and_then(|v| v.as_str())
        .unwrap_or("allow");
    let risk_score = result
        .get("risk_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    if recommendation == "deny" || recommendation == "review" {
        let advisory_id = generate_session_token();
        // Trim to 16 chars for advisory IDs
        let advisory_id = advisory_id[..16].to_string();

        let signals: Vec<String> = result
            .get("signals")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.get("signal").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let command_lower = body.command.to_lowercase();
        let command_hash = innerwarden_core::audit::sha256_hex(command_lower.trim());
        let command_preview = if body.command.len() > 120 {
            format!("{}...", &body.command[..120])
        } else {
            body.command.clone()
        };

        let entry = AdvisoryEntry {
            advisory_id: advisory_id.clone(),
            command_hash,
            command_preview,
            risk_score,
            recommendation: recommendation.to_string(),
            signals,
            ts: Utc::now(),
        };

        if let Ok(mut cache) = state.advisory_cache.write() {
            if cache.len() >= 256 {
                cache.pop_front();
            }
            cache.push_back(entry);
        }

        result["advisory_id"] = serde_json::Value::String(advisory_id);
    }

    Json(result)
}

// ---------------------------------------------------------------------------
// Prometheus metrics endpoint
// ---------------------------------------------------------------------------
// Agent Guard API
// ---------------------------------------------------------------------------

/// POST /api/agent-guard/connect — an AI agent registers itself with InnerWarden.
///
/// Request: { "name": "openclaw", "pid": 1234, "label": "work-agent" }
/// Response: { "connected": true, "agent_id": "ag-0001", "check_command": "...", "policy": {...} }
pub(super) async fn api_agent_guard_connect(
    State(state): State<DashboardState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("unknown");
    let pid = body["pid"].as_u64().unwrap_or(0) as u32;
    let label = body["label"].as_str();

    let mut registry = state.agent_registry.lock().await;
    match registry.connect(name, pid, label) {
        Ok(agent_id) => {
            tracing::info!(agent_id = %agent_id, name, pid, "agent-guard: agent connected via API");
            Json(serde_json::json!({
                "connected": true,
                "agent_id": agent_id,
                "check_command": "http://localhost:8787/api/agent/check-command",
                "security_context": "http://localhost:8787/api/agent/security-context",
                "policy": {
                    "mode": "warn",
                    "sensitive_paths_blocked": true,
                    "max_calls_per_minute": 30,
                }
            }))
        }
        Err(e) => Json(serde_json::json!({
            "connected": false,
            "error": e,
        })),
    }
}

/// POST /api/agent-guard/disconnect — remove an agent from monitoring.
///
/// Request: { "agent_id": "ag-0001" }
pub(super) async fn api_agent_guard_disconnect(
    State(state): State<DashboardState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_id = body["agent_id"].as_str().unwrap_or("");
    let mut registry = state.agent_registry.lock().await;
    let ok = registry.disconnect(agent_id);
    Json(serde_json::json!({ "disconnected": ok }))
}

/// GET /api/agent-guard/agents — list all connected agents and detected tools.
pub(super) async fn api_agent_guard_list(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let registry = state.agent_registry.lock().await;
    let agents = registry.list();
    Json(serde_json::json!({
        "agents": agents,
        "total": registry.count_total(),
        "agents_count": registry.count_agents(),
        "tools_count": registry.count_tools(),
    }))
}

// ---------------------------------------------------------------------------

pub(super) async fn api_prometheus_metrics(
    State(state): State<DashboardState>,
) -> axum::response::Response {
    let date = resolve_date(None);

    // Read latest telemetry snapshot (small file, already cached)
    let telem = crate::telemetry::read_latest_snapshot(&state.data_dir, &date);

    let mut out = String::with_capacity(2048);

    // Help + type headers for Prometheus scraper
    out.push_str("# HELP innerwarden_events_total Total events collected today by collector\n");
    out.push_str("# TYPE innerwarden_events_total counter\n");
    if let Some(ref t) = telem {
        for (collector, count) in &t.events_by_collector {
            out.push_str(&format!(
                "innerwarden_events_total{{collector=\"{collector}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_incidents_total Total incidents detected today by detector\n");
    out.push_str("# TYPE innerwarden_incidents_total counter\n");
    if let Some(ref t) = telem {
        for (detector, count) in &t.incidents_by_detector {
            out.push_str(&format!(
                "innerwarden_incidents_total{{detector=\"{detector}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_decisions_total Total AI/auto decisions today by action\n");
    out.push_str("# TYPE innerwarden_decisions_total counter\n");
    if let Some(ref t) = telem {
        for (action, count) in &t.decisions_by_action {
            out.push_str(&format!(
                "innerwarden_decisions_total{{action=\"{action}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_ai_calls_total Total AI provider calls today\n");
    out.push_str("# TYPE innerwarden_ai_calls_total counter\n");
    if let Some(ref t) = telem {
        out.push_str(&format!("innerwarden_ai_calls_total {}\n", t.ai_sent_count));
    }

    out.push_str("# HELP innerwarden_ai_latency_avg_ms Average AI decision latency in ms\n");
    out.push_str("# TYPE innerwarden_ai_latency_avg_ms gauge\n");
    if let Some(ref t) = telem {
        out.push_str(&format!(
            "innerwarden_ai_latency_avg_ms {:.1}\n",
            t.avg_decision_latency_ms
        ));
    }

    out.push_str("# HELP innerwarden_errors_total Errors by component\n");
    out.push_str("# TYPE innerwarden_errors_total counter\n");
    if let Some(ref t) = telem {
        for (component, count) in &t.errors_by_component {
            out.push_str(&format!(
                "innerwarden_errors_total{{component=\"{component}\"}} {count}\n"
            ));
        }
    }

    out.push_str("# HELP innerwarden_executions_total Skill executions today (dry_run vs live)\n");
    out.push_str("# TYPE innerwarden_executions_total counter\n");
    if let Some(ref t) = telem {
        out.push_str(&format!(
            "innerwarden_executions_total{{mode=\"dry_run\"}} {}\n",
            t.dry_run_execution_count
        ));
        out.push_str(&format!(
            "innerwarden_executions_total{{mode=\"live\"}} {}\n",
            t.real_execution_count
        ));
    }

    // Response lifecycle metrics (from responses blob/file snapshot).
    let responses_data = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("responses").ok().flatten())
        .or_else(|| {
            // Canonicalize data_dir to prevent path traversal (CodeQL: path-injection).
            let canonical = std::fs::canonicalize(&state.data_dir).ok()?;
            let target = canonical.join("responses.json");
            if !target.starts_with(&canonical) {
                return None;
            }
            std::fs::read_to_string(target).ok()
        });
    if let Some(data) = responses_data {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
            out.push_str("# HELP innerwarden_responses_active Currently active response actions\n");
            out.push_str("# TYPE innerwarden_responses_active gauge\n");
            if let Some(count) = json["active_count"].as_u64() {
                out.push_str(&format!("innerwarden_responses_active {count}\n"));
            }
            out.push_str("# HELP innerwarden_responses_total Total response actions registered\n");
            out.push_str("# TYPE innerwarden_responses_total counter\n");
            if let Some(count) = json["totals"]["registered"].as_u64() {
                out.push_str(&format!("innerwarden_responses_total {count}\n"));
            }
            out.push_str("# HELP innerwarden_responses_expired_total Responses expired by TTL\n");
            out.push_str("# TYPE innerwarden_responses_expired_total counter\n");
            if let Some(count) = json["totals"]["expired"].as_u64() {
                out.push_str(&format!("innerwarden_responses_expired_total {count}\n"));
            }
            out.push_str(
                "# HELP innerwarden_responses_reverted_total Responses manually reverted\n",
            );
            out.push_str("# TYPE innerwarden_responses_reverted_total counter\n");
            if let Some(count) = json["totals"]["reverted"].as_u64() {
                out.push_str(&format!("innerwarden_responses_reverted_total {count}\n"));
            }
        }
    }

    // Spec 024 drift metrics — appended after legacy metrics so any existing
    // Prometheus scrape keeps reading the same fields.
    append_spec024_metrics(&mut out, &state, chrono::Utc::now());

    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(out))
        .unwrap()
        .into_response()
}

// ---------------------------------------------------------------------------
// Spec 024 — drift metrics
// ---------------------------------------------------------------------------

/// Emits the 10 metrics defined in `/.specify/features/024-regression-safety-net/spec.md`.
///
/// Design notes:
/// - Counter-like metrics (`*_total`) are cumulative and monotonic across the
///   life of the sqlite store. Gauge-like metrics (`*_per_hour`) are computed
///   over a trailing 1-hour window so alert thresholds in
///   `docs/prometheus-alerts.yaml` stay consistent even without an external
///   Prometheus instance doing `rate()`.
/// - Cardinality is bounded by construction: every label is a small enum
///   (severity, backend, provider, pattern, source) — never per-IP or per
///   incident, per spec 024 §Risks.
/// - Best-effort: if sqlite is not attached, JSONL files are missing, or a
///   query fails, the metric is emitted as 0 with the same labels. Never
///   panics. Never blocks.
pub(super) fn append_spec024_metrics(
    out: &mut String,
    state: &DashboardState,
    now: chrono::DateTime<chrono::Utc>,
) {
    let hour_ago = now - chrono::Duration::hours(1);
    let today = now.date_naive().format("%Y-%m-%d").to_string();
    let hour_ago_date = hour_ago.date_naive().format("%Y-%m-%d").to_string();

    // ── 1. innerwarden_incidents_per_hour{severity} ─────────────────
    out.push_str("# HELP innerwarden_incidents_per_hour Incidents emitted in the last hour, grouped by severity. Spec 024.\n");
    out.push_str("# TYPE innerwarden_incidents_per_hour gauge\n");
    let sev_counts = count_incidents_last_hour_by_severity(state, &hour_ago);
    for sev in &["critical", "high", "medium", "low", "info", "debug"] {
        let n = sev_counts.get(*sev).copied().unwrap_or(0);
        out.push_str(&format!(
            "innerwarden_incidents_per_hour{{severity=\"{sev}\"}} {n}\n"
        ));
    }

    // ── 2. innerwarden_telegram_msgs_per_hour ───────────────────────
    out.push_str("# HELP innerwarden_telegram_msgs_per_hour Telegram messages sent in the last hour. Spec 024.\n");
    out.push_str("# TYPE innerwarden_telegram_msgs_per_hour gauge\n");
    let telegram_n = read_telegram_msgs_last_hour(&state.data_dir, now);
    out.push_str(&format!(
        "innerwarden_telegram_msgs_per_hour {telegram_n}\n"
    ));

    // ── 3. innerwarden_blocks_per_hour{backend} ─────────────────────
    out.push_str("# HELP innerwarden_blocks_per_hour Block decisions in the last hour, grouped by backend. Spec 024.\n");
    out.push_str("# TYPE innerwarden_blocks_per_hour gauge\n");
    let backend_counts =
        count_blocks_last_hour_by_backend(&state.data_dir, &today, &hour_ago_date, &hour_ago);
    for backend in &[
        "ufw",
        "xdp",
        "iptables",
        "nftables",
        "pf",
        "cloudflare",
        "unknown",
    ] {
        let n = backend_counts.get(*backend).copied().unwrap_or(0);
        out.push_str(&format!(
            "innerwarden_blocks_per_hour{{backend=\"{backend}\"}} {n}\n"
        ));
    }

    // ── 4. innerwarden_honeypot_sessions_per_hour ──────────────────
    out.push_str("# HELP innerwarden_honeypot_sessions_per_hour Honeypot sessions recorded in the last hour. Spec 024.\n");
    out.push_str("# TYPE innerwarden_honeypot_sessions_per_hour gauge\n");
    let honeypot_n =
        count_honeypot_sessions_last_hour(&state.data_dir, &today, &hour_ago_date, &hour_ago);
    out.push_str(&format!(
        "innerwarden_honeypot_sessions_per_hour {honeypot_n}\n"
    ));

    // ── 5. innerwarden_tracker_detections_per_hour{pattern} ────────
    out.push_str("# HELP innerwarden_tracker_detections_per_hour Kill chain tracker detections in the last hour by pattern. Spec 024.\n");
    out.push_str("# TYPE innerwarden_tracker_detections_per_hour gauge\n");
    let patt_counts = count_killchain_last_hour_by_pattern(state, &hour_ago);
    // Always emit the known patterns so scrapers see zeros rather than missing keys.
    for pattern in &[
        "reverse_shell",
        "bind_shell",
        "code_inject",
        "data_exfil",
        "full_exploit",
        "privesc",
        "persistence",
        "c2_callback",
        "unknown",
    ] {
        let n = patt_counts.get(*pattern).copied().unwrap_or(0);
        out.push_str(&format!(
            "innerwarden_tracker_detections_per_hour{{pattern=\"{pattern}\"}} {n}\n"
        ));
    }

    // ── 6. innerwarden_orphaned_responses_total ────────────────────
    // Already emitted from the responses blob above, but only when the blob
    // exists. Re-emit here with a zero floor so alert rules always see the
    // metric (critical alert on any increment needs a present series).
    out.push_str("# HELP innerwarden_orphaned_responses_total Responses the system gave up on — rule may still be live in kernel/firewall. Any increment is a critical alert. Spec 024.\n");
    out.push_str("# TYPE innerwarden_orphaned_responses_total counter\n");
    let orphaned = read_responses_total(state, "orphaned");
    out.push_str(&format!(
        "innerwarden_orphaned_responses_total {orphaned}\n"
    ));

    // ── 7. innerwarden_revert_failures_total ───────────────────────
    out.push_str(
        "# HELP innerwarden_revert_failures_total Cumulative revert command failures. Spec 024.\n",
    );
    out.push_str("# TYPE innerwarden_revert_failures_total counter\n");
    let revert_total = read_responses_total(state, "revert_failures");
    out.push_str(&format!(
        "innerwarden_revert_failures_total {revert_total}\n"
    ));

    // ── 8. innerwarden_ai_provider_errors_per_hour{provider} ───────
    out.push_str("# HELP innerwarden_ai_provider_errors_per_hour AI provider errors today by provider name. Spec 024.\n");
    out.push_str("# TYPE innerwarden_ai_provider_errors_per_hour gauge\n");
    let ai_err = read_telemetry_error_count(&state.data_dir, &today, "ai_provider");
    // Provider label is the configured provider or "unknown". Telemetry
    // does not tag the provider per error today (see spec 024 follow-ups),
    // so we use "unknown" as a placeholder until that lands.
    out.push_str(&format!(
        "innerwarden_ai_provider_errors_per_hour{{provider=\"unknown\"}} {ai_err}\n"
    ));

    // ── 9. innerwarden_gate_suppressed_total ───────────────────────
    out.push_str("# HELP innerwarden_gate_suppressed_total Notifications dropped by notification_gate (DailyBriefingOnly + Drop). Spec 024.\n");
    out.push_str("# TYPE innerwarden_gate_suppressed_total counter\n");
    let suppressed = read_gate_suppressed_total(&state.data_dir, &today);
    out.push_str(&format!("innerwarden_gate_suppressed_total {suppressed}\n"));

    // ── 10. innerwarden_event_rate_per_hour{source} ────────────────
    // Intentionally a trailing-1h delta from telemetry snapshots (not
    // day-to-date average) so a silent source legitimately reaches 0/h.
    out.push_str("# HELP innerwarden_event_rate_per_hour Events observed in the last hour per source. Spec 024.\n");
    out.push_str("# TYPE innerwarden_event_rate_per_hour gauge\n");
    let per_source = read_event_rate_per_hour(&state.data_dir, &today, now);
    for (source, rate) in &per_source {
        // Escape quotes just in case a source name contains them (shouldn't).
        let safe = source.replace('"', "_");
        out.push_str(&format!(
            "innerwarden_event_rate_per_hour{{source=\"{safe}\"}} {rate:.2}\n"
        ));
    }
    if per_source.is_empty() {
        // Keep the metric present for the alert rule to evaluate even on a
        // quiet host — exporting no rows would hide the silent-source alert.
        out.push_str("innerwarden_event_rate_per_hour{source=\"none\"} 0\n");
    }
}

fn count_incidents_last_hour_by_severity(
    state: &DashboardState,
    hour_ago: &chrono::DateTime<chrono::Utc>,
) -> std::collections::HashMap<String, u64> {
    let mut out = std::collections::HashMap::new();
    let Some(store) = state.sqlite_store.as_ref() else {
        return out;
    };
    let Ok(conn) = store.conn() else {
        return out;
    };
    let threshold = hour_ago.to_rfc3339();
    let Ok(mut stmt) =
        conn.prepare("SELECT severity, COUNT(*) FROM incidents WHERE ts > ?1 GROUP BY severity")
    else {
        return out;
    };
    let iter = stmt.query_map([threshold.as_str()], |row| {
        let s: String = row.get(0)?;
        let n: i64 = row.get(1)?;
        Ok((s, n))
    });
    if let Ok(rows) = iter {
        for row in rows.flatten() {
            out.insert(row.0.to_lowercase(), row.1 as u64);
        }
    }
    out
}

fn read_telegram_msgs_last_hour(
    data_dir: &std::path::Path,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    let today = now.date_naive().format("%Y-%m-%d").to_string();
    let Some(latest) = crate::telemetry::read_latest_snapshot(data_dir, &today) else {
        return 0;
    };
    let hour_ago = now - chrono::Duration::hours(1);
    let hour_ago_date = hour_ago.date_naive().format("%Y-%m-%d").to_string();
    let baseline = crate::telemetry::read_snapshot_at(data_dir, &hour_ago_date, hour_ago)
        .map(|snap| snap.telegram_sent_count)
        .unwrap_or(0);
    latest.telegram_sent_count.saturating_sub(baseline)
}

fn count_blocks_last_hour_by_backend(
    data_dir: &std::path::Path,
    today: &str,
    hour_ago_date: &str,
    hour_ago: &chrono::DateTime<chrono::Utc>,
) -> std::collections::HashMap<String, u64> {
    let mut out = std::collections::HashMap::new();
    let Some(canonical) = std::fs::canonicalize(data_dir).ok() else {
        return out;
    };
    let mut dates = vec![today.to_string()];
    if hour_ago_date != today {
        dates.push(hour_ago_date.to_string());
    }
    for date in dates {
        let target = canonical.join(format!("decisions-{date}.jsonl"));
        if !target.starts_with(&canonical) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&target) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let action = v.get("action_type").and_then(|a| a.as_str()).unwrap_or("");
            if action != "block_ip" {
                continue;
            }
            let ts = v.get("ts").and_then(|t| t.as_str()).unwrap_or("");
            let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(ts) else {
                continue;
            };
            if parsed.with_timezone(&chrono::Utc) <= *hour_ago {
                continue;
            }
            // Backend is encoded in skill_id ("block-ip-ufw" → "ufw").
            let backend = v
                .get("skill_id")
                .and_then(|s| s.as_str())
                .and_then(|s| s.strip_prefix("block-ip-"))
                .unwrap_or("unknown")
                .to_string();
            *out.entry(backend).or_insert(0) += 1;
        }
    }
    out
}

fn count_honeypot_sessions_last_hour(
    data_dir: &std::path::Path,
    today: &str,
    hour_ago_date: &str,
    hour_ago: &chrono::DateTime<chrono::Utc>,
) -> u64 {
    // Honeypot sessions are written to honeypot-sessions-YYYY-MM-DD.jsonl when
    // the always-on listener is enabled. Absence of the file is a legitimate
    // zero.
    let Some(canonical) = std::fs::canonicalize(data_dir).ok() else {
        return 0;
    };
    let mut dates = vec![today.to_string()];
    if hour_ago_date != today {
        dates.push(hour_ago_date.to_string());
    }
    let mut n = 0u64;
    for date in dates {
        let target = canonical.join(format!("honeypot-sessions-{date}.jsonl"));
        if !target.starts_with(&canonical) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&target) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let ts = v
                .get("ended_at")
                .or_else(|| v.get("started_at"))
                .or_else(|| v.get("ts"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(ts) else {
                continue;
            };
            if parsed.with_timezone(&chrono::Utc) > *hour_ago {
                n += 1;
            }
        }
    }
    n
}

fn count_killchain_last_hour_by_pattern(
    state: &DashboardState,
    hour_ago: &chrono::DateTime<chrono::Utc>,
) -> std::collections::HashMap<String, u64> {
    let mut out = std::collections::HashMap::new();
    let Some(store) = state.sqlite_store.as_ref() else {
        return out;
    };
    let Ok(conn) = store.conn() else {
        return out;
    };
    let threshold = hour_ago.to_rfc3339();
    // Kill chain incident_ids take the form "kill_chain:detected:<PATTERN>:<pid>:<ts>".
    let Ok(mut stmt) =
        conn.prepare("SELECT incident_id FROM incidents WHERE ts > ?1 AND detector = 'kill_chain'")
    else {
        return out;
    };
    let iter = stmt.query_map([threshold.as_str()], |row| row.get::<_, String>(0));
    if let Ok(rows) = iter {
        for row in rows.flatten() {
            let pattern = row.split(':').nth(2).unwrap_or("unknown").to_lowercase();
            *out.entry(pattern).or_insert(0) += 1;
        }
    }
    out
}

fn read_responses_total(state: &DashboardState, field: &str) -> u64 {
    let data = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("responses").ok().flatten())
        .or_else(|| {
            let canonical = std::fs::canonicalize(&state.data_dir).ok()?;
            let target = canonical.join("responses.json");
            if !target.starts_with(&canonical) {
                return None;
            }
            std::fs::read_to_string(target).ok()
        });
    let Some(content) = data else { return 0 };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) else {
        return 0;
    };
    v["totals"][field].as_u64().unwrap_or(0)
}

fn read_telemetry_error_count(data_dir: &std::path::Path, date: &str, component: &str) -> u64 {
    let Some(snapshot) = crate::telemetry::read_latest_snapshot(data_dir, date) else {
        return 0;
    };
    snapshot
        .errors_by_component
        .get(component)
        .copied()
        .unwrap_or(0)
}

fn read_gate_suppressed_total(data_dir: &std::path::Path, date: &str) -> u64 {
    let Some(snapshot) = crate::telemetry::read_latest_snapshot(data_dir, date) else {
        return 0;
    };
    snapshot.gate_suppressed_total
}

fn read_event_rate_per_hour(
    data_dir: &std::path::Path,
    date: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<(String, f64)> {
    let Some(latest) = crate::telemetry::read_latest_snapshot(data_dir, date) else {
        return Vec::new();
    };

    let hour_ago = now - chrono::Duration::hours(1);
    let hour_ago_date = hour_ago.date_naive().format("%Y-%m-%d").to_string();
    let baseline = crate::telemetry::read_snapshot_at(data_dir, &hour_ago_date, hour_ago);

    let mut sources = std::collections::BTreeSet::new();
    sources.extend(latest.events_by_collector.keys().cloned());
    if let Some(ref previous) = baseline {
        sources.extend(previous.events_by_collector.keys().cloned());
    }

    let mut out: Vec<(String, f64)> = sources
        .into_iter()
        .map(|source| {
            let current = latest
                .events_by_collector
                .get(&source)
                .copied()
                .unwrap_or(0);
            let previous = baseline
                .as_ref()
                .and_then(|snap| snap.events_by_collector.get(&source).copied())
                .unwrap_or(0);
            let delta = current.saturating_sub(previous);
            (source, delta as f64)
        })
        .collect();

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// GET /api/incident-groups — spec 005 T017.
///
/// Returns the grouping engine's active-group snapshot. The agent writes
/// `incident-groups.json` in `data_dir` at every slow-loop tick; this handler
/// reads that file. Missing file means the agent has not emitted a snapshot
/// yet (normal right after boot) — return an empty shape rather than 404 so
/// the dashboard can render "no active campaigns" calmly.
pub(super) async fn api_incident_groups(
    State(state): State<DashboardState>,
) -> axum::response::Response {
    // Canonicalize data_dir to prevent path traversal (matches the pattern used
    // by api_responses).
    let snapshot = std::fs::canonicalize(&state.data_dir)
        .ok()
        .and_then(|canonical| {
            let target = canonical.join("incident-groups.json");
            if !target.starts_with(&canonical) {
                return None;
            }
            std::fs::read_to_string(target).ok()
        });

    let payload = match snapshot {
        Some(text) => text,
        None => serde_json::json!({
            "active_count": 0,
            "groups": [],
            "snapshot_ts": chrono::Utc::now().to_rfc3339(),
        })
        .to_string(),
    };

    axum::response::Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap()
        .into_response()
}

/// GET /api/responses — active and historical response actions with TTL.
pub(super) async fn api_responses(State(state): State<DashboardState>) -> axum::response::Response {
    // Try SQLite blob first, fall back to JSON file
    let data = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("responses").ok().flatten())
        .or_else(|| {
            // Canonicalize data_dir to prevent path traversal (CodeQL: path-injection).
            let canonical = std::fs::canonicalize(&state.data_dir).ok()?;
            let target = canonical.join("responses.json");
            if !target.starts_with(&canonical) {
                return None;
            }
            std::fs::read_to_string(target).ok()
        });
    match data {
        Some(data) => axum::response::Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(data))
            .unwrap()
            .into_response(),
        None => {
            let empty = serde_json::json!({"active": [], "active_count": 0, "history": [], "totals": {"registered": 0, "expired": 0, "reverted": 0}});
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&empty).unwrap()))
                .unwrap()
                .into_response()
        }
    }
}

/// GET /api/mitre/navigator — ATT&CK Navigator layer JSON.
/// Download and load at https://mitre-attack.github.io/attack-navigator/
pub(super) async fn api_mitre_navigator() -> axum::response::Response {
    let layer = crate::mitre::generate_navigator_layer();
    axum::response::Response::builder()
        .header("content-type", "application/json")
        .header(
            "content-disposition",
            "attachment; filename=\"innerwarden-coverage.json\"",
        )
        .body(Body::from(
            serde_json::to_string_pretty(&layer).unwrap_or_default(),
        ))
        .unwrap()
        .into_response()
}

/// GET /api/mitre/coverage — detailed per-tactic coverage with active status.
///
/// Two layers: "enabled" detectors (all that InnerWarden ships with, since all
/// are on by default) and "fired" detectors (those that generated incidents
/// today). The coverage view shows enabled status — the operator cares about
/// what their server CAN detect, not just what happened today.
pub(super) async fn api_mitre_coverage(
    State(state): State<DashboardState>,
) -> axum::response::Response {
    use crate::knowledge_graph::types::{Node, NodeType};

    // Read sensor config to determine which detectors are actually enabled.
    // Falls back to "all enabled" if config can't be read.
    let enabled_detectors: std::collections::HashSet<String> = {
        let all_shipped = vec![
            "ssh_bruteforce",
            "credential_stuffing",
            "distributed_ssh",
            "credential_harvest",
            "suspicious_login",
            "port_scan",
            "web_scan",
            "user_agent_scanner",
            "search_abuse",
            "crypto_miner",
            "outbound_anomaly",
            "ransomware",
            "execution_guard",
            "reverse_shell",
            "process_tree",
            "docker_anomaly",
            "fileless",
            "integrity_alert",
            "log_tampering",
            "rootkit",
            "process_injection",
            "web_shell",
            "ssh_key_injection",
            "kernel_module_load",
            "crontab_persistence",
            "systemd_persistence",
            "user_creation",
            "container_escape",
            "privesc",
            "sudo_abuse",
            "c2_callback",
            "dns_tunneling",
            "data_exfiltration",
            "lateral_movement",
            "sensitive_write",
            "at_job_persist",
            "file_permission_mod",
            "hidden_artifact",
            "remote_access_tool",
            "service_stop",
            "system_shutdown",
            "network_sniffing",
            "masquerading",
            "data_archive",
            "proxy_tunnel",
            "data_exfil_ebpf",
        ];

        // Try reading sensor config to find disabled detectors.
        let disabled = read_disabled_detectors_from_config();

        all_shipped
            .into_iter()
            .filter(|d| !disabled.contains(*d))
            .map(|s| s.to_string())
            .collect()
    };

    // Detectors that actually fired today (from knowledge graph).
    let fired_detectors: std::collections::HashSet<String> = {
        let graph = state.knowledge_graph.read().unwrap();
        let incident_nodes = graph.nodes_of_type(NodeType::Incident);
        let mut detectors = std::collections::HashSet::new();
        for &id in &incident_nodes {
            if let Some(Node::Incident { detector, .. }) = graph.get_node(id) {
                detectors.insert(detector.clone());
            }
        }
        detectors
    };

    let all_ids = crate::mitre::all_technique_ids();
    // Coverage uses detectors enabled in sensor config.
    let (tactics, recommendations) = crate::mitre::coverage_by_tactic(&enabled_detectors);

    let total_techniques = all_ids.len();
    let active_techniques: usize = tactics
        .iter()
        .flat_map(|t| &t.techniques)
        .filter(|t| t.active)
        .count();

    let summary = serde_json::json!({
        "total_techniques": total_techniques,
        "active_techniques": active_techniques,
        "coverage_pct": if total_techniques > 0 {
            (active_techniques as f64 / total_techniques as f64 * 100.0).round() as u32
        } else { 0 },
        "enabled_detectors": enabled_detectors.len(),
        "fired_today": fired_detectors.len(),
        "tactics": tactics,
        "recommendations": recommendations,
        "navigator_url": "/api/mitre/navigator",
    });

    axum::response::Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&summary).unwrap_or_default(),
        ))
        .unwrap()
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_disabled_detectors() {
        // Parses explicit detector toggles and returns only disabled ones.
        let toml_data = r#"
[detectors.crypto_miner]
enabled = false
[detectors.ssh_bruteforce]
enabled = true
[detectors.ransomware]
enabled = false
        "#;

        let disabled = parse_disabled_detectors(toml_data);
        assert_eq!(disabled.len(), 2);
        assert!(disabled.contains("crypto_miner"));
        assert!(disabled.contains("ransomware"));
        assert!(!disabled.contains("ssh_bruteforce"));
    }

    #[test]
    fn test_security_context_calm_with_zero_incidents() {
        // Zero incidents should map to calm context.
        assert_eq!(security_context_level(0), "calm");
    }

    #[test]
    fn test_security_context_elevated_with_small_volume() {
        // A small incident window should map to elevated.
        assert_eq!(security_context_level(1), "elevated");
        assert_eq!(security_context_level(5), "elevated");
    }

    #[test]
    fn test_security_context_high_with_large_volume() {
        // Six or more incidents should map to high.
        assert_eq!(security_context_level(6), "high");
    }

    #[test]
    fn test_check_ip_blocked_sets_avoid_recommendation() {
        // Blocked IPs must return avoid recommendation and blocked=true semantics.
        assert_eq!(check_ip_recommendation(true, 0), "avoid");
        assert_eq!(check_ip_recommendation(true, 10), "avoid");
    }

    // ─── Spec 024 /metrics helpers ──────────────────────────────────
    //
    // scenario-qa validates the underlying sqlite/JSONL artifacts that
    // feed these metrics but does not exercise GET /metrics or
    // append_spec024_metrics end-to-end.

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn telemetry_snapshot(
        ts: chrono::DateTime<chrono::Utc>,
        events: &[(&str, u64)],
        telegram_sent_count: u64,
        gate_suppressed_total: u64,
        ai_provider_errors: u64,
    ) -> crate::telemetry::TelemetrySnapshot {
        crate::telemetry::TelemetrySnapshot {
            ts,
            tick: "incident_tick".into(),
            events_by_collector: events.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            incidents_by_detector: Default::default(),
            gate_pass_count: 0,
            gate_suppressed_total,
            ai_sent_count: 0,
            telegram_sent_count,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: std::collections::BTreeMap::from([(
                "ai_provider".to_string(),
                ai_provider_errors,
            )]),
            decisions_by_action: Default::default(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
        }
    }

    fn write_telemetry_snapshots(
        dir: &std::path::Path,
        date: &str,
        snapshots: &[crate::telemetry::TelemetrySnapshot],
    ) {
        let path = dir.join(format!("telemetry-{date}.jsonl"));
        let content = snapshots
            .iter()
            .map(|snap| serde_json::to_string(snap).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, format!("{content}\n")).unwrap();
    }

    fn dashboard_state_for_metrics(
        data_dir: &std::path::Path,
        sqlite_store: Option<std::sync::Arc<innerwarden_store::Store>>,
    ) -> DashboardState {
        let (event_tx, _) = tokio::sync::broadcast::channel(8);
        let (agent_alert_tx, _agent_alert_rx) = tokio::sync::mpsc::channel(8);
        DashboardState {
            data_dir: data_dir.to_path_buf(),
            action_cfg: std::sync::Arc::new(DashboardActionConfig::default()),
            event_tx,
            web_push_vapid_public_key: String::new(),
            insecure_http: false,
            last_activity: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sensor_cache: std::sync::Arc::new(tokio::sync::Mutex::new((0, serde_json::json!({})))),
            trusted_proxies: std::sync::Arc::new(Vec::new()),
            sessions: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            session_timeout_minutes: 30,
            max_sessions: 16,
            advisory_cache: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::VecDeque::new(),
            )),
            agent_registry: std::sync::Arc::new(tokio::sync::Mutex::new(
                innerwarden_agent_guard::registry::Registry::new(),
            )),
            rule_engine: std::sync::Arc::new(innerwarden_agent_guard::rules::RuleEngine::empty()),
            agent_alert_tx,
            deep_security: std::sync::Arc::new(std::sync::RwLock::new(
                DeepSecuritySnapshot::default(),
            )),
            knowledge_graph: std::sync::Arc::new(std::sync::RwLock::new(
                crate::knowledge_graph::KnowledgeGraph::new(),
            )),
            ai_provider: None,
            latest_briefing: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            briefing_hour: 0,
            briefing_minute: 0,
            sqlite_store,
        }
    }

    #[test]
    fn read_telegram_msgs_last_hour_uses_snapshot_delta() {
        let td = tmpdir();
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-17T12:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let date = "2026-04-17";
        write_telemetry_snapshots(
            td.path(),
            date,
            &[
                telemetry_snapshot(
                    chrono::DateTime::parse_from_rfc3339("2026-04-17T11:20:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    &[("auth.log", 10)],
                    12,
                    0,
                    0,
                ),
                telemetry_snapshot(
                    chrono::DateTime::parse_from_rfc3339("2026-04-17T12:25:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    &[("auth.log", 30)],
                    20,
                    0,
                    0,
                ),
            ],
        );
        assert_eq!(read_telegram_msgs_last_hour(td.path(), now), 8);
    }

    #[test]
    fn read_telegram_msgs_last_hour_returns_zero_when_snapshot_missing() {
        let td = tmpdir();
        let now = chrono::Utc::now();
        assert_eq!(read_telegram_msgs_last_hour(td.path(), now), 0);
    }

    #[test]
    fn count_blocks_last_hour_filters_by_action_type_and_ts() {
        let td = tmpdir();
        let now = chrono::Utc::now();
        let today = now.date_naive().format("%Y-%m-%d").to_string();
        let path = td.path().join(format!("decisions-{today}.jsonl"));
        let old = now - chrono::Duration::hours(3);
        let recent = now - chrono::Duration::minutes(5);
        let mut contents = String::new();
        contents.push_str(&format!(
            "{{\"ts\":\"{}\",\"action_type\":\"block_ip\",\"skill_id\":\"block-ip-ufw\"}}\n",
            recent.to_rfc3339()
        ));
        contents.push_str(&format!(
            "{{\"ts\":\"{}\",\"action_type\":\"block_ip\",\"skill_id\":\"block-ip-xdp\"}}\n",
            recent.to_rfc3339()
        ));
        contents.push_str(&format!(
            "{{\"ts\":\"{}\",\"action_type\":\"monitor\",\"skill_id\":\"monitor-ip\"}}\n",
            recent.to_rfc3339()
        ));
        contents.push_str(&format!(
            "{{\"ts\":\"{}\",\"action_type\":\"block_ip\",\"skill_id\":\"block-ip-ufw\"}}\n",
            old.to_rfc3339()
        ));
        std::fs::write(&path, contents).unwrap();
        let counts = count_blocks_last_hour_by_backend(
            td.path(),
            &today,
            &today,
            &(now - chrono::Duration::hours(1)),
        );
        assert_eq!(counts.get("ufw").copied(), Some(1));
        assert_eq!(counts.get("xdp").copied(), Some(1));
        assert!(counts.get("monitor-ip").is_none(), "only block_ip counts");
    }

    #[test]
    fn count_blocks_last_hour_defaults_backend_to_unknown() {
        let td = tmpdir();
        let now = chrono::Utc::now();
        let today = now.date_naive().format("%Y-%m-%d").to_string();
        let path = td.path().join(format!("decisions-{today}.jsonl"));
        let recent = now - chrono::Duration::minutes(5);
        let contents = format!(
            "{{\"ts\":\"{}\",\"action_type\":\"block_ip\"}}\n",
            recent.to_rfc3339()
        );
        std::fs::write(&path, contents).unwrap();
        let counts = count_blocks_last_hour_by_backend(
            td.path(),
            &today,
            &today,
            &(now - chrono::Duration::hours(1)),
        );
        assert_eq!(counts.get("unknown").copied(), Some(1));
    }

    #[test]
    fn count_honeypot_sessions_last_hour_empty() {
        let td = tmpdir();
        let now = chrono::Utc::now();
        let today = now.date_naive().format("%Y-%m-%d").to_string();
        // No file ⇒ 0.
        let n = count_honeypot_sessions_last_hour(
            td.path(),
            &today,
            &today,
            &(now - chrono::Duration::hours(1)),
        );
        assert_eq!(n, 0);
    }

    #[test]
    fn count_honeypot_sessions_last_hour_respects_ended_at() {
        let td = tmpdir();
        let now = chrono::Utc::now();
        let today = now.date_naive().format("%Y-%m-%d").to_string();
        let path = td.path().join(format!("honeypot-sessions-{today}.jsonl"));
        let old = now - chrono::Duration::hours(2);
        let recent = now - chrono::Duration::minutes(10);
        let contents = format!(
            "{{\"ended_at\":\"{}\"}}\n{{\"ended_at\":\"{}\"}}\n",
            recent.to_rfc3339(),
            old.to_rfc3339()
        );
        std::fs::write(&path, contents).unwrap();
        let n = count_honeypot_sessions_last_hour(
            td.path(),
            &today,
            &today,
            &(now - chrono::Duration::hours(1)),
        );
        assert_eq!(n, 1);
    }

    #[test]
    fn file_backed_last_hour_metrics_include_previous_day_after_midnight() {
        let td = tmpdir();
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-18T00:15:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let hour_ago = now - chrono::Duration::hours(1);
        let today = now.date_naive().format("%Y-%m-%d").to_string();
        let yesterday = hour_ago.date_naive().format("%Y-%m-%d").to_string();

        std::fs::write(
            td.path().join(format!("decisions-{yesterday}.jsonl")),
            format!(
                "{{\"ts\":\"2026-04-17T23:50:00Z\",\"action_type\":\"block_ip\",\"skill_id\":\"block-ip-ufw\"}}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            td.path().join(format!("decisions-{today}.jsonl")),
            format!(
                "{{\"ts\":\"2026-04-18T00:05:00Z\",\"action_type\":\"block_ip\",\"skill_id\":\"block-ip-xdp\"}}\n"
            ),
        )
        .unwrap();

        std::fs::write(
            td.path()
                .join(format!("honeypot-sessions-{yesterday}.jsonl")),
            "{\"ended_at\":\"2026-04-17T23:50:00Z\"}\n",
        )
        .unwrap();
        std::fs::write(
            td.path().join(format!("honeypot-sessions-{today}.jsonl")),
            "{\"ended_at\":\"2026-04-18T00:05:00Z\"}\n",
        )
        .unwrap();

        let block_counts =
            count_blocks_last_hour_by_backend(td.path(), &today, &yesterday, &hour_ago);
        assert_eq!(block_counts.get("ufw").copied(), Some(1));
        assert_eq!(block_counts.get("xdp").copied(), Some(1));

        let honeypot_n =
            count_honeypot_sessions_last_hour(td.path(), &today, &yesterday, &hour_ago);
        assert_eq!(honeypot_n, 2);
    }

    #[test]
    fn read_event_rate_per_hour_uses_trailing_hour_delta() {
        let td = tmpdir();
        let date = "2026-04-17";
        write_telemetry_snapshots(
            td.path(),
            date,
            &[
                telemetry_snapshot(
                    chrono::DateTime::parse_from_rfc3339("2026-04-17T11:25:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    &[("auth.log", 100), ("journald", 60)],
                    0,
                    0,
                    0,
                ),
                telemetry_snapshot(
                    chrono::DateTime::parse_from_rfc3339("2026-04-17T12:20:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    &[("auth.log", 130), ("journald", 60)],
                    0,
                    0,
                    0,
                ),
            ],
        );
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-17T12:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let rates = read_event_rate_per_hour(td.path(), date, now);
        assert_eq!(rates.len(), 2);
        let auth = rates.iter().find(|(s, _)| s == "auth.log").unwrap().1;
        let journal = rates.iter().find(|(s, _)| s == "journald").unwrap().1;
        assert!((auth - 30.0).abs() < 0.01);
        assert!((journal - 0.0).abs() < 0.01);
    }

    #[test]
    fn read_event_rate_per_hour_handles_missing_telemetry() {
        let td = tmpdir();
        let rates = read_event_rate_per_hour(td.path(), "2026-04-17", chrono::Utc::now());
        assert!(rates.is_empty());
    }

    #[test]
    fn append_spec024_metrics_emits_expected_lines_from_artifacts() {
        let td = tmpdir();
        let store = std::sync::Arc::new(innerwarden_store::Store::open(td.path()).unwrap());
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-17T12:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let today = now.date_naive().format("%Y-%m-%d").to_string();

        let high_incident = innerwarden_core::incident::Incident {
            ts: now - chrono::Duration::minutes(5),
            host: "srv-01".to_string(),
            incident_id: "ssh_bruteforce:198.51.100.10:test".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH brute force".to_string(),
            summary: "many failed logins".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: Vec::new(),
            tags: Vec::new(),
            entities: vec![innerwarden_core::entities::EntityRef::ip("198.51.100.10")],
        };
        store.insert_incident(&high_incident).unwrap();

        let killchain_incident = innerwarden_core::incident::Incident {
            ts: now - chrono::Duration::minutes(3),
            host: "srv-01".to_string(),
            incident_id: "kill_chain:detected:reverse_shell:42:2026-04-17T12:27:00Z".to_string(),
            severity: innerwarden_core::event::Severity::Critical,
            title: "Kill chain".to_string(),
            summary: "reverse shell sequence".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: Vec::new(),
            tags: Vec::new(),
            entities: vec![innerwarden_core::entities::EntityRef::ip("203.0.113.2")],
        };
        store.insert_incident(&killchain_incident).unwrap();

        store
            .set_blob(
                "responses",
                r#"{"totals":{"orphaned":2,"revert_failures":3}}"#,
            )
            .unwrap();

        std::fs::write(
            td.path().join(format!("decisions-{today}.jsonl")),
            "{\"ts\":\"2026-04-17T12:22:00Z\",\"action_type\":\"block_ip\",\"skill_id\":\"block-ip-ufw\"}\n",
        )
        .unwrap();
        std::fs::write(
            td.path().join(format!("honeypot-sessions-{today}.jsonl")),
            "{\"ended_at\":\"2026-04-17T12:15:00Z\"}\n",
        )
        .unwrap();

        write_telemetry_snapshots(
            td.path(),
            &today,
            &[
                telemetry_snapshot(
                    chrono::DateTime::parse_from_rfc3339("2026-04-17T11:20:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    &[("auth.log", 100), ("journald", 40)],
                    10,
                    2,
                    1,
                ),
                telemetry_snapshot(
                    chrono::DateTime::parse_from_rfc3339("2026-04-17T12:25:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    &[("auth.log", 130), ("journald", 40)],
                    18,
                    5,
                    4,
                ),
            ],
        );

        let state = dashboard_state_for_metrics(td.path(), Some(store));
        let mut out = String::new();
        append_spec024_metrics(&mut out, &state, now);

        assert!(out.contains("innerwarden_incidents_per_hour{severity=\"high\"} 1"));
        assert!(out.contains("innerwarden_incidents_per_hour{severity=\"critical\"} 1"));
        assert!(out.contains("innerwarden_telegram_msgs_per_hour 8"));
        assert!(out.contains("innerwarden_blocks_per_hour{backend=\"ufw\"} 1"));
        assert!(out.contains("innerwarden_honeypot_sessions_per_hour 1"));
        assert!(out.contains("innerwarden_orphaned_responses_total 2"));
        assert!(out.contains("innerwarden_revert_failures_total 3"));
        assert!(out.contains("innerwarden_ai_provider_errors_per_hour{provider=\"unknown\"} 4"));
        assert!(out.contains("innerwarden_gate_suppressed_total 5"));
        assert!(out.contains("innerwarden_event_rate_per_hour{source=\"auth.log\"} 30.00"));
    }

    #[test]
    fn read_telemetry_error_count_returns_zero_for_missing_component() {
        let td = tmpdir();
        let date = "2026-04-17";
        let path = td.path().join(format!("telemetry-{date}.jsonl"));
        let snap = crate::telemetry::TelemetrySnapshot {
            ts: chrono::Utc::now(),
            tick: "incident_tick".into(),
            events_by_collector: Default::default(),
            incidents_by_detector: Default::default(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 0,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: std::collections::BTreeMap::from([(
                "ai_provider".to_string(),
                7u64,
            )]),
            decisions_by_action: Default::default(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
        };
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&snap).unwrap()),
        )
        .unwrap();
        assert_eq!(
            read_telemetry_error_count(td.path(), date, "ai_provider"),
            7
        );
        assert_eq!(
            read_telemetry_error_count(td.path(), date, "nonexistent"),
            0
        );
    }
}
