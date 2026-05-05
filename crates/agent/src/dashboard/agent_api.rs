// Auto-extracted from mod.rs — dashboard agent_api handlers

use super::*;

// ---------------------------------------------------------------------------
// Agent-guard alert drop counters (Spec 037 I-13 follow-up #5)
// ---------------------------------------------------------------------------
//
// `run_analysis` below sends alerts into a bounded `mpsc::channel(64)`
// via `try_send`. Pre-PR the failure path was a silent `let _ = ..`,
// so a backlogged channel (downstream notification I/O stalled) or a
// crashed receiver task was completely invisible to the operator —
// alerts just disappeared.
//
// These counters surface the two `TrySendError` variants:
//
//   - `full`: 64 alerts pending, receiver alive but slow to drain.
//     Recoverable; counter-only signal so the operator can spot
//     sustained backlogs via `/metrics`.
//   - `closed`: receiver task dropped (panic or early exit). Severe
//     — all subsequent alerts are permanently lost until process
//     restart. One-shot `warn!` on first occurrence per process so
//     the operator gets an immediate log signal, plus the counter
//     for post-hoc accounting. Subsequent drops increment the
//     counter silently to avoid log-spam if check-command is
//     called repeatedly while the receiver is gone.
//
// Both counters surface via `/metrics` as
// `innerwarden_agent_alert_drops_total{reason="full"|"closed"}`.
// Cardinality is fixed (2 series); no per-agent label to avoid
// operator-controlled cardinality explosion.

static AGENT_ALERT_DROPS_FULL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static AGENT_ALERT_DROPS_CLOSED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
static CLOSED_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Read-side accessor for the metrics renderer.
pub(crate) fn agent_alert_drops_full() -> u64 {
    AGENT_ALERT_DROPS_FULL.load(std::sync::atomic::Ordering::Relaxed)
}

/// Read-side accessor for the metrics renderer.
pub(crate) fn agent_alert_drops_closed() -> u64 {
    AGENT_ALERT_DROPS_CLOSED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Record a `try_send` failure on the agent-alert channel. Bumps the
/// counter for the matched `TrySendError` variant; on `Closed`, also
/// emits a one-shot `warn!` per process (subsequent Closed drops
/// increment the counter silently).
///
/// Returns `()` so the call site stays one-line and the
/// downstream-decision flow in `run_analysis` continues regardless
/// of the drop outcome (matches the prior `let _ =` no-propagate
/// behaviour).
fn record_agent_alert_drop(err: tokio::sync::mpsc::error::TrySendError<AgentGuardAlert>) {
    use std::sync::atomic::Ordering;
    use tokio::sync::mpsc::error::TrySendError;
    match err {
        TrySendError::Full(_) => {
            AGENT_ALERT_DROPS_FULL.fetch_add(1, Ordering::Relaxed);
        }
        TrySendError::Closed(_) => {
            AGENT_ALERT_DROPS_CLOSED.fetch_add(1, Ordering::Relaxed);
            // `swap(true, Relaxed)` returns the previous value. On
            // the first Closed of the process the swap returns
            // `false` and we warn; on every subsequent Closed it
            // returns `true` and we stay silent.
            if !CLOSED_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    "agent_alert channel CLOSED — receiver task is gone, \
                     alerts permanently lost until restart"
                );
            }
        }
    }
}

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

/// Count unique IP addresses that have an auto-executed `block_ip`
/// decision attached to a non-internal Incident node currently live
/// in the graph. Keeps the "Blocked Today" KPI aligned across
/// `/api/live-feed`, the dashboard Home, and `/api/agent/security-context`.
///
/// Filters out research-only and "internal noise" incidents the same
/// way the public Live Feed does, so the same IP that the site shows
/// as a real attacker is the one that surfaces in this counter.
pub(super) fn count_unique_ips_blocked_in_graph(
    graph: &crate::knowledge_graph::KnowledgeGraph,
) -> usize {
    use crate::knowledge_graph::types::{Node, NodeType, Relation};

    let mut blocked_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for id in graph.nodes_of_type(NodeType::Incident) {
        let Some(Node::Incident {
            decision,
            auto_executed,
            detector,
            title,
            research_only,
            ..
        }) = graph.get_node(id)
        else {
            continue;
        };
        if *research_only {
            continue;
        }
        let Some(dec) = decision else { continue };
        if dec != "block_ip" || !*auto_executed {
            continue;
        }
        // Walk edges once so we know both whether there is an
        // external IP (filter input) and which IPs to count.
        let mut external_ips: Vec<String> = Vec::new();
        for edge in graph.outgoing_edges(id) {
            if edge.relation == Relation::TriggeredBy {
                if let Some(Node::Ip { addr, .. }) = graph.get_node(edge.to) {
                    external_ips.push(addr.clone());
                }
            }
        }
        let has_external_ip = !external_ips.is_empty();
        if super::live_feed::is_internal_incident_fields(detector, title, has_external_ip) {
            continue;
        }
        for ip in external_ips {
            blocked_ips.insert(ip);
        }
    }
    blocked_ips.len()
}

/// GET /api/agent/security-context - threat overview for AI agents (Phase 6A: graph-only)
pub(super) async fn api_agent_security_context(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let date = resolve_date(None);

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    use crate::knowledge_graph::types::Relation;
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    let mut total_incidents = 0usize;
    let mut high_or_critical = 0usize;
    let mut detector_counts = std::collections::HashMap::<String, usize>::new();

    // Fix (prod 2026-04-22): align "Detections Today" on /home with the
    // public Live Feed's "Events (24h)". Without filtering, the agent
    // counted advisory-only detectors and self-traffic that the site
    // hides — making the same incident set show 126 here and 22 on
    // the site for the same window.
    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            severity,
            title,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            if *research_only {
                continue;
            }
            let has_external_ip = graph.outgoing_edges(id).iter().any(|e| {
                e.relation == Relation::TriggeredBy
                    && matches!(graph.get_node(e.to), Some(Node::Ip { .. }))
            });
            if super::live_feed::is_internal_incident_fields(detector, title, has_external_ip) {
                continue;
            }
            total_incidents += 1;
            let sev = severity.to_lowercase();
            if sev == "high" || sev == "critical" {
                high_or_critical += 1;
            }
            *detector_counts.entry(detector.clone()).or_default() += 1;
        }
    }
    // Unique IPs blocked today — pinned in a pure helper so
    // `/api/live-feed` and `/api/agent/security-context` share the
    // same definition of "Blocked Today".
    let blocks_today = count_unique_ips_blocked_in_graph(&graph);

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
                // Wave 1 (AUDIT-WAVE1-UTF8): `&command[..200]` panicked
                // on multi-byte UTF-8. Attacker-supplied command going
                // through agent-guard inspection could DoS the snitch
                // alert builder.
                format!("{}...", crate::text_util::safe_truncate(command, 200))
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
        // Spec 037 I-13 follow-up #5: surface drop counts via
        // `innerwarden_agent_alert_drops_total{reason="full"|"closed"}`
        // on `/metrics`. `try_send` is intentionally non-blocking
        // here — the calling HTTP handler must not stall on a
        // backlogged channel — but the failure path is now visible
        // instead of silently throwing alerts away.
        if let Err(e) = state.agent_alert_tx.try_send(alert) {
            record_agent_alert_drop(e);
        }
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

/// `GET /metrics` — Prometheus exposition format.
///
/// The body reads per-tick telemetry snapshots from disk, the `responses`
/// blob/JSON (path-canonicalized) from either SQLite or the data
/// directory, and two synchronous SQLite queries inside
/// `append_spec024_metrics`. Running this on an async worker thread would
/// stall every other dashboard request handled by the same worker under
/// WAL contention (`RECURRING_BUGS.md` "Dashboard handlers block tokio
/// worker threads"). `tokio::task::spawn_blocking` moves the work to the
/// blocking pool so async workers stay responsive.
pub(super) async fn api_prometheus_metrics(
    State(state): State<DashboardState>,
) -> axum::response::Response {
    let body = tokio::task::spawn_blocking(move || {
        build_prometheus_metrics_text(&state, chrono::Utc::now())
    })
    .await
    .unwrap_or_default();

    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
        .into_response()
}

/// Pure helper extracted from `api_prometheus_metrics` so the heavy work
/// runs on the blocking pool and stays unit-testable. The telemetry
/// snapshot file is named with a LOCAL date (see `crate::telemetry`
/// writer at line 154 / 167), so this path uses `resolve_date_local`
/// to keep the filename byte-identical with what the writer just
/// produced. The dashboard's SQLite queries use the UTC-based
/// `resolve_date` (see helpers.rs).
pub(super) fn build_prometheus_metrics_text(
    state: &DashboardState,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let date = resolve_date_local(None);

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

    // Spec 037 slice 5: dated KG snapshot load provenance. `sqlite` should
    // dominate once PR-2 has been in prod for a cycle; a rising `json`
    // counter means the fallback is still load-bearing (block PR-3);
    // `miss`/`error` are the operator-alarm signals.
    out.push_str("# HELP innerwarden_kg_dated_load_total Dated KG snapshot loads by source\n");
    out.push_str("# TYPE innerwarden_kg_dated_load_total counter\n");
    for (source, count) in crate::knowledge_graph::persistence::load_dated_metrics_snapshot() {
        out.push_str(&format!(
            "innerwarden_kg_dated_load_total{{source=\"{source}\"}} {count}\n"
        ));
    }

    // Disk-low guard skips. A rising counter means the agent declined to
    // write a critical SQLite blob because the data_dir filesystem fell
    // below the safe threshold (5 % free or 500 MB). Operator alarm —
    // disk needs cleanup.
    out.push_str("# HELP innerwarden_disk_low_skips_total SQLite writes skipped due to low disk\n");
    out.push_str("# TYPE innerwarden_disk_low_skips_total counter\n");
    out.push_str(&format!(
        "innerwarden_disk_low_skips_total{{operation=\"kg_snapshot\"}} {}\n",
        crate::loops::slow_loop::disk_low_skips_kg_snapshot()
    ));

    // Agent-guard alert drop counts. A rising `full` counter means
    // the alert channel is backlogged (downstream notification I/O
    // stalled). A non-zero `closed` counter means the receiver task
    // is dead and alerts are permanently lost until process restart
    // — the `warn!` at first occurrence is the immediate signal,
    // this metric carries the post-hoc count.
    out.push_str(
        "# HELP innerwarden_agent_alert_drops_total Agent guard alerts dropped (channel send failed)\n",
    );
    out.push_str("# TYPE innerwarden_agent_alert_drops_total counter\n");
    out.push_str(&format!(
        "innerwarden_agent_alert_drops_total{{reason=\"full\"}} {}\n",
        agent_alert_drops_full()
    ));
    out.push_str(&format!(
        "innerwarden_agent_alert_drops_total{{reason=\"closed\"}} {}\n",
        agent_alert_drops_closed()
    ));

    // JSONL tail-read failures by file kind. A non-zero counter
    // means a dashboard render path tried to read a JSONL file
    // (events / incidents / decisions / admin-actions) and the
    // read failed (permission flip, race with rotation, IO error).
    // Symptom: dashboard list renders empty when data is on disk.
    // The first failure of each kind also fires a `warn!` with
    // path + error; subsequent failures of the same kind bump the
    // counter silently to avoid log-spam under sustained failure.
    out.push_str(
        "# HELP innerwarden_tail_read_failures_total JSONL tail-read failures by file kind\n",
    );
    out.push_str("# TYPE innerwarden_tail_read_failures_total counter\n");
    for kind in ["events", "incidents", "decisions", "admin_actions", "other"] {
        out.push_str(&format!(
            "innerwarden_tail_read_failures_total{{kind=\"{kind}\"}} {}\n",
            crate::dashboard::helpers::tail_read_failures(kind)
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
    append_spec024_metrics(&mut out, state, now);

    out
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

    // ── 11. innerwarden_orphan_resolutions_total{kind} (PR #422 W4a) ──
    // Operator-recorded resolutions for orphaned responses. Reads from
    // the sidecar JSONL maintained by the dashboard. Two labels in use
    // ("cleared", "already_gone") matching `OrphanResolution::KIND_*`.
    // A non-zero rate paired with a flat orphaned counter signals
    // "operator is keeping up with maintenance debt" (good).
    out.push_str(
        "# HELP innerwarden_orphan_resolutions_total Operator-recorded \
         orphan resolutions, by kind. Latest value is last-write-wins per id.\n",
    );
    out.push_str("# TYPE innerwarden_orphan_resolutions_total counter\n");
    let by_kind = count_orphan_resolutions_by_kind(&state.data_dir);
    // Always emit both rows so alert queries see a present series.
    for kind in ["cleared", "already_gone"] {
        let n = by_kind.get(kind).copied().unwrap_or(0);
        out.push_str(&format!(
            "innerwarden_orphan_resolutions_total{{kind=\"{kind}\"}} {n}\n"
        ));
    }
}

/// PR #422 Wave 4a: count orphan resolutions per kind. Reads the
/// sidecar JSONL and folds last-wins per orphan id (an operator who
/// resolves the same id twice with different kinds counts only the
/// latest decision). Empty map if the file is missing — Prometheus
/// rows are still emitted as zeros.
fn count_orphan_resolutions_by_kind(
    data_dir: &std::path::Path,
) -> std::collections::HashMap<&'static str, u64> {
    let mut out: std::collections::HashMap<&'static str, u64> = std::collections::HashMap::new();
    for r in crate::response_lifecycle::read_orphan_resolutions(data_dir).values() {
        let key = match r.kind.as_str() {
            "cleared" => "cleared",
            "already_gone" => "already_gone",
            _ => continue,
        };
        *out.entry(key).or_insert(0) += 1;
    }
    out
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

    // Wave 6b: snapshot keys are `Arc<str>`. Keep the local set in
    // `Arc<str>` so map lookups stay pointer-cheap; convert to owned
    // `String` only at the output boundary (this function returns
    // `Vec<(String, f64)>` to keep the JSON wire format unchanged).
    let mut sources: std::collections::BTreeSet<std::sync::Arc<str>> =
        std::collections::BTreeSet::new();
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
            (source.to_string(), delta as f64)
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

/// Empty-state payload for `/api/responses`. Both `state_counts` and
/// `totals` must be populated: responses.js reads `r.state_counts.revert_pending`
/// and `r.totals.registered` and would evaluate `undefined.field` on a
/// clean install without the full shape. Kept as a standalone helper so
/// tests can assert on the shape without standing up a `DashboardState`.
pub(super) fn empty_responses_payload() -> serde_json::Value {
    serde_json::json!({
        "active": [],
        "active_count": 0,
        "history": [],
        "state_counts": {
            "pending": 0,
            "active": 0,
            "expired": 0,
            "revert_pending": 0,
            "revert_failed": 0,
            "reverted": 0,
        },
        "totals": {
            "registered": 0,
            "expired": 0,
            "reverted": 0,
        },
    })
}

/// 2026-05-03 (PR #419 Wave 2): GET /api/responses/orphans — orphan
/// diagnostic. Read-only. Read the persisted responses.json (or
/// SQLite blob), filter `history` for entries whose reason starts
/// with `"orphaned:"`, classify each into an `OrphanErrorCluster`,
/// then probe kernel state once and annotate each orphan with
/// whether the rule is still live or already gone.
///
/// The probe is a single `ufw status` + `iptables -L INPUT -n`
/// fork, NOT one fork per orphan — keeps the endpoint cheap even
/// with hundreds of orphans. Result cached for 30s in the dashboard
/// state's existing `last_activity` rate limit; under load the
/// operator gets the previous probe's data with a hint that it's
/// from N seconds ago.
///
/// Wave 3 will add `POST /api/admin-action/clear-orphan/:id` with
/// 2FA + CSRF behind the same diagnostic surface.
pub(super) async fn api_responses_orphans(
    State(state): State<DashboardState>,
) -> axum::response::Response {
    use crate::response_lifecycle::{enumerate_orphans_from_responses_json, OrphanErrorCluster};

    // Read the persisted lifecycle JSON (same precedence as
    // /api/responses — SQLite blob first, file fallback).
    let raw = state
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
        })
        .unwrap_or_default();

    let orphans = enumerate_orphans_from_responses_json(&raw);

    // PR #420 Wave 3: load operator-recorded resolutions and join in.
    // Read failure → empty map → resolutions field is `null` per
    // orphan (same as before Wave 3). Tolerant by design.
    let resolutions = crate::response_lifecycle::read_orphan_resolutions(&state.data_dir);

    // Probe kernel state ONCE, then check each orphan's target IP
    // against the captured outputs. Best-effort — failure of the
    // probe means each orphan reports `kernel_state: "probe_failed"`
    // but the rest of the diagnostic still flows.
    let (ufw_text, iptables_text) = probe_kernel_state_once().await;

    let enriched: Vec<serde_json::Value> = orphans
        .iter()
        .map(|o| {
            let kernel_state = classify_kernel_state(&o.target, &ufw_text, &iptables_text);
            let resolution = resolutions.get(&o.id).map(|r| {
                serde_json::json!({
                    "kind": r.kind,
                    "reason": r.reason,
                    "operator": r.operator,
                    "resolved_at": r.resolved_at.to_rfc3339(),
                })
            });
            serde_json::json!({
                "id": o.id,
                "target": o.target,
                "backend": o.backend,
                "incident_id": o.incident_id,
                "created_at": o.created_at.to_rfc3339(),
                "reverted_at": o.reverted_at.to_rfc3339(),
                "last_error": o.last_error,
                "cluster": o.cluster,
                "revert_command": o.revert_command,
                "kernel_state": kernel_state,
                "resolution": resolution,
            })
        })
        .collect();

    // Cluster summary groups *unresolved* orphans only — resolved ones
    // already have an operator decision and don't need cluster-level
    // suggested-fix nudges.
    let mut by_cluster: std::collections::HashMap<OrphanErrorCluster, usize> =
        std::collections::HashMap::new();
    for o in &orphans {
        if resolutions.contains_key(&o.id) {
            continue;
        }
        *by_cluster.entry(o.cluster).or_insert(0) += 1;
    }
    let clusters: Vec<serde_json::Value> = by_cluster
        .into_iter()
        .map(|(cluster, count)| {
            serde_json::json!({
                "cluster": cluster,
                "count": count,
                "suggested_fix": cluster_suggested_fix(cluster),
            })
        })
        .collect();

    let unresolved = orphans
        .iter()
        .filter(|o| !resolutions.contains_key(&o.id))
        .count();
    let body = serde_json::json!({
        "total": orphans.len(),
        "unresolved": unresolved,
        "resolved": orphans.len() - unresolved,
        "orphans": enriched,
        "clusters": clusters,
        "probe_available": !(ufw_text.is_empty() && iptables_text.is_empty()),
    });

    axum::response::Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap_or_default()))
        .unwrap()
        .into_response()
}

/// 2026-05-03: best-effort kernel state probe. Returns (ufw_status,
/// iptables_input). Either is empty string on failure (sudo missing,
/// command not found, etc.). Single fork per backend, NOT one per
/// orphan — keeps the endpoint O(1) on probe cost regardless of
/// orphan count.
async fn probe_kernel_state_once() -> (String, String) {
    let ufw = tokio::process::Command::new("sudo")
        .args(["-n", "ufw", "status", "numbered"])
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let iptables = tokio::process::Command::new("sudo")
        .args(["-n", "iptables", "-L", "INPUT", "-n", "--line-numbers"])
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    (ufw, iptables)
}

/// Classify whether a target IP still appears in the kernel's
/// rule set. `still_blocked` = found in either ufw or iptables;
/// `already_gone` = both probes returned text and neither contained
/// the target; `probe_failed` = both probes returned empty (no
/// information).
fn classify_kernel_state(target: &str, ufw: &str, iptables: &str) -> &'static str {
    if ufw.is_empty() && iptables.is_empty() {
        return "probe_failed";
    }
    if ufw.contains(target) || iptables.contains(target) {
        return "still_blocked";
    }
    "already_gone"
}

/// 2026-05-03: operator-facing "what to do about it" string per
/// cluster. Maps the heuristic classification onto a concrete
/// remediation hint shown on the dashboard above the per-orphan
/// cards. Pure mapping — no I/O.
fn cluster_suggested_fix(cluster: crate::response_lifecycle::OrphanErrorCluster) -> &'static str {
    use crate::response_lifecycle::OrphanErrorCluster as C;
    match cluster {
        C::Ipv6Mismatch => {
            "Enable IPv6 in /etc/default/ufw (IPV6=yes) so v6 rules can be created/removed cleanly. \
             Or restrict block_ip skills to IPv4 targets via config."
        }
        C::NftablesHandleMissing => {
            "nftables handle was not stored at create time — rule cannot be removed by handle. \
             Manual fix: `sudo nft list ruleset | grep <ip>` then `sudo nft delete rule ...`."
        }
        C::RuleAlreadyAbsent => {
            "Kernel state is already clean — these are false orphans (revert command rejected \
             because the rule was already gone). Wave 4 root-cause fix re-classifies these as \
             AlreadyAbsent at create time."
        }
        C::PermissionDenied => {
            "Agent's sudoers entries don't allow the revert command. Re-run \
             `innerwarden harden` to refresh sudoers, or check /etc/sudoers.d/innerwarden-*."
        }
        C::ExternalMutation => {
            "Another tool (fail2ban / ipset / manual) modified the firewall between create \
             and revert. Coordinate or disable the conflicting tool."
        }
        C::Unknown => {
            "Cluster not recognised. Check the per-orphan `last_error` field for the raw \
             stderr — file an issue with that string for classifier coverage."
        }
    }
}

// ─── PR #420 Wave 3 — orphan resolution endpoints ───────────────────
//
// Two POST routes wire the operator's "clear" / "mark already gone"
// decisions through to the persisted JSONL. All sensitive paths share:
//
//   1. Auth (basic / bearer) via the dashboard's existing auth_layer.
//   2. CSRF via X-Requested-With (csrf_protection middleware).
//   3. 2FA via verify_dashboard_totp() when `[security].method = "totp"`.
//   4. Body limit via DefaultBodyLimit (already on the router).
//   5. Audit row via append_admin_action — the same hash-chained
//      JSONL Compliance tab already reads.
//
// The action itself appends an OrphanResolution to
// `<data_dir>/orphan_resolutions.jsonl`. Idempotent: a second
// call with the same id last-wins per `read_orphan_resolutions`.

#[derive(Debug, serde::Deserialize)]
pub(super) struct OrphanResolutionRequest {
    /// Mandatory free-text operator note. Trimmed; rejected if empty.
    #[serde(default)]
    reason: String,
    /// 6-digit TOTP code. Required when `[security].method = "totp"`,
    /// ignored when method = "none".
    #[serde(default)]
    totp: String,
}

/// Verify a TOTP code against the dashboard's configured secret.
/// Returns `Ok(())` when 2FA is disabled (no enforcement) OR when the
/// supplied code matches. Returns `Err(reason)` otherwise so the
/// caller can include the human-readable cause in the audit row.
fn verify_dashboard_totp(state: &DashboardState, supplied: &str) -> Result<(), &'static str> {
    if !state.two_factor.is_enforced() {
        return Ok(());
    }
    if supplied.is_empty() {
        return Err("2FA required: TOTP code missing");
    }
    let provider = match crate::two_factor::TotpProvider::new(&state.two_factor.totp_secret) {
        Some(p) => p,
        None => return Err("2FA configured but TOTP secret is invalid"),
    };
    if !provider.verify(supplied) {
        return Err("2FA verification failed");
    }
    Ok(())
}

/// Shared body for both endpoints. Validates input, gates 2FA, writes
/// the resolution + audit row, returns the new resolution. Splitting
/// the kind here keeps the route handlers as one-line dispatchers.
async fn record_orphan_resolution(
    state: DashboardState,
    operator: String,
    orphan_id: String,
    kind: &'static str,
    body: OrphanResolutionRequest,
) -> axum::response::Response {
    use crate::response_lifecycle::{append_orphan_resolution, OrphanResolution};
    use axum::http::StatusCode;
    use innerwarden_core::audit::{append_admin_action, AdminActionEntry};

    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return (StatusCode::BAD_REQUEST, "reason is required").into_response();
    }
    if reason.len() > 1024 {
        return (StatusCode::BAD_REQUEST, "reason must be <= 1024 chars").into_response();
    }
    if orphan_id.is_empty() || orphan_id.len() > 128 {
        return (StatusCode::BAD_REQUEST, "invalid orphan id").into_response();
    }

    if let Err(e) = verify_dashboard_totp(&state, &body.totp) {
        return (StatusCode::UNAUTHORIZED, e).into_response();
    }

    let resolution = OrphanResolution {
        orphan_id: orphan_id.clone(),
        kind: kind.to_string(),
        reason: reason.clone(),
        operator: operator.clone(),
        resolved_at: chrono::Utc::now(),
    };

    if let Err(e) = append_orphan_resolution(&state.data_dir, &resolution) {
        tracing::warn!(error = %e, orphan_id = %orphan_id, "failed to append orphan resolution");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist resolution",
        )
            .into_response();
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator,
        source: "dashboard".to_string(),
        action: if kind == OrphanResolution::KIND_CLEARED {
            "orphan_clear".to_string()
        } else if kind == OrphanResolution::KIND_ALREADY_GONE {
            "orphan_mark_already_gone".to_string()
        } else {
            "orphan_resolve".to_string()
        },
        target: orphan_id.clone(),
        parameters: serde_json::json!({
            "reason": reason,
            "kind": kind,
            "two_factor_enforced": state.two_factor.is_enforced(),
        }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&state.data_dir, &mut audit) {
        // The resolution is already on disk — log and continue. The
        // operator-visible audit table is best-effort here; we don't
        // want to roll back the resolution because the chain write
        // failed (would create the inverse problem of a resolved
        // orphan with no log of who did it).
        tracing::warn!(error = %e, orphan_id = %orphan_id, "failed to append admin action audit row");
    }

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "ok": true,
                "id": orphan_id,
                "kind": kind,
                "operator": resolution.operator,
                "resolved_at": resolution.resolved_at.to_rfc3339(),
            }))
            .unwrap_or_default(),
        ))
        .unwrap()
        .into_response()
}

/// PR #422 Wave 4a: extract the authenticated username from the
/// request extension injected by `require_auth`. Falls back to the
/// `AuthenticatedUser::ANONYMOUS` sentinel when no auth layer ran
/// (loopback bind without credentials, test harness).
fn operator_from_extension(
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
) -> String {
    user.map(|axum::Extension(u)| u.0)
        .unwrap_or_else(|| crate::dashboard::auth::AuthenticatedUser::ANONYMOUS.to_string())
}

/// POST /api/responses/orphans/:id/clear — operator confirms the
/// orphan entry should be cleared from the diagnostic surface (e.g.
/// stale entry, no longer relevant). Audit-trail entry written.
pub(super) async fn api_orphan_clear(
    State(state): State<DashboardState>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(body): axum::Json<OrphanResolutionRequest>,
) -> axum::response::Response {
    use crate::response_lifecycle::OrphanResolution;
    let operator = operator_from_extension(user);
    record_orphan_resolution(state, operator, id, OrphanResolution::KIND_CLEARED, body).await
}

/// POST /api/responses/orphans/:id/mark-already-gone — operator
/// confirms the kernel state was actually clean (false orphan), so
/// the dashboard hides it from the unresolved cluster summary.
pub(super) async fn api_orphan_mark_already_gone(
    State(state): State<DashboardState>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(body): axum::Json<OrphanResolutionRequest>,
) -> axum::response::Response {
    use crate::response_lifecycle::OrphanResolution;
    let operator = operator_from_extension(user);
    record_orphan_resolution(
        state,
        operator,
        id,
        OrphanResolution::KIND_ALREADY_GONE,
        body,
    )
    .await
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
            let empty = empty_responses_payload();
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
    fn empty_responses_payload_covers_every_field_responses_js_reads() {
        // responses.js crashes with TypeError if any of these are missing;
        // this test locks in the shape so a future edit to the handler
        // cannot silently drop a key the renderer expects.
        let payload = empty_responses_payload();
        for k in ["active", "history"] {
            assert!(payload[k].is_array(), "{k} must be an array");
        }
        assert_eq!(payload["active_count"], 0);
        for k in [
            "pending",
            "active",
            "expired",
            "revert_pending",
            "revert_failed",
            "reverted",
        ] {
            assert!(
                payload["state_counts"][k].is_u64(),
                "state_counts.{k} missing"
            );
        }
        for k in ["registered", "expired", "reverted"] {
            assert!(payload["totals"][k].is_u64(), "totals.{k} missing");
        }
    }

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

    // ── count_unique_ips_blocked_in_graph ───────────────────────────────

    fn make_block_incident(
        graph: &mut crate::knowledge_graph::KnowledgeGraph,
        incident_id: &str,
        ip_addr: &str,
        decision: Option<&str>,
        auto_executed: bool,
    ) {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        let now = chrono::Utc::now();
        let ip_id = graph.upsert_node(Node::Ip {
            addr: ip_addr.into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 10,
            is_tor: false,
            first_seen: now,
            last_seen: now,
            attempted_usernames: vec![],
        });
        let incident_id_node = graph.upsert_node(Node::Incident {
            incident_id: incident_id.into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "T".into(),
            summary: "S".into(),
            ts: now,
            mitre_ids: vec![],
            decision: decision.map(str::to_string),
            confidence: Some(0.9),
            decision_reason: None,
            decision_target: Some(ip_addr.into()),
            auto_executed,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_edge(Edge::new(
            incident_id_node,
            ip_id,
            Relation::TriggeredBy,
            now,
        ));
    }

    #[test]
    fn count_unique_ips_blocked_in_graph_dedups_same_ip_across_incidents() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        // Three incidents, all blocking the same IP -> 1.
        make_block_incident(&mut graph, "i1", "10.0.0.1", Some("block_ip"), true);
        make_block_incident(&mut graph, "i2", "10.0.0.1", Some("block_ip"), true);
        make_block_incident(&mut graph, "i3", "10.0.0.1", Some("block_ip"), true);
        assert_eq!(count_unique_ips_blocked_in_graph(&graph), 1);
    }

    #[test]
    fn count_unique_ips_blocked_in_graph_counts_distinct_ips() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        make_block_incident(&mut graph, "i1", "10.0.0.1", Some("block_ip"), true);
        make_block_incident(&mut graph, "i2", "10.0.0.2", Some("block_ip"), true);
        make_block_incident(&mut graph, "i3", "10.0.0.3", Some("block_ip"), true);
        assert_eq!(count_unique_ips_blocked_in_graph(&graph), 3);
    }

    #[test]
    fn count_unique_ips_blocked_in_graph_skips_non_block_and_non_auto_executed() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        make_block_incident(&mut graph, "i1", "10.0.0.1", Some("monitor"), true);
        make_block_incident(&mut graph, "i2", "10.0.0.2", Some("block_ip"), false);
        make_block_incident(&mut graph, "i3", "10.0.0.3", None, true);
        assert_eq!(count_unique_ips_blocked_in_graph(&graph), 0);
    }

    #[test]
    fn count_unique_ips_blocked_in_graph_empty_graph_returns_zero() {
        let graph = crate::knowledge_graph::KnowledgeGraph::new();
        assert_eq!(count_unique_ips_blocked_in_graph(&graph), 0);
    }

    #[test]
    fn count_unique_ips_blocked_in_graph_skips_advisory_only_detectors() {
        // Bug fix (prod 2026-04-22 cross-view inconsistency): the
        // counter now matches the public Live Feed by ignoring
        // advisory-only detectors (`neural_anomaly`, `host_drift`,
        // ...). Without this, /home reported 126 detections while
        // the site showed 22 over the same window.
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip_id = graph.upsert_node(Node::Ip {
            addr: "203.0.113.50".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 10,
            is_tor: false,
            first_seen: now,
            last_seen: now,
            attempted_usernames: vec![],
        });
        let inc_id = graph.upsert_node(Node::Incident {
            incident_id: "host_drift:noise:1".into(),
            detector: "host_drift".into(),
            severity: "low".into(),
            title: "drift".into(),
            summary: "S".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            confidence: Some(0.95),
            decision_reason: None,
            decision_target: Some("203.0.113.50".into()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_edge(Edge::new(inc_id, ip_id, Relation::TriggeredBy, now));

        // host_drift is advisory-only — must not surface in the
        // operator-facing counter even though the decision happened.
        assert_eq!(count_unique_ips_blocked_in_graph(&graph), 0);
    }

    #[test]
    fn count_unique_ips_blocked_in_graph_skips_research_only_incidents() {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip_id = graph.upsert_node(Node::Ip {
            addr: "203.0.113.51".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 10,
            is_tor: false,
            first_seen: now,
            last_seen: now,
            attempted_usernames: vec![],
        });
        let inc_id = graph.upsert_node(Node::Incident {
            incident_id: "ssh_bruteforce:research:1".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "brute".into(),
            summary: "S".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            confidence: Some(0.95),
            decision_reason: None,
            decision_target: Some("203.0.113.51".into()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: true,
        });
        graph.add_edge(Edge::new(inc_id, ip_id, Relation::TriggeredBy, now));

        assert_eq!(count_unique_ips_blocked_in_graph(&graph), 0);
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
            events_by_collector: events
                .iter()
                .map(|(k, v)| (std::sync::Arc::<str>::from(*k), *v))
                .collect(),
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
            ai_router: crate::ai::AiRouter::disabled(),
            latest_briefing: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            briefing_hour: 0,
            briefing_minute: 0,
            sqlite_store,
            fleet_state: None,
            two_factor: std::sync::Arc::new(crate::dashboard::TwoFactorSettings::default()),
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

    // ── Spec 035 A4: /metrics async handler anchor ──────────────────
    //
    // The async handler moves the full metrics build (telemetry snapshot
    // read, `responses` blob/JSON path canonicalize + read, and two
    // synchronous SQLite queries inside `append_spec024_metrics`) to the
    // blocking pool via `tokio::task::spawn_blocking`. These two tests
    // pin the contract:
    //   1. The extracted sync builder emits the expected HELP/TYPE
    //      headers even on an empty state — Prometheus `rate()` and
    //      absent-alert queries rely on these being present.
    //   2. The async handler's response shape (status + content-type +
    //      body containing builder output) is preserved across the
    //      spawn_blocking wrap.
    // A future refactor that re-inlines the sync calls into the async
    // handler will not break these tests (they still pass) — the guard
    // against re-regression is the `ReleaseNotes` + the module-level
    // comment. For a non-blocking-runtime proof, see the multi-thread
    // integration in scenario-qa (too flaky to pin as a unit timing
    // test).

    #[test]
    fn build_prometheus_metrics_text_emits_stable_headers_on_empty_state() {
        let td = tmpdir();
        let state = dashboard_state_for_metrics(td.path(), None);
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-23T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let out = super::build_prometheus_metrics_text(&state, now);

        for family in &[
            "innerwarden_events_total",
            "innerwarden_incidents_total",
            "innerwarden_decisions_total",
            "innerwarden_ai_calls_total",
            "innerwarden_ai_latency_avg_ms",
            "innerwarden_errors_total",
            "innerwarden_executions_total",
            "innerwarden_incidents_per_hour",
            "innerwarden_blocks_per_hour",
        ] {
            assert!(
                out.contains(&format!("# HELP {family} "))
                    && out.contains(&format!("# TYPE {family} ")),
                "metric family {family} missing HELP/TYPE headers on empty state",
            );
        }
    }

    #[tokio::test]
    async fn api_prometheus_metrics_handler_returns_builder_output_with_prom_content_type() {
        use axum::body::to_bytes;
        use axum::extract::State;

        let td = tmpdir();
        let state = dashboard_state_for_metrics(td.path(), None);
        let response = super::api_prometheus_metrics(State(state)).await;

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            content_type, "text/plain; version=0.0.4; charset=utf-8",
            "Prometheus exposition content-type must survive spawn_blocking wrap",
        );

        let body = response.into_body();
        let bytes = to_bytes(body, 64 * 1024).await.expect("body bytes");
        let body_str = std::str::from_utf8(&bytes).expect("utf8 body");
        assert!(
            body_str.contains("# HELP innerwarden_events_total")
                && body_str.contains("# HELP innerwarden_incidents_per_hour"),
            "handler response must include both legacy and spec 024 headers produced by the sync builder",
        );
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

    // ── Spec 037 I-13 follow-up #5 — alert drop counter anchors ────
    //
    // `record_agent_alert_drop` records `try_send` failures into two
    // process-global counters and (for `Closed` only) emits a
    // one-shot warn. Tests pin three contracts:
    //
    //   1. `Full` increments the full counter, no warn fires.
    //   2. `Closed` increments the closed counter.
    //   3. `Closed` emits the warn EXACTLY ONCE per process — first
    //      Closed warns, subsequent Closed drops are silent (the
    //      counter still increments but no log spam).
    //
    // Cross-test interference: counters are process-global, so
    // tests serialize via the same `crate::TRACING_CAPTURE_LOCK`
    // used by the I-13 sweep (PR-1...PR-5 + #310 follow-up). Each
    // test takes the lock + resets `CLOSED_WARNED` + reads the
    // counters via delta-from-baseline rather than absolute
    // equality, so other tests bumping the same counters in
    // parallel cannot poison the assertion.

    fn make_alert() -> AgentGuardAlert {
        AgentGuardAlert {
            ts: Utc::now(),
            agent_name: "test-agent".to_string(),
            command: "ls /".to_string(),
            risk_score: 0,
            severity: "low".to_string(),
            recommendation: "review".to_string(),
            signals: Vec::new(),
            atr_rule_ids: Vec::new(),
            explanation: "test".to_string(),
        }
    }

    #[test]
    fn record_agent_alert_drop_increments_full_counter() {
        use std::sync::atomic::Ordering;
        use tokio::sync::mpsc::error::TrySendError;

        let _guard = crate::test_util::arm_capture();

        let before_full = AGENT_ALERT_DROPS_FULL.load(Ordering::Relaxed);
        let before_closed = AGENT_ALERT_DROPS_CLOSED.load(Ordering::Relaxed);

        record_agent_alert_drop(TrySendError::Full(make_alert()));

        let after_full = AGENT_ALERT_DROPS_FULL.load(Ordering::Relaxed);
        let after_closed = AGENT_ALERT_DROPS_CLOSED.load(Ordering::Relaxed);

        assert!(
            after_full > before_full,
            "full counter must increment — before={before_full} after={after_full}"
        );
        assert_eq!(
            after_closed, before_closed,
            "closed counter must NOT change on Full — before={before_closed} after={after_closed}"
        );
    }

    #[test]
    fn record_agent_alert_drop_increments_closed_counter() {
        use std::sync::atomic::Ordering;
        use tokio::sync::mpsc::error::TrySendError;

        let _guard = crate::test_util::arm_capture();

        let before_full = AGENT_ALERT_DROPS_FULL.load(Ordering::Relaxed);
        let before_closed = AGENT_ALERT_DROPS_CLOSED.load(Ordering::Relaxed);

        record_agent_alert_drop(TrySendError::Closed(make_alert()));

        let after_full = AGENT_ALERT_DROPS_FULL.load(Ordering::Relaxed);
        let after_closed = AGENT_ALERT_DROPS_CLOSED.load(Ordering::Relaxed);

        assert!(
            after_closed > before_closed,
            "closed counter must increment — before={before_closed} after={after_closed}"
        );
        assert_eq!(
            after_full, before_full,
            "full counter must NOT change on Closed — before={before_full} after={after_full}"
        );
    }

    #[test]
    fn record_agent_alert_drop_warns_once_on_closed_then_silent() {
        // Pin the one-shot warn semantic: first Closed of the
        // process emits a warn; every subsequent Closed bumps the
        // counter silently. The capture buffer should contain the
        // warn message exactly once across two consecutive Closed
        // drops.
        use std::sync::atomic::Ordering;
        use tokio::sync::mpsc::error::TrySendError;

        let _guard = crate::test_util::arm_capture();

        // Reset the one-shot flag — other tests may have flipped it.
        // The capture lock ensures no concurrent observer sees the
        // partial state.
        CLOSED_WARNED.store(false, Ordering::Relaxed);

        record_agent_alert_drop(TrySendError::Closed(make_alert()));
        record_agent_alert_drop(TrySendError::Closed(make_alert()));

        let captured_str = crate::test_util::drain_capture();

        // The warn message must appear EXACTLY ONCE. Two
        // occurrences means the one-shot flag isn't gating
        // subsequent calls — log spam under sustained Closed.
        let occurrences = captured_str.matches("agent_alert channel CLOSED").count();
        assert_eq!(
            occurrences, 1,
            "one-shot warn must fire exactly once across two Closed drops — got {occurrences} occurrences in: {captured_str}"
        );
    }

    // ─── PR #420 Wave 3 — orphan resolution endpoint coverage ───
    //
    // Pure-helper + handler tests for the surface added in PR #420.
    // codecov/patch flagged the patch coverage at 32 %; these tests
    // exercise the validation, 2FA gate, audit row write, and the
    // GET-side resolution join.

    fn state_with_two_factor(
        data_dir: &std::path::Path,
        method: &str,
        secret: &str,
    ) -> DashboardState {
        let mut s = dashboard_state_for_metrics(data_dir, None);
        s.two_factor =
            std::sync::Arc::new(crate::dashboard::TwoFactorSettings::new(method, secret));
        s
    }

    #[test]
    fn verify_dashboard_totp_passes_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let s = state_with_two_factor(dir.path(), "none", "");
        // Method "none" — short-circuits regardless of supplied code.
        assert!(verify_dashboard_totp(&s, "").is_ok());
        assert!(verify_dashboard_totp(&s, "garbage").is_ok());
        assert!(verify_dashboard_totp(&s, "123456").is_ok());
    }

    #[test]
    fn verify_dashboard_totp_passes_when_method_totp_but_no_secret() {
        // Operator started 2FA setup but never finished — secret empty.
        // is_enforced() returns false, so the gate stays open.
        let dir = tempfile::tempdir().unwrap();
        let s = state_with_two_factor(dir.path(), "totp", "");
        assert!(verify_dashboard_totp(&s, "").is_ok());
        assert!(verify_dashboard_totp(&s, "123456").is_ok());
    }

    #[test]
    fn verify_dashboard_totp_rejects_empty_when_enforced() {
        let dir = tempfile::tempdir().unwrap();
        // Valid base32 secret (>=10 bytes after decode). The exact
        // value doesn't matter for the empty-input branch.
        let s = state_with_two_factor(dir.path(), "totp", "JBSWY3DPEHPK3PXP");
        let err = verify_dashboard_totp(&s, "").unwrap_err();
        assert!(err.contains("TOTP code missing"), "got: {err}");
    }

    #[test]
    fn verify_dashboard_totp_rejects_bad_code() {
        let dir = tempfile::tempdir().unwrap();
        let s = state_with_two_factor(dir.path(), "totp", "JBSWY3DPEHPK3PXP");
        let err = verify_dashboard_totp(&s, "000000").unwrap_err();
        assert!(err.contains("verification failed"), "got: {err}");
    }

    #[test]
    fn verify_dashboard_totp_rejects_invalid_secret_format() {
        // method=totp + non-base32 secret — TotpProvider::new returns None.
        let dir = tempfile::tempdir().unwrap();
        let s = state_with_two_factor(dir.path(), "totp", "not-base32!!!@@@@");
        // is_enforced() is true (method=totp + non-empty secret), but
        // construction fails internally — handler must return a
        // distinct error rather than crashing.
        let err = verify_dashboard_totp(&s, "123456").unwrap_err();
        assert!(err.contains("invalid"), "got: {err}");
    }

    #[tokio::test]
    async fn record_orphan_resolution_rejects_empty_reason() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_two_factor(dir.path(), "none", "");
        let body = OrphanResolutionRequest {
            reason: "   ".to_string(), // whitespace-only
            totp: "".to_string(),
        };
        let resp = record_orphan_resolution(
            state,
            "alice".to_string(),
            "orph-1".to_string(),
            "cleared",
            body,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn record_orphan_resolution_rejects_long_reason() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_two_factor(dir.path(), "none", "");
        let body = OrphanResolutionRequest {
            reason: "x".repeat(2048),
            totp: "".to_string(),
        };
        let resp = record_orphan_resolution(
            state,
            "alice".to_string(),
            "orph-1".to_string(),
            "cleared",
            body,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn record_orphan_resolution_rejects_bad_orphan_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_two_factor(dir.path(), "none", "");
        // Empty id.
        let body = OrphanResolutionRequest {
            reason: "ok".to_string(),
            totp: "".to_string(),
        };
        let resp = record_orphan_resolution(
            state.clone(),
            "alice".to_string(),
            "".to_string(),
            "cleared",
            body,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);

        // Excessively long id (>128 chars).
        let body = OrphanResolutionRequest {
            reason: "ok".to_string(),
            totp: "".to_string(),
        };
        let resp =
            record_orphan_resolution(state, "alice".to_string(), "x".repeat(200), "cleared", body)
                .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn record_orphan_resolution_returns_unauthorized_when_2fa_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_two_factor(dir.path(), "totp", "JBSWY3DPEHPK3PXP");
        let body = OrphanResolutionRequest {
            reason: "stale entry".to_string(),
            totp: "".to_string(), // 2FA enforced + no code
        };
        let resp = record_orphan_resolution(
            state,
            "alice".to_string(),
            "orph-1".to_string(),
            "cleared",
            body,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn record_orphan_resolution_happy_path_writes_resolution_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_two_factor(dir.path(), "none", "");
        let body = OrphanResolutionRequest {
            reason: "operator confirms IP no longer relevant".to_string(),
            totp: "".to_string(),
        };
        let resp = record_orphan_resolution(
            state,
            "alice".to_string(),
            "orph-happy".to_string(),
            "cleared",
            body,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Sidecar JSONL must exist with one entry.
        let resolutions = crate::response_lifecycle::read_orphan_resolutions(dir.path());
        let got = resolutions.get("orph-happy").expect("resolution persisted");
        assert_eq!(got.kind, "cleared");
        assert_eq!(got.reason, "operator confirms IP no longer relevant");
    }

    #[tokio::test]
    async fn record_orphan_resolution_writes_admin_audit_row() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_two_factor(dir.path(), "none", "");
        let body = OrphanResolutionRequest {
            reason: "audit row test".to_string(),
            totp: "".to_string(),
        };
        let resp = record_orphan_resolution(
            state,
            "alice".to_string(),
            "orph-audit".to_string(),
            "already_gone",
            body,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // admin-actions-YYYY-MM-DD.jsonl exists with the right action.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let audit_path = dir.path().join(format!("admin-actions-{today}.jsonl"));
        let raw = std::fs::read_to_string(&audit_path).expect("audit jsonl exists");
        assert!(raw.contains("orphan_mark_already_gone"), "got: {raw}");
        assert!(raw.contains("\"target\":\"orph-audit\""), "got: {raw}");
        assert!(raw.contains("\"audit row test\""), "reason in audit: {raw}");
    }

    // ─── PR #422 Wave 4a — operator field + telemetry ──────────

    #[tokio::test]
    async fn orphan_resolution_uses_authenticated_username() {
        // The handler stamps the audit row + sidecar JSONL with the
        // username pulled from the auth-layer extension, NOT the
        // hardcoded "dashboard" placeholder Wave 3 used.
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_two_factor(dir.path(), "none", "");
        let body = OrphanResolutionRequest {
            reason: "test".to_string(),
            totp: "".to_string(),
        };
        let resp = record_orphan_resolution(
            state,
            "alice".to_string(), // simulates auth layer's AuthenticatedUser
            "orph-user".to_string(),
            "cleared",
            body,
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Sidecar JSONL carries the operator.
        let resolutions = crate::response_lifecycle::read_orphan_resolutions(dir.path());
        let got = resolutions.get("orph-user").unwrap();
        assert_eq!(got.operator, "alice");

        // Audit row also carries the operator (no longer "dashboard").
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let audit_path = dir.path().join(format!("admin-actions-{today}.jsonl"));
        let raw = std::fs::read_to_string(&audit_path).unwrap();
        assert!(raw.contains("\"operator\":\"alice\""), "got: {raw}");
    }

    #[test]
    fn count_orphan_resolutions_by_kind_folds_last_wins() {
        // Operator resolves orph-A as cleared, then revises to
        // already_gone. Counter should attribute the latest decision
        // (already_gone), not both.
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();
        for r in [
            crate::response_lifecycle::OrphanResolution {
                orphan_id: "orph-A".to_string(),
                kind: "cleared".to_string(),
                reason: "first".to_string(),
                operator: "alice".to_string(),
                resolved_at: now,
            },
            crate::response_lifecycle::OrphanResolution {
                orphan_id: "orph-A".to_string(),
                kind: "already_gone".to_string(),
                reason: "revised".to_string(),
                operator: "alice".to_string(),
                resolved_at: now + chrono::Duration::seconds(1),
            },
            crate::response_lifecycle::OrphanResolution {
                orphan_id: "orph-B".to_string(),
                kind: "cleared".to_string(),
                reason: "ok".to_string(),
                operator: "alice".to_string(),
                resolved_at: now,
            },
        ] {
            crate::response_lifecycle::append_orphan_resolution(dir.path(), &r).unwrap();
        }
        let counts = count_orphan_resolutions_by_kind(dir.path());
        assert_eq!(counts.get("cleared").copied().unwrap_or(0), 1);
        assert_eq!(counts.get("already_gone").copied().unwrap_or(0), 1);
    }

    #[test]
    fn prometheus_emits_orphan_resolutions_metric_even_when_empty() {
        // Floor-zero: even on a fresh deploy with no orphans yet,
        // both label rows must be present so alert rules see a series.
        let dir = tempfile::tempdir().unwrap();
        let state = dashboard_state_for_metrics(dir.path(), None);
        let now = chrono::Utc::now();
        let text = build_prometheus_metrics_text(&state, now);
        assert!(
            text.contains("innerwarden_orphan_resolutions_total{kind=\"cleared\"} 0"),
            "missing cleared row: {text}"
        );
        assert!(
            text.contains("innerwarden_orphan_resolutions_total{kind=\"already_gone\"} 0"),
            "missing already_gone row: {text}"
        );
    }

    #[test]
    fn prometheus_orphan_resolutions_metric_increments() {
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();
        for i in 0..3 {
            let r = crate::response_lifecycle::OrphanResolution {
                orphan_id: format!("orph-{i}"),
                kind: "cleared".to_string(),
                reason: "ok".to_string(),
                operator: "alice".to_string(),
                resolved_at: now,
            };
            crate::response_lifecycle::append_orphan_resolution(dir.path(), &r).unwrap();
        }
        let state = dashboard_state_for_metrics(dir.path(), None);
        let text = build_prometheus_metrics_text(&state, now);
        assert!(
            text.contains("innerwarden_orphan_resolutions_total{kind=\"cleared\"} 3"),
            "expected count=3: {text}"
        );
    }

    #[test]
    fn parse_disabled_detectors_returns_empty_on_empty_content() {
        let disabled = parse_disabled_detectors("");
        assert!(disabled.is_empty());
    }

    #[test]
    fn parse_disabled_detectors_returns_empty_on_invalid_toml() {
        let disabled = parse_disabled_detectors("[detectors\ninvalid = toml");
        assert!(disabled.is_empty());
    }

    #[test]
    fn parse_disabled_detectors_identifies_disabled_ones() {
        let toml = r#"
        [detectors.ssh_bruteforce]
        enabled = false

        [detectors.port_scan]
        enabled = true

        [detectors.docker_anomaly]
        enabled = false
        "#;
        let disabled = parse_disabled_detectors(toml);
        assert_eq!(disabled.len(), 2);
        assert!(disabled.contains("ssh_bruteforce"));
        assert!(disabled.contains("docker_anomaly"));
        assert!(!disabled.contains("port_scan"));
    }

    #[test]
    fn parse_disabled_detectors_ignores_missing_enabled_flag() {
        let toml = r#"
        [detectors.reverse_shell]
        threshold = 5
        "#;
        let disabled = parse_disabled_detectors(toml);
        assert!(disabled.is_empty());
    }
}
