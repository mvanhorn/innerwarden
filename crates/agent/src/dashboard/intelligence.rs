// Auto-extracted from mod.rs — dashboard intelligence handlers

use super::*;

// ── Attacker Intelligence & Monthly Reports ────────────────────────

/// `GET /api/attacker-profiles` - list attacker profiles sorted by risk.
pub(super) async fn api_attacker_profiles(
    State(state): State<DashboardState>,
    Query(query): Query<AttackerProfilesQuery>,
) -> Json<serde_json::Value> {
    let limit = query.limit.unwrap_or(50).min(500);
    let offset = query.offset.unwrap_or(0);
    let min_risk = query.min_risk.unwrap_or(0);
    let sort = query.sort.as_deref().unwrap_or("risk_score");

    let profiles: Vec<serde_json::Value> = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("attacker_profiles").ok().flatten())
        .or_else(|| safe_read_data_file(&state.data_dir, "attacker-profiles.json"))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let mut filtered: Vec<serde_json::Value> = profiles
        .into_iter()
        .filter(|p| p["risk_score"].as_u64().unwrap_or(0) >= min_risk as u64)
        .collect();

    match sort {
        "last_seen" => {
            filtered.sort_by(|a, b| b["last_seen"].as_str().cmp(&a["last_seen"].as_str()))
        }
        "incidents" => filtered.sort_by(|a, b| {
            b["total_incidents"]
                .as_u64()
                .cmp(&a["total_incidents"].as_u64())
        }),
        _ => filtered.sort_by(|a, b| b["risk_score"].as_u64().cmp(&a["risk_score"].as_u64())),
    }

    let total = filtered.len();
    let page: Vec<serde_json::Value> = filtered.into_iter().skip(offset).take(limit).collect();

    Json(serde_json::json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "profiles": page,
    }))
}

#[derive(Deserialize)]
pub(super) struct AttackerProfilesQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    sort: Option<String>,
    min_risk: Option<u8>,
}

/// `GET /api/attacker-profiles/:ip` - single attacker profile detail.
pub(super) async fn api_attacker_profile_detail(
    State(state): State<DashboardState>,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let profiles: Vec<serde_json::Value> = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("attacker_profiles").ok().flatten())
        .or_else(|| safe_read_data_file(&state.data_dir, "attacker-profiles.json"))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let profile = profiles.into_iter().find(|p| p["ip"].as_str() == Some(&ip));
    match profile {
        Some(p) => Json(p),
        None => Json(serde_json::json!({"error": "profile not found"})),
    }
}

/// `GET /api/threat-report?month=YYYY-MM` - monthly threat report.
pub(super) async fn api_threat_report(
    State(state): State<DashboardState>,
    Query(query): Query<ThreatReportQuery>,
) -> Json<serde_json::Value> {
    let month = query.month.unwrap_or_else(|| {
        // Default to previous month if available, else current
        let today = chrono::Local::now().date_naive();
        if today.day() >= 2 {
            let prev = today - chrono::Duration::days(today.day() as i64);
            prev.format("%Y-%m").to_string()
        } else {
            today.format("%Y-%m").to_string()
        }
    });

    // Validate month format to prevent path traversal via crafted month param
    if !month.chars().all(|c| c.is_ascii_digit() || c == '-') || month.len() > 7 {
        return Json(serde_json::json!({"error": "invalid month format"}));
    }
    let filename = format!("monthly-report-{month}.json");
    if let Some(content) = safe_read_data_file(&state.data_dir, &filename) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            return Json(val);
        }
    }

    // Report doesn't exist - generate on demand
    let data_dir = state.data_dir.clone();
    let month_clone = month.clone();
    let sq_store = state.sqlite_store.clone();
    match tokio::task::spawn_blocking(move || {
        // Load profiles from snapshot for generation (blob first, file fallback)
        let profiles: std::collections::HashMap<String, crate::attacker_intel::AttackerProfile> =
            sq_store
                .as_ref()
                .and_then(|sq| sq.get_blob("attacker_profiles").ok().flatten())
                .or_else(|| safe_read_data_file(&data_dir, "attacker-profiles.json"))
                .and_then(|s| {
                    serde_json::from_str::<Vec<crate::attacker_intel::AttackerProfile>>(&s).ok()
                })
                .map(|v| v.into_iter().map(|p| (p.ip.clone(), p)).collect())
                .unwrap_or_default();
        crate::threat_report::generate_monthly(&data_dir, &month_clone, &profiles).and_then(
            |report| {
                crate::threat_report::write_report(&report, &data_dir)?;
                Ok(report)
            },
        )
    })
    .await
    {
        Ok(Ok(report)) => match serde_json::to_value(&report) {
            Ok(val) => Json(val),
            Err(_) => Json(serde_json::json!({"error": "serialization failed"})),
        },
        Ok(Err(e)) => Json(serde_json::json!({"error": format!("{e:#}")})),
        Err(e) => Json(serde_json::json!({"error": format!("task failed: {e}")})),
    }
}

#[derive(Deserialize)]
pub(super) struct ThreatReportQuery {
    month: Option<String>,
}

/// `GET /api/threat-report/months` - list available months.
pub(super) async fn api_threat_report_months(
    State(state): State<DashboardState>,
) -> Json<Vec<String>> {
    Json(crate::threat_report::available_months(&state.data_dir))
}

/// `GET /api/correlation-chains` - recent attack chain detections.
pub(super) async fn api_correlation_chains(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let chains: Vec<serde_json::Value> = safe_read_data_file(&state.data_dir, "attack-chains.json")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Json(serde_json::json!({
        "total": chains.len(),
        "chains": chains,
    }))
}

/// `GET /api/graph/stats` - knowledge graph metrics (live from shared graph).
pub(super) async fn api_graph_stats(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let graph = state.knowledge_graph.read().unwrap();
    let metrics = graph.metrics();
    Json(serde_json::to_value(&metrics).unwrap_or_default())
}

/// `GET /api/graph/view` - live graph as Cytoscape.js elements (capped at 500 nodes).
pub(super) async fn api_graph_view(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    use crate::knowledge_graph::types::*;

    let graph = state.knowledge_graph.read().unwrap();

    if graph.node_count() == 0 {
        return Json(serde_json::json!({"nodes": [], "edges": []}));
    }

    // Build a useful subgraph: incidents + their connected entities (IPs, processes, users).
    // This shows the "attack story" rather than a blob of unrelated infrastructure.
    let mut keep: std::collections::HashSet<NodeId> = std::collections::HashSet::new();

    // 1. Add all recent incidents (max 20).
    let mut incidents: Vec<(NodeId, chrono::DateTime<chrono::Utc>)> = graph
        .nodes()
        .iter()
        .filter_map(|(&id, n)| match n {
            Node::Incident { ts, .. } => Some((id, *ts)),
            _ => None,
        })
        .collect();
    incidents.sort_by(|a, b| b.1.cmp(&a.1));
    incidents.truncate(20);
    for (id, _) in &incidents {
        keep.insert(*id);
        // Add nodes connected to each incident (IP, process, user).
        for edge in graph.all_edges(*id) {
            keep.insert(edge.from);
            keep.insert(edge.to);
        }
    }

    // 2. Fill remaining slots with high-degree infrastructure nodes (IPs, processes).
    if keep.len() < 80 {
        let mut scored: Vec<(NodeId, usize)> = graph
            .nodes()
            .iter()
            .filter(|(id, n)| !keep.contains(id) && n.node_type() != NodeType::Incident)
            .map(|(&id, _)| {
                let out = graph.outgoing.get(&id).map(|v| v.len()).unwrap_or(0);
                let inc = graph.incoming.get(&id).map(|v| v.len()).unwrap_or(0);
                (id, out + inc)
            })
            .filter(|(_, degree)| *degree >= 3)
            .collect();
        scored.sort_by(|a, b| b.1.cmp(&a.1));
        for (id, _) in scored.into_iter().take(80 - keep.len()) {
            keep.insert(id);
        }
    }

    // Cap at 100 nodes to prevent browser crash.
    let node_ids: Vec<NodeId> = keep.iter().copied().collect();

    let cy_nodes: Vec<serde_json::Value> = node_ids
        .iter()
        .filter_map(|&id| {
            graph.get_node(id).map(|n| {
                serde_json::json!({
                    "data": {
                        "id": format!("n{}", id),
                        "label": n.label(),
                        "type": format!("{:?}", n.node_type()),
                        "sensitive": n.is_sensitive_file(),
                    }
                })
            })
        })
        .collect();

    let cy_edges: Vec<serde_json::Value> = graph
        .edges_slice()
        .iter()
        .enumerate()
        .filter(|(_, e)| keep.contains(&e.from) && keep.contains(&e.to) && !e.is_snapshot())
        .take(200) // Hard cap — prevent browser crash
        .map(|(i, e)| {
            serde_json::json!({
                "data": {
                    "id": format!("e{}", i),
                    "source": format!("n{}", e.from),
                    "target": format!("n{}", e.to),
                    "relation": format!("{:?}", e.relation),
                    "ts": e.ts.to_rfc3339(),
                }
            })
        })
        .collect();

    Json(serde_json::json!({
        "nodes": cy_nodes,
        "edges": cy_edges,
    }))
}

/// `GET /api/graph/neighborhood?type=ip&value=1.2.3.4&depth=2` — subgraph around a node.
pub(super) async fn api_graph_neighborhood(
    State(state): State<DashboardState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let subject_type = params.get("type").map(|s| s.as_str()).unwrap_or("ip");
    let subject_value = match params.get("value") {
        Some(v) => v.clone(),
        None => return Json(serde_json::json!({"nodes": [], "edges": []})),
    };
    let depth: usize = params
        .get("depth")
        .and_then(|d| d.parse().ok())
        .unwrap_or(2)
        .min(4);

    let graph = state.knowledge_graph.read().unwrap();
    if graph.node_count() == 0 {
        return Json(serde_json::json!({"nodes": [], "edges": []}));
    }

    // Find center node
    let center = match subject_type {
        "ip" => graph.find_by_ip(&subject_value),
        "user" => graph.find_by_user(&subject_value),
        "path" | "file" => graph.find_by_path(&subject_value),
        "container" => graph.find_by_container(&subject_value),
        "domain" => graph.find_by_domain(&subject_value),
        "incident" => graph.find_by_incident(&subject_value),
        _ => graph.find_by_ip(&subject_value),
    };

    let center_id = match center {
        Some(id) => id,
        None => return Json(serde_json::json!({"nodes": [], "edges": []})),
    };

    let sub = graph.neighborhood(center_id, depth);

    let cy_nodes: Vec<serde_json::Value> = sub
        .nodes
        .iter()
        .map(|(id, n)| {
            serde_json::json!({
                "data": {
                    "id": format!("n{}", id),
                    "label": n.label(),
                    "type": format!("{:?}", n.node_type()),
                    "sensitive": n.is_sensitive_file(),
                    "center": *id == center_id,
                }
            })
        })
        .collect();

    let cy_edges: Vec<serde_json::Value> = sub
        .edges
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.is_snapshot())
        .map(|(i, e)| {
            serde_json::json!({
                "data": {
                    "id": format!("ne{}", i),
                    "source": format!("n{}", e.from),
                    "target": format!("n{}", e.to),
                    "relation": format!("{:?}", e.relation),
                    "ts": e.ts.to_rfc3339(),
                }
            })
        })
        .collect();

    Json(serde_json::json!({
        "center": format!("n{}", center_id),
        "nodes": cy_nodes,
        "edges": cy_edges,
    }))
}

/// `GET /api/baseline-status` - baseline learning status and recent anomalies.
pub(super) async fn api_baseline_status(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let baseline: serde_json::Value = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("baseline").ok().flatten())
        .or_else(|| safe_read_data_file(&state.data_dir, "baseline.json"))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({"mature": false, "training_days": 0}));
    Json(baseline)
}

/// `GET /api/playbook-log` - recent playbook executions.
pub(super) async fn api_playbook_log(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let log: Vec<serde_json::Value> = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("playbook_log").ok().flatten())
        .or_else(|| safe_read_data_file(&state.data_dir, "playbook-log.json"))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Json(serde_json::json!({
        "total": log.len(),
        "executions": log,
    }))
}
/// `GET /api/deep-security` - aggregated status from firmware, hypervisor, killchain, DNA.
pub(super) async fn api_deep_security(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let snap = state.deep_security.read().unwrap();
    Json(serde_json::to_value(&*snap).unwrap_or_default())
}

/// `GET /api/campaigns` - detected campaign clusters (DNA + IOC correlation).
pub(super) async fn api_campaigns(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let campaigns: Vec<serde_json::Value> = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("campaigns").ok().flatten())
        .or_else(|| safe_read_data_file(&state.data_dir, "campaigns.json"))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Json(serde_json::json!({
        "total": campaigns.len(),
        "campaigns": campaigns,
    }))
}

// ── Knowledge Graph Phase 2 endpoints ────────────────────────────────

/// `GET /api/graph/path?from=N&to=N&max_depth=10` — shortest path between two nodes.
pub(super) async fn api_graph_path(
    State(state): State<DashboardState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let from: u64 = params.get("from").and_then(|v| v.parse().ok()).unwrap_or(0);
    let to: u64 = params.get("to").and_then(|v| v.parse().ok()).unwrap_or(0);
    let max_depth: usize = params
        .get("max_depth")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
        .min(10);

    let graph = state.knowledge_graph.read().unwrap();
    match graph.path_between(from, to, max_depth) {
        Some(edges) => {
            let items: Vec<serde_json::Value> = edges
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "from": e.from, "to": e.to,
                        "relation": format!("{:?}", e.relation),
                        "ts": e.ts.to_rfc3339(),
                        "properties": e.properties,
                    })
                })
                .collect();
            Json(serde_json::json!({ "path": items }))
        }
        None => Json(serde_json::json!({ "path": [] })),
    }
}

/// `GET /api/graph/process-tree?pid=1234` — ancestors + descendants of a process.
pub(super) async fn api_graph_process_tree(
    State(state): State<DashboardState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    use crate::knowledge_graph::types::*;

    let pid: u32 = params.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0);
    let graph = state.knowledge_graph.read().unwrap();

    let ancestors = graph.ancestors(pid);
    let descendants = graph.descendants(pid);
    let center = graph.find_by_pid(pid);

    let mut all_ids: Vec<NodeId> = ancestors
        .iter()
        .chain(descendants.iter())
        .copied()
        .collect();
    if let Some(c) = center {
        all_ids.push(c);
    }
    all_ids.sort();
    all_ids.dedup();

    let keep: std::collections::HashSet<NodeId> = all_ids.iter().copied().collect();

    let cy_nodes: Vec<serde_json::Value> = all_ids
        .iter()
        .filter_map(|&id| {
            graph.get_node(id).map(|n| {
                serde_json::json!({
                    "data": {
                        "id": format!("n{}", id),
                        "label": n.label(),
                        "type": format!("{:?}", n.node_type()),
                        "is_center": center == Some(id),
                    }
                })
            })
        })
        .collect();

    let cy_edges: Vec<serde_json::Value> = graph
        .edges_slice()
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            keep.contains(&e.from)
                && keep.contains(&e.to)
                && matches!(e.relation, Relation::SpawnedBy)
        })
        .map(|(i, e)| {
            serde_json::json!({
                "data": {
                    "id": format!("e{}", i),
                    "source": format!("n{}", e.from),
                    "target": format!("n{}", e.to),
                    "relation": format!("{:?}", e.relation),
                    "ts": e.ts.to_rfc3339(),
                }
            })
        })
        .collect();

    Json(serde_json::json!({ "nodes": cy_nodes, "edges": cy_edges }))
}

/// `GET /api/graph/timeline?node_id=N` — chronological edges of a node.
pub(super) async fn api_graph_timeline(
    State(state): State<DashboardState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let node_id: u64 = params
        .get("node_id")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let graph = state.knowledge_graph.read().unwrap();

    let edges = graph.timeline(node_id);
    let items: Vec<serde_json::Value> = edges
        .iter()
        .map(|e| {
            let from_label = graph
                .get_node(e.from)
                .map(|n| n.label().to_string())
                .unwrap_or_default();
            let to_label = graph
                .get_node(e.to)
                .map(|n| n.label().to_string())
                .unwrap_or_default();
            serde_json::json!({
                "from": e.from, "to": e.to,
                "from_label": from_label, "to_label": to_label,
                "relation": format!("{:?}", e.relation),
                "ts": e.ts.to_rfc3339(),
                "properties": e.properties,
            })
        })
        .collect();

    Json(serde_json::json!({ "timeline": items }))
}

/// `GET /api/graph/threats` — all process→IP connections where IP has threat intel datasets.
pub(super) async fn api_graph_threats(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let graph = state.knowledge_graph.read().unwrap();
    let hits = graph.threat_intel_hits();

    let items: Vec<serde_json::Value> = hits
        .iter()
        .map(|(proc_id, ip_id, dataset)| {
            let proc_label = graph
                .get_node(*proc_id)
                .map(|n| n.label().to_string())
                .unwrap_or_default();
            let ip_label = graph
                .get_node(*ip_id)
                .map(|n| n.label().to_string())
                .unwrap_or_default();
            serde_json::json!({
                "process_id": proc_id, "process_label": proc_label,
                "ip_id": ip_id, "ip_label": ip_label,
                "dataset": dataset,
            })
        })
        .collect();

    Json(serde_json::json!({ "total": items.len(), "hits": items }))
}
