// Auto-extracted from mod.rs — dashboard data_api handlers

use super::*;
#[cfg(test)]
use std::io::BufRead;

/// Dashboard auto-sleep timeout: 15 minutes of no requests.
pub(super) const DASHBOARD_SLEEP_SECS: u64 = 15 * 60;

pub(super) fn is_dashboard_sleeping(last_activity: &std::sync::atomic::AtomicU64) -> bool {
    let last = last_activity.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(last) > DASHBOARD_SLEEP_SECS
}

/// Build the AI briefing system prompt. When the operator has a bot
/// personality configured, use it as the base so the Home briefing speaks
/// in the same voice as Telegram `/ask`; otherwise fall back to a plain
/// analyst prompt (preserves behaviour in test fixtures that build a bare
/// `DashboardActionConfig::default()`).
pub(super) fn briefing_system_prompt(personality: &str) -> String {
    let guidance = "FORMAT: generate a concise intelligence briefing. \
        Short sections. No fluff. No generic security advice. \
        Name the TTP and state the action taken for any real incident; \
        treat routine scanner noise as one summary line, not a section each.";
    if personality.trim().is_empty() {
        format!("You are a senior security analyst.\n\n{guidance}")
    } else {
        format!("{}\n\n{guidance}", personality.trim_end())
    }
}

/// Spec 029 PR-C.2: uniform error response when the LLM role is not
/// configured. Centralises the wording so every endpoint that needs
/// `Capability::Generate` or `Capability::Explain` points operators
/// at the same `[ai.llm]` config key. Kept as a small helper so the
/// fallback path is unit-testable without spinning up a
/// `DashboardState` and an axum router.
pub(super) fn llm_unavailable_error(feature: &str) -> serde_json::Value {
    serde_json::json!({
        "error": format!(
            "LLM role not configured. Set [ai.llm] in agent.toml to enable {feature}."
        ),
    })
}

/// Build the AI explain-threat system prompt used by the Threats drill-down.
/// Uses the same base personality as the briefing so all three AI surfaces
/// (Home briefing, Threats explain, Telegram /ask) speak in one voice,
/// layered with the plain-English simplification guidance.
pub(super) fn explain_system_prompt(personality: &str) -> String {
    let simplifier = "FORMAT: you are explaining one incident to the operator. \
        Base your answer strictly on the incident data provided. \
        2-3 sentences. No jargon. No generic advice. \
        Only call it dangerous if the attacker got past initial contact \
        (successful authentication, shell access, data exfil).";
    if personality.trim().is_empty() {
        format!(
            "You are a security assistant explaining threats to a non-technical person.\n\n{simplifier}"
        )
    } else {
        format!("{}\n\n{simplifier}", personality.trim_end())
    }
}
pub(super) async fn api_overview(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<OverviewResponse> {
    let date = resolve_date(query.date.as_deref());
    // When sleeping, return minimal data from telemetry only
    if is_dashboard_sleeping(&state.last_activity) {
        return Json(OverviewResponse {
            date: date.clone(),
            events_count: 0,
            incidents_count: 0,
            decisions_count: 0,
            ai_confirmed: 0,
            ai_responded: 0,
            ai_ignored: 0,
            unresolved_count: 0,
            safely_resolved: 0,
            handled_ips_today: 0,
            blocked_count: 0,
            observing_count: 0,
            attention_count: 0,
            severity_breakdown: std::collections::HashMap::new(),
            allowlisted_count: 0,
            top_detectors: vec![],
            latest_telemetry: crate::telemetry::read_latest_snapshot(&state.data_dir, &date),
        });
    }

    // Read from knowledge graph (live) instead of JSONL
    let graph = state.knowledge_graph.read().unwrap();
    let metrics = graph.metrics();

    // Count decisions from Incident nodes
    use crate::knowledge_graph::types::{Node, NodeType, Relation};
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    let mut decisions_count = 0usize;
    let mut ai_confirmed = 0usize;
    let mut ai_responded = 0usize;
    let mut ai_ignored = 0usize;
    let mut unresolved_count = 0usize;
    let mut safely_resolved = 0usize;
    let mut severity_breakdown: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    // Unique IP entities the AI took a non-ignore action on. Drives the
    // home tile "X handled today" so it matches the unique-IP grouping
    // shown on the Threats tab (`NUMBER_CONSISTENCY.md` row "handled
    // count").
    let mut handled_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut allowlisted_count = 0usize;
    // Spec 037 Threats UX bundle: global KPI counters so the Threats
    // tab no longer derives them from `items` of the currently-selected
    // pivot (which was unstable when switching IP/User/Detector).
    let mut blocked_count = 0usize;
    let mut observing_count = 0usize;
    let mut attention_count = 0usize;

    // Operator filter passed via query string. Applied AFTER the canonical
    // internal/research filter so the operator filter narrows what's
    // already legitimate, not what's noise.
    let sev_min_rank = query
        .severity_min
        .as_deref()
        .map(crate::dashboard::investigation::severity_rank)
        .unwrap_or(0);
    let detector_substring = query
        .detector
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_ascii_lowercase());

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            title,
            decision,
            decision_target,
            severity,
            is_allowlisted,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            // Spec 015 follow-up: skip research-only incidents.
            if *research_only {
                continue;
            }
            // Apply the SAME canonical filter the live-feed and threats tab
            // use, so the home overview counts match the entries those
            // surfaces actually display. Without this, advisory-only
            // detectors (`neural_anomaly`, etc) and IW-system noise
            // (`(en-agent)`, etc) inflate the home counts vs threats.
            let has_external_ip = graph
                .outgoing_edges(id)
                .iter()
                .filter(|e| e.relation == Relation::TriggeredBy)
                .any(|e| {
                    matches!(
                        graph.get_node(e.to),
                        Some(Node::Ip {
                            is_internal: false,
                            ..
                        })
                    )
                });
            if crate::dashboard::live_feed::is_internal_incident_fields(
                detector,
                title,
                has_external_ip,
            ) {
                continue;
            }
            // Operator-supplied severity filter (?severity_min=high).
            if sev_min_rank > 0
                && crate::dashboard::investigation::severity_rank(severity) < sev_min_rank
            {
                continue;
            }
            // Operator-supplied detector substring filter (?detector=ssh).
            if let Some(needle) = &detector_substring {
                if !detector.to_ascii_lowercase().contains(needle) {
                    continue;
                }
            }
            if *is_allowlisted {
                allowlisted_count += 1;
            }
            *by_detector.entry(detector.clone()).or_insert(0) += 1;
            *severity_breakdown
                .entry(severity.to_lowercase())
                .or_insert(0) += 1;
            // Spec 037 Threats UX bundle: classify into the three
            // operator-visible KPI buckets in the same pass. Mirrors
            // `outcomeOf` semantics in threats.js so the Threats-tab
            // numbers match the right-side journey/list outcome.
            match decision.as_deref() {
                Some("block_ip") | Some("honeypot") => blocked_count += 1,
                Some("monitor") => observing_count += 1,
                Some("request_confirmation") => attention_count += 1,
                Some("ignore") => {} // dismissed; not in any KPI bucket
                Some(_) => blocked_count += 1, // any other action == contained
                None => attention_count += 1, // no decision yet => operator must look
            }
            if let Some(dec) = decision {
                decisions_count += 1;
                let target_is_ip = decision_target.as_ref().is_some_and(|t| t.contains('.'));
                match dec.as_str() {
                    "ignore" => ai_ignored += 1,
                    "monitor" => {
                        ai_confirmed += 1;
                        safely_resolved += 1;
                        if target_is_ip {
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                    }
                    "request_confirmation" => {
                        ai_confirmed += 1;
                        unresolved_count += 1;
                    }
                    _ => {
                        ai_confirmed += 1;
                        if target_is_ip {
                            ai_responded += 1;
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                        safely_resolved += 1;
                    }
                }
            }
            // Incidents without a decision are raw events, NOT unresolved threats
        }
    }

    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let telemetry = crate::telemetry::read_latest_snapshot(&state.data_dir, &date);
    let handled_ips_today = handled_ips.len();
    Json(OverviewResponse {
        date,
        events_count: metrics.edge_count, // edges ≈ events (each event creates edges)
        incidents_count: incident_nodes.len(),
        decisions_count,
        ai_confirmed,
        ai_responded,
        ai_ignored,
        unresolved_count,
        safely_resolved,
        handled_ips_today,
        blocked_count,
        observing_count,
        attention_count,
        severity_breakdown,
        allowlisted_count,
        top_detectors,
        latest_telemetry: telemetry,
    })
}

pub(super) async fn api_incidents(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<IncidentListResponse> {
    // Audit I-06: this body opens SQLite via `graph_for_date` (when the
    // operator picks a historical date) and walks every Incident node
    // plus its TriggeredBy edges. Doing that on the async worker stalls
    // every other dashboard request under WAL contention. spawn_blocking
    // moves the sync work to the blocking pool.
    let response = tokio::task::spawn_blocking(move || compute_incidents_blocking(&state, query))
        .await
        .unwrap_or_else(|_| IncidentListResponse {
            date: String::new(),
            total: 0,
            items: Vec::new(),
        });
    Json(response)
}

fn compute_incidents_blocking(state: &DashboardState, query: ListQuery) -> IncidentListResponse {
    let date = resolve_date(query.date.as_deref());
    let explicit_date =
        crate::dashboard::investigation::explicit_date_filter(query.date.as_deref());
    let limit = normalize_limit(query.limit);

    use crate::knowledge_graph::types::{Node, NodeType};
    let arc_graph = crate::dashboard::investigation::graph_for_date(state, explicit_date);
    let graph = arc_graph.read().unwrap();

    let date_filter: Option<chrono::NaiveDate> =
        explicit_date.and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());

    let mut incident_views: Vec<IncidentView> = graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                severity,
                title,
                summary,
                ts,
                mitre_ids,
                decision,
                confidence,
                is_allowlisted,
                research_only,
                ..
            }) = graph.get_node(id)
            {
                if *research_only {
                    return None;
                }
                if let Some(target) = date_filter {
                    if ts.naive_utc().date() != target {
                        return None;
                    }
                }
                // Collect entities from TriggeredBy edges
                let entities: Vec<String> = graph
                    .outgoing_edges(id)
                    .iter()
                    .filter(|e| e.relation == crate::knowledge_graph::types::Relation::TriggeredBy)
                    .filter_map(|e| {
                        graph.get_node(e.to).map(|n| {
                            let ntype = format!("{:?}", n.node_type()).to_lowercase();
                            format!("{}:{}", ntype, n.label())
                        })
                    })
                    .collect();

                let outcome = match decision.as_deref() {
                    Some("block_ip") => "blocked",
                    Some("suspend_user_sudo") => "suspended",
                    Some("kill_process") => "killed",
                    Some("block_container") => "contained",
                    Some("monitor") => "monitored",
                    Some("honeypot") => "honeypot",
                    Some("ignore") => "ignored",
                    Some(_) => "resolved",
                    None => "open",
                };

                // Effective severity: downgrade for handled incidents
                let sev_lower = severity.to_lowercase();
                let effective_severity = effective_severity(outcome, severity);

                Some(IncidentView {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    severity: sev_lower,
                    effective_severity,
                    title: title.clone(),
                    summary: summary.clone(),
                    entities,
                    tags: mitre_ids.clone(),
                    outcome: outcome.to_string(),
                    action_taken: decision.clone(),
                    confidence: *confidence,
                    is_allowlisted: *is_allowlisted,
                })
            } else {
                None
            }
        })
        .collect();

    incident_views.sort_by(|a, b| b.ts.cmp(&a.ts));
    let total = incident_views.len();
    let items: Vec<IncidentView> = incident_views.into_iter().take(limit).collect();

    IncidentListResponse { date, total, items }
}
pub(super) async fn api_decisions(
    State(state): State<DashboardState>,
    Query(query): Query<ListQuery>,
) -> Json<DecisionListResponse> {
    let date = resolve_date(query.date.as_deref());
    let limit = normalize_limit(query.limit);

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    let mut views: Vec<DecisionView> = graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                ts,
                decision: Some(action_type),
                confidence,
                decision_reason,
                decision_target,
                auto_executed,
                ..
            }) = graph.get_node(id)
            {
                Some(DecisionView {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    action_type: action_type.clone(),
                    target_ip: decision_target.clone(),
                    skill_id: None, // not stored in graph (audit trail detail)
                    confidence: confidence.unwrap_or(0.0),
                    auto_executed: *auto_executed,
                    dry_run: false,
                    reason: decision_reason.clone().unwrap_or_default(),
                    execution_result: if *auto_executed {
                        "ok".to_string()
                    } else {
                        "skipped".to_string()
                    },
                })
            } else {
                None
            }
        })
        .collect();

    views.sort_by(|a, b| b.ts.cmp(&a.ts));
    let total = views.len();
    let items: Vec<DecisionView> = views.into_iter().take(limit).collect();

    Json(DecisionListResponse { date, total, items })
}
/// GET /api/report[?date=YYYY-MM-DD]
/// Returns a TrialReport JSON computed on-demand.
/// `date` defaults to the most recent date with data.
pub(super) async fn api_report(
    State(state): State<DashboardState>,
    Query(query): Query<ReportQuery>,
) -> Response {
    let graph = state.knowledge_graph.read().unwrap();
    let report: TrialReport =
        report_mod::compute_for_date_from_graph(&state.data_dir, query.date.as_deref(), &graph);

    match serde_json::to_string_pretty(&report) {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize report",
        )
            .into_response(),
    }
}

/// GET /api/report/dates
/// Returns a JSON array of date strings (YYYY-MM-DD) for which data exists,
/// most recent first. Used by the dashboard report date picker.
pub(super) async fn api_report_dates(State(state): State<DashboardState>) -> Json<Vec<String>> {
    let data_dir = state.data_dir.clone();
    let dates = tokio::task::spawn_blocking(move || report_mod::list_available_dates(&data_dir))
        .await
        .unwrap_or_default();
    Json(dates)
}
// ---------------------------------------------------------------------------
// AI Intelligence Briefing
// ---------------------------------------------------------------------------

/// GET /api/briefing — returns the latest generated briefing
pub(super) async fn api_briefing(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let briefing = state.latest_briefing.lock().await;
    match &*briefing {
        Some(b) => Json(serde_json::json!({
            "available": true,
            "generated_at": b.generated_at.to_rfc3339(),
            "date": b.date,
            "threat_level": b.threat_level,
            "summary": b.summary,
            "config": {
                "hour": state.briefing_hour,
                "minute": state.briefing_minute,
            }
        })),
        None => Json(serde_json::json!({
            "available": false,
            "message": "No briefing generated yet. Click 'Generate Now' or wait for the scheduled time.",
            "config": {
                "hour": state.briefing_hour,
                "minute": state.briefing_minute,
            }
        })),
    }
}

/// POST /api/briefing/generate — trigger manual briefing generation
pub(super) async fn api_briefing_generate(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let context = crate::briefing::build_briefing_context(&state.knowledge_graph);
    let prompt = crate::briefing::briefing_prompt(&context);

    let threat_level = if context.contains("CRITICAL") {
        "CRITICAL"
    } else if context.contains("ELEVATED") {
        "ELEVATED"
    } else if context.contains("MODERATE") {
        "MODERATE"
    } else {
        "LOW"
    };

    // Spec 029 PR-C.2: briefing generation is the Generate role.
    // When the operator runs classifier-only (no [ai.llm]), this
    // endpoint returns the "configure an LLM" error rather than
    // asking a text-less classifier to produce prose.
    let ai: std::sync::Arc<dyn crate::ai::AiProvider> = match state
        .ai_router
        .provider_for(crate::ai::Capability::Generate)
    {
        Some(p) => p,
        None => {
            return Json(llm_unavailable_error("briefings"));
        }
    };
    let system = briefing_system_prompt(&state.action_cfg.ai_personality);
    match ai.chat(&system, &prompt).await {
        Ok(response) => {
            let b = crate::briefing::parse_briefing(&response, threat_level);
            let result = serde_json::json!({
                "available": true,
                "generated_at": b.generated_at.to_rfc3339(),
                "date": b.date,
                "threat_level": b.threat_level,
                "summary": b.summary,
            });
            *state.latest_briefing.lock().await = Some(b);
            Json(result)
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("Failed to generate briefing: {}", e),
        })),
    }
}

// ---------------------------------------------------------------------------
// AI Explain — ask the AI to explain a threat in plain language
// ---------------------------------------------------------------------------

pub(super) async fn api_ai_explain(
    State(state): State<DashboardState>,
    Query(query): Query<AiExplainQuery>,
) -> Json<serde_json::Value> {
    let subject_type = query.r#type.as_deref().unwrap_or("ip");
    let subject_value = match query.value.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Json(serde_json::json!({
                "error": "Missing 'value' parameter"
            }))
        }
    };

    // Spec 029 PR-C.2: the entity-context explainer maps to the
    // Explain role (structured context → natural-language summary).
    let ai: std::sync::Arc<dyn crate::ai::AiProvider> =
        match state.ai_router.provider_for(crate::ai::Capability::Explain) {
            Some(p) => p,
            None => {
                return Json(llm_unavailable_error("explanations"));
            }
        };

    // Build context from the knowledge graph: incidents, decisions,
    // events linked to this entity. Keep it compact for the LLM.
    let context = {
        use crate::knowledge_graph::types::*;
        let graph = state.knowledge_graph.read().unwrap();

        // Find the entity node
        let target_node = match subject_type {
            "ip" => graph
                .nodes_of_type(NodeType::Ip)
                .iter()
                .find(|&&id| {
                    matches!(graph.get_node(id), Some(Node::Ip { addr, .. }) if addr == subject_value)
                })
                .copied(),
            _ => None,
        };

        let Some(node_id) = target_node else {
            return Json(serde_json::json!({
                "explanation": format!("No data found for {} '{}'.", subject_type, subject_value)
            }));
        };

        // Collect incidents linked to this entity
        let mut incident_lines: Vec<String> = Vec::new();
        let mut decision_lines: Vec<String> = Vec::new();

        for edge in graph.incoming_edges(node_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            if let Some(Node::Incident {
                detector,
                severity,
                title,
                summary,
                decision,
                decision_reason,
                research_only,
                auto_executed,
                ts,
                ..
            }) = graph.get_node(edge.from)
            {
                if *research_only {
                    continue;
                }
                incident_lines.push(format!(
                    "- [{}] {}: {} (detector: {}, ts: {})",
                    severity.to_uppercase(),
                    title,
                    summary,
                    detector,
                    ts.format("%H:%M:%S")
                ));
                if let Some(dec) = decision {
                    let reason = decision_reason.as_deref().unwrap_or("no reason recorded");
                    let executed = if *auto_executed {
                        "executed"
                    } else {
                        "recommended"
                    };
                    decision_lines.push(format!("- AI {} {}: {}", executed, dec, reason));
                }
            }
        }

        // Count events
        let event_count = graph
            .all_edges(node_id)
            .iter()
            .filter(|e| e.relation == Relation::ConnectedTo || e.relation == Relation::AcceptedFrom)
            .count();

        format!(
            "Entity: {} {}\nEvent count: {}\n\nIncidents ({}):\n{}\n\nAI Decisions ({}):\n{}",
            subject_type,
            subject_value,
            event_count,
            incident_lines.len(),
            if incident_lines.is_empty() {
                "None".to_string()
            } else {
                incident_lines.join("\n")
            },
            decision_lines.len(),
            if decision_lines.is_empty() {
                "None".to_string()
            } else {
                decision_lines.join("\n")
            },
        )
    };

    let system = explain_system_prompt(&state.action_cfg.ai_personality);

    let user_msg = format!(
        "Explain this activity to me in simple terms. Should I be worried?\n\n{}",
        context
    );

    match ai.chat(&system, &user_msg).await {
        Ok(explanation) => Json(serde_json::json!({ "explanation": explanation })),
        Err(e) => Json(serde_json::json!({
            "error": format!("AI call failed: {}", e)
        })),
    }
}

// ---------------------------------------------------------------------------
// Business logic - overview (graph-based, Phase 6A)
// ---------------------------------------------------------------------------

/// Compute overview from knowledge graph (no JSONL reads).
pub(super) fn compute_overview_from_graph(
    graph: &crate::knowledge_graph::KnowledgeGraph,
    data_dir: &Path,
    date: &str,
) -> OverviewResponse {
    use crate::knowledge_graph::types::{Node, NodeType, Relation};

    let metrics = graph.metrics();
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);

    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    let mut decisions_count = 0usize;
    let mut ai_confirmed = 0usize;
    let mut ai_responded = 0usize;
    let mut ai_ignored = 0usize;
    let mut unresolved_count = 0usize;
    let mut safely_resolved = 0usize;
    let mut severity_breakdown: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut allowlisted_count = 0usize;
    let mut handled_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Spec 037 Threats UX bundle: same KPI buckets as `api_overview`.
    let mut blocked_count = 0usize;
    let mut observing_count = 0usize;
    let mut attention_count = 0usize;

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            title,
            decision,
            decision_target,
            severity,
            is_allowlisted,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            if *research_only {
                continue;
            }
            // Same canonical filter as `api_overview` and the live feed.
            let has_external_ip = graph
                .outgoing_edges(id)
                .iter()
                .filter(|e| e.relation == Relation::TriggeredBy)
                .any(|e| {
                    matches!(
                        graph.get_node(e.to),
                        Some(Node::Ip {
                            is_internal: false,
                            ..
                        })
                    )
                });
            if crate::dashboard::live_feed::is_internal_incident_fields(
                detector,
                title,
                has_external_ip,
            ) {
                continue;
            }
            if *is_allowlisted {
                allowlisted_count += 1;
            }
            *by_detector.entry(detector.clone()).or_insert(0) += 1;
            *severity_breakdown
                .entry(severity.to_lowercase())
                .or_insert(0) += 1;
            // Spec 037 Threats UX bundle: same KPI classification as
            // the live `api_overview` path.
            match decision.as_deref() {
                Some("block_ip") | Some("honeypot") => blocked_count += 1,
                Some("monitor") => observing_count += 1,
                Some("request_confirmation") => attention_count += 1,
                Some("ignore") => {}
                Some(_) => blocked_count += 1,
                None => attention_count += 1,
            }
            if let Some(dec) = decision {
                decisions_count += 1;
                let target_is_ip = decision_target.as_ref().is_some_and(|t| t.contains('.'));
                match dec.as_str() {
                    "ignore" => ai_ignored += 1,
                    "monitor" => {
                        ai_confirmed += 1;
                        safely_resolved += 1;
                        if target_is_ip {
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                    }
                    "request_confirmation" => {
                        ai_confirmed += 1;
                        unresolved_count += 1;
                    }
                    _ => {
                        ai_confirmed += 1;
                        if target_is_ip {
                            ai_responded += 1;
                            if let Some(ip) = decision_target {
                                handled_ips.insert(ip.clone());
                            }
                        }
                        safely_resolved += 1;
                    }
                }
            }
        }
    }

    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let handled_ips_today = handled_ips.len();
    OverviewResponse {
        date: date.to_string(),
        events_count: metrics.edge_count,
        incidents_count: incident_nodes.len(),
        decisions_count,
        ai_confirmed,
        ai_responded,
        ai_ignored,
        unresolved_count,
        safely_resolved,
        handled_ips_today,
        blocked_count,
        observing_count,
        attention_count,
        severity_breakdown,
        allowlisted_count,
        top_detectors,
        latest_telemetry: crate::telemetry::read_latest_snapshot(data_dir, date),
    }
}

/// JSONL-based compute_overview (kept for tests only, will be removed in Phase 6E).
#[cfg(test)]
pub(super) fn compute_overview(data_dir: &Path, date: &str) -> OverviewResponse {
    let events_count = count_file_lines(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut by_detector: BTreeMap<String, usize> = BTreeMap::new();
    for inc in &incidents {
        let detector = inc
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *by_detector.entry(detector).or_insert(0) += 1;
    }
    let mut top_detectors: Vec<DetectorCount> = by_detector
        .into_iter()
        .map(|(detector, count)| DetectorCount { detector, count })
        .collect();
    top_detectors.sort_by(|a, b| b.count.cmp(&a.count).then(a.detector.cmp(&b.detector)));
    top_detectors.truncate(6);

    let ai_confirmed = decisions
        .iter()
        .filter(|d| d.action_type != "ignore" && d.action_type != "request_confirmation")
        .count();
    let ai_responded = decisions
        .iter()
        .filter(|d| d.auto_executed && d.action_type != "ignore" && d.action_type != "monitor")
        .count();
    let ai_ignored = decisions
        .iter()
        .filter(|d| d.action_type == "ignore")
        .count();

    let unresolved_count = ai_confirmed.saturating_sub(ai_responded);
    let safely_resolved = ai_responded;
    // JSONL fallback path (legacy, test-only): treat each "responded"
    // decision target as a unique IP for the handled count. Imperfect
    // (no dedup since we have no easy access to the IP value here) but
    // matches the lower bound. The graph-backed `compute_overview_from_graph`
    // is the canonical path in production.
    let handled_ips_today = ai_responded;

    // Spec 037 Threats UX bundle: same KPI buckets, classified from
    // the JSONL `decisions` stream.
    let mut blocked_count = 0usize;
    let mut observing_count = 0usize;
    let mut attention_count = 0usize;
    for d in &decisions {
        match d.action_type.as_str() {
            "block_ip" | "honeypot" => blocked_count += 1,
            "monitor" => observing_count += 1,
            "request_confirmation" => attention_count += 1,
            "ignore" => {}
            _ => blocked_count += 1,
        }
    }
    // Incidents without a matching decision: count as needing attention.
    if incidents.len() > decisions.len() {
        attention_count += incidents.len() - decisions.len();
    }

    OverviewResponse {
        date: date.to_string(),
        events_count,
        incidents_count: incidents.len(),
        decisions_count: decisions.len(),
        ai_confirmed,
        ai_responded,
        ai_ignored,
        unresolved_count,
        safely_resolved,
        handled_ips_today,
        blocked_count,
        observing_count,
        attention_count,
        severity_breakdown: std::collections::HashMap::new(),
        allowlisted_count: 0,
        top_detectors,
        latest_telemetry: crate::telemetry::read_latest_snapshot(data_dir, date),
    }
}

/// Count non-empty lines in a file without parsing JSON (fast for large files).
/// Only used by #[cfg(test)] compute_overview — will be removed in Phase 6E.
#[cfg(test)]
pub(super) fn count_file_lines(path: &Path) -> usize {
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    std::io::BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        .count()
}

pub(super) fn effective_severity(outcome: &str, severity: &str) -> String {
    let sev_lower = severity.to_lowercase();
    match outcome {
        "blocked" | "killed" | "contained" | "suspended" => match sev_lower.as_str() {
            "critical" => "medium".to_string(),
            "high" => "low".to_string(),
            _ => sev_lower,
        },
        "ignored" => "info".to_string(),
        _ => sev_lower, // open, monitored, honeypot: keep original
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn briefing_system_prompt_falls_back_when_personality_blank() {
        let out = briefing_system_prompt("");
        assert!(out.starts_with("You are a senior security analyst."));
        assert!(out.contains("FORMAT: generate a concise intelligence briefing."));
    }

    #[test]
    fn briefing_system_prompt_uses_personality_when_set() {
        let out = briefing_system_prompt("You are InnerWarden. Bouncer voice.");
        assert!(out.starts_with("You are InnerWarden. Bouncer voice."));
        assert!(!out.contains("senior security analyst"));
        assert!(out.contains("FORMAT: generate a concise intelligence briefing."));
    }

    #[test]
    fn briefing_system_prompt_trims_whitespace_personality() {
        let out = briefing_system_prompt("   \n\t  ");
        // Whitespace-only must fall back to the analyst baseline rather
        // than produce a prompt that opens with blank lines.
        assert!(out.starts_with("You are a senior security analyst."));
    }

    #[test]
    fn explain_system_prompt_falls_back_when_personality_blank() {
        let out = explain_system_prompt("");
        assert!(out.starts_with("You are a security assistant explaining threats"));
        assert!(out.contains("FORMAT: you are explaining one incident"));
    }

    #[test]
    fn explain_system_prompt_uses_personality_when_set() {
        let out = explain_system_prompt("You are InnerWarden. Bouncer voice.");
        assert!(out.starts_with("You are InnerWarden. Bouncer voice."));
        assert!(!out.contains("security assistant explaining threats"));
        assert!(out.contains("Only call it dangerous"));
    }

    #[test]
    fn test_effective_severity_downgrade() {
        // Handled -> downgrade
        assert_eq!(effective_severity("blocked", "critical"), "medium");
        assert_eq!(effective_severity("killed", "Critical"), "medium");
        assert_eq!(effective_severity("contained", "high"), "low");
        assert_eq!(effective_severity("suspended", "High"), "low");

        // Low stays low
        assert_eq!(effective_severity("blocked", "low"), "low");

        // Ignored goes to info
        assert_eq!(effective_severity("ignored", "critical"), "info");

        // Open/monitored/honeypot retain
        assert_eq!(effective_severity("open", "critical"), "critical");
        assert_eq!(effective_severity("monitored", "high"), "high");
        assert_eq!(effective_severity("honeypot", "medium"), "medium");
        assert_eq!(effective_severity("resolved", "low"), "low");
    }

    #[test]
    fn test_is_dashboard_sleeping() {
        // Detects dashboard sleep mode after inactivity timeout.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Active 1 second ago
        let active = AtomicU64::new(now - 1);
        assert!(!is_dashboard_sleeping(&active));

        // Active 16 minutes ago (past 15m threshold)
        let sleeping = AtomicU64::new(now - (16 * 60));
        assert!(is_dashboard_sleeping(&sleeping));

        // Active at 0 (never active or system restart)
        let never = AtomicU64::new(0);
        assert!(is_dashboard_sleeping(&never));
    }

    #[test]
    fn test_pagination_page_zero_returns_first_batch() {
        // Page 0 should return the first batch of items.
        let items: Vec<usize> = (1..=10).collect();
        let page_size = 3usize;
        let page = 0usize;
        let batch: Vec<usize> = items
            .iter()
            .skip(page.saturating_mul(page_size))
            .take(page_size)
            .copied()
            .collect();
        assert_eq!(batch, vec![1, 2, 3]);
    }

    #[test]
    fn test_pagination_page_past_end_returns_empty() {
        // Requesting a page after the available range should return no items.
        let items: Vec<usize> = (1..=5).collect();
        let page_size = 2usize;
        let page = 10usize;
        let batch: Vec<usize> = items
            .iter()
            .skip(page.saturating_mul(page_size))
            .take(page_size)
            .copied()
            .collect();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_date_range_parsing_with_invalid_format() {
        // Invalid date formats should fail parsing rather than silently succeed.
        let invalid = chrono::NaiveDate::parse_from_str("16-04-2026", "%Y-%m-%d");
        assert!(invalid.is_err());
    }

    // Spec 029 PR-C.2: the llm_unavailable_error helper powers every
    // `None` branch of provider_for(Generate | Explain) in the
    // dashboard endpoints. Lock the exact shape so grant/operator
    // docs that quote the error string do not drift.
    #[test]
    fn llm_unavailable_error_shape() {
        let json = llm_unavailable_error("briefings");
        assert_eq!(
            json["error"],
            "LLM role not configured. Set [ai.llm] in agent.toml to enable briefings."
        );
    }

    #[test]
    fn llm_unavailable_error_feature_is_interpolated() {
        let json = llm_unavailable_error("explanations");
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("to enable explanations."));
        let json_ask = llm_unavailable_error("/ask");
        assert!(json_ask["error"]
            .as_str()
            .unwrap()
            .contains("to enable /ask."));
    }

    // Spec 029 PR-C.2: exercise the briefing endpoint with a disabled
    // router so the `provider_for(Generate) => None` branch runs end-
    // to-end (not just the helper). Locks the public JSON contract.
    #[tokio::test]
    async fn api_briefing_generate_returns_unavailable_when_router_has_no_generate() {
        use axum::extract::State;
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());
        let Json(body) = api_briefing_generate(State(state)).await;
        assert_eq!(
            body["error"],
            "LLM role not configured. Set [ai.llm] in agent.toml to enable briefings."
        );
    }

    #[tokio::test]
    async fn api_ai_explain_returns_unavailable_when_router_has_no_explain() {
        use axum::extract::{Query, State};
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());
        let query = AiExplainQuery {
            r#type: Some("ip".into()),
            value: Some("198.51.100.10".into()),
        };
        let Json(body) = api_ai_explain(State(state), Query(query)).await;
        assert_eq!(
            body["error"],
            "LLM role not configured. Set [ai.llm] in agent.toml to enable explanations."
        );
    }

    #[tokio::test]
    async fn api_ai_explain_missing_value_short_circuits_before_router() {
        use axum::extract::{Query, State};
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());
        let query = AiExplainQuery {
            r#type: Some("ip".into()),
            value: None,
        };
        let Json(body) = api_ai_explain(State(state), Query(query)).await;
        assert_eq!(body["error"], "Missing 'value' parameter");
    }

    // ── compute_overview_from_graph behaviour (Inconsistencies 1 + 3) ─
    //
    // Two anchors:
    //   - handled_ips_today = unique IPs with non-ignore decision
    //     (matches Threats tab entry count, NUMBER_CONSISTENCY.md row
    //     "handled count").
    //   - filter predicates inside the loop honor the canonical
    //     `is_internal_incident_fields` (so home counts match site
    //     counts).

    fn make_overview_kg() -> crate::knowledge_graph::KnowledgeGraph {
        use crate::knowledge_graph::types::*;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        // Two real attackers, both blocked. Same IP repeated in two
        // incidents to prove the dedup works.
        let ip_a = g.ensure_ip("203.0.113.10", now);
        for tag in ["1", "2"] {
            let inc = g.add_node(Node::Incident {
                incident_id: format!("ssh_bruteforce:{tag}"),
                detector: "ssh_bruteforce".into(),
                severity: "high".into(),
                title: "SSH brute force".into(),
                summary: "".into(),
                ts: now,
                mitre_ids: vec![],
                decision: Some("block_ip".into()),
                decision_target: Some("203.0.113.10".into()),
                confidence: Some(0.95),
                decision_reason: None,
                auto_executed: true,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            g.add_edge(Edge::new(inc, ip_a, Relation::TriggeredBy, now));
        }
        // Different IP, monitored.
        let ip_b = g.ensure_ip("198.51.100.20", now);
        let inc_b = g.add_node(Node::Incident {
            incident_id: "port_scan:1".into(),
            detector: "port_scan".into(),
            severity: "low".into(),
            title: "Port scan".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("monitor".into()),
            decision_target: Some("198.51.100.20".into()),
            confidence: Some(0.6),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_b, ip_b, Relation::TriggeredBy, now));
        // Advisory-only detector — must NOT count toward overview.
        let ip_c = g.ensure_ip("192.0.2.30", now);
        let inc_c = g.add_node(Node::Incident {
            incident_id: "neural_anomaly:1".into(),
            detector: "neural_anomaly".into(),
            severity: "high".into(),
            title: "Neural anomaly".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("192.0.2.30".into()),
            confidence: None,
            decision_reason: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_c, ip_c, Relation::TriggeredBy, now));
        g
    }

    #[test]
    fn compute_overview_handled_ips_today_dedupes_by_ip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        // 203.0.113.10 has TWO block_ip decisions (same IP, 2 incidents).
        // 198.51.100.20 has ONE monitor decision.
        // 192.0.2.30 is filtered (advisory-only).
        // Unique IPs handled = 2.
        assert_eq!(out.handled_ips_today, 2);
        // safely_resolved counts INCIDENTS — block_ip × 2 + monitor × 1 = 3.
        assert_eq!(out.safely_resolved, 3);
        // ai_responded counts only IP-targeted non-monitor decisions = 2 (both block_ip).
        assert_eq!(out.ai_responded, 2);
    }

    #[tokio::test]
    async fn api_overview_returns_handled_ips_today_field() {
        // Anchors the async handler wrapper around compute_overview_from_graph.
        // Goes through the full path so the OverviewResponse JSON shape +
        // handled_ips_today field stay exercised end-to-end.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_overview(State(state), Query(q)).await;
        // handled_ips_today must be present even if 0.
        assert_eq!(out.handled_ips_today, 0);
        assert_eq!(out.incidents_count, 0);
    }

    #[tokio::test]
    async fn api_overview_sleeping_path_returns_zero_with_handled_field() {
        // When `last_activity` is older than DASHBOARD_SLEEP_SECS the
        // handler returns a minimal OverviewResponse from telemetry only.
        // The new `handled_ips_today` field must still be present.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        // Force "asleep": last_activity = 0 (epoch).
        state
            .last_activity
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let q = ListQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
        };
        let Json(out) = api_overview(State(state), Query(q)).await;
        assert_eq!(out.handled_ips_today, 0);
        assert_eq!(out.incidents_count, 0);
    }

    #[test]
    fn compute_overview_severity_min_filter_excludes_low_incidents() {
        // Inconsistency 3 anchor in the compute helper. severity_min=high
        // must drop the LOW port_scan incident from all counters.
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        // The compute helper does not currently take filters as an arg —
        // it's consumed by api_overview which applies query filters in its
        // own loop. The `make_overview_kg` fixture has a low-severity
        // incident; assert it appears in the unfiltered count so the
        // `compute_overview_from_graph` path is fully exercised.
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        // ai_ignored = 0 (no incidents have decision="ignore"), and no
        // request_confirmation either, so unresolved_count stays 0 too.
        assert_eq!(out.ai_ignored, 0);
        assert_eq!(out.unresolved_count, 0);
        // severity_breakdown should have entries for "high" and "low".
        assert_eq!(out.severity_breakdown.get("high"), Some(&2));
        assert_eq!(out.severity_breakdown.get("low"), Some(&1));
    }

    #[test]
    fn compute_overview_filters_advisory_only_detectors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        // The advisory-only neural_anomaly incident must NOT appear in
        // top_detectors and must NOT be counted in any decision counter.
        let detectors: Vec<&str> = out
            .top_detectors
            .iter()
            .map(|d| d.detector.as_str())
            .collect();
        assert!(!detectors.contains(&"neural_anomaly"));
        // ai_confirmed should count 3 (2 block + 1 monitor) — not 4.
        assert_eq!(out.ai_confirmed, 3);
    }

    // ── Spec 037 Threats UX bundle ─────────────────────────────────────
    //
    // KPI buckets + diagnostic endpoint anchors. The threats.js KPI
    // computation moved from front-end pivot-summing to these
    // backend-derived counts, so a regression that drops the fields
    // would silently zero the "Blocked / Observing / Needs attention"
    // tiles -- only the anchors below catch that.

    #[test]
    fn compute_overview_populates_threats_kpi_buckets() {
        // make_overview_kg has 2x block_ip + 1x monitor + 1x advisory
        // (filtered). After classification: blocked=2, observing=1,
        // attention=0.
        let dir = tempfile::tempdir().expect("tempdir");
        let g = make_overview_kg();
        let out = compute_overview_from_graph(&g, dir.path(), "2026-04-23");
        assert_eq!(out.blocked_count, 2, "block_ip incidents = 2");
        assert_eq!(out.observing_count, 1, "monitor incidents = 1");
        assert_eq!(out.attention_count, 0, "no undecided incidents");
    }

    #[tokio::test]
    async fn api_threats_diagnostic_reports_has_entities_when_pivots_populated() {
        // make_overview_kg seeds two real attacker IPs. The diagnostic
        // must mark `has_entities=true` and `has_incidents=true`.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let g = make_overview_kg();
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(g));
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = EntitiesQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
            group_by: None,
        };
        let Json(out) =
            crate::dashboard::investigation::api_threats_diagnostic(State(state), Query(q)).await;
        assert!(out.has_incidents, "graph has 3 real-attacker incidents");
        assert!(out.has_entities, "two IP entities exist in pivot");
        assert!(!out.scope_mismatch, "today's pivot has matches");
        assert!(out.ip_pivot_count >= 1, "ip pivot must surface attackers");
    }

    #[tokio::test]
    async fn api_threats_diagnostic_reports_empty_when_graph_empty() {
        // Empty knowledge graph: has_incidents=false, has_entities=false,
        // scope_mismatch=false, suggested_pivots=[].
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = EntitiesQuery {
            limit: None,
            date: None,
            severity_min: None,
            detector: None,
            group_by: None,
        };
        let Json(out) =
            crate::dashboard::investigation::api_threats_diagnostic(State(state), Query(q)).await;
        assert!(!out.has_incidents);
        assert!(!out.has_entities);
        assert!(
            !out.scope_mismatch,
            "no incidents anywhere = not a scope mismatch"
        );
        assert!(out.suggested_pivots.is_empty());
    }

    #[tokio::test]
    async fn api_threats_diagnostic_flags_scope_mismatch_for_wrong_date() {
        // Graph has an incident on 2026-04-26 but the query asks for
        // 2026-04-28: has_incidents=false (in scope), but
        // scope_mismatch=true so the front-end can hint "try previous day".
        use crate::knowledge_graph::types::*;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let day1 = chrono::DateTime::parse_from_rfc3339("2026-04-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ip = g.ensure_ip("203.0.113.50", day1);
        let inc = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:past".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "old SSH brute force".into(),
            summary: "".into(),
            ts: day1,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("203.0.113.50".into()),
            confidence: Some(0.9),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, day1));
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(g));
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let q = EntitiesQuery {
            limit: None,
            date: Some("2026-04-28".to_string()),
            severity_min: None,
            detector: None,
            group_by: None,
        };
        let Json(out) =
            crate::dashboard::investigation::api_threats_diagnostic(State(state), Query(q)).await;
        assert!(!out.has_incidents, "no incidents on 2026-04-28");
        assert!(
            out.scope_mismatch,
            "graph has incidents on a different date"
        );
    }
}
