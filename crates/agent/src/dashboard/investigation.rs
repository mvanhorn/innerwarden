// Auto-extracted from mod.rs — dashboard investigation handlers

use super::threat_contract;
use super::*;

/// Spec 037 Threats UX bundle: tells the empty-state renderer WHY
/// the right panel has nothing to show. Three states the operator
/// needs to distinguish:
///   * `has_incidents=false`: no incidents in scope -- nothing wrong,
///     just a quiet day or a too-narrow filter.
///   * `has_incidents=true && has_entities=false`: backend has
///     incidents but couldn't link any IP/User entities, so the IP
///     pivot is empty even though there are incidents to investigate.
///     `suggested_pivots: ["detector"]` so the operator can still drill
///     in via the Detector pivot.
///   * `scope_mismatch=true`: incidents exist in graph but not on the
///     requested date -- the front-end should hint at "try previous day".
#[derive(Debug, serde::Serialize)]
pub(crate) struct ThreatsDiagnostic {
    pub(super) date: String,
    pub(super) has_incidents: bool,
    pub(super) has_entities: bool,
    pub(super) scope_mismatch: bool,
    pub(super) suggested_pivots: Vec<String>,
    pub(super) incidents_in_scope: usize,
    pub(super) ip_pivot_count: usize,
    pub(super) user_pivot_count: usize,
    pub(super) detector_pivot_count: usize,
    /// 2026-04-29: historical dates with on-disk graph snapshots that
    /// the operator can drill into via the date filter. Front-end
    /// renders these as clickable chips in the empty-state hint.
    pub(super) available_dates: Vec<String>,
}

pub(super) async fn api_threats_diagnostic(
    State(state): State<DashboardState>,
    Query(query): Query<EntitiesQuery>,
) -> Json<ThreatsDiagnostic> {
    // Audit I-06: the body opens SQLite (graph_for_date snapshot read +
    // separate available_dates query) and runs three pivot builders.
    // All sync. spawn_blocking moves it off the async worker.
    let response = tokio::task::spawn_blocking(move || {
        let display_date = resolve_date(query.date.as_deref());
        let explicit_date = explicit_date_filter(query.date.as_deref()).map(|s| s.to_string());
        let filters = InvestigationFilters::from_query(
            query.severity_min.as_deref(),
            query.detector.as_deref(),
        );

        // Phase 12 (QA fix #3): the diagnostic now mirrors the same
        // SQLite path the entities/pivots endpoints use, so its
        // counts match the actual data the operator's list shows.
        // Pre-Phase-12 the diagnostic walked the lossy KG and
        // reported `scope_mismatch=true` whenever the KG was sparse,
        // even though SQLite had the data — wrong empty-state copy.
        let pivots_from_sqlite = state.sqlite_store.as_ref().map(|store| {
            let ip_items =
                build_pivots_from_sqlite(store, &display_date, PivotKind::Ip, &filters, 500)
                    .unwrap_or_default();
            let user_items =
                build_pivots_from_sqlite(store, &display_date, PivotKind::User, &filters, 500)
                    .unwrap_or_default();
            let det_items =
                build_pivots_from_sqlite(store, &display_date, PivotKind::Detector, &filters, 500)
                    .unwrap_or_default();
            (ip_items, user_items, det_items)
        });
        let (ip_count, user_count, det_count, incidents_in_scope) = match pivots_from_sqlite {
            Some((ip_items, user_items, det_items)) => {
                let inc_sum: usize = det_items.iter().map(|p| p.incident_count).sum();
                (ip_items.len(), user_items.len(), det_items.len(), inc_sum)
            }
            None => {
                let graph = graph_for_date(&state, explicit_date.as_deref());
                let ip_count = build_pivots_from_graph(
                    &graph,
                    PivotKind::Ip,
                    500,
                    &filters,
                    explicit_date.as_deref(),
                )
                .len();
                let user_count = build_pivots_from_graph(
                    &graph,
                    PivotKind::User,
                    500,
                    &filters,
                    explicit_date.as_deref(),
                )
                .len();
                let det_count = build_pivots_from_graph(
                    &graph,
                    PivotKind::Detector,
                    500,
                    &filters,
                    explicit_date.as_deref(),
                )
                .len();
                let inc_sum: usize = build_pivots_from_graph(
                    &graph,
                    PivotKind::Detector,
                    500,
                    &filters,
                    explicit_date.as_deref(),
                )
                .iter()
                .map(|p| p.incident_count)
                .sum();
                (ip_count, user_count, det_count, inc_sum)
            }
        };
        let total_pivot = ip_count + user_count + det_count;

        let has_incidents = incidents_in_scope > 0;
        let has_entities = (ip_count + user_count) > 0;

        let scope_mismatch = if has_incidents || explicit_date.is_none() {
            false
        } else {
            use crate::knowledge_graph::types::NodeType;
            let live = state.knowledge_graph.read().unwrap();
            !live.nodes_of_type(NodeType::Incident).is_empty()
        };

        let mut suggested_pivots = Vec::new();
        if ip_count > 0 {
            suggested_pivots.push("ip".to_string());
        }
        if user_count > 0 {
            suggested_pivots.push("user".to_string());
        }
        if det_count > 0 && total_pivot > ip_count + user_count {
            suggested_pivots.push("detector".to_string());
        }

        let mut available_dates: Vec<String> = Vec::new();
        if let Ok(store) = innerwarden_store::Store::open(&state.data_dir) {
            if let Ok(conn) = store.conn() {
                if let Ok(mut stmt) =
                    conn.prepare("SELECT date FROM graph_snapshots ORDER BY date DESC LIMIT 7")
                {
                    if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                        for row in rows.flatten() {
                            available_dates.push(row);
                        }
                    }
                }
            }
        }

        ThreatsDiagnostic {
            date: display_date,
            has_incidents,
            has_entities,
            scope_mismatch,
            suggested_pivots,
            incidents_in_scope,
            ip_pivot_count: ip_count,
            user_pivot_count: user_count,
            detector_pivot_count: det_count,
            available_dates,
        }
    })
    .await
    .unwrap_or_else(|_| ThreatsDiagnostic {
        date: String::new(),
        has_incidents: false,
        has_entities: false,
        scope_mismatch: false,
        suggested_pivots: Vec::new(),
        incidents_in_scope: 0,
        ip_pivot_count: 0,
        user_pivot_count: 0,
        detector_pivot_count: 0,
        available_dates: Vec::new(),
    });
    Json(response)
}

pub(super) async fn api_entities(
    State(state): State<DashboardState>,
    Query(query): Query<EntitiesQuery>,
) -> Json<EntitiesResponse> {
    // Audit I-06 (2026-04-29): the body opens SQLite (via `graph_for_date`
    // when the operator picked a historical date), decompresses + parses
    // a ~3 MB gzipped snapshot, and runs the pivot builder. Doing this on
    // the async worker stalls every other dashboard request handled by
    // the same worker under WAL contention. `spawn_blocking` moves the
    // sync work to the blocking pool so async workers stay responsive.
    let response = tokio::task::spawn_blocking(move || {
        let display_date = resolve_date(query.date.as_deref());
        let explicit_date = explicit_date_filter(query.date.as_deref()).map(|s| s.to_string());
        let limit = normalize_limit(query.limit);
        let filters = InvestigationFilters::from_query(
            query.severity_min.as_deref(),
            query.detector.as_deref(),
        );
        // Phase 6 (audit RC-2 deeper close, second surface): the
        // Threats left-rail list must read from durable SQLite, not
        // the lossy in-memory KG. Phase 5 closed `/api/overview`'s
        // count source. This closes the per-attacker list source so
        // the operator no longer sees "Home: 22 handled / Threats:
        // 1 attacker" because the KG TTL-evicted 109 of 110 IPs.
        let sqlite_attackers = state
            .sqlite_store
            .as_ref()
            .and_then(|store| build_attackers_from_sqlite(store, &display_date, &filters, limit));
        let attackers = if let Some(att) = sqlite_attackers {
            att
        } else {
            let graph = graph_for_date(&state, explicit_date.as_deref());
            build_attackers_from_graph(
                &graph,
                limit,
                &filters,
                explicit_date.as_deref(),
                state.sqlite_store.as_ref(),
            )
        };
        EntitiesResponse {
            date: display_date,
            attackers,
        }
    })
    .await
    .unwrap_or_else(|_| EntitiesResponse {
        date: String::new(),
        attackers: Vec::new(),
    });
    Json(response)
}

pub(super) async fn api_pivots(
    State(state): State<DashboardState>,
    Query(query): Query<EntitiesQuery>,
) -> Json<PivotResponse> {
    // Phase 12 (QA fix #3, 2026-04-29): the User and Detector pivots
    // were still reading from the lossy in-memory KG via
    // `build_pivots_from_graph`, the same way Phase 6 found the IP
    // pivot to be broken. With operator's severity=critical filter
    // applied, the lossy KG returns 0 because today's earlier
    // critical incidents got TTL-evicted, and the empty list shows
    // the "No incidents on YYYY-MM-DD / Pick a date with data"
    // diagnostic — even though SQLite has the incidents intact.
    // Migration mirrors Phase 6 / 8 / 10: read SQLite primarily,
    // fall back to graph only when the store is unreachable (test
    // fixtures).
    let response = tokio::task::spawn_blocking(move || {
        let display_date = resolve_date(query.date.as_deref());
        let explicit_date = explicit_date_filter(query.date.as_deref()).map(|s| s.to_string());
        let limit = normalize_limit(query.limit);
        let group_by = PivotKind::parse(query.group_by.as_deref());
        let filters = InvestigationFilters::from_query(
            query.severity_min.as_deref(),
            query.detector.as_deref(),
        );
        let sqlite_items = state.sqlite_store.as_ref().and_then(|store| {
            build_pivots_from_sqlite(store, &display_date, group_by, &filters, limit)
        });
        let items = if let Some(items) = sqlite_items {
            items
        } else {
            let graph = graph_for_date(&state, explicit_date.as_deref());
            build_pivots_from_graph(&graph, group_by, limit, &filters, explicit_date.as_deref())
        };
        PivotResponse {
            date: display_date,
            group_by: group_by.as_str().to_string(),
            total: items.len(),
            items,
        }
    })
    .await
    .unwrap_or_else(|_| PivotResponse {
        date: String::new(),
        group_by: "ip".to_string(),
        total: 0,
        items: Vec::new(),
    });
    Json(response)
}

/// Returns `Some(date_str)` only when the caller passed a parseable
/// `YYYY-MM-DD` value. Empty string, missing param, and unparseable
/// inputs all collapse to `None` so the builder applies no date
/// filter at all (and the operator sees the whole graph by default).
pub(super) fn explicit_date_filter(raw: Option<&str>) -> Option<&str> {
    let candidate = raw?.trim();
    if candidate.len() != 10 {
        return None;
    }
    if chrono::NaiveDate::parse_from_str(candidate, "%Y-%m-%d").is_err() {
        return None;
    }
    Some(candidate)
}

/// Resolve which knowledge-graph snapshot to read for a request.
///
/// The live `state.knowledge_graph` only contains TODAY's incidents
/// (the agent's snapshot model is one-day-per-graph; older days live
/// in the `graph_snapshots` SQLite table as gzipped blobs but are
/// never merged into the in-memory graph). Pre-2026-04-29 the Threats
/// page relied on the live graph regardless of which date the
/// operator picked, so any historical-date selection silently
/// returned 0 incidents -- the graph simply did not contain them.
///
/// This helper inspects the explicit-date filter:
///   * `None` or `Some(today)` -> use the live in-memory graph.
///   * `Some(historical_date)` -> load that date's snapshot from
///     SQLite (`load_dated_sqlite_first`). Falls back to the live
///     graph if the snapshot is missing/corrupt so the request never
///     errors out -- empty result is a normal outcome that the
///     diagnostic endpoint surfaces to the operator.
///
/// Returned graph is owned (a fresh `Arc<RwLock<...>>`) when loaded
/// from SQLite; cloned when the live graph is reused. The caller
/// holds it for the duration of the request only.
pub(super) fn graph_for_date(
    state: &DashboardState,
    explicit_date: Option<&str>,
) -> std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>> {
    let Some(date) = explicit_date else {
        return state.knowledge_graph.clone();
    };
    let today = chrono::Utc::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    if date == today {
        return state.knowledge_graph.clone();
    }
    match crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(&state.data_dir, date) {
        Some(g) => std::sync::Arc::new(std::sync::RwLock::new(g)),
        None => state.knowledge_graph.clone(),
    }
}
pub(super) async fn api_clusters(
    State(state): State<DashboardState>,
    Query(query): Query<ClusterQuery>,
) -> Json<ClusterResponse> {
    // Audit I-06: same blocking-pool treatment as api_entities. Cluster
    // computation iterates every Incident node, walks edges, and (when
    // the operator picks a historical date) reads a fresh ~3 MB snapshot
    // off SQLite via `graph_for_date`.
    let response = tokio::task::spawn_blocking(move || compute_clusters_blocking(&state, query))
        .await
        .unwrap_or_else(|_| ClusterResponse {
            date: String::new(),
            total: 0,
            items: Vec::new(),
        });
    Json(response)
}

fn compute_clusters_blocking(state: &DashboardState, query: ClusterQuery) -> ClusterResponse {
    let date = resolve_date(query.date.as_deref());
    let explicit_date = explicit_date_filter(query.date.as_deref());
    let limit = normalize_limit(query.limit);
    let window_seconds = query.window_seconds.unwrap_or(300).clamp(30, 3600);
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());

    use crate::knowledge_graph::types::{Node, Relation};
    let arc_graph = graph_for_date(state, explicit_date);
    let graph = arc_graph.read().unwrap();

    let date_filter: Option<chrono::NaiveDate> =
        explicit_date.and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());

    // 2026-04-29: route through `qualifying_incident_ids` so clusters
    // apply the SAME filter stack as IP/User/Detector pivots
    // (research_only + internal_incident_fields + severity + detector
    // substring). Pre-fix this function only honoured the date_filter
    // and `decision != Some("ignore")`, so clusters could include
    // self-traffic IPs and advisory-only detectors that the pivots
    // had rejected -- the operator-reported "click cluster see X
    // IPs, click pivot see fewer" contradiction (audit RC-3).
    let qualifying = qualifying_incident_ids(
        &graph,
        date_filter,
        filters.severity_min_rank(),
        filters.detector_lower(),
    );

    let mut incidents_by_ip: std::collections::HashMap<
        String,
        Vec<(chrono::DateTime<Utc>, String, String)>,
    > = std::collections::HashMap::new();

    for inc_id in qualifying {
        if let Some(Node::Incident {
            incident_id,
            detector,
            ts,
            ..
        }) = graph.get_node(inc_id)
        {
            for edge in graph.outgoing_edges(inc_id) {
                if edge.relation == Relation::TriggeredBy {
                    if let Some(Node::Ip {
                        addr, is_internal, ..
                    }) = graph.get_node(edge.to)
                    {
                        if *is_internal {
                            continue;
                        }
                        if crate::cloud_safelist::is_self_traffic_ip(addr) {
                            continue;
                        }
                        incidents_by_ip.entry(addr.clone()).or_default().push((
                            *ts,
                            incident_id.clone(),
                            detector.clone(),
                        ));
                    }
                }
            }
        }
    }

    let window = chrono::Duration::seconds(window_seconds as i64);
    let mut items: Vec<ClusterItem> = Vec::new();

    for (ip, mut incs) in incidents_by_ip {
        if incs.len() < 2 {
            continue;
        }
        incs.sort_by_key(|(ts, _, _)| *ts);

        // Group into temporal clusters
        let mut cluster_start = incs[0].0;
        let mut cluster_incs = vec![incs[0].clone()];

        for inc in incs.iter().skip(1) {
            if inc.0 - cluster_incs.last().unwrap().0 <= window {
                cluster_incs.push(inc.clone());
            } else {
                if cluster_incs.len() >= 2 {
                    let dets: Vec<String> = cluster_incs
                        .iter()
                        .map(|(_, _, d)| d.clone())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();
                    let ids: Vec<String> =
                        cluster_incs.iter().map(|(_, id, _)| id.clone()).collect();
                    items.push(ClusterItem {
                        cluster_id: format!("cluster-{:03}", items.len() + 1),
                        pivot: format!("ip:{}", ip),
                        pivot_type: "ip".to_string(),
                        pivot_value: ip.clone(),
                        start_ts: cluster_start,
                        end_ts: cluster_incs.last().unwrap().0,
                        incident_count: cluster_incs.len(),
                        detector_kinds: dets,
                        incident_ids: ids,
                    });
                }
                cluster_start = inc.0;
                cluster_incs = vec![inc.clone()];
            }
        }
        // Flush last cluster
        if cluster_incs.len() >= 2 {
            let dets: Vec<String> = cluster_incs
                .iter()
                .map(|(_, _, d)| d.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            let ids: Vec<String> = cluster_incs.iter().map(|(_, id, _)| id.clone()).collect();
            items.push(ClusterItem {
                cluster_id: format!("cluster-{:03}", items.len() + 1),
                pivot: format!("ip:{}", ip),
                pivot_type: "ip".to_string(),
                pivot_value: ip.clone(),
                start_ts: cluster_start,
                end_ts: cluster_incs.last().unwrap().0,
                incident_count: cluster_incs.len(),
                detector_kinds: dets,
                incident_ids: ids,
            });
        }
    }

    items.sort_by(|a, b| b.incident_count.cmp(&a.incident_count));
    items.truncate(limit);

    ClusterResponse {
        date,
        total: items.len(),
        items,
    }
}
pub(super) async fn api_journey(
    State(state): State<DashboardState>,
    Query(query): Query<JourneyQuery>,
) -> Json<JourneyResponse> {
    let date = resolve_date(query.date.as_deref());
    let subject_type = PivotKind::parse(query.subject_type.as_deref());
    let window_seconds = query.window_seconds.map(|w| w.clamp(60, 86_400));
    let subject = query
        .subject
        .or(query.ip)
        .unwrap_or_default()
        .trim()
        .to_string();
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());

    if subject.is_empty() {
        return Json(JourneyResponse {
            subject_type: subject_type.as_str().to_string(),
            subject: String::new(),
            date,
            first_seen: None,
            last_seen: None,
            outcome: "unknown".to_string(),
            summary: JourneySummary {
                total_entries: 0,
                events_count: 0,
                incidents_count: 0,
                decisions_count: 0,
                honeypot_count: 0,
                first_event: None,
                first_incident: None,
                first_decision: None,
                first_honeypot: None,
                pivot_shortcuts: Vec::new(),
                hints: vec!["Select a subject to start investigation.".to_string()],
            },
            verdict: JourneyVerdict {
                entry_vector: "unknown".to_string(),
                access_status: "inconclusive".to_string(),
                privilege_status: "no_evidence".to_string(),
                containment_status: "unknown".to_string(),
                honeypot_status: "not_engaged".to_string(),
                confidence: "low".to_string(),
            },
            chapters: vec![],
            entries: vec![],
            block_state: None,
            // Spec 049 PR10: empty subject → no profile to look up.
            recurrence: None,
        });
    }

    // Audit I-06: build_journey_from_graph now does sync SQLite reads
    // (xdp_block_times kv lookup) on top of the pre-existing graph
    // read-lock + JSONL scan. Wrap in spawn_blocking so the dashboard
    // async workers stay responsive under WAL contention.
    let kg = std::sync::Arc::clone(&state.knowledge_graph);
    let data_dir = state.data_dir.clone();
    let sqlite = state.sqlite_store.clone();
    let date_for_fallback = date.clone();
    let subject_for_fallback = subject.clone();
    // Clone the sqlite handle a second time so we still have access
    // after the spawn_blocking move below — the PR10 recurrence
    // overlay needs to read `attacker_profiles` blob post-build.
    let sqlite_for_recurrence = state.sqlite_store.clone();
    let subject_for_recurrence = subject.clone();
    let response = tokio::task::spawn_blocking(move || {
        build_journey_from_graph(
            &kg,
            &data_dir,
            &date,
            subject_type,
            &subject,
            &filters,
            window_seconds,
            sqlite.as_ref(),
        )
    })
    .await
    .unwrap_or_else(|_| empty_journey(subject_type, &subject_for_fallback, &date_for_fallback));
    // Spec 049 PR10: attach the recurrence block from attacker_profiles
    // for IP subjects. Read directly from SQLite (same blob the
    // Intelligence > Profiles tab uses). Failures fall through to
    // `None` — the drill-down keeps working, the block just hides.
    let response = overlay_recurrence_block(
        response,
        subject_type,
        &subject_for_recurrence,
        sqlite_for_recurrence.as_ref(),
    );
    Json(response)
}

/// Spec 049 PR10 — look up the AttackerProfile for `subject` (when
/// it is an IP) in the SQLite `attacker_profiles` blob, derive the
/// recurrence block via `case_recurrence::recurrence_from_profile`,
/// and attach to the response. No-op for non-IP subjects (user /
/// detector pivots have no single IP to query) and for missing or
/// unreadable profiles — the drill-down keeps working without the
/// block in those cases.
fn overlay_recurrence_block(
    mut response: JourneyResponse,
    subject_type: PivotKind,
    subject: &str,
    sqlite: Option<&std::sync::Arc<innerwarden_store::Store>>,
) -> JourneyResponse {
    if subject_type != PivotKind::Ip {
        return response;
    }
    let Some(store) = sqlite else {
        return response;
    };
    let Ok(Some(blob)) = store.get_blob("attacker_profiles") else {
        return response;
    };
    let Ok(profiles) = serde_json::from_str::<Vec<crate::attacker_intel::AttackerProfile>>(&blob)
    else {
        return response;
    };
    if let Some(profile) = profiles.iter().find(|p| p.ip == subject) {
        response.recurrence = Some(crate::dashboard::case_recurrence::recurrence_from_profile(
            profile,
        ));
    }
    response
}

pub(super) async fn api_export(
    State(state): State<DashboardState>,
    Query(query): Query<ExportQuery>,
) -> Response {
    // Acquires the KG read lock multiple times (overview + pivots +
    // clusters + journey) and serialises a potentially-large snapshot to
    // JSON or markdown — order of tens of milliseconds on a busy host.
    // Run the whole pipeline on the blocking pool so the dashboard's async
    // workers stay responsive (`RECURRING_BUGS.md` "Dashboard handlers
    // block tokio worker threads").
    let kg = std::sync::Arc::clone(&state.knowledge_graph);
    let data_dir = state.data_dir.clone();
    let sqlite = state.sqlite_store.clone();
    let result = tokio::task::spawn_blocking(move || {
        build_export_response(kg, data_dir, sqlite.as_ref(), query)
    })
    .await;
    match result {
        Ok(resp) => resp,
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "export task panicked").into_response(),
    }
}

fn build_export_response(
    kg: std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: std::path::PathBuf,
    sqlite: Option<&std::sync::Arc<innerwarden_store::Store>>,
    query: ExportQuery,
) -> Response {
    let date = resolve_date(query.date.as_deref());
    let format = query
        .format
        .as_deref()
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase();
    let subject_type = PivotKind::parse(query.subject_type.as_deref());
    let subject = query.subject.or(query.ip).map(|s| s.trim().to_string());
    let filters =
        InvestigationFilters::from_query(query.severity_min.as_deref(), query.detector.as_deref());
    let group_by = PivotKind::parse(query.group_by.as_deref());
    let limit = normalize_limit(query.limit);
    let window_seconds = query.window_seconds.unwrap_or(300).clamp(30, 3600);

    let overview = {
        let graph = kg.read().unwrap();
        compute_overview_from_graph(&graph, &data_dir, &date)
    };
    let pivots = build_pivots_from_graph(
        &kg,
        group_by,
        limit,
        &filters,
        explicit_date_filter(query.date.as_deref()),
    );
    let clusters = build_cluster_items_from_graph(&kg, limit, window_seconds);
    let journey = subject.as_ref().filter(|s| !s.is_empty()).map(|s| {
        build_journey_from_graph(
            &kg,
            &data_dir,
            &date,
            subject_type,
            s,
            &filters,
            Some(window_seconds),
            sqlite,
        )
    });

    let snapshot = InvestigationExport {
        generated_at: Utc::now(),
        date: date.clone(),
        filters: serde_json::json!({
            "date": date,
            "severity_min": query.severity_min,
            "detector": query.detector,
            "group_by": group_by.as_str(),
            "window_seconds": window_seconds,
            "limit": limit,
        }),
        group_by: group_by.as_str().to_string(),
        subject_type: subject.as_ref().map(|_| subject_type.as_str().to_string()),
        subject,
        overview,
        pivots,
        clusters,
        journey,
    };

    if format == "md" || format == "markdown" {
        let markdown = render_markdown_snapshot(&snapshot);
        return (
            [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
            markdown,
        )
            .into_response();
    }

    match serde_json::to_string_pretty(&snapshot) {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize export snapshot",
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Business logic - D2 entities / journey
// ---------------------------------------------------------------------------

/// 2026-04-29: extracted from `build_pivots_from_graph` so
/// `compute_clusters_blocking` can apply the same filter stack.
/// Returns the list of Incident node ids that qualify under the
/// shared filter (date, research_only, internal/self-traffic,
/// severity, detector substring).
///
/// Pre-extraction `/api/clusters` re-implemented incident iteration
/// without the filter stack, which meant clusters could include
/// incidents that the IP/User/Detector pivots had rejected. The
/// audit (RC-3) flagged this as the most concrete cross-endpoint
/// drift the operator could see in one session.
pub(super) fn qualifying_incident_ids(
    graph: &crate::knowledge_graph::KnowledgeGraph,
    date_filter: Option<chrono::NaiveDate>,
    sev_min_rank: u8,
    detector_substring: Option<&str>,
) -> Vec<crate::knowledge_graph::types::NodeId> {
    use crate::knowledge_graph::types::*;
    graph
        .nodes_of_type(NodeType::Incident)
        .into_iter()
        .filter(|&inc_id| {
            let Some(Node::Incident {
                research_only,
                detector,
                title,
                severity,
                ts,
                ..
            }) = graph.get_node(inc_id)
            else {
                return false;
            };
            if let Some(target) = date_filter {
                if ts.naive_utc().date() != target {
                    return false;
                }
            }
            if *research_only {
                return false;
            }
            let has_external_ip = graph
                .outgoing_edges(inc_id)
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
            let internal = crate::dashboard::live_feed::is_internal_incident_fields(
                detector,
                title,
                has_external_ip,
            );
            if internal {
                return false;
            }
            if sev_min_rank > 0 && severity_rank(severity) < sev_min_rank {
                return false;
            }
            if let Some(needle) = detector_substring {
                if !detector.to_ascii_lowercase().contains(needle) {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Build the attacker list for a given date.
/// Only IPs that appear in at least one incident are included.
/// Build pivot items from the knowledge graph (live, no JSONL).
pub(super) fn build_pivots_from_graph(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    group_by: PivotKind,
    limit: usize,
    filters: &InvestigationFilters,
    date: Option<&str>,
) -> Vec<PivotItem> {
    use crate::knowledge_graph::types::*;
    let graph = kg.read().unwrap();
    let sev_min_rank = filters.severity_min_rank();
    let detector_substring = filters.detector_lower();

    // Spec 037 Threats UX hotfix: `date` is an OPTIONAL filter.
    //   * `None` -> no temporal filter; all qualifying incidents in the
    //     graph appear (default load behaviour the operator expects).
    //   * `Some("YYYY-MM-DD")` -> filter Incident nodes whose UTC date
    //     equals the parsed value.
    //   * `Some(garbage)` collapses to no filter so a malformed UI
    //     query never spuriously empties the page.
    let date_filter: Option<chrono::NaiveDate> =
        date.and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());

    let node_type = match group_by {
        PivotKind::Ip => NodeType::Ip,
        PivotKind::User => NodeType::User,
        PivotKind::Detector => NodeType::Incident, // group by detector
    };

    // Identify the host's own IPs to exclude from attacker pivots
    // Exclude ALL internal IPs from attacker pivots — they're the server, not attackers.
    let internal_ips: std::collections::HashSet<String> = graph
        .nodes_of_type(NodeType::Ip)
        .iter()
        .filter_map(|&id| {
            if let Some(crate::knowledge_graph::types::Node::Ip {
                addr,
                is_internal: true,
                ..
            }) = graph.get_node(id)
            {
                Some(addr.clone())
            } else {
                None
            }
        })
        .collect();

    // Spec 037 Threats data contract: single pass to identify the
    // qualifying incidents under the same filter for ALL pivots
    // (date scope + research_only + internal/self-traffic + severity
    // + detector substring). The Detector pivot used to skip every
    // filter except node-type and ended up returning incidents the
    // IP/User pivots had rejected -- "click Detector see X, click
    // IP see 0" was the operator-reported contradiction.
    let qualifying_incidents: Vec<NodeId> =
        qualifying_incident_ids(&graph, date_filter, sev_min_rank, detector_substring);

    if group_by == PivotKind::Detector {
        // Spec 037 Threats data contract: Detector pivot now uses the
        // same `qualifying_incidents` slice as IP/User. Outcome derives
        // from the same decision-field logic (was hardcoded "active").
        let mut by_det: std::collections::HashMap<String, Vec<NodeId>> =
            std::collections::HashMap::new();
        for &inc_id in &qualifying_incidents {
            if let Some(Node::Incident { detector, .. }) = graph.get_node(inc_id) {
                by_det.entry(detector.clone()).or_default().push(inc_id);
            }
        }
        let mut items: Vec<PivotItem> = by_det
            .into_iter()
            .map(|(det, inc_ids)| {
                let mut first: Option<chrono::DateTime<chrono::Utc>> = None;
                let mut last: Option<chrono::DateTime<chrono::Utc>> = None;
                let mut max_sev = "low".to_string();
                // 2026-04-29: outcome string aggregation moved to
                // `threat_contract::aggregate_outcomes` so the
                // Detector pivot agrees with IP/User pivots and with
                // `/api/incidents.outcome`. Pre-fix the keeper
                // pattern on `ignore` and the `_ => "resolved"`
                // fallback diverged from every other site.
                let mut individual_outcomes: Vec<&'static str> = Vec::with_capacity(inc_ids.len());
                for &iid in &inc_ids {
                    if let Some(Node::Incident {
                        ts,
                        severity,
                        decision,
                        ..
                    }) = graph.get_node(iid)
                    {
                        first = Some(first.map_or(*ts, |f| f.min(*ts)));
                        last = Some(last.map_or(*ts, |l| l.max(*ts)));
                        if severity_rank(severity) > severity_rank(&max_sev) {
                            max_sev = severity.to_lowercase();
                        }
                        individual_outcomes.push(threat_contract::classify_decision(
                            decision.as_deref(),
                            None,
                        ));
                    }
                }
                let outcome = threat_contract::aggregate_outcomes(&individual_outcomes).to_string();
                PivotItem {
                    group_by: "detector".to_string(),
                    value: det.clone(),
                    first_seen: first.unwrap_or_else(chrono::Utc::now),
                    last_seen: last.unwrap_or_else(chrono::Utc::now),
                    max_severity: max_sev,
                    incident_count: inc_ids.len(),
                    event_count: 0,
                    outcome,
                    detectors: vec![det],
                }
            })
            .collect();
        items.sort_by(|a, b| {
            b.incident_count
                .cmp(&a.incident_count)
                .then(b.last_seen.cmp(&a.last_seen))
        });
        items.truncate(limit);
        return items;
    }

    // Group by IP or User: find which have TriggeredBy edges from incidents.
    let mut pivot_data: std::collections::HashMap<NodeId, (String, Vec<NodeId>)> =
        std::collections::HashMap::new();

    for &inc_id in &qualifying_incidents {
        for edge in graph.outgoing_edges(inc_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            if let Some(node) = graph.get_node(edge.to) {
                if node.node_type() == node_type {
                    let label = node.label();
                    // Skip internal IPs — they're the server, not the attacker
                    if node_type == NodeType::Ip && internal_ips.contains(&label) {
                        continue;
                    }
                    // Skip self-traffic IPs (cloud providers, agent
                    // service endpoints, local interfaces) — these are
                    // infrastructure, not attackers.
                    if node_type == NodeType::Ip
                        && crate::cloud_safelist::is_self_traffic_ip(&label)
                    {
                        continue;
                    }
                    // RC-2 follow-up (2026-04-30): drop the "unknown"
                    // placeholder on the User pivot for the same reason
                    // as build_pivots_from_sqlite — it is the literal
                    // string used when a detector cannot resolve a real
                    // account, and surfacing it as a user account
                    // pollutes the pivot.
                    if node_type == NodeType::User && label.eq_ignore_ascii_case("unknown") {
                        continue;
                    }
                    pivot_data
                        .entry(edge.to)
                        .or_insert_with(|| (label, Vec::new()))
                        .1
                        .push(inc_id);
                }
            }
        }
    }

    let mut items: Vec<PivotItem> = pivot_data
        .into_iter()
        .map(|(node_id, (label, inc_ids))| {
            let edges = graph.all_edges(node_id);
            let first = edges.first().map(|e| e.ts);
            let last = edges.last().map(|e| e.ts);

            let mut detectors = std::collections::HashSet::new();
            let mut max_sev = "low".to_string();
            // 2026-04-29: same `aggregate_outcomes` path as the
            // Detector branch above. The pre-fix keeper pattern on
            // `ignore` survived from the very first pivot
            // implementation and silently masked drift between
            // pivots and the journey endpoint.
            let mut individual_outcomes: Vec<&'static str> = Vec::with_capacity(inc_ids.len());

            for &iid in &inc_ids {
                if let Some(Node::Incident {
                    detector,
                    severity,
                    decision,
                    ..
                }) = graph.get_node(iid)
                {
                    detectors.insert(detector.clone());
                    if severity_rank(severity) > severity_rank(&max_sev) {
                        max_sev = severity.to_lowercase();
                    }
                    individual_outcomes.push(threat_contract::classify_decision(
                        decision.as_deref(),
                        None,
                    ));
                }
            }
            let outcome = threat_contract::aggregate_outcomes(&individual_outcomes).to_string();

            PivotItem {
                group_by: group_by.as_str().to_string(),
                value: label,
                first_seen: first.unwrap_or_else(chrono::Utc::now),
                last_seen: last.unwrap_or_else(chrono::Utc::now),
                max_severity: max_sev,
                incident_count: inc_ids.len(),
                event_count: edges.len(),
                outcome,
                detectors: detectors.into_iter().collect(),
            }
        })
        .collect();

    items.sort_by(|a, b| {
        b.incident_count
            .cmp(&a.incident_count)
            .then(b.last_seen.cmp(&a.last_seen))
    });
    items.truncate(limit);
    items
}

pub(super) fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// Phase 6 (audit RC-2 second surface): build the IP-pivot attacker list
/// from the durable SQLite store, not the lossy in-memory KG.
///
/// The KG's TTL eviction culls nodes after ~12h. Today's earlier
/// attackers vanish from the KG by the afternoon, even though their
/// incidents and decisions are still in SQLite. The operator's
/// Threats list ended up showing 1 IP when 110 had actually fired
/// during the day -- 99% drift. This SQL path reads the canonical
/// store, applies the same canonical filters as `/api/overview`
/// (Phase 5), and aggregates by IP exactly the way the prior
/// graph-pivot path did.
///
/// Returns `None` if the SQL read fails (caller should fall back to
/// graph path). Returns `Some(empty vec)` when SQLite is reachable
/// but no qualifying incidents exist for `date` -- that is a real
/// answer, not a fallback signal.
/// Phase 12 (QA fix #3, 2026-04-29): SQLite-backed pivot builder
/// for User and Detector groupings (IP grouping uses
/// `build_attackers_from_sqlite` and is converted via the wrapper
/// below). Mirrors the filter stack of the IP-pivot path so all
/// three pivots agree on which incidents qualify.
///
/// Returns `None` if the SQL read fails — caller falls back to the
/// graph-based path.
pub(super) fn build_pivots_from_sqlite(
    store: &std::sync::Arc<innerwarden_store::Store>,
    date: &str,
    group_by: PivotKind,
    filters: &InvestigationFilters,
    limit: usize,
) -> Option<Vec<PivotItem>> {
    use crate::dashboard::threat_contract;

    // For IP pivot, reuse the existing function and project to PivotItem.
    if group_by == PivotKind::Ip {
        let attackers = build_attackers_from_sqlite(store, date, filters, limit)?;
        return Some(
            attackers
                .into_iter()
                .map(|a| PivotItem {
                    group_by: "ip".to_string(),
                    value: a.ip,
                    first_seen: a.first_seen,
                    last_seen: a.last_seen,
                    max_severity: a.max_severity,
                    incident_count: a.incident_count,
                    event_count: a.event_count,
                    outcome: a.outcome,
                    detectors: a.detectors,
                })
                .collect(),
        );
    }

    // User and Detector branches: walk SQLite incidents+latest decision,
    // group by the appropriate value.
    #[derive(Default)]
    struct Acc {
        first_seen: Option<chrono::DateTime<Utc>>,
        last_seen: Option<chrono::DateTime<Utc>>,
        max_severity_rank: u8,
        max_severity_str: String,
        detectors: BTreeSet<String>,
        incident_outcomes: Vec<&'static str>,
        incident_count: usize,
        any_allowlisted: bool,
    }
    let conn = store.conn().ok()?;
    let pattern = format!("{date}%");
    let mut stmt = conn
        .prepare_cached(
            "SELECT i.incident_id, i.ts, i.detector, i.severity, i.title, i.data, \
                    i.is_allowlisted, d.action_type \
             FROM incidents i \
             LEFT JOIN ( \
                 SELECT incident_id, action_type, \
                        ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY id DESC) AS rn \
                 FROM decisions \
             ) d ON d.incident_id = i.incident_id AND d.rn = 1 \
             WHERE i.ts LIKE ?1",
        )
        .ok()?;
    let rows = stmt
        .query_map([&pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })
        .ok()?;
    let mut grouped: std::collections::HashMap<String, Acc> = std::collections::HashMap::new();
    for row in rows {
        let Ok((_iid, ts_iso, detector, severity, title, data, allow_flag, action_type)) = row
        else {
            continue;
        };
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if parsed
            .get("research_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        // Pull external IPs to feed is_internal_incident_fields. Same
        // semantic as the IP-pivot path: IP must be external for the
        // incident to be operator-relevant.
        let external_ip_present = parsed
            .get("entities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().any(|e| {
                    let is_ip = e
                        .get("type")
                        .and_then(|t| t.as_str())
                        .map(|t| t.eq_ignore_ascii_case("ip"))
                        .unwrap_or(false);
                    if !is_ip {
                        return false;
                    }
                    let value = e.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    !value.is_empty() && !crate::incident_auto_rules::is_internal_ip_pub(value)
                })
            })
            .unwrap_or(false);
        if crate::dashboard::live_feed::is_internal_incident_fields(
            &detector,
            &title,
            external_ip_present,
        ) {
            continue;
        }
        // Severity + detector operator filters.
        let min_rank = filters.severity_min_rank();
        if min_rank > 0 && severity_rank(&severity) < min_rank {
            continue;
        }
        if let Some(needle) = filters.detector_lower() {
            if !detector.to_ascii_lowercase().contains(needle) {
                continue;
            }
        }
        let ts: chrono::DateTime<Utc> = match chrono::DateTime::parse_from_rfc3339(&ts_iso) {
            Ok(t) => t.with_timezone(&Utc),
            Err(_) => continue,
        };
        let sev_rank = severity_rank(&severity);
        let outcome = threat_contract::classify_decision(action_type.as_deref(), Some("ok"));
        let detector_label = detector.split(':').next().unwrap_or(&detector).to_string();

        // Extract group keys per pivot kind.
        let keys: Vec<String> = match group_by {
            PivotKind::User => parsed
                .get("entities")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| {
                            let is_user = e
                                .get("type")
                                .and_then(|t| t.as_str())
                                .map(|t| t.eq_ignore_ascii_case("user"))
                                .unwrap_or(false);
                            if !is_user {
                                return None;
                            }
                            let value = e.get("value").and_then(|v| v.as_str())?;
                            // RC-2 follow-up (2026-04-30): drop the
                            // "unknown" placeholder. Some legacy
                            // detector paths (and a still-deploying
                            // execution_guard fix) emit User entities
                            // with value="unknown" when they cannot
                            // resolve a real account. Treating the
                            // placeholder as a user produced a
                            // dominant bogus bucket on the pivot.
                            // Defense-in-depth alongside the source
                            // fix in execution_guard.rs.
                            if value.is_empty() || value.eq_ignore_ascii_case("unknown") {
                                return None;
                            }
                            Some(value.to_string())
                        })
                        .collect()
                })
                .unwrap_or_default(),
            PivotKind::Detector => vec![detector_label.clone()],
            PivotKind::Ip => unreachable!("IP pivot handled above"),
        };
        if keys.is_empty() {
            continue;
        }
        for key in keys {
            let entry = grouped.entry(key).or_default();
            entry.incident_count += 1;
            entry.detectors.insert(detector_label.clone());
            entry.incident_outcomes.push(outcome);
            if allow_flag != 0 {
                entry.any_allowlisted = true;
            }
            match entry.first_seen {
                Some(prev) if prev <= ts => {}
                _ => entry.first_seen = Some(ts),
            }
            match entry.last_seen {
                Some(prev) if prev >= ts => {}
                _ => entry.last_seen = Some(ts),
            }
            if sev_rank > entry.max_severity_rank {
                entry.max_severity_rank = sev_rank;
                entry.max_severity_str = severity.to_lowercase();
            }
        }
    }
    let now = Utc::now();
    let group_label = group_by.as_str().to_string();
    let mut items: Vec<PivotItem> = grouped
        .into_iter()
        .map(|(value, acc)| {
            let aggregate = if acc.any_allowlisted {
                "allowlisted"
            } else {
                threat_contract::aggregate_outcomes(acc.incident_outcomes)
            };
            PivotItem {
                group_by: group_label.clone(),
                value,
                first_seen: acc.first_seen.unwrap_or(now),
                last_seen: acc.last_seen.unwrap_or(now),
                max_severity: if acc.max_severity_str.is_empty() {
                    "info".to_string()
                } else {
                    acc.max_severity_str
                },
                incident_count: acc.incident_count,
                event_count: 0,
                outcome: aggregate.to_string(),
                detectors: acc.detectors.into_iter().collect(),
            }
        })
        .collect();
    items.sort_by(|a, b| {
        b.incident_count
            .cmp(&a.incident_count)
            .then(b.last_seen.cmp(&a.last_seen))
    });
    items.truncate(limit);
    Some(items)
}

pub(super) fn build_attackers_from_sqlite(
    store: &std::sync::Arc<innerwarden_store::Store>,
    date: &str,
    filters: &InvestigationFilters,
    limit: usize,
) -> Option<Vec<AttackerSummary>> {
    use crate::dashboard::threat_contract;

    #[derive(Default)]
    struct Acc {
        first_seen: Option<chrono::DateTime<Utc>>,
        last_seen: Option<chrono::DateTime<Utc>>,
        max_severity_rank: u8,
        max_severity_str: String,
        detectors: BTreeSet<String>,
        incident_outcomes: Vec<&'static str>,
        incident_count: usize,
        // Phase 7: when ANY incident on this IP was allowlisted, the
        // aggregate outcome is "allowlisted" (precedence-overrides
        // even blocked, because the operator's trust rule explicitly
        // silenced them). The dashboard renders allowlisted attackers
        // in their own group so the operator can audit silenced trust.
        any_allowlisted: bool,
    }
    let conn = store.conn().ok()?;
    let pattern = format!("{date}%");
    let mut stmt = conn
        .prepare_cached(
            "SELECT i.incident_id, i.ts, i.detector, i.severity, i.title, i.data, \
                    i.is_allowlisted, d.action_type \
             FROM incidents i \
             LEFT JOIN ( \
                 SELECT incident_id, action_type, \
                        ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY id DESC) AS rn \
                 FROM decisions \
             ) d ON d.incident_id = i.incident_id AND d.rn = 1 \
             WHERE i.ts LIKE ?1",
        )
        .ok()?;
    let rows = stmt
        .query_map([&pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,         // incident_id
                row.get::<_, String>(1)?,         // ts iso
                row.get::<_, String>(2)?,         // detector
                row.get::<_, String>(3)?,         // severity
                row.get::<_, String>(4)?,         // title
                row.get::<_, String>(5)?,         // data (JSON)
                row.get::<_, i64>(6)?,            // is_allowlisted (0/1)
                row.get::<_, Option<String>>(7)?, // action_type
            ))
        })
        .ok()?;
    let mut by_ip: std::collections::HashMap<String, Acc> = std::collections::HashMap::new();
    for row in rows {
        let Ok((_iid, ts_iso, detector, severity, title, data, is_allowlisted_flag, action_type)) =
            row
        else {
            continue;
        };
        let is_allowlisted = is_allowlisted_flag != 0;
        // Parse JSON to extract IPs + research_only.
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if parsed
            .get("research_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        // External IPs only (RFC 1918 / loopback excluded).
        let ips: Vec<String> = parsed
            .get("entities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let is_ip = e
                            .get("type")
                            .and_then(|t| t.as_str())
                            .map(|t| t.eq_ignore_ascii_case("ip"))
                            .unwrap_or(false);
                        if !is_ip {
                            return None;
                        }
                        let value = e.get("value").and_then(|v| v.as_str())?;
                        if value.is_empty() || crate::incident_auto_rules::is_internal_ip_pub(value)
                        {
                            return None;
                        }
                        Some(value.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        if ips.is_empty() {
            continue;
        }
        // Same is_internal_incident_fields filter the live feed and
        // /api/overview use, so the Threats list aggregates over
        // exactly the same incidents the Home tile counts.
        let has_external_ip = !ips.is_empty();
        if crate::dashboard::live_feed::is_internal_incident_fields(
            &detector,
            &title,
            has_external_ip,
        ) {
            continue;
        }
        // Operator severity_min filter.
        let min_rank = filters.severity_min_rank();
        if min_rank > 0 && severity_rank(&severity) < min_rank {
            continue;
        }
        // Operator detector substring filter (already lowercased by from_query).
        if let Some(needle) = filters.detector_lower() {
            if !detector.to_ascii_lowercase().contains(needle) {
                continue;
            }
        }
        let ts: chrono::DateTime<Utc> = match chrono::DateTime::parse_from_rfc3339(&ts_iso) {
            Ok(t) => t.with_timezone(&Utc),
            Err(_) => continue,
        };
        let sev_rank = severity_rank(&severity);
        let outcome = threat_contract::classify_decision(action_type.as_deref(), Some("ok"));
        // Detector display label: strip the suffix after the first
        // colon so "ssh_bruteforce:178.105.x" displays as
        // "ssh_bruteforce" -- matches the existing graph pivot
        // detector aggregation.
        let detector_label = detector.split(':').next().unwrap_or(&detector).to_string();
        for ip in ips {
            let entry = by_ip.entry(ip).or_default();
            entry.incident_count += 1;
            entry.detectors.insert(detector_label.clone());
            entry.incident_outcomes.push(outcome);
            if is_allowlisted {
                entry.any_allowlisted = true;
            }
            match entry.first_seen {
                Some(prev) if prev <= ts => {}
                _ => entry.first_seen = Some(ts),
            }
            match entry.last_seen {
                Some(prev) if prev >= ts => {}
                _ => entry.last_seen = Some(ts),
            }
            if sev_rank > entry.max_severity_rank {
                entry.max_severity_rank = sev_rank;
                entry.max_severity_str = severity.to_lowercase();
            }
        }
    }
    let now = Utc::now();
    let mut summaries: Vec<AttackerSummary> = by_ip
        .into_iter()
        .map(|(ip, acc)| {
            // Phase 7: when the operator's trust rule silenced this
            // IP on at least one of today's incidents, surface it as
            // outcome="allowlisted". This overrides the per-incident
            // aggregate because the operator's intent was clear and
            // we want the audit-friendly group on the Threats list.
            // The rest of the metadata (first_seen, max_severity,
            // detectors) still reflects what *would* have fired,
            // so the operator can audit what their trust silenced.
            let aggregate = if acc.any_allowlisted {
                "allowlisted"
            } else {
                threat_contract::aggregate_outcomes(acc.incident_outcomes)
            };
            AttackerSummary {
                block_state: Some(threat_contract::block_state_for_ip(Some(store), &ip, now)),
                ip,
                first_seen: acc.first_seen.unwrap_or(now),
                last_seen: acc.last_seen.unwrap_or(now),
                max_severity: if acc.max_severity_str.is_empty() {
                    "info".to_string()
                } else {
                    acc.max_severity_str
                },
                detectors: acc.detectors.into_iter().collect(),
                outcome: aggregate.to_string(),
                incident_count: acc.incident_count,
                event_count: 0,
            }
        })
        .collect();
    // Same sort order the graph path used: most incidents first, then
    // most recent.
    summaries.sort_by(|a, b| {
        b.incident_count
            .cmp(&a.incident_count)
            .then(b.last_seen.cmp(&a.last_seen))
    });
    summaries.truncate(limit);
    Some(summaries)
}

pub(super) fn build_attackers_from_graph(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    limit: usize,
    filters: &InvestigationFilters,
    date: Option<&str>,
    sqlite: Option<&std::sync::Arc<innerwarden_store::Store>>,
) -> Vec<AttackerSummary> {
    let now = Utc::now();
    build_pivots_from_graph(kg, PivotKind::Ip, limit, filters, date)
        .into_iter()
        .map(|p| AttackerSummary {
            block_state: sqlite.map(|_| {
                crate::dashboard::threat_contract::block_state_for_ip(sqlite, &p.value, now)
            }),
            ip: p.value,
            first_seen: p.first_seen,
            last_seen: p.last_seen,
            max_severity: p.max_severity,
            detectors: p.detectors,
            outcome: p.outcome,
            incident_count: p.incident_count,
            event_count: p.event_count,
        })
        .collect()
}

#[cfg(test)]
pub(super) fn build_attackers(
    data_dir: &Path,
    date: &str,
    filters: &InvestigationFilters,
    limit: usize,
) -> Vec<AttackerSummary> {
    build_pivots(data_dir, date, PivotKind::Ip, filters, limit)
        .into_iter()
        .map(|p| AttackerSummary {
            ip: p.value,
            first_seen: p.first_seen,
            last_seen: p.last_seen,
            max_severity: p.max_severity,
            detectors: p.detectors,
            outcome: p.outcome,
            incident_count: p.incident_count,
            event_count: p.event_count,
            block_state: None,
        })
        .collect()
}

#[cfg(test)]
pub(super) fn build_pivots(
    data_dir: &Path,
    date: &str,
    group_by: PivotKind,
    filters: &InvestigationFilters,
    limit: usize,
) -> Vec<PivotItem> {
    let events =
        read_jsonl::<innerwarden_core::event::Event>(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut grouped: BTreeMap<String, IpAccumulator> = BTreeMap::new();

    for incident in &incidents {
        if !incident_matches_filters(incident, filters) {
            continue;
        }

        let detector = incident_detector(&incident.incident_id).to_string();
        let sev_str = format!("{:?}", incident.severity).to_lowercase();
        let sev_ord = severity_order(&sev_str);
        let incident_ips = extract_entity_values(&incident.entities, EntityType::Ip);

        for key in incident_group_values(incident, group_by) {
            let entry = grouped.entry(key.clone()).or_default();
            entry.update_time(incident.ts);
            entry.incident_count += 1;
            if sev_ord > entry.max_severity {
                entry.max_severity = sev_ord;
                entry.max_severity_str = sev_str.clone();
            }
            entry.detectors.insert(detector.clone());
            for ip in &incident_ips {
                entry.ips.insert(ip.clone());
            }
            if group_by == PivotKind::Ip {
                entry.ips.insert(key);
            }
        }
    }

    for event in &events {
        if !event_matches_filters(event, filters) {
            continue;
        }

        for key in event_group_values(event, group_by) {
            if let Some(entry) = grouped.get_mut(&key) {
                entry.event_count += 1;
                entry.update_time(event.ts);
                for ip in extract_ip_entities(&event.entities) {
                    entry.ips.insert(ip);
                }
            }
        }
    }

    let mut items: Vec<PivotItem> = grouped
        .into_iter()
        .map(|(value, acc)| {
            let outcome = if group_by == PivotKind::Ip {
                determine_outcome(&decisions, &value, acc.incident_count > 0)
            } else {
                determine_outcome_for_ips(&decisions, &acc.ips, acc.incident_count > 0)
            };

            PivotItem {
                group_by: group_by.as_str().to_string(),
                value,
                first_seen: acc.first_seen.unwrap_or_else(Utc::now),
                last_seen: acc.last_seen.unwrap_or_else(Utc::now),
                max_severity: acc.max_severity_str,
                incident_count: acc.incident_count,
                event_count: acc.event_count,
                outcome,
                detectors: acc.detectors.into_iter().collect(),
            }
        })
        .collect();

    items.sort_by(|a, b| {
        severity_order(&b.max_severity)
            .cmp(&severity_order(&a.max_severity))
            .then(b.incident_count.cmp(&a.incident_count))
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.value.cmp(&b.value))
    });
    items.truncate(limit);
    items
}

#[cfg(test)]
pub(super) fn build_cluster_items(
    data_dir: &Path,
    date: &str,
    filters: &InvestigationFilters,
    limit: usize,
    window_seconds: u64,
) -> Vec<ClusterItem> {
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));

    let filtered: Vec<innerwarden_core::incident::Incident> = incidents
        .into_iter()
        .filter(|incident| incident_matches_filters(incident, filters))
        .collect();
    if filtered.is_empty() {
        return Vec::new();
    }

    let mut clusters = build_clusters(&filtered, window_seconds);
    clusters.truncate(limit);

    clusters
        .into_iter()
        .enumerate()
        .map(|(idx, cluster)| {
            let (pivot_type, pivot_value) = parse_cluster_pivot(&cluster.pivot);
            let incident_count = cluster.incident_ids.len();
            ClusterItem {
                cluster_id: format!("cluster-{:03}", idx + 1),
                pivot: cluster.pivot,
                pivot_type,
                pivot_value,
                start_ts: cluster.start_ts,
                end_ts: cluster.end_ts,
                incident_count,
                detector_kinds: cluster.detector_kinds,
                incident_ids: cluster.incident_ids,
            }
        })
        .collect()
}

/// Build cluster items from the knowledge graph (no JSONL reads). Phase 6A.
pub(super) fn build_cluster_items_from_graph(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    limit: usize,
    window_seconds: u64,
) -> Vec<ClusterItem> {
    use crate::knowledge_graph::types::*;

    let graph = kg.read().unwrap();

    // Resolve hostname from System node (used for Incident.host)
    let hostname = graph
        .system_node
        .and_then(|id| graph.get_node(id))
        .map(|n| n.label())
        .unwrap_or_default();

    // Extract lightweight incidents from graph for clustering
    let mut incidents: Vec<innerwarden_core::incident::Incident> = Vec::new();
    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            incident_id,
            severity,
            title,
            summary,
            ts,
            mitre_ids,
            ..
        }) = graph.get_node(id)
        {
            // Collect entities from TriggeredBy edges (all types)
            let entities: Vec<innerwarden_core::entities::EntityRef> = graph
                .outgoing_edges(id)
                .iter()
                .filter(|e| e.relation == Relation::TriggeredBy)
                .filter_map(|e| {
                    graph.get_node(e.to).map(|n| match n {
                        Node::Ip { addr, .. } => innerwarden_core::entities::EntityRef {
                            r#type: innerwarden_core::entities::EntityType::Ip,
                            value: addr.clone(),
                        },
                        Node::User { name, .. } => innerwarden_core::entities::EntityRef {
                            r#type: innerwarden_core::entities::EntityType::User,
                            value: name.clone(),
                        },
                        Node::Container {
                            container_id, name, ..
                        } => innerwarden_core::entities::EntityRef {
                            r#type: innerwarden_core::entities::EntityType::Container,
                            value: name.as_deref().unwrap_or(container_id).to_string(),
                        },
                        Node::File { path, .. } => innerwarden_core::entities::EntityRef {
                            r#type: innerwarden_core::entities::EntityType::Path,
                            value: path.clone(),
                        },
                        Node::Process { comm, pid, .. } => innerwarden_core::entities::EntityRef {
                            r#type: innerwarden_core::entities::EntityType::Service,
                            value: format!("{comm}({pid})"),
                        },
                        // Domain/Port/Device/System/Incident/Campaign: not entity types
                        _ => innerwarden_core::entities::EntityRef {
                            r#type: innerwarden_core::entities::EntityType::Service,
                            value: n.label(),
                        },
                    })
                })
                .collect();

            let sev = match severity.to_lowercase().as_str() {
                "critical" => innerwarden_core::event::Severity::Critical,
                "high" => innerwarden_core::event::Severity::High,
                "medium" => innerwarden_core::event::Severity::Medium,
                "low" => innerwarden_core::event::Severity::Low,
                _ => innerwarden_core::event::Severity::Info,
            };

            incidents.push(innerwarden_core::incident::Incident {
                incident_id: incident_id.clone(),
                ts: *ts,
                severity: sev,
                title: title.clone(),
                summary: summary.clone(),
                entities,
                tags: mitre_ids.clone(),
                recommended_checks: Vec::new(),
                evidence: serde_json::Value::Null,
                host: hostname.clone(),
            });
        }
    }

    drop(graph);

    if incidents.is_empty() {
        return Vec::new();
    }

    let mut clusters = crate::correlation::build_clusters(&incidents, window_seconds);
    clusters.truncate(limit);

    clusters
        .into_iter()
        .enumerate()
        .map(|(idx, cluster)| {
            let (pivot_type, pivot_value) = parse_cluster_pivot(&cluster.pivot);
            let incident_count = cluster.incident_ids.len();
            ClusterItem {
                cluster_id: format!("cluster-{:03}", idx + 1),
                pivot: cluster.pivot,
                pivot_type,
                pivot_value,
                start_ts: cluster.start_ts,
                end_ts: cluster.end_ts,
                incident_count,
                detector_kinds: cluster.detector_kinds,
                incident_ids: cluster.incident_ids,
            }
        })
        .collect()
}

/// Phase 8 (audit RC-2 / 2026-04-29 fourth surface): build a per-IP
/// or per-user journey timeline directly from SQLite. Used as the
/// fallback path inside `build_journey_from_graph` when the KG misses
/// (TTL eviction, post-deploy state, historical date).
///
/// The function joins `incidents` with the latest decision per
/// `incident_id`, then for each row whose `entities` contain the
/// requested IP/user, emits a `JourneyEntry` for the incident itself
/// and (when present) a separate `JourneyEntry` for the decision.
/// Sorting and verdict derivation match the KG path so the front-end
/// renders the same structure regardless of which path produced it.
///
/// Returns `None` only when the SQLite read fails or no qualifying
/// incidents exist — caller turns that into `empty_journey`.
pub(super) fn build_journey_from_sqlite(
    store: &std::sync::Arc<innerwarden_store::Store>,
    date: &str,
    subject_type: PivotKind,
    subject: &str,
    window_seconds: Option<u64>,
) -> Option<JourneyResponse> {
    use crate::dashboard::threat_contract;

    let conn = store.conn().ok()?;
    let pattern = format!("{date}%");
    // PR #423 Wave 4c: select `d.data` so we can parse the real
    // `execution_result` from the decision JSON. The decisions table
    // doesn't have a dedicated column for it (audit-trail invariant
    // is hash-chained JSON), so we read the blob and pull the field
    // out per-row. Cost: one extra column over the wire per incident
    // joined with a decision; cheap relative to the network round trip.
    let mut stmt = conn
        .prepare_cached(
            "SELECT i.incident_id, i.ts, i.detector, i.severity, i.title, i.summary, i.data, \
                    d.action_type, d.target_ip, d.confidence, d.auto_executed, d.reason, d.data \
             FROM incidents i \
             LEFT JOIN ( \
                 SELECT incident_id, action_type, target_ip, confidence, auto_executed, reason, data, \
                        ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY id DESC) AS rn \
                 FROM decisions \
             ) d ON d.incident_id = i.incident_id AND d.rn = 1 \
             WHERE i.ts LIKE ?1",
        )
        .ok()?;
    let rows = stmt
        .query_map([&pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,          // incident_id
                row.get::<_, String>(1)?,          // ts iso
                row.get::<_, String>(2)?,          // detector
                row.get::<_, String>(3)?,          // severity
                row.get::<_, String>(4)?,          // title
                row.get::<_, Option<String>>(5)?,  // summary
                row.get::<_, String>(6)?,          // data JSON
                row.get::<_, Option<String>>(7)?,  // action_type
                row.get::<_, Option<String>>(8)?,  // target_ip
                row.get::<_, Option<f64>>(9)?,     // confidence
                row.get::<_, Option<i64>>(10)?,    // auto_executed
                row.get::<_, Option<String>>(11)?, // reason
                row.get::<_, Option<String>>(12)?, // d.data JSON (may be NULL when no decision)
            ))
        })
        .ok()?;

    let mut entries: Vec<JourneyEntry> = Vec::new();
    let mut related_ips: BTreeSet<String> = BTreeSet::new();
    let mut related_users: BTreeSet<String> = BTreeSet::new();
    let mut related_detectors: BTreeSet<String> = BTreeSet::new();
    let mut incident_outcomes: Vec<&'static str> = Vec::new();

    for row in rows {
        let Ok((
            incident_id,
            ts_iso,
            detector,
            severity,
            title,
            summary,
            data,
            action_type,
            target_ip,
            confidence,
            auto_executed,
            reason,
            decision_data,
        )) = row
        else {
            continue;
        };
        let parsed: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if parsed
            .get("research_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }

        // Filter to entries that mention the subject in their entities array.
        let mut subject_match = false;
        let entities = parsed.get("entities").and_then(|v| v.as_array());
        let mut row_ips: BTreeSet<String> = BTreeSet::new();
        let mut row_users: BTreeSet<String> = BTreeSet::new();
        if let Some(arr) = entities {
            for entity in arr {
                let kind = entity.get("type").and_then(|t| t.as_str()).unwrap_or("");
                let value = entity.get("value").and_then(|v| v.as_str()).unwrap_or("");
                if value.is_empty() {
                    continue;
                }
                if kind.eq_ignore_ascii_case("ip") {
                    row_ips.insert(value.to_string());
                    if subject_type == PivotKind::Ip && value == subject {
                        subject_match = true;
                    }
                } else if kind.eq_ignore_ascii_case("user") {
                    row_users.insert(value.to_string());
                    if subject_type == PivotKind::User && value == subject {
                        subject_match = true;
                    }
                }
            }
        }
        if !subject_match {
            continue;
        }

        let ts: chrono::DateTime<Utc> = match chrono::DateTime::parse_from_rfc3339(&ts_iso) {
            Ok(t) => t.with_timezone(&Utc),
            Err(_) => continue,
        };
        let detector_label = detector.split(':').next().unwrap_or(&detector).to_string();
        related_detectors.insert(detector_label.clone());
        for ip in &row_ips {
            if subject_type != PivotKind::Ip || ip != subject {
                related_ips.insert(ip.clone());
            }
        }
        for user in &row_users {
            if subject_type != PivotKind::User || user != subject {
                related_users.insert(user.clone());
            }
        }

        let mitre_ids = parsed
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Incident entry.
        entries.push(JourneyEntry {
            ts,
            kind: "incident".to_string(),
            data: serde_json::json!({
                "incident_id": incident_id,
                "severity": severity.to_lowercase(),
                "title": title,
                "summary": summary.unwrap_or_default(),
                "tags": mitre_ids,
                "detector": detector_label,
            }),
        });

        // PR #423 Wave 4c: parse the real `execution_result` from the
        // decision JSON blob. Previously this was derived from
        // `auto_executed` ("ok" | "skipped"), which lied for cases where
        // a block was attempted but skipped because the IP was already
        // blocked, or where the dry_run flag prevented the actual call.
        // The real values stored by `DecisionWriter` are "ok",
        // "skipped", "skipped: <why>", or "failed: <why>".
        //
        // Spec 049 PR9: extract `ai_provider` from the same parsed
        // decision JSON so the journey decision row can carry an
        // explicit `decision_layer` label (instead of forcing the
        // operator to infer it from the reason string).
        let parsed_decision = decision_data
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let real_execution_result = parsed_decision.as_ref().and_then(|v| {
            v.get("execution_result")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        });
        let decision_ai_provider = parsed_decision
            .as_ref()
            .and_then(|v| v.get("ai_provider").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string();

        // Decision entry (if present). Outcome is computed via the
        // canonical contract so the verdict line agrees with the
        // Home tile and the Threats list.
        let outcome = threat_contract::classify_decision(action_type.as_deref(), Some("ok"));
        incident_outcomes.push(outcome);
        if let Some(action) = &action_type {
            // Honest execution result: prefer the stored field, fall
            // back to the auto_executed-derived value only when the
            // decision JSON is missing or malformed.
            let execution_result = real_execution_result.clone().unwrap_or_else(|| {
                if auto_executed.unwrap_or(0) != 0 {
                    "ok".to_string()
                } else {
                    "skipped".to_string()
                }
            });
            // Spec 049 PR9: classify the decision provenance from the
            // already-parsed fields and inject the operator-facing
            // labels into the journey row. Pure read-time derivation —
            // see `decision_provenance::classify_decision_layer_from_fields`.
            let reason_str = reason.clone().unwrap_or_default();
            let confidence_f32 = confidence.map(|c| c as f32);
            let provenance =
                crate::dashboard::decision_provenance::classify_decision_layer_from_fields(
                    &decision_ai_provider,
                    &reason_str,
                    confidence_f32,
                );
            entries.push(JourneyEntry {
                ts,
                kind: "decision".to_string(),
                data: serde_json::json!({
                    "action_type": action,
                    "confidence": confidence.unwrap_or(0.0),
                    "auto_executed": auto_executed.unwrap_or(0) != 0,
                    "reason": reason_str,
                    "target_ip": target_ip,
                    "incident_id": incident_id,
                    "execution_result": execution_result,
                    // Spec 049 PR9 fields.
                    "ai_provider": decision_ai_provider,
                    "decision_layer": provenance.layer,
                    "decision_layer_detail": provenance.detail,
                }),
            });
        } else {
            // PR #423 Wave 4c: an incident with no associated decision
            // is an audit gap. Render an explicit placeholder so the
            // operator sees "this incident reached the agent but no
            // decision was recorded for it" rather than a silently
            // missing row. Real prod observation 2026-05-03: SSH-login-
            // attempt incidents at 13:46 / 13:53 in 164.90.237.71's
            // journey had no decision row, leaving the operator unable
            // to audit what (if anything) happened.
            entries.push(JourneyEntry {
                ts,
                kind: "decision_missing".to_string(),
                data: serde_json::json!({
                    "incident_id": incident_id,
                    "note": "No decision recorded for this incident. Either the AI gate suppressed it (rule-based filter, allowlist match, or no provider available) or the incident wrote-without-deciding. Cross-check the agent log for this incident_id.",
                }),
            });
        }
    }

    if entries.is_empty() {
        return None;
    }

    entries.sort_by_key(|e| e.ts);
    if let Some(window) = window_seconds {
        if let Some(last_ts) = entries.last().map(|e| e.ts) {
            let cutoff = last_ts - chrono::Duration::seconds(window as i64);
            entries.retain(|entry| entry.ts >= cutoff);
        }
    }

    let first_seen = entries.first().map(|e| e.ts);
    let last_seen = entries.last().map(|e| e.ts);
    let outcome = threat_contract::aggregate_outcomes(incident_outcomes).to_string();

    let summary = build_journey_summary(
        &entries,
        &outcome,
        subject_type,
        subject,
        &related_ips,
        &related_users,
        &related_detectors,
    );
    let verdict = derive_verdict(&entries, &outcome);
    let chapters = derive_chapters(&entries);

    let now = Utc::now();
    let block_state = if subject_type == PivotKind::Ip {
        Some(threat_contract::block_state_for_ip(
            Some(store),
            subject,
            now,
        ))
    } else {
        None
    };

    Some(JourneyResponse {
        subject_type: subject_type.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        summary,
        verdict,
        chapters,
        entries,
        block_state,
        // Spec 049 PR10: this builder stays profile-agnostic. The
        // `api_journey` handler overlays the recurrence block from
        // `attacker_profiles` SQLite blob AFTER spawn_blocking
        // returns. Keeps the builder free of I/O it does not need.
        recurrence: None,
    })
}

/// Build the full journey timeline for a selected subject on a given date.
/// Build a journey timeline from the knowledge graph (live, no JSONL).
/// Falls back to honeypot JSONL for honeypot sessions (not in graph yet).
// 8 args after Phase 3 added the SQLite handle for kernel-evidence
// reads. Refactoring to a parameter struct churn would touch every
// caller (3 prod + 2 tests) without changing semantics; revisit when
// any caller passes a 9th arg.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_journey_from_graph(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: &Path,
    date: &str,
    subject_type: PivotKind,
    subject: &str,
    _filters: &InvestigationFilters,
    window_seconds: Option<u64>,
    sqlite: Option<&std::sync::Arc<innerwarden_store::Store>>,
) -> JourneyResponse {
    use crate::knowledge_graph::types::*;

    let graph = kg.read().unwrap();

    // Detector pivot has no "center node" — it aggregates every Incident whose
    // `detector` field matches the subject. Branch early so we do not go
    // through the IP/User-oriented center_id path below, which would otherwise
    // return an empty journey and make the Threats tab drill-down look broken.
    if subject_type == PivotKind::Detector {
        return build_detector_journey(&graph, data_dir, date, subject, window_seconds);
    }

    // Find the center node (IP or User pivot)
    let center = match subject_type {
        PivotKind::Ip => graph.find_by_ip(subject),
        PivotKind::User => graph.find_by_user(subject),
        PivotKind::Detector => unreachable!("handled above"),
    };

    let center_id = match center {
        Some(id) => id,
        None => {
            // Phase 8 (audit RC-2 fourth surface, 2026-04-29): KG misses
            // because of TTL eviction. The Threats list shows the IP
            // (post-Phase-6 reads SQLite) but clicking it landed in
            // an empty journey because this function used to bail
            // here. Fall back to the SQLite-backed journey so the
            // operator sees the actual incidents+decisions for the
            // subject — same data that drove the list count.
            drop(graph); // release read lock before re-entering with sqlite
            if let Some(store) = sqlite {
                if let Some(j) =
                    build_journey_from_sqlite(store, date, subject_type, subject, window_seconds)
                {
                    return j;
                }
            }
            return empty_journey(subject_type, subject, date);
        }
    };

    let mut entries: Vec<JourneyEntry> = Vec::new();
    let mut related_ips: BTreeSet<String> = BTreeSet::new();
    let mut related_users: BTreeSet<String> = BTreeSet::new();
    let mut related_detectors: BTreeSet<String> = BTreeSet::new();
    let mut has_incident = false;

    // 1. Find all Incident nodes connected to this entity via TriggeredBy.
    // Perf: use incoming_edges(center_id) — the graph already indexes incoming
    // adjacency by node. Previously this scanned ALL incident nodes + their
    // outgoing edges (O(I·E)), which made /api/journey take 10+ seconds on
    // production servers with 900+ incidents. Now O(E_to_center), typically <10ms.
    let incident_ids: Vec<_> = graph
        .incoming_edges(center_id)
        .iter()
        .filter(|e| e.relation == Relation::TriggeredBy)
        .map(|e| e.from)
        .collect();

    // PR #423 Wave 4c: pre-load real `execution_result` per incident
    // from SQLite. The graph's Incident node only stores
    // `auto_executed: bool`, which lies for "skipped: already blocked"
    // and similar real outcomes. Batched once here so the per-incident
    // decision entry emit below can use the truth without N+1 queries.
    let execution_results: std::collections::HashMap<String, String> =
        load_execution_results_for_date(sqlite, date);

    for inc_id in incident_ids {
        if let Some(Node::Incident {
            incident_id,
            detector,
            severity,
            title,
            summary,
            ts,
            mitre_ids,
            decision,
            confidence,
            decision_reason,
            decision_target,
            auto_executed,
            ..
        }) = graph.get_node(inc_id)
        {
            has_incident = true;
            related_detectors.insert(detector.clone());

            // Collect other entities from this incident
            for edge in graph.outgoing_edges(inc_id) {
                if edge.relation == Relation::TriggeredBy && edge.to != center_id {
                    if let Some(Node::Ip { addr, .. }) = graph.get_node(edge.to) {
                        related_ips.insert(addr.clone());
                    }
                    if let Some(Node::User { name, .. }) = graph.get_node(edge.to) {
                        related_users.insert(name.clone());
                    }
                }
            }

            entries.push(JourneyEntry {
                ts: *ts,
                kind: "incident".to_string(),
                data: serde_json::json!({
                    "incident_id": incident_id,
                    "severity": severity.to_lowercase(),
                    "title": title,
                    "summary": summary,
                    "tags": mitre_ids,
                    "detector": detector,
                }),
            });

            if let Some(action) = decision {
                // PR #423 Wave 4c: prefer the real execution_result
                // (from SQLite cross-lookup) over the auto_executed-
                // derived fallback. Same fix as the SQLite path.
                let execution_result =
                    execution_results
                        .get(incident_id)
                        .cloned()
                        .unwrap_or_else(|| {
                            if *auto_executed {
                                "ok".to_string()
                            } else {
                                "skipped".to_string()
                            }
                        });
                // Spec 049 PR9: classify provenance. The KG Incident
                // node does NOT carry `ai_provider`, so this path
                // relies on the reason-string heuristics in the
                // classifier. When the reason is generic, the layer
                // falls through to `unknown` (honest — no provider
                // recorded). The SQLite path (production primary)
                // has the provider and produces precise labels.
                let reason_str = decision_reason.as_deref().unwrap_or("").to_string();
                // KG path: confidence is already `Option<f32>` on the
                // Incident node — no cast required.
                let provenance =
                    crate::dashboard::decision_provenance::classify_decision_layer_from_fields(
                        "",
                        &reason_str,
                        *confidence,
                    );
                entries.push(JourneyEntry {
                    ts: *ts,
                    kind: "decision".to_string(),
                    data: serde_json::json!({
                        "action_type": action,
                        "confidence": confidence.unwrap_or(0.0),
                        "auto_executed": auto_executed,
                        "reason": reason_str,
                        "target_ip": decision_target,
                        "incident_id": incident_id,
                        "execution_result": execution_result,
                        // Spec 049 PR9 fields. ai_provider is empty
                        // on the KG path (the Incident node does not
                        // store it).
                        "ai_provider": "",
                        "decision_layer": provenance.layer,
                        "decision_layer_detail": provenance.detail,
                    }),
                });
            } else {
                // PR #423 Wave 4c: same audit-gap visibility as the
                // SQLite path. The Incident node has no decision field
                // either because no AI decision was made (gate-suppressed,
                // no provider) or because the ingestion path didn't
                // attach one. Either way, surface it explicitly.
                entries.push(JourneyEntry {
                    ts: *ts,
                    kind: "decision_missing".to_string(),
                    data: serde_json::json!({
                        "incident_id": incident_id,
                        "note": "No decision recorded for this incident. Either the AI gate suppressed it (rule-based filter, allowlist match, or no provider available) or the incident wrote-without-deciding. Cross-check the agent log for this incident_id.",
                    }),
                });
            }
        }
    }

    // 2. Direct edges from/to this node (depth=1 only, capped)
    let direct_edges = graph.all_edges(center_id);
    for edge in direct_edges.iter().rev().take(50) {
        if edge.is_snapshot() {
            continue;
        }

        let from_label = graph
            .get_node(edge.from)
            .map(|n| n.label())
            .unwrap_or_default();
        let to_label = graph
            .get_node(edge.to)
            .map(|n| n.label())
            .unwrap_or_default();
        let event_source = edge
            .properties
            .get("event_source")
            .and_then(|v| v.as_str())
            .unwrap_or("sensor");
        let event_kind = edge
            .properties
            .get("event_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let summary = edge
            .properties
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let severity = edge
            .properties
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info");

        // Skip edges that are just TriggeredBy (already covered by incidents above)
        if matches!(edge.relation, Relation::TriggeredBy) {
            continue;
        }

        // PR #423 Wave 4c: defense-in-depth filter against agent-self
        // metadata leaking into an attacker IP's journey. Real prod
        // observation 2026-05-03: a file.read_access summary from
        // tokio-rt-worker (the agent's own thread) appeared under IP
        // 164.90.237.71's journey. The root cause was stale
        // `_current_event_*` enriching out-of-cycle edges (fixed
        // separately in `ingestion.rs`); this filter is the second
        // line so any future regression that re-introduces the same
        // class of bug doesn't reach the operator. Skips edges whose
        // event_kind / summary clearly references agent self-traffic.
        if subject_type == PivotKind::Ip && summary_references_agent_self(&summary, event_kind) {
            continue;
        }

        let display_summary = if !summary.is_empty() {
            summary
        } else {
            format!("{} {} → {}", event_kind, from_label, to_label)
        };

        entries.push(JourneyEntry {
            ts: edge.ts,
            kind: "event".to_string(),
            data: serde_json::json!({
                "severity": severity,
                "source": event_source,
                "event_kind": if event_kind.is_empty() { format!("{:?}", edge.relation) } else { event_kind.to_string() },
                "summary": display_summary,
                "details": edge.properties,
                "tags": [],
            }),
        });
    }

    // Honeypot sessions from JSONL (not yet in graph)
    let mut honeypot_ips = related_ips.clone();
    if subject_type == PivotKind::Ip {
        honeypot_ips.insert(subject.to_string());
    }
    let mut hp_entries = scan_honeypot_sessions(data_dir, date, &honeypot_ips);
    entries.append(&mut hp_entries);

    // Sort and window
    entries.sort_by_key(|e| e.ts);
    if let Some(window) = window_seconds {
        if let Some(last_ts) = entries.last().map(|e| e.ts) {
            let cutoff = last_ts - chrono::Duration::seconds(window as i64);
            entries.retain(|entry| entry.ts >= cutoff);
        }
    }

    let first_seen = entries.first().map(|e| e.ts);
    let last_seen = entries.last().map(|e| e.ts);

    // Determine outcome from journey entries
    let outcome = entries
        .iter()
        .filter(|e| e.kind == "decision")
        .filter_map(|e| e.data.get("action_type").and_then(|v| v.as_str()))
        .find_map(|d| match d {
            "block_ip" => Some("blocked"),
            "honeypot" => Some("honeypot"),
            "monitor" => Some("monitoring"),
            _ => None,
        })
        .unwrap_or(if has_incident { "active" } else { "unknown" })
        .to_string();

    let mut summary = build_journey_summary(
        &entries,
        &outcome,
        subject_type,
        subject,
        &related_ips,
        &related_users,
        &related_detectors,
    );

    // ── Intelligence enrichment from knowledge graph ────────────────
    // Replace generic hints with context from real data: connection
    // count, severity distribution, GeoIP, threat feeds, risk
    // assessment. This is what makes the operator understand what
    // happened without technical knowledge.
    if subject_type == PivotKind::Ip {
        summary.hints.clear();

        // Connection count
        let conn_count = graph
            .all_edges(center_id)
            .iter()
            .filter(|e| matches!(e.relation, Relation::ConnectedTo | Relation::AcceptedFrom))
            .count();

        // Incident severity distribution
        let mut sev_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut blocked = false;
        let mut has_threat_intel = false;
        for edge in graph.incoming_edges(center_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            if let Some(Node::Incident {
                severity,
                detector,
                decision,
                research_only,
                ..
            }) = graph.get_node(edge.from)
            {
                if *research_only {
                    continue;
                }
                *sev_counts.entry(severity.to_lowercase()).or_insert(0) += 1;
                if detector == "threat_intel" || detector == "graph_threat_intel" {
                    has_threat_intel = true;
                }
                if decision.as_deref() == Some("block_ip") {
                    blocked = true;
                }
            }
        }

        // GeoIP from edge properties (if available)
        let geo = graph.all_edges(center_id).iter().find_map(|e| {
            e.properties
                .get("country")
                .and_then(|v| v.as_str())
                .map(|c| c.to_string())
        });

        // Build human-readable intelligence hints
        let total_incidents: usize = sev_counts.values().sum();
        let critical = sev_counts.get("critical").copied().unwrap_or(0);
        let high = sev_counts.get("high").copied().unwrap_or(0);

        // Origin
        if let Some(country) = &geo {
            summary.hints.push(format!("Origin: {country}."));
        }

        // Threat intelligence
        if has_threat_intel {
            summary
                .hints
                .push("This IP is in a known malicious threat intelligence feed.".to_string());
        }

        // Activity summary
        if conn_count > 0 {
            summary.hints.push(format!(
                "{} connection attempt{} observed today.",
                conn_count,
                if conn_count > 1 { "s" } else { "" }
            ));
        }

        // Severity assessment. Bug fix (prod 2026-04-22, IP
        // 160.119.76.50): the previous version emitted both "Low
        // activity — Not dangerous" AND "AI has blocked this IP" on
        // the same journey, which is contradictory and undermines
        // operator trust in the dashboard. Now: when the system
        // already blocked but the activity profile says "low /
        // routine", surface the contradiction explicitly as a
        // possible auto-rule false positive instead of pretending
        // both are fine.
        let low_activity_no_intel = total_incidents <= 2 && !has_threat_intel;
        if critical > 0 {
            summary.hints.push(format!(
                "{} critical and {} high severity incident{}. Investigate immediately.",
                critical,
                high,
                if total_incidents > 1 { "s" } else { "" }
            ));
        } else if high > 0 && has_threat_intel {
            summary.hints.push(format!(
                "Known malicious IP with {} incident{}. AI should handle automatically.",
                total_incidents,
                if total_incidents > 1 { "s" } else { "" }
            ));
        } else if low_activity_no_intel && !blocked {
            summary.hints.push(
                "Low activity — likely a routine internet scanner. Not dangerous.".to_string(),
            );
        }

        // Outcome — never paired with "Not dangerous" above.
        if blocked {
            if low_activity_no_intel {
                summary.hints.push(
                    "Auto-blocked despite low activity and no threat-intel hit — possible false positive, review the triggering rule."
                        .to_string(),
                );
            } else {
                summary
                    .hints
                    .push("AI has blocked this IP. No further action needed.".to_string());
            }
        } else if outcome == "active" || outcome == "monitoring" {
            if total_incidents <= 2 && critical == 0 && high == 0 {
                summary.hints.push(
                    "Routine scanner activity. The AI is monitoring but no action is needed."
                        .to_string(),
                );
            } else {
                summary
                    .hints
                    .push("The AI is still evaluating this activity.".to_string());
            }
        }
    }

    let verdict = derive_verdict(&entries, &outcome);
    let chapters = derive_chapters(&entries);

    // Phase 3 (audit RC-4): kernel-evidence block state for IP pivots.
    // Detector / user pivots have no single IP to query against
    // xdp_block_times so they leave block_state at None.
    let block_state = if subject_type == PivotKind::Ip {
        Some(crate::dashboard::threat_contract::block_state_for_ip(
            sqlite,
            subject,
            chrono::Utc::now(),
        ))
    } else {
        None
    };

    JourneyResponse {
        subject_type: subject_type.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        summary,
        verdict,
        chapters,
        entries,
        block_state,
        // Spec 049 PR10: builder stays I/O-free. api_journey
        // overlays the recurrence block from attacker_profiles
        // SQLite blob after spawn_blocking returns.
        recurrence: None,
    }
}

pub(super) fn empty_journey(subject_type: PivotKind, subject: &str, date: &str) -> JourneyResponse {
    JourneyResponse {
        subject_type: subject_type.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen: None,
        last_seen: None,
        outcome: "unknown".to_string(),
        summary: JourneySummary {
            total_entries: 0,
            events_count: 0,
            incidents_count: 0,
            decisions_count: 0,
            honeypot_count: 0,
            first_event: None,
            first_incident: None,
            first_decision: None,
            first_honeypot: None,
            pivot_shortcuts: vec![],
            hints: vec!["No data found for this entity in the knowledge graph.".to_string()],
        },
        verdict: JourneyVerdict {
            entry_vector: "unknown".to_string(),
            access_status: "inconclusive".to_string(),
            privilege_status: "inconclusive".to_string(),
            containment_status: "unknown".to_string(),
            honeypot_status: "not_engaged".to_string(),
            confidence: "low".to_string(),
        },
        chapters: vec![],
        entries: vec![],
        block_state: None,
        // Spec 049 PR10: empty journey → no profile to look up.
        recurrence: None,
    }
}

#[cfg(test)]
pub(super) fn build_journey(
    data_dir: &Path,
    date: &str,
    subject_type: PivotKind,
    subject: &str,
    filters: &InvestigationFilters,
    window_seconds: Option<u64>,
) -> JourneyResponse {
    let events =
        read_jsonl::<innerwarden_core::event::Event>(&dated_path(data_dir, "events", date));
    let incidents = read_jsonl::<innerwarden_core::incident::Incident>(&dated_path(
        data_dir,
        "incidents",
        date,
    ));
    let decisions = read_jsonl::<DecisionEntry>(&dated_path(data_dir, "decisions", date));

    let mut entries: Vec<JourneyEntry> = Vec::new();
    let mut related_ips: BTreeSet<String> = BTreeSet::new();
    let mut related_users: BTreeSet<String> = BTreeSet::new();
    let mut related_detectors: BTreeSet<String> = BTreeSet::new();
    let mut has_incident = false;

    for incident in incidents {
        if !incident_matches_filters(&incident, filters) {
            continue;
        }
        if !incident_matches_subject(&incident, subject_type, subject) {
            continue;
        }

        has_incident = true;
        related_detectors.insert(incident_detector(&incident.incident_id));
        for ip in extract_ip_entities(&incident.entities) {
            related_ips.insert(ip);
        }
        for user in extract_entity_values(&incident.entities, EntityType::User) {
            related_users.insert(user);
        }

        entries.push(JourneyEntry {
            ts: incident.ts,
            kind: "incident".to_string(),
            data: serde_json::json!({
                "incident_id": incident.incident_id,
                "severity": format!("{:?}", incident.severity).to_lowercase(),
                "title": incident.title,
                "summary": incident.summary,
                "evidence": incident.evidence,
                "tags": incident.tags,
            }),
        });
    }

    for event in events {
        if !event_matches_filters(&event, filters) {
            continue;
        }

        let matches_subject = match subject_type {
            PivotKind::Ip => extract_ip_entities(&event.entities)
                .iter()
                .any(|e| e == subject),
            PivotKind::User => {
                extract_entity_values(&event.entities, EntityType::User)
                    .iter()
                    .any(|u| u == subject)
                    || has_intersection(&extract_ip_entities(&event.entities), &related_ips)
            }
            PivotKind::Detector => {
                !related_ips.is_empty()
                    && has_intersection(&extract_ip_entities(&event.entities), &related_ips)
            }
        };

        if matches_subject {
            for ip in extract_ip_entities(&event.entities) {
                related_ips.insert(ip);
            }
            for user in extract_entity_values(&event.entities, EntityType::User) {
                related_users.insert(user);
            }
            entries.push(JourneyEntry {
                ts: event.ts,
                kind: "event".to_string(),
                data: serde_json::json!({
                    "severity": format!("{:?}", event.severity).to_lowercase(),
                    "source": event.source,
                    "event_kind": event.kind,
                    "summary": event.summary,
                    "details": event.details,
                    "tags": event.tags,
                }),
            });
        }
    }

    for decision in &decisions {
        if let Some(detector_filter) = &filters.detector {
            if incident_detector(&decision.incident_id) != *detector_filter {
                continue;
            }
        }
        related_detectors.insert(incident_detector(&decision.incident_id));

        let matches_subject = match subject_type {
            PivotKind::Ip => decision.target_ip.as_deref() == Some(subject),
            PivotKind::User | PivotKind::Detector => decision
                .target_ip
                .as_ref()
                .map(|ip| related_ips.contains(ip))
                .unwrap_or(false),
        };

        if matches_subject {
            entries.push(JourneyEntry {
                ts: decision.ts,
                kind: "decision".to_string(),
                data: serde_json::json!({
                    "action_type": decision.action_type,
                    "confidence": decision.confidence,
                    "auto_executed": decision.auto_executed,
                    "dry_run": decision.dry_run,
                    "reason": decision.reason,
                    "execution_result": decision.execution_result,
                    "skill_id": decision.skill_id,
                    "target_ip": decision.target_ip,
                    "incident_id": decision.incident_id,
                }),
            });
        }
    }

    let mut honeypot_ips = related_ips.clone();
    if subject_type == PivotKind::Ip {
        honeypot_ips.insert(subject.to_string());
    }
    let mut hp_entries = scan_honeypot_sessions(data_dir, date, &honeypot_ips);
    entries.append(&mut hp_entries);

    entries.sort_by_key(|e| e.ts);
    if let Some(window) = window_seconds {
        if let Some(last_ts) = entries.last().map(|e| e.ts) {
            let cutoff = last_ts - chrono::Duration::seconds(window as i64);
            entries.retain(|entry| entry.ts >= cutoff);
        }
    }

    let first_seen = entries.first().map(|e| e.ts);
    let last_seen = entries.last().map(|e| e.ts);
    let outcome = if subject_type == PivotKind::Ip {
        determine_outcome(&decisions, subject, has_incident)
    } else {
        determine_outcome_for_ips(&decisions, &related_ips, has_incident)
    };
    let summary = build_journey_summary(
        &entries,
        &outcome,
        subject_type,
        subject,
        &related_ips,
        &related_users,
        &related_detectors,
    );

    let verdict = derive_verdict(&entries, &outcome);
    let chapters = derive_chapters(&entries);

    JourneyResponse {
        subject_type: subject_type.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        summary,
        verdict,
        chapters,
        entries,
        block_state: None,
        // Spec 049 PR10: test fixture path.
        recurrence: None,
    }
}

pub(super) fn build_journey_summary(
    entries: &[JourneyEntry],
    outcome: &str,
    subject_type: PivotKind,
    subject: &str,
    related_ips: &BTreeSet<String>,
    related_users: &BTreeSet<String>,
    related_detectors: &BTreeSet<String>,
) -> JourneySummary {
    let mut summary = JourneySummary {
        total_entries: entries.len(),
        events_count: 0,
        incidents_count: 0,
        decisions_count: 0,
        honeypot_count: 0,
        first_event: None,
        first_incident: None,
        first_decision: None,
        first_honeypot: None,
        pivot_shortcuts: build_pivot_shortcuts(
            subject_type,
            subject,
            related_ips,
            related_users,
            related_detectors,
        ),
        hints: Vec::new(),
    };

    let mut decision_actions: BTreeMap<String, usize> = BTreeMap::new();

    for entry in entries {
        match entry.kind.as_str() {
            "event" => {
                summary.events_count += 1;
                if summary.first_event.is_none() {
                    summary.first_event = Some(entry.ts);
                }
            }
            "incident" => {
                summary.incidents_count += 1;
                if summary.first_incident.is_none() {
                    summary.first_incident = Some(entry.ts);
                }
            }
            "decision" => {
                summary.decisions_count += 1;
                if summary.first_decision.is_none() {
                    summary.first_decision = Some(entry.ts);
                }
                if let Some(action_type) = entry.data.get("action_type").and_then(|v| v.as_str()) {
                    *decision_actions.entry(action_type.to_string()).or_insert(0) += 1;
                }
            }
            kind if kind.starts_with("honeypot_") => {
                summary.honeypot_count += 1;
                if summary.first_honeypot.is_none() {
                    summary.first_honeypot = Some(entry.ts);
                }
            }
            _ => {}
        }
    }

    if summary.total_entries == 0 {
        summary
            .hints
            .push("No timeline entries for current filters/window.".to_string());
        return summary;
    }

    if let (Some(first_event), Some(first_incident)) = (summary.first_event, summary.first_incident)
    {
        let lag = (first_incident - first_event).num_seconds();
        summary.hints.push(format!(
            "Escalation: first incident raised {} after first signal.",
            format_duration(lag)
        ));
    } else if summary.events_count > 0 && summary.incidents_count == 0 {
        summary.hints.push(
            "Signals observed in this window, but no incident met detector thresholds.".to_string(),
        );
    }

    if let (Some(first_incident), Some(first_decision)) =
        (summary.first_incident, summary.first_decision)
    {
        let lag = (first_decision - first_incident).num_seconds();
        summary.hints.push(format!(
            "Response lag: first decision recorded {} after first incident.",
            format_duration(lag)
        ));
    } else if summary.incidents_count > 0 && summary.decisions_count == 0 {
        summary.hints.push(
            "Incidents detected, but no AI decision was recorded in this window.".to_string(),
        );
    }

    if summary.honeypot_count > 0 {
        summary.hints.push(format!(
            "Honeypot engaged with {} artifact(s) captured.",
            summary.honeypot_count
        ));
    }

    if !decision_actions.is_empty() {
        let action_line = decision_actions
            .iter()
            .map(|(action, count)| format!("{action} ({count})"))
            .collect::<Vec<_>>()
            .join(", ");
        summary
            .hints
            .push(format!("Decision mix in window: {action_line}."));
    }

    let outcome_hint = match outcome {
        "blocked" => "Outcome indicates containment was applied (blocked).",
        "honeypot" => "Outcome indicates attacker flow was redirected to honeypot controls.",
        "monitoring" => "Outcome indicates monitoring response without direct containment.",
        "active" => "Outcome indicates active threat path without confirmed containment.",
        _ => "Outcome is unknown for this scope.",
    };
    summary.hints.push(outcome_hint.to_string());

    summary
}

pub(super) fn build_pivot_shortcuts(
    subject_type: PivotKind,
    subject: &str,
    related_ips: &BTreeSet<String>,
    related_users: &BTreeSet<String>,
    related_detectors: &BTreeSet<String>,
) -> Vec<String> {
    let mut shortcuts = Vec::new();
    let mut seen = BTreeSet::new();

    let push_token = |token: String, shortcuts: &mut Vec<String>, seen: &mut BTreeSet<String>| {
        if token.is_empty() {
            return;
        }
        if seen.insert(token.clone()) {
            shortcuts.push(token);
        }
    };

    push_token(
        format!("{}:{}", subject_type.as_str(), subject),
        &mut shortcuts,
        &mut seen,
    );
    for ip in related_ips.iter().take(3) {
        push_token(format!("ip:{ip}"), &mut shortcuts, &mut seen);
    }
    for user in related_users.iter().take(3) {
        push_token(format!("user:{user}"), &mut shortcuts, &mut seen);
    }
    for detector in related_detectors.iter().take(3) {
        push_token(format!("detector:{detector}"), &mut shortcuts, &mut seen);
    }
    shortcuts.truncate(8);
    shortcuts
}

// ── D5 - Story derivation ──────────────────────────────────────────────────

/// Derive a high-level attack verdict from the assembled journey entries.
pub(super) fn derive_verdict(entries: &[JourneyEntry], outcome: &str) -> JourneyVerdict {
    // Entry vector: first incident's detector prefix
    let entry_vector = entries
        .iter()
        .find(|e| e.kind == "incident")
        .and_then(|e| e.data.get("incident_id").and_then(|v| v.as_str()))
        .map(|id| {
            match id.split(':').next().unwrap_or("unknown") {
                "ssh_bruteforce" => "ssh_bruteforce",
                "credential_stuffing" => "credential_stuffing",
                "port_scan" => "port_scan",
                "sudo_abuse" => "sudo_abuse",
                _ => "unknown",
            }
            .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Access status: any login success events?
    let has_success = entries.iter().any(|e| {
        e.kind == "event"
            && e.data
                .get("event_kind")
                .and_then(|v| v.as_str())
                .map(|k| k.contains("login_success") || k.contains("_accepted"))
                .unwrap_or(false)
    });
    let has_events = entries.iter().any(|e| e.kind == "event");
    let access_status = if has_success {
        "likely_success"
    } else if has_events {
        "no_evidence_of_success"
    } else {
        "inconclusive"
    }
    .to_string();

    // Privilege status: sudo_abuse incidents or sudo events?
    let has_sudo = entries.iter().any(|e| {
        (e.kind == "incident"
            && e.data
                .get("incident_id")
                .and_then(|v| v.as_str())
                .map(|id| id.starts_with("sudo_abuse"))
                .unwrap_or(false))
            || (e.kind == "event"
                && e.data
                    .get("event_kind")
                    .and_then(|v| v.as_str())
                    .map(|k| k.contains("sudo"))
                    .unwrap_or(false))
    });
    let privilege_status = if has_sudo { "attempted" } else { "no_evidence" }.to_string();

    // Honeypot status
    let has_honeypot = entries.iter().any(|e| e.kind.starts_with("honeypot_"));
    let honeypot_status = if outcome == "honeypot" {
        "diverted"
    } else if has_honeypot {
        "engaged"
    } else {
        "not_engaged"
    }
    .to_string();

    // Containment status mirrors outcome
    let containment_status = match outcome {
        "blocked" => "blocked",
        "monitoring" => "monitored",
        "honeypot" => "honeypot",
        "active" => "active",
        _ => "unknown",
    }
    .to_string();

    // Confidence based on data richness
    let has_incident = entries.iter().any(|e| e.kind == "incident");
    let has_decision = entries.iter().any(|e| e.kind == "decision");
    let confidence = if has_incident && has_decision && has_events {
        "high"
    } else if has_incident && (has_events || has_decision) {
        "medium"
    } else {
        "low"
    }
    .to_string();

    JourneyVerdict {
        entry_vector,
        access_status,
        privilege_status,
        containment_status,
        honeypot_status,
        confidence,
    }
}

/// Derive human-readable attack chapters from the journey entries.
pub(super) fn derive_chapters(entries: &[JourneyEntry]) -> Vec<JourneyChapter> {
    if entries.is_empty() {
        return vec![];
    }

    // Assign each entry to a logical stage. Bug fix (prod 2026-04-22,
    // IP 160.119.76.50): the previous catch-all dumped every event
    // kind into `initial_access_attempt`, which then got rendered as
    // "Brute-force burst" / "Login attempt(s)" — including plain HTTP
    // GETs and `tcp_stream.ssh` taps. Only events that actually look
    // like login attempts go to `initial_access_attempt`; everything
    // else falls through to `observed_activity` with neutral wording.
    let stages: Vec<&str> = entries
        .iter()
        .map(|e| match e.kind.as_str() {
            "event" => {
                let kind = e
                    .data
                    .get("event_kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if kind.contains("port_scan") || kind.starts_with("dns.") || kind.contains("recon")
                {
                    "reconnaissance"
                } else if kind.contains("login_success") || kind.contains("_accepted") {
                    "access_success"
                } else if kind.contains("sudo") || kind.contains("privesc") {
                    "privilege_abuse"
                } else if is_login_attempt_kind(kind) {
                    "initial_access_attempt"
                } else {
                    "observed_activity"
                }
            }
            "incident" => {
                let id = e
                    .data
                    .get("incident_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if id.starts_with("port_scan") {
                    "reconnaissance"
                } else if id.starts_with("sudo_abuse") {
                    "privilege_abuse"
                } else {
                    "response"
                }
            }
            "decision" => "containment",
            k if k.starts_with("honeypot_") => "honeypot_interaction",
            _ => "unknown",
        })
        .collect();

    // Group consecutive same-stage entries into chapters
    let mut chapters: Vec<JourneyChapter> = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let stage = stages[i];
        let chapter_start = i;
        while i < entries.len() && stages[i] == stage {
            i += 1;
        }
        let chapter_entries = &entries[chapter_start..i];
        let (title, summary, highlights) = describe_chapter(stage, chapter_entries);
        chapters.push(JourneyChapter {
            stage: stage.to_string(),
            title,
            summary,
            start_ts: chapter_entries[0].ts,
            end_ts: chapter_entries.last().unwrap().ts,
            entry_count: chapter_entries.len(),
            evidence_highlights: highlights,
            entry_indices: (chapter_start..i).collect(),
        });
    }
    chapters
}

/// Classify whether an event kind represents a login attempt that
/// should be grouped under `initial_access_attempt`. Anything that does
/// not match this is generic activity and lands in `observed_activity`.
///
/// Conservative on purpose: false negatives (a real login attempt
/// mislabeled as activity) are noticeably less harmful than false
/// positives (an HTTP GET mislabeled as "brute-force burst", which
/// pushed the prod 2026-04-22 false-block decision).
pub(super) fn is_login_attempt_kind(kind: &str) -> bool {
    kind.contains("login_failed")
        || kind.contains("login_failure")
        || kind.contains("login_attempt")
        || kind.contains("auth_failed")
        || kind.contains("auth_failure")
        || kind.contains("ssh_bruteforce")
        || kind.contains("credential_stuffing")
        || kind.contains("invalid_user")
        || kind.contains("password_attempt")
}

/// PR #423 Wave 4c: load `(incident_id, execution_result)` for every
/// decision recorded today. Used by `build_journey_from_graph` to
/// surface the real outcome (e.g. "skipped: already blocked") on
/// decision entries built from graph nodes. Returns an empty map on
/// any error or when no SQLite store is available — callers fall back
/// to the auto_executed-derived value.
pub(super) fn load_execution_results_for_date(
    sqlite: Option<&std::sync::Arc<innerwarden_store::Store>>,
    date: &str,
) -> std::collections::HashMap<String, String> {
    let mut out: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let Some(store) = sqlite else { return out };
    let Ok(conn) = store.conn() else { return out };
    let pattern = format!("{date}%");
    let Ok(mut stmt) = conn.prepare_cached(
        "SELECT incident_id, data FROM ( \
             SELECT incident_id, data, \
                    ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY id DESC) AS rn \
             FROM decisions WHERE ts LIKE ?1 \
         ) WHERE rn = 1",
    ) else {
        return out;
    };
    let Ok(iter) = stmt.query_map([&pattern], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }) else {
        return out;
    };
    for r in iter {
        let Ok((incident_id, data)) = r else { continue };
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(er) = parsed
                .get("execution_result")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
            {
                out.insert(incident_id, er);
            }
        }
    }
    out
}

/// PR #423 Wave 4c: returns true when an edge's `summary` references
/// the agent's own threads/binaries — the same comm allow-list the
/// killchain inline tracker uses to ignore self-traffic. Used by the
/// IP-pivot journey to drop any edge whose origin is plainly the agent
/// itself, regardless of how the metadata got attached to an
/// IP-touching edge.
///
/// Stays narrow on purpose: matches only against the `comm` allow-list,
/// not against generic event_kind. A future post-pivot scenario where
/// an attacker process performs file IO on the host should still
/// surface in the journey — those events would NOT have an agent
/// comm in their summary and would correctly pass this filter.
///
/// `event_kind` retained as a parameter for forward-compatibility (the
/// filter may grow into kind-aware checks for specific narrow cases),
/// currently unused.
pub(super) fn summary_references_agent_self(summary: &str, _event_kind: &str) -> bool {
    let lower = summary.to_ascii_lowercase();
    for needle in crate::killchain_inline::KILLCHAIN_SELF_EXCLUDED_COMMS {
        if lower.contains(&needle.to_ascii_lowercase()) {
            return true;
        }
    }
    false
}

/// Generate human-readable title / summary / highlights for a chapter.
pub(super) fn describe_chapter(
    stage: &str,
    entries: &[JourneyEntry],
) -> (String, String, Vec<String>) {
    match stage {
        "observed_activity" => {
            // Neutral wording for the catch-all bucket so plain HTTP
            // GETs / TCP taps / file reads no longer surface as
            // "Brute-force burst".
            let kinds: Vec<String> = entries
                .iter()
                .filter_map(|e| {
                    e.data
                        .get("event_kind")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .take(5)
                .collect();
            let title = format!("Observed activity ({} events)", entries.len());
            let summary = if kinds.is_empty() {
                "Generic activity not classified as an attack stage".to_string()
            } else {
                format!("Event kinds: {}", kinds.join(", "))
            };
            (title, summary, kinds)
        }
        "reconnaissance" => {
            let title = "Reconnaissance activity".to_string();
            let summary = format!("{} probe event(s) detected", entries.len());
            (title, summary, vec![])
        }
        "initial_access_attempt" => {
            // Collect distinct usernames attempted
            let usernames: Vec<String> = entries
                .iter()
                .flat_map(|e| {
                    let mut names = Vec::new();
                    if let Some(d) = e.data.get("details") {
                        for key in ["user", "username"] {
                            if let Some(u) = d.get(key).and_then(|v| v.as_str()) {
                                names.push(u.to_string());
                            }
                        }
                    }
                    names
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .take(5)
                .collect();
            let ev_count = entries.iter().filter(|e| e.kind == "event").count();
            let title = if ev_count > 3 {
                format!("Brute-force burst ({} attempts)", ev_count)
            } else {
                "Login attempt(s)".to_string()
            };
            let summary = format!("{} failed login attempt(s)", entries.len());
            (title, summary, usernames)
        }
        "access_success" => {
            let user = entries
                .iter()
                .find_map(|e| {
                    e.data
                        .get("details")
                        .and_then(|d| d.get("user"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                })
                .unwrap_or_default();
            let title = "Login success detected".to_string();
            let summary = "Evidence of successful authentication".to_string();
            let highlights = if user.is_empty() { vec![] } else { vec![user] };
            (title, summary, highlights)
        }
        "privilege_abuse" => {
            let title = "Privilege escalation attempt".to_string();
            let summary = format!("{} sudo-related event(s)", entries.len());
            (title, summary, vec![])
        }
        "response" => {
            let titles: Vec<String> = entries
                .iter()
                .filter_map(|e| {
                    e.data
                        .get("title")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                })
                .take(2)
                .collect();
            let title = titles
                .first()
                .cloned()
                .unwrap_or_else(|| "Incident detected".to_string());
            let summary = format!("{} detector incident(s) raised", entries.len());
            (title, summary, titles)
        }
        "containment" => {
            let action = entries
                .iter()
                .find_map(|e| {
                    e.data
                        .get("action_type")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                })
                .unwrap_or_default();
            let is_dry = entries.iter().any(|e| {
                e.data
                    .get("dry_run")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            });
            let title = if is_dry {
                format!("AI decision - {} (dry run)", action)
            } else {
                format!("AI decision - {}", action)
            };
            let conf = entries
                .iter()
                .find_map(|e| {
                    e.data
                        .get("confidence")
                        .and_then(|v| v.as_f64())
                        .map(|c| format!("conf {:.0}%", c * 100.0))
                })
                .unwrap_or_default();
            let summary = format!("{} decision(s)", entries.len());
            let highlights = if conf.is_empty() { vec![] } else { vec![conf] };
            (title, summary, highlights)
        }
        "honeypot_interaction" => {
            let creds: Vec<String> = entries
                .iter()
                .flat_map(|e| {
                    e.data
                        .get("auth_attempts")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|a| {
                                    let user = a.get("username").and_then(|v| v.as_str())?;
                                    let pass = a.get("password").and_then(|v| v.as_str())?;
                                    Some(format!("{}/{}", user, pass))
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .take(5)
                .collect();
            let title = "Honeypot interaction".to_string();
            let summary = format!("{} honeypot session(s)", entries.len());
            (title, summary, creds)
        }
        _ => {
            let title = format!("{} event(s)", entries.len());
            let summary = "Unclassified activity".to_string();
            (title, summary, vec![])
        }
    }
}

pub(super) fn format_duration(seconds: i64) -> String {
    let secs = seconds.max(0);
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    let rem = secs % 60;
    if mins < 60 {
        if rem == 0 {
            return format!("{mins}m");
        }
        return format!("{mins}m {rem}s");
    }
    let hours = mins / 60;
    let min_rem = mins % 60;
    if min_rem == 0 {
        return format!("{hours}h");
    }
    format!("{hours}h {min_rem}m")
}

/// Scan all honeypot JSONL session files for connections from tracked IPs on `date`.
pub(super) fn scan_honeypot_sessions(
    data_dir: &Path,
    date: &str,
    tracked_ips: &BTreeSet<String>,
) -> Vec<JourneyEntry> {
    if tracked_ips.is_empty() {
        return Vec::new();
    }

    let honeypot_dir = data_dir.join("honeypot");
    let mut entries = Vec::new();

    let read_dir = match std::fs::read_dir(&honeypot_dir) {
        Ok(d) => d,
        Err(_) => return entries,
    };

    for dir_entry in read_dir {
        let Ok(dir_entry) = dir_entry else { continue };
        let path = dir_entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("listener-session-") || !name.ends_with(".jsonl") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Filter by peer_ip.
            let peer_ip = match val.get("peer_ip").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => continue,
            };
            if !tracked_ips.contains(peer_ip) {
                continue;
            }

            // Filter by date using the ts field.
            let ts_str = match val.get("ts").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => continue,
            };
            if !ts_str.starts_with(date) {
                continue;
            }

            // Parse timestamp.
            let ts = match chrono::DateTime::parse_from_rfc3339(ts_str) {
                Ok(dt) => dt.with_timezone(&Utc),
                Err(_) => continue,
            };

            // Map evidence type to journey kind.
            let kind = match val.get("type").and_then(|v| v.as_str()) {
                Some("ssh_connection") => "honeypot_ssh",
                Some("http_connection") => "honeypot_http",
                Some("connection") => "honeypot_banner",
                _ => continue, // skip connection_rejected and unknown types
            };

            entries.push(JourneyEntry {
                ts,
                kind: kind.to_string(),
                data: val,
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Detector-pivot journey
// ---------------------------------------------------------------------------
//
// Unlike IP/User pivots, a detector name ("sigma", "graph_crypto_miner", …)
// is not a single node in the graph: it is a field shared by many Incident
// nodes. The drill-down collects every incident that reports this detector
// for the requested date and aggregates their timestamps, related entities,
// and decision history into a JourneyResponse shaped like the IP/User one.
// Previously the drill-down returned `empty_journey` unconditionally, making
// the Threats tab look broken when the operator clicked a detector group.

fn build_detector_journey(
    graph: &crate::knowledge_graph::KnowledgeGraph,
    data_dir: &Path,
    date: &str,
    subject: &str,
    window_seconds: Option<u64>,
) -> JourneyResponse {
    use crate::knowledge_graph::types::*;

    let mut entries: Vec<JourneyEntry> = Vec::new();
    let mut related_ips: BTreeSet<String> = BTreeSet::new();
    let mut related_users: BTreeSet<String> = BTreeSet::new();
    let mut related_detectors: BTreeSet<String> = BTreeSet::new();
    related_detectors.insert(subject.to_string());
    let mut has_incident = false;

    // Scan every Incident node — detector is an internal field so there is
    // no direct index. The graph typically holds O(hundreds) of incidents
    // so the linear pass is fine; add a secondary index later if needed.
    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            incident_id,
            detector,
            severity,
            title,
            summary,
            ts,
            mitre_ids,
            decision,
            confidence,
            decision_reason,
            decision_target,
            auto_executed,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            if *research_only || detector != subject {
                continue;
            }
            has_incident = true;

            for edge in graph.outgoing_edges(id) {
                if edge.relation == Relation::TriggeredBy {
                    if let Some(Node::Ip { addr, .. }) = graph.get_node(edge.to) {
                        related_ips.insert(addr.clone());
                    } else if let Some(Node::User { name, .. }) = graph.get_node(edge.to) {
                        related_users.insert(name.clone());
                    }
                }
            }

            entries.push(JourneyEntry {
                ts: *ts,
                kind: "incident".to_string(),
                data: serde_json::json!({
                    "incident_id": incident_id,
                    "severity": severity.to_lowercase(),
                    "title": title,
                    "summary": summary,
                    "tags": mitre_ids,
                    "detector": detector,
                }),
            });

            if let Some(action) = decision {
                entries.push(JourneyEntry {
                    ts: *ts,
                    kind: "decision".to_string(),
                    data: serde_json::json!({
                        "action_type": action,
                        "confidence": confidence.unwrap_or(0.0),
                        "auto_executed": auto_executed,
                        "reason": decision_reason.as_deref().unwrap_or(""),
                        "target_ip": decision_target,
                        "incident_id": incident_id,
                        "execution_result": if *auto_executed { "ok" } else { "skipped" },
                    }),
                });
            }
        }
    }

    // Honeypot sessions surface through related_ips (not the detector name).
    let mut hp_entries = scan_honeypot_sessions(data_dir, date, &related_ips);
    entries.append(&mut hp_entries);

    entries.sort_by_key(|e| e.ts);
    if let Some(window) = window_seconds {
        if let Some(last_ts) = entries.last().map(|e| e.ts) {
            let cutoff = last_ts - chrono::Duration::seconds(window as i64);
            entries.retain(|entry| entry.ts >= cutoff);
        }
    }

    let first_seen = entries.first().map(|e| e.ts);
    let last_seen = entries.last().map(|e| e.ts);

    // 2026-04-29: route through `threat_contract::aggregate_outcomes`
    // so the Detector journey verdict agrees with the Detector pivot
    // row's outcome when the operator drills in. The pre-fix
    // `find_map` short-circuited on the first decision with a known
    // action_type and skipped block_ip / monitor / honeypot pairs
    // emitted in different orders.
    let individual: Vec<&'static str> = entries
        .iter()
        .filter(|e| e.kind == "decision")
        .filter_map(|e| e.data.get("action_type").and_then(|v| v.as_str()))
        .map(|d| threat_contract::classify_decision(Some(d), None))
        .collect();
    let outcome = if !individual.is_empty() {
        threat_contract::aggregate_outcomes(&individual).to_string()
    } else if has_incident {
        // Same fallback the IP/User journey uses (`active` =
        // incident observed but no decision yet). Kept distinct
        // from threat_contract's `OUTCOME_OPEN` because the
        // journey-side rendering keys on `active` for the
        // "incident observed, awaiting decision" empty-state copy.
        "active".to_string()
    } else {
        "unknown".to_string()
    };

    let summary = build_journey_summary(
        &entries,
        &outcome,
        PivotKind::Detector,
        subject,
        &related_ips,
        &related_users,
        &related_detectors,
    );

    let verdict = derive_verdict(&entries, &outcome);
    let chapters = derive_chapters(&entries);

    JourneyResponse {
        subject_type: PivotKind::Detector.as_str().to_string(),
        subject: subject.to_string(),
        date: date.to_string(),
        first_seen,
        last_seen,
        outcome,
        summary,
        verdict,
        chapters,
        entries,
        block_state: None,
        // Spec 049 PR10: detector subject has no single IP — no
        // attacker profile to look up.
        recurrence: None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn parse_cluster_pivot(pivot: &str) -> (String, String) {
    if let Some((kind, value)) = pivot.split_once(':') {
        return (kind.to_string(), value.to_string());
    }
    ("detector".to_string(), pivot.to_string())
}
pub(super) fn render_markdown_snapshot(snapshot: &InvestigationExport) -> String {
    let mut out = String::new();
    out.push_str("# InnerWarden Investigation Snapshot\n\n");
    out.push_str(&format!("- Generated at: `{}`\n", snapshot.generated_at));
    out.push_str(&format!("- Date: `{}`\n", snapshot.date));
    out.push_str(&format!("- Group by: `{}`\n", snapshot.group_by));
    if let (Some(subject_type), Some(subject)) = (&snapshot.subject_type, &snapshot.subject) {
        out.push_str(&format!("- Subject: `{subject_type}:{subject}`\n"));
    }
    out.push('\n');

    out.push_str("## Overview\n\n");
    out.push_str(&format!(
        "- Events: **{}**\n- Incidents: **{}**\n- Decisions: **{}**\n\n",
        snapshot.overview.events_count,
        snapshot.overview.incidents_count,
        snapshot.overview.decisions_count
    ));

    out.push_str("## Top Pivots\n\n");
    if snapshot.pivots.is_empty() {
        out.push_str("_No pivots for current filters._\n\n");
    } else {
        for pivot in &snapshot.pivots {
            out.push_str(&format!(
                "- `{}` · severity `{}` · incidents `{}` · events `{}` · outcome `{}`\n",
                pivot.value,
                pivot.max_severity,
                pivot.incident_count,
                pivot.event_count,
                pivot.outcome
            ));
        }
        out.push('\n');
    }

    out.push_str("## Correlation Clusters\n\n");
    if snapshot.clusters.is_empty() {
        out.push_str("_No clusters for current filters._\n\n");
    } else {
        for cluster in &snapshot.clusters {
            out.push_str(&format!(
                "- {} · pivot `{}` · incidents `{}` · detectors `{}` · `{}` → `{}`\n",
                cluster.cluster_id,
                cluster.pivot,
                cluster.incident_count,
                cluster.detector_kinds.join(", "),
                cluster.start_ts,
                cluster.end_ts
            ));
        }
        out.push('\n');
    }

    out.push_str("## Journey\n\n");
    match &snapshot.journey {
        Some(journey) => {
            out.push_str(&format!(
                "- Subject: `{}`:`{}`\n- Outcome: `{}`\n- Entries: `{}`\n\n",
                journey.subject_type,
                journey.subject,
                journey.outcome,
                journey.entries.len()
            ));
            out.push_str("### Guided Summary\n\n");
            out.push_str(&format!(
                "- Events: `{}`\n- Incidents: `{}`\n- Decisions: `{}`\n- Honeypot: `{}`\n\n",
                journey.summary.events_count,
                journey.summary.incidents_count,
                journey.summary.decisions_count,
                journey.summary.honeypot_count
            ));
            if !journey.summary.hints.is_empty() {
                out.push_str("### Investigation Hints\n\n");
                for hint in &journey.summary.hints {
                    out.push_str(&format!("- {}\n", hint));
                }
                out.push('\n');
            }
            for entry in &journey.entries {
                out.push_str(&format!("- `{}` · **{}**\n", entry.ts, entry.kind));
            }
            out.push('\n');
        }
        None => out.push_str("_No journey selected for export._\n\n"),
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use tempfile::TempDir;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(-10), "0s"); // fallback handling
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(120), "2m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(3665), "1h 1m");
    }

    #[test]
    fn test_derive_verdict_blocked() {
        let ts = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let entries = vec![
            JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "nmap_port_scan"}),
            },
            JourneyEntry {
                ts,
                kind: "incident".to_string(),
                data: serde_json::json!({"incident_id": "port_scan:1"}),
            },
            JourneyEntry {
                ts,
                kind: "decision".to_string(),
                data: serde_json::json!({"action_type": "block_ip"}),
            },
        ];

        let verdict = derive_verdict(&entries, "blocked");
        assert_eq!(verdict.entry_vector, "port_scan");
        assert_eq!(verdict.access_status, "no_evidence_of_success");
        assert_eq!(verdict.containment_status, "blocked");
        assert_eq!(verdict.confidence, "high"); // has event + incident + decision
    }

    #[test]
    fn test_derive_chapters() {
        let ts = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let entries = vec![
            JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "login_attempt", "details": {"user": "admin"}}),
            },
            JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "login_attempt", "details": {"user": "root"}}),
            },
            JourneyEntry {
                ts,
                kind: "incident".to_string(),
                data: serde_json::json!({"incident_id": "ssh_bruteforce:1"}),
            },
        ];

        let chapters = derive_chapters(&entries);
        assert_eq!(chapters.len(), 2);

        let ch1 = &chapters[0];
        assert_eq!(ch1.stage, "initial_access_attempt");
        assert_eq!(ch1.entry_count, 2);
        assert!(
            ch1.evidence_highlights.contains(&"admin".to_string())
                || ch1.evidence_highlights.contains(&"root".to_string())
        );

        let ch2 = &chapters[1];
        assert_eq!(ch2.stage, "response");
        assert_eq!(ch2.entry_count, 1);
    }

    #[test]
    fn test_build_journey_summary_with_hints() {
        // Build summary with no entries
        let summary = build_journey_summary(
            &[],
            "unknown",
            PivotKind::Ip,
            "10.0.0.1",
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(summary.total_entries, 0);
        assert!(summary.hints[0].contains("No timeline entries"));
    }
    #[test]
    fn test_severity_rank() {
        assert_eq!(severity_rank("critical"), 5);
        assert_eq!(severity_rank("HIGH"), 4);
        assert_eq!(severity_rank("Medium"), 3);
        assert_eq!(severity_rank("low"), 2);
        assert_eq!(severity_rank("info"), 1);
        assert_eq!(severity_rank("unknown"), 0);
    }

    #[test]
    fn test_classify_phase_attack_matrix() {
        // Covers ATT&CK-like event kind mapping used by journey timeline phases.
        let cases = [
            ("initial_access", "initial_access_attempt"),
            ("execution", "execution"),
            ("persistence", "persistence"),
            ("privilege_escalation", "privilege_abuse"),
            ("defense_evasion", "initial_access_attempt"),
            ("credential_access", "initial_access_attempt"),
            ("lateral_movement", "initial_access_attempt"),
            ("exfiltration", "initial_access_attempt"),
            ("impact", "initial_access_attempt"),
            ("honeypot_interaction", "initial_access_attempt"),
            ("response", "initial_access_attempt"),
            ("containment", "initial_access_attempt"),
        ];
        for (kind, expected) in cases {
            assert_eq!(classify_phase(kind), expected);
        }
    }

    #[test]
    fn test_describe_chapter_bruteforce_burst_title() {
        // Verifies that a large burst is collapsed into a concise brute-force title.
        let ts = Utc::now();
        let entries: Vec<JourneyEntry> = (0..50)
            .map(|_| JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "ssh_login_failed", "details": {"username": "root"}}),
            })
            .collect();
        let (title, _, _) = describe_chapter("initial_access_attempt", &entries);
        assert_eq!(title, "Brute-force burst (50 attempts)");
    }

    #[test]
    fn test_journey_entries_sorted_most_recent_first() {
        // Ensures timeline rendering can show newest events first when requested.
        let older = Utc::now() - chrono::Duration::minutes(5);
        let newer = Utc::now();
        let mut entries = vec![
            JourneyEntry {
                ts: older,
                kind: "event".to_string(),
                data: serde_json::json!({}),
            },
            JourneyEntry {
                ts: newer,
                kind: "incident".to_string(),
                data: serde_json::json!({}),
            },
        ];
        entries.sort_by(|a, b| b.ts.cmp(&a.ts));
        assert!(entries[0].ts >= entries[1].ts);
    }

    #[test]
    fn test_journey_summary_incident_counts_edge_values() {
        // Validates 0/1/100 incident count scenarios in the summary builder.
        let ts = Utc::now();
        let summary_zero = build_journey_summary(
            &[],
            "unknown",
            PivotKind::Ip,
            "1.2.3.4",
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(summary_zero.incidents_count, 0);

        let one = vec![JourneyEntry {
            ts,
            kind: "incident".to_string(),
            data: serde_json::json!({"incident_id": "one:1"}),
        }];
        let summary_one = build_journey_summary(
            &one,
            "active",
            PivotKind::Ip,
            "1.2.3.4",
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(summary_one.incidents_count, 1);

        let many: Vec<JourneyEntry> = (0..100)
            .map(|idx| JourneyEntry {
                ts,
                kind: "incident".to_string(),
                data: serde_json::json!({"incident_id": format!("bulk:{idx}")}),
            })
            .collect();
        let summary_many = build_journey_summary(
            &many,
            "active",
            PivotKind::Ip,
            "1.2.3.4",
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(summary_many.incidents_count, 100);
    }

    #[test]
    fn test_journey_summary_ip_with_only_honeypot_sessions() {
        // Confirms honeypot-only timelines are counted without requiring incidents.
        let ts = Utc::now();
        let entries = vec![JourneyEntry {
            ts,
            kind: "honeypot_ssh".to_string(),
            data: serde_json::json!({"peer_ip": "4.3.2.1"}),
        }];
        let summary = build_journey_summary(
            &entries,
            "honeypot",
            PivotKind::Ip,
            "4.3.2.1",
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(summary.honeypot_count, 1);
        assert_eq!(summary.incidents_count, 0);
    }

    #[test]
    fn test_journey_summary_decision_without_incident() {
        // Ensures decision-only timelines are represented even when no incident is present.
        let ts = Utc::now();
        let entries = vec![JourneyEntry {
            ts,
            kind: "decision".to_string(),
            data: serde_json::json!({"action_type": "monitor"}),
        }];
        let summary = build_journey_summary(
            &entries,
            "monitoring",
            PivotKind::Ip,
            "9.9.9.9",
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(summary.decisions_count, 1);
        assert_eq!(summary.incidents_count, 0);
    }

    #[test]
    fn test_journey_window_first_and_last_seen() {
        // Verifies the investigation window is computed from first to last seen entry.
        let first = Utc::now() - chrono::Duration::minutes(10);
        let last = Utc::now();
        let entries = vec![
            JourneyEntry {
                ts: first,
                kind: "event".to_string(),
                data: serde_json::json!({}),
            },
            JourneyEntry {
                ts: last,
                kind: "decision".to_string(),
                data: serde_json::json!({"action_type": "block_ip"}),
            },
        ];
        let first_seen = entries.first().map(|e| e.ts);
        let last_seen = entries.last().map(|e| e.ts);
        assert_eq!(first_seen, Some(first));
        assert_eq!(last_seen, Some(last));
        assert_eq!((last - first).num_minutes(), 10);
    }

    #[test]
    fn test_describe_chapter_response_summary_pluralization() {
        // Keeps response chapter summary stable for multiple incidents.
        let ts = Utc::now();
        let entries = vec![
            JourneyEntry {
                ts,
                kind: "incident".to_string(),
                data: serde_json::json!({"title": "Incident A"}),
            },
            JourneyEntry {
                ts,
                kind: "incident".to_string(),
                data: serde_json::json!({"title": "Incident B"}),
            },
        ];
        let (_, summary, _) = describe_chapter("response", &entries);
        assert_eq!(summary, "2 detector incident(s) raised");
    }

    #[test]
    fn test_build_pivot_shortcuts_no_duplicates() {
        // Guarantees shortcut list remains deduplicated when subject repeats in related sets.
        let mut related_ips = BTreeSet::new();
        related_ips.insert("1.2.3.4".to_string());
        let mut related_users = BTreeSet::new();
        related_users.insert("alice".to_string());
        let mut related_detectors = BTreeSet::new();
        related_detectors.insert("ssh_bruteforce".to_string());
        let shortcuts = build_pivot_shortcuts(
            PivotKind::Ip,
            "1.2.3.4",
            &related_ips,
            &related_users,
            &related_detectors,
        );
        let unique = shortcuts.iter().collect::<BTreeSet<_>>();
        assert_eq!(shortcuts.len(), unique.len());
    }

    #[test]
    fn test_describe_chapter_honeypot_highlights_extract_credentials() {
        // Checks credential highlights extraction from honeypot auth attempts.
        let ts = Utc::now();
        let entries = vec![JourneyEntry {
            ts,
            kind: "honeypot_ssh".to_string(),
            data: serde_json::json!({
                "auth_attempts": [
                    {"username": "root", "password": "toor"}
                ]
            }),
        }];
        let (_, _, highlights) = describe_chapter("honeypot_interaction", &entries);
        assert_eq!(highlights, vec!["root/toor".to_string()]);
    }

    // ─── Detector-pivot journey tests ──────────────────────────────────
    //
    // Cover `build_detector_journey` — the path exercised when the
    // operator clicks a detector group (e.g. `sigma`) from the Threats
    // tab. Previously the handler short-circuited to `empty_journey`
    // and the drill-down was blank; regression-guard the new aggregator.

    fn detector_test_incident(
        detector: &str,
        ip: Option<&str>,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: format!("{detector}:probe:test-{}", detector.len()),
            severity: innerwarden_core::event::Severity::High,
            title: format!("{detector} fired"),
            summary: format!("{detector} summary"),
            evidence: serde_json::json!([]),
            recommended_checks: vec![],
            tags: vec![],
            entities: match ip {
                Some(ip) => vec![innerwarden_core::entities::EntityRef::ip(ip)],
                None => vec![],
            },
        }
    }

    #[test]
    fn detector_journey_empty_graph_returns_unknown_outcome() {
        let graph = crate::knowledge_graph::KnowledgeGraph::new();
        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        assert_eq!(journey.subject_type, "detector");
        assert_eq!(journey.subject, "sigma");
        assert_eq!(journey.outcome, "unknown");
        assert!(journey.entries.is_empty());
        assert!(journey.first_seen.is_none());
        assert!(journey.last_seen.is_none());
    }

    #[test]
    fn detector_journey_collects_incidents_matching_detector_name() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", Some("198.51.100.9"));
        graph.ingest_incident(&inc);
        // A non-matching detector must not pollute the journey
        let other = detector_test_incident("proto_anomaly", Some("198.51.100.10"));
        graph.ingest_incident(&other);

        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        assert_eq!(
            journey.entries.len(),
            1,
            "only matching detector should appear"
        );
        assert_eq!(journey.outcome, "active");
        // IP from TriggeredBy edge must surface in pivot shortcuts
        assert!(
            journey
                .summary
                .pivot_shortcuts
                .iter()
                .any(|t| t.contains("198.51.100.9")),
            "related IP should be in pivot shortcuts"
        );
    }

    #[test]
    fn detector_journey_skips_research_only_incidents() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let mut inc = detector_test_incident("sigma", None);
        inc.incident_id = "sigma:research:x".to_string();
        graph.ingest_incident(&inc);
        // Flip research_only after ingest
        {
            let id = graph
                .find_by_incident("sigma:research:x")
                .expect("incident node");
            if let Some(crate::knowledge_graph::types::Node::Incident { research_only, .. }) =
                graph.get_node_mut(id)
            {
                *research_only = true;
            }
        }

        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        assert!(
            journey.entries.is_empty(),
            "research-only incidents must not appear in operator journey"
        );
        assert_eq!(journey.outcome, "unknown");
    }

    #[test]
    fn detector_journey_outcome_reflects_decision_block_ip() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", Some("198.51.100.11"));
        graph.ingest_incident(&inc);
        graph.ingest_decision(
            &inc.incident_id,
            "block_ip",
            Some("198.51.100.11"),
            0.9,
            "unit test",
            true,
            Utc::now(),
        );
        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        // incident + decision entries
        assert_eq!(journey.entries.len(), 2);
        assert_eq!(journey.outcome, "blocked");
    }

    #[test]
    fn detector_journey_outcome_reflects_decision_honeypot() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", None);
        graph.ingest_incident(&inc);
        graph.ingest_decision(
            &inc.incident_id,
            "honeypot",
            None,
            0.8,
            "unit test",
            true,
            Utc::now(),
        );
        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        assert_eq!(journey.outcome, "honeypot");
    }

    #[test]
    fn detector_journey_outcome_reflects_decision_monitor() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", None);
        graph.ingest_incident(&inc);
        graph.ingest_decision(
            &inc.incident_id,
            "monitor",
            None,
            0.7,
            "unit test",
            true,
            Utc::now(),
        );
        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        assert_eq!(journey.outcome, "monitoring");
    }

    #[test]
    fn detector_journey_collects_triggered_user_and_ignores_non_triggered_entities() {
        use crate::knowledge_graph::types::{Edge, Relation};

        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", Some("198.51.100.9"));
        graph.ingest_incident(&inc);
        let inc_id = graph
            .find_by_incident(&inc.incident_id)
            .expect("incident node should exist");
        let user_id = graph.ensure_user("alice");
        let ignored_ip_id = graph.ensure_ip("203.0.113.88", Utc::now());
        let other_id = graph.ensure_file("/tmp/ignored-evidence");
        let now = Utc::now();

        graph.add_edge(Edge::new(inc_id, user_id, Relation::TriggeredBy, now));
        graph.add_edge(Edge::new(
            inc_id,
            ignored_ip_id,
            Relation::CorrelatedWith,
            now,
        ));
        graph.add_edge(Edge::new(inc_id, other_id, Relation::TriggeredBy, now));

        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        assert!(
            journey
                .summary
                .pivot_shortcuts
                .iter()
                .any(|s| s == "user:alice"),
            "TriggeredBy User must be included as related user"
        );
        assert!(
            !journey
                .summary
                .pivot_shortcuts
                .iter()
                .any(|s| s == "ip:203.0.113.88"),
            "non-TriggeredBy edges must not contribute related entities"
        );
    }

    #[test]
    fn detector_journey_unknown_decision_falls_back_to_open() {
        // 2026-04-29: pre-contract this test asserted "active" for
        // an unknown decision string. The audit (RC-2) consolidated
        // the outcome vocabulary on `OUTCOME_OPEN` for any decision
        // that does not resolve to a known action, including
        // forward-compat unknowns. The journey UI (helpers.js
        // `outcomeBadgeHtml`) already maps both "open" and "active"
        // to the same "OBSERVING" badge, so the rename is
        // operator-invisible -- only the contract layer changes.
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", None);
        graph.ingest_incident(&inc);
        graph.ingest_decision(
            &inc.incident_id,
            "escalate_manually",
            None,
            0.5,
            "unit test",
            false,
            Utc::now(),
        );
        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", None);
        assert_eq!(journey.outcome, "open");
    }

    #[test]
    fn detector_journey_window_trims_old_entries() {
        // Two incidents: one recent, one > 1 hour old. Window 600s keeps
        // only the recent one.
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let old = innerwarden_core::incident::Incident {
            ts: Utc::now() - chrono::Duration::hours(2),
            incident_id: "sigma:old:x".to_string(),
            ..detector_test_incident("sigma", None)
        };
        let recent = detector_test_incident("sigma", None);
        graph.ingest_incident(&old);
        graph.ingest_incident(&recent);

        let dir = TempDir::new().expect("tmpdir");
        let journey = build_detector_journey(&graph, dir.path(), "2026-04-18", "sigma", Some(600));
        // Window drops the 2h-old incident, leaves just the fresh one.
        assert_eq!(journey.entries.len(), 1);
    }

    #[test]
    fn build_journey_from_graph_detector_pivot_uses_detector_path() {
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", Some("198.51.100.77"));
        graph.ingest_incident(&inc);
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let filters = InvestigationFilters::from_query(None, None);
        let dir = TempDir::new().expect("tmpdir");

        let journey = build_journey_from_graph(
            &kg,
            dir.path(),
            "2026-04-18",
            PivotKind::Detector,
            "sigma",
            &filters,
            None,
            None,
        );

        assert_eq!(journey.subject_type, "detector");
        assert_eq!(journey.subject, "sigma");
        assert_eq!(journey.entries.len(), 1);
        assert_eq!(journey.outcome, "active");
    }

    // ── Bug fix: journey misclassification of plain HTTP/TCP events ──

    #[test]
    fn is_login_attempt_kind_matches_login_event_families() {
        for k in [
            "ssh.login_failed",
            "auth.login_failure",
            "login_attempt",
            "ssh.invalid_user",
            "credential_stuffing.burst",
            "ssh_bruteforce",
            "password_attempt.shadow",
        ] {
            assert!(is_login_attempt_kind(k), "{k} should be a login attempt");
        }
    }

    #[test]
    fn is_login_attempt_kind_rejects_generic_traffic() {
        for k in [
            "http.request",
            "tcp_stream.ssh",
            "file.read_access",
            "dns.query",
            "ssh.login_success",
        ] {
            assert!(
                !is_login_attempt_kind(k),
                "{k} should NOT be classified as a login attempt"
            );
        }
    }

    #[test]
    fn derive_chapters_groups_plain_http_as_observed_activity_not_brute_force() {
        // Reproduces the prod 2026-04-22 IP 160.119.76.50 journey:
        // four HTTP GETs to public paths used to render as
        // "Brute-force burst (4 attempts)" / "Login attempt(s)".
        // After the fix they belong in `observed_activity` with a
        // neutral title.
        let ts = Utc.with_ymd_and_hms(2026, 4, 22, 16, 51, 54).unwrap();
        let entries = vec![
            JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "http.request"}),
            },
            JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "http.request"}),
            },
            JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "http.request"}),
            },
            JourneyEntry {
                ts,
                kind: "event".to_string(),
                data: serde_json::json!({"event_kind": "http.request"}),
            },
        ];

        let chapters = derive_chapters(&entries);
        assert_eq!(chapters.len(), 1);
        let ch = &chapters[0];
        assert_eq!(ch.stage, "observed_activity");
        assert!(
            !ch.title.contains("Brute-force"),
            "title leaked old brute-force wording: {}",
            ch.title
        );
        assert!(
            !ch.title.contains("Login"),
            "title still claims login: {}",
            ch.title
        );
        assert!(
            ch.title.contains("Observed activity"),
            "title should be neutral, got {}",
            ch.title
        );
    }

    #[test]
    fn derive_chapters_keeps_real_login_failures_as_initial_access_attempt() {
        // Make sure the fix did not silence real brute-force grouping.
        let ts = Utc.with_ymd_and_hms(2026, 4, 22, 16, 51, 54).unwrap();
        let entries: Vec<JourneyEntry> = (0..5)
            .map(|i| JourneyEntry {
                ts: ts + chrono::Duration::seconds(i),
                kind: "event".to_string(),
                data: serde_json::json!({
                    "event_kind": "ssh.login_failed",
                    "details": {"user": format!("user{i}")}
                }),
            })
            .collect();

        let chapters = derive_chapters(&entries);
        assert_eq!(chapters.len(), 1);
        let ch = &chapters[0];
        assert_eq!(ch.stage, "initial_access_attempt");
        assert!(ch.title.contains("Brute-force burst"));
    }

    // ── Bug fix: contradictory hints (Not dangerous + AI has blocked) ──

    fn ip_journey_with_block(blocked: bool) -> JourneyResponse {
        // Real call path: build_journey_from_graph runs the IP-pivot
        // intelligence enrichment that the bug actually lives in.
        // Going through build_journey_summary directly would skip
        // it, which is why my first attempt at this test failed.
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let mut inc = detector_test_incident("packet_flood", Some("160.119.76.50"));
        inc.incident_id = "packet_flood:rate_anomaly:2026-04-22".into();
        graph.ingest_incident(&inc);
        if blocked {
            graph.ingest_decision(
                &inc.incident_id,
                "block_ip",
                Some("160.119.76.50"),
                0.95,
                "Auto-blocked: packet_flood (rule-based)",
                true,
                chrono::Utc::now(),
            );
        }

        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let filters = InvestigationFilters::from_query(None, None);
        let dir = TempDir::new().expect("tmpdir");
        build_journey_from_graph(
            &kg,
            dir.path(),
            &chrono::Utc::now().date_naive().to_string(),
            PivotKind::Ip,
            "160.119.76.50",
            &filters,
            None,
            None,
        )
    }

    #[test]
    fn ip_summary_does_not_emit_not_dangerous_when_blocked() {
        // Reproduces the contradiction the operator flagged on
        // 2026-04-22: same journey said "Not dangerous" AND "AI has
        // blocked this IP". After the fix, "Not dangerous" must not
        // appear when the IP is blocked.
        let journey = ip_journey_with_block(true);
        let joined = journey.summary.hints.join(" || ");
        assert!(
            !joined.contains("Not dangerous"),
            "hints contradict outcome (blocked + Not dangerous): {joined}"
        );
        assert!(
            joined.contains("possible false positive") || joined.contains("AI has blocked"),
            "expected FP-review hint or block confirmation, got: {joined}"
        );
    }

    #[test]
    fn ip_summary_emits_low_activity_only_when_not_blocked() {
        let journey = ip_journey_with_block(false);
        let joined = journey.summary.hints.join(" || ");
        assert!(
            joined.contains("Low activity") || joined.contains("Routine scanner"),
            "expected low-activity hint when not blocked, got: {joined}"
        );
    }

    // ── build_pivots_from_graph filter behavior (Inconsistencies 2 + 3) ─
    //
    // Anchors for two complementary fixes:
    //   - Inconsistency 2: incidents that pass `is_internal_incident_fields`
    //     (advisory-only detectors, IW-system processes) must be excluded.
    //   - Inconsistency 3: operator-supplied severity_min and detector
    //     filters must narrow the result set.

    fn make_kg_with_attackers(
    ) -> std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>> {
        use crate::knowledge_graph::types::*;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let now = Utc::now();
        // External IP, ssh_bruteforce HIGH — should pass all filters.
        let ip_a = g.ensure_ip("203.0.113.10", now);
        let inc_a_id = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:1".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "SSH brute force from 203.0.113.10".into(),
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
        g.add_edge(Edge::new(inc_a_id, ip_a, Relation::TriggeredBy, now));
        // External IP, port_scan LOW — passes filter only without severity_min.
        let ip_b = g.ensure_ip("198.51.100.20", now);
        let inc_b_id = g.add_node(Node::Incident {
            incident_id: "port_scan:1".into(),
            detector: "port_scan".into(),
            severity: "low".into(),
            title: "Port scan from 198.51.100.20".into(),
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
        g.add_edge(Edge::new(inc_b_id, ip_b, Relation::TriggeredBy, now));
        // Advisory-only detector — must be EXCLUDED by Inconsistency 2 fix.
        let ip_c = g.ensure_ip("192.0.2.30", now);
        let inc_c_id = g.add_node(Node::Incident {
            incident_id: "neural_anomaly:1".into(),
            detector: "neural_anomaly".into(),
            severity: "high".into(),
            title: "Neural anomaly".into(),
            summary: "".into(),
            ts: now,
            mitre_ids: vec![],
            decision: None,
            decision_target: None,
            confidence: None,
            decision_reason: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_c_id, ip_c, Relation::TriggeredBy, now));
        std::sync::Arc::new(std::sync::RwLock::new(g))
    }

    #[test]
    fn build_pivots_from_graph_excludes_advisory_only_detectors() {
        let kg = make_kg_with_attackers();
        let items = build_pivots_from_graph(&kg, PivotKind::Ip, 100, &Default::default(), None);
        // 2 attackers should remain (ssh + port_scan). neural_anomaly is filtered.
        let ips: std::collections::HashSet<&str> = items.iter().map(|p| p.value.as_str()).collect();
        assert!(ips.contains("203.0.113.10"));
        assert!(ips.contains("198.51.100.20"));
        assert!(
            !ips.contains("192.0.2.30"),
            "neural_anomaly is advisory-only and must not appear as an attacker"
        );
    }

    #[test]
    fn build_pivots_from_graph_severity_min_filter_narrows_results() {
        let kg = make_kg_with_attackers();
        let high_only = InvestigationFilters::from_query(Some("high"), None);
        let items = build_pivots_from_graph(&kg, PivotKind::Ip, 100, &high_only, None);
        let ips: std::collections::HashSet<&str> = items.iter().map(|p| p.value.as_str()).collect();
        assert!(
            ips.contains("203.0.113.10"),
            "ssh_bruteforce HIGH should pass"
        );
        assert!(
            !ips.contains("198.51.100.20"),
            "port_scan LOW must be filtered when severity_min=high"
        );
    }

    #[test]
    fn build_pivots_from_graph_detector_filter_narrows_results() {
        let kg = make_kg_with_attackers();
        let ssh_only = InvestigationFilters::from_query(None, Some("ssh"));
        let items = build_pivots_from_graph(&kg, PivotKind::Ip, 100, &ssh_only, None);
        let ips: std::collections::HashSet<&str> = items.iter().map(|p| p.value.as_str()).collect();
        assert!(
            ips.contains("203.0.113.10"),
            "ssh_bruteforce should match detector=ssh"
        );
        assert!(
            !ips.contains("198.51.100.20"),
            "port_scan must not match detector=ssh"
        );
    }

    #[test]
    fn build_pivots_from_graph_combined_filters_intersect() {
        let kg = make_kg_with_attackers();
        let critical_ssh = InvestigationFilters::from_query(Some("critical"), Some("ssh"));
        let items = build_pivots_from_graph(&kg, PivotKind::Ip, 100, &critical_ssh, None);
        // No ssh incident is critical-severity → empty.
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn api_entities_async_handler_applies_filters() {
        // Anchors the api_entities async handler — proves the
        // EntitiesQuery → InvestigationFilters → build_attackers_from_graph
        // wiring is reachable end-to-end.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        // Replace the empty graph with the fixture from the helper above.
        state.knowledge_graph = make_kg_with_attackers();

        let q = EntitiesQuery {
            limit: Some(50),
            date: None,
            severity_min: Some("high".to_string()),
            detector: None,
            group_by: None,
        };
        let Json(resp) = api_entities(State(state), Query(q)).await;
        let ips: std::collections::HashSet<&str> =
            resp.attackers.iter().map(|a| a.ip.as_str()).collect();
        assert!(ips.contains("203.0.113.10"));
        assert!(!ips.contains("198.51.100.20"));
    }

    #[tokio::test]
    async fn api_pivots_async_handler_applies_filters() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        state.knowledge_graph = make_kg_with_attackers();

        let q = EntitiesQuery {
            limit: Some(50),
            date: None,
            severity_min: None,
            detector: Some("ssh".to_string()),
            group_by: Some("ip".to_string()),
        };
        let Json(resp) = api_pivots(State(state), Query(q)).await;
        let values: std::collections::HashSet<&str> =
            resp.items.iter().map(|p| p.value.as_str()).collect();
        assert!(values.contains("203.0.113.10"));
        assert!(!values.contains("198.51.100.20"));
        assert_eq!(resp.group_by, "ip");
        assert_eq!(resp.total, resp.items.len());
    }

    #[test]
    fn build_attackers_from_graph_forwards_filters() {
        let kg = make_kg_with_attackers();
        let high = InvestigationFilters::from_query(Some("high"), None);
        let attackers = build_attackers_from_graph(&kg, 100, &high, None, None);
        let ips: std::collections::HashSet<&str> =
            attackers.iter().map(|a| a.ip.as_str()).collect();
        assert!(ips.contains("203.0.113.10"));
        assert!(!ips.contains("198.51.100.20"));
    }

    // ── Phase 6 anchors: attackers list from SQLite, KG-eviction-resistant ──
    //
    // The pre-Phase-6 Threats list iterated the in-memory KG. By
    // afternoon TTL eviction had culled most of the day's attackers,
    // and the operator saw "Home: 22 handled / Threats list: 1 IP"
    // (99% drift, prod 2026-04-29). These anchors lock the SQLite
    // path so any future revert is caught.

    fn insert_attacker_test_incident(
        store: &innerwarden_store::Store,
        incident_id: &str,
        ts_iso: &str,
        severity: &str,
        title: &str,
        ip: &str,
    ) {
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;
        let sev = match severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let inc = Incident {
            ts: chrono::DateTime::parse_from_rfc3339(ts_iso)
                .unwrap()
                .with_timezone(&Utc),
            host: "test-host".into(),
            incident_id: incident_id.into(),
            severity: sev,
            title: title.into(),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        store.insert_incident(&inc).expect("insert");
    }

    fn insert_attacker_test_decision(
        store: &innerwarden_store::Store,
        incident_id: &str,
        ts_iso: &str,
        action: &str,
        ip: &str,
    ) {
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts_iso.into(),
            incident_id: incident_id.into(),
            action_type: action.into(),
            target_ip: Some(ip.into()),
            target_user: None,
            confidence: 1.0,
            auto_executed: true,
            reason: Some("test".into()),
            data: serde_json::json!({"action_type": action}).to_string(),
        };
        store.insert_decision(&row).expect("insert");
    }

    #[test]
    fn build_attackers_from_sqlite_returns_all_external_ips_for_date() {
        // The motivating regression: 110 unique IPs fired today on
        // prod, KG showed 1 because TTL eviction culled the rest.
        // SQLite path must return ALL of today's external IPs.
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-29";
        // 3 different external IPs across 4 incidents.
        insert_attacker_test_incident(
            &store,
            "ssh:bf:1",
            "2026-04-29T01:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.10",
        );
        insert_attacker_test_decision(
            &store,
            "ssh:bf:1",
            "2026-04-29T01:00:01Z",
            "block_ip",
            "203.0.113.10",
        );
        insert_attacker_test_incident(
            &store,
            "ssh:bf:2",
            "2026-04-29T05:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.10",
        );
        insert_attacker_test_decision(
            &store,
            "ssh:bf:2",
            "2026-04-29T05:00:01Z",
            "block_ip",
            "203.0.113.10",
        );
        insert_attacker_test_incident(
            &store,
            "ssh:bf:3",
            "2026-04-29T06:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.20",
        );
        insert_attacker_test_decision(
            &store,
            "ssh:bf:3",
            "2026-04-29T06:00:01Z",
            "monitor",
            "203.0.113.20",
        );
        insert_attacker_test_incident(
            &store,
            "ssh:bf:4",
            "2026-04-29T11:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.30",
        );
        // No decision for ssh:bf:4 -> open.
        // Yesterday's incident must NOT leak.
        insert_attacker_test_incident(
            &store,
            "ssh:bf:old",
            "2026-04-28T22:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.99",
        );

        let filters = InvestigationFilters::from_query(None, None);
        let attackers = build_attackers_from_sqlite(&store, date, &filters, 100)
            .expect("sqlite path returns Some");
        let ips: std::collections::HashSet<&str> =
            attackers.iter().map(|a| a.ip.as_str()).collect();
        assert_eq!(attackers.len(), 3, "today's 3 unique IPs (not yesterday)");
        assert!(ips.contains("203.0.113.10"));
        assert!(ips.contains("203.0.113.20"));
        assert!(ips.contains("203.0.113.30"));
        assert!(!ips.contains("203.0.113.99"), "yesterday must not leak");
        // 203.0.113.10 had 2 incidents.
        let ip10 = attackers
            .iter()
            .find(|a| a.ip == "203.0.113.10")
            .expect("ip10");
        assert_eq!(ip10.incident_count, 2);
        // Aggregate outcome for IP-with-block_ip-decisions = blocked.
        assert_eq!(ip10.outcome, "blocked");
    }

    #[test]
    fn build_attackers_from_sqlite_excludes_internal_ips() {
        // RFC 1918 IPs must be excluded -- otherwise the operator
        // sees their own server's outbound NAT IP as an attacker.
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-29";
        insert_attacker_test_incident(
            &store,
            "ssh:internal",
            "2026-04-29T01:00:00Z",
            "high",
            "ssh brute",
            "10.0.0.5",
        );
        insert_attacker_test_incident(
            &store,
            "ssh:external",
            "2026-04-29T02:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.10",
        );
        let filters = InvestigationFilters::from_query(None, None);
        let attackers = build_attackers_from_sqlite(&store, date, &filters, 100)
            .expect("sqlite path returns Some");
        let ips: Vec<&str> = attackers.iter().map(|a| a.ip.as_str()).collect();
        assert_eq!(ips, vec!["203.0.113.10"]);
    }

    #[test]
    fn build_attackers_from_sqlite_routes_allowlisted_to_own_outcome() {
        // Phase 7 anchor: when at least one of an IP's incidents is
        // flagged is_allowlisted=1, the aggregate outcome MUST be
        // "allowlisted" so the Threats list renders the dedicated
        // group instead of inflating "needs_attention". Pre-Phase-7
        // the IP would have shown up under "needs_attention" because
        // the allowlist branch never wrote a decision.
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-29";
        insert_attacker_test_incident(
            &store,
            "ssh:trusted",
            "2026-04-29T01:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.10",
        );
        // Simulate the agent fast loop's SkipAllowlisted branch.
        store
            .set_incident_allowlisted("ssh:trusted")
            .expect("set allowlisted");
        // A second IP, NOT allowlisted, with a real block decision —
        // must coexist as a "blocked" attacker without contaminating
        // the allowlisted bucket.
        insert_attacker_test_incident(
            &store,
            "ssh:hostile",
            "2026-04-29T02:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.20",
        );
        insert_attacker_test_decision(
            &store,
            "ssh:hostile",
            "2026-04-29T02:00:01Z",
            "block_ip",
            "203.0.113.20",
        );

        let filters = InvestigationFilters::from_query(None, None);
        let attackers = build_attackers_from_sqlite(&store, date, &filters, 100)
            .expect("sqlite path returns Some");
        let trusted = attackers
            .iter()
            .find(|a| a.ip == "203.0.113.10")
            .expect("trusted IP present");
        assert_eq!(
            trusted.outcome, "allowlisted",
            "IP whose incident was allowlisted must surface as outcome=allowlisted"
        );
        let hostile = attackers
            .iter()
            .find(|a| a.ip == "203.0.113.20")
            .expect("hostile IP present");
        assert_eq!(
            hostile.outcome, "blocked",
            "non-allowlisted IP keeps its real outcome"
        );
    }

    // ── Phase 12 anchors: pivots from SQLite (User + Detector) ────────
    //
    // Phase 6 migrated /api/entities (IP pivot only) to SQLite, but
    // /api/pivots (User + Detector) was still reading from the lossy
    // KG. With operator's severity=critical filter, the lossy KG
    // returned 0 because today's earlier critical incidents got
    // TTL-evicted, and the empty list rendered the "No incidents on
    // YYYY-MM-DD / Pick a date" diagnostic — even though SQLite
    // had the incidents intact. These anchors prove the SQLite path
    // returns the right groupings under severity filter.

    #[test]
    fn build_pivots_from_sqlite_user_groups_under_severity_filter() {
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-29";
        // Insert a CRITICAL incident with both an IP and a user entity.
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;
        let inc = Incident {
            ts: chrono::DateTime::parse_from_rfc3339("2026-04-29T01:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            host: "h".into(),
            incident_id: "ssh:bf:1".into(),
            severity: Severity::Critical,
            title: "ssh brute".into(),
            summary: "x".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("alice")],
        };
        store.insert_incident(&inc).expect("insert");
        // Also insert a LOW incident that must NOT appear under the
        // critical filter — proves filter actually narrows.
        let inc_low = Incident {
            ts: chrono::DateTime::parse_from_rfc3339("2026-04-29T02:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            host: "h".into(),
            incident_id: "noise:1".into(),
            severity: Severity::Low,
            title: "noise".into(),
            summary: "x".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.20"), EntityRef::user("bob")],
        };
        store.insert_incident(&inc_low).expect("insert");

        let critical_filter = InvestigationFilters::from_query(Some("critical"), None);
        let users = build_pivots_from_sqlite(&store, date, PivotKind::User, &critical_filter, 100)
            .expect("user pivot returns Some");
        let names: Vec<&str> = users.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(names, vec!["alice"], "only user from critical incident");
    }

    #[test]
    fn build_pivots_from_sqlite_user_drops_unknown_placeholder() {
        // RC-2 follow-up (2026-04-30): incidents whose User EntityRef
        // is the literal string "unknown" (sentinel for "could not
        // resolve a real account") must NOT appear in the User pivot.
        // Prod showed 11 incidents whose only user entity was
        // "unknown" — the operator saw a dominant bogus bucket. This
        // anchor reproduces the case (mixed real + placeholder users)
        // and pins the dashboard fix.
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-30";
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;
        let inc_real = Incident {
            ts: chrono::DateTime::parse_from_rfc3339("2026-04-30T01:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            host: "h".into(),
            incident_id: "real:1".into(),
            severity: Severity::High,
            title: "real user".into(),
            summary: "x".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };
        let inc_placeholder = Incident {
            ts: chrono::DateTime::parse_from_rfc3339("2026-04-30T02:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            host: "h".into(),
            incident_id: "ph:1".into(),
            severity: Severity::High,
            title: "placeholder user".into(),
            summary: "x".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.11"), EntityRef::user("unknown")],
        };
        // Mixed-case placeholder must also be dropped.
        let inc_uppercase = Incident {
            ts: chrono::DateTime::parse_from_rfc3339("2026-04-30T03:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            host: "h".into(),
            incident_id: "ph:2".into(),
            severity: Severity::High,
            title: "uppercase placeholder".into(),
            summary: "x".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.12"), EntityRef::user("Unknown")],
        };
        store.insert_incident(&inc_real).expect("insert real");
        store
            .insert_incident(&inc_placeholder)
            .expect("insert placeholder");
        store
            .insert_incident(&inc_uppercase)
            .expect("insert uppercase placeholder");

        let no_filter = InvestigationFilters::from_query(None, None);
        let users = build_pivots_from_sqlite(&store, date, PivotKind::User, &no_filter, 100)
            .expect("user pivot returns Some");
        let names: Vec<&str> = users.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(
            names,
            vec!["root"],
            "only the real account survives — both 'unknown' and 'Unknown' filtered"
        );
    }

    #[test]
    fn build_pivots_from_sqlite_detector_groups_under_severity_filter() {
        // Same scenario, detector pivot. Critical kill_chain incident
        // must surface under critical filter; low proto_anomaly must
        // not.
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-29";
        insert_attacker_test_incident(
            &store,
            "kill_chain:detected:1",
            "2026-04-29T01:00:00Z",
            "critical",
            "Kill chain DATA_EXFIL",
            "203.0.113.10",
        );
        insert_attacker_test_incident(
            &store,
            "proto_anomaly:weird",
            "2026-04-29T02:00:00Z",
            "low",
            "weird ssh",
            "203.0.113.20",
        );
        let critical_filter = InvestigationFilters::from_query(Some("critical"), None);
        let detectors =
            build_pivots_from_sqlite(&store, date, PivotKind::Detector, &critical_filter, 100)
                .expect("detector pivot");
        let labels: Vec<&str> = detectors.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(labels, vec!["kill_chain"], "only critical detector");
    }

    #[tokio::test]
    async fn api_pivots_falls_back_to_sqlite_when_kg_evicted() {
        // End-to-end through api_pivots: KG empty (post-eviction),
        // SQLite has incidents. The handler must surface them.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let today = chrono::Utc::now().date_naive().to_string();
        let ts = format!("{today}T01:00:00Z");
        insert_attacker_test_incident(
            &store,
            "kill_chain:detected:1",
            &ts,
            "critical",
            "Kill chain DATA_EXFIL",
            "203.0.113.10",
        );
        state.sqlite_store = Some(store);
        let q = EntitiesQuery {
            limit: Some(100),
            date: None,
            severity_min: Some("critical".to_string()),
            detector: None,
            group_by: Some("detector".to_string()),
        };
        let Json(resp) = api_pivots(State(state), Query(q)).await;
        assert_eq!(
            resp.items.len(),
            1,
            "SQLite must surface critical detector even with empty KG"
        );
        assert_eq!(resp.items[0].value, "kill_chain");
    }

    #[tokio::test]
    async fn api_entities_uses_sqlite_when_kg_evicted() {
        // End-to-end: graph empty (TTL eviction simulated), SQLite has
        // attackers. The handler must return them from SQLite, not 0.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let today = chrono::Utc::now().date_naive().to_string();
        let ts = format!("{today}T01:00:00Z");
        insert_attacker_test_incident(&store, "ssh:1", &ts, "high", "ssh brute", "203.0.113.10");
        insert_attacker_test_decision(
            &store,
            "ssh:1",
            &format!("{today}T01:00:01Z"),
            "block_ip",
            "203.0.113.10",
        );
        state.sqlite_store = Some(store);
        // KG stays empty -> simulates the post-eviction state.
        let q = EntitiesQuery {
            limit: Some(50),
            date: None,
            severity_min: None,
            detector: None,
            group_by: None,
        };
        let Json(resp) = api_entities(State(state), Query(q)).await;
        assert_eq!(resp.attackers.len(), 1, "must return SQLite attacker");
        assert_eq!(resp.attackers[0].ip, "203.0.113.10");
        assert_eq!(resp.attackers[0].outcome, "blocked");
    }

    // ── Phase 8 anchors: journey from SQLite, RC-2 fourth surface ─────
    //
    // The 2026-04-29 17:00 incident: Threats list correctly showed
    // 197.243.0.62 as an attacker (Phase 6 reads SQLite), but
    // clicking the row landed on an empty journey because
    // `build_journey_from_graph` bailed on KG center-node miss.
    // SQLite had 2 incidents + 3 decisions for the IP. Phase 8
    // makes the journey path SQLite-aware so the operator drills
    // into the real history regardless of KG TTL eviction state.

    #[test]
    fn build_journey_from_sqlite_returns_incidents_and_decisions_for_subject_ip() {
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-29";
        // 2 incidents on the target IP, 1 decision.
        insert_attacker_test_incident(
            &store,
            "ssh:bf:1",
            "2026-04-29T01:00:00Z",
            "high",
            "ssh brute",
            "203.0.113.10",
        );
        insert_attacker_test_incident(
            &store,
            "ti:1",
            "2026-04-29T01:30:00Z",
            "high",
            "threat intel match",
            "203.0.113.10",
        );
        insert_attacker_test_decision(
            &store,
            "ssh:bf:1",
            "2026-04-29T01:00:01Z",
            "block_ip",
            "203.0.113.10",
        );
        // A different IP — must NOT leak into the journey.
        insert_attacker_test_incident(
            &store,
            "other:1",
            "2026-04-29T02:00:00Z",
            "high",
            "scan",
            "198.51.100.20",
        );

        let journey = build_journey_from_sqlite(&store, date, PivotKind::Ip, "203.0.113.10", None)
            .expect("journey returned");
        // PR #423 Wave 4c: incidents without an associated decision
        // now emit a `decision_missing` placeholder so the audit gap
        // is visible. Counts: 2 incidents + 1 real decision (for
        // ssh:bf:1) + 1 decision_missing placeholder (for ti:1) = 4.
        assert_eq!(
            journey.entries.len(),
            4,
            "2 incidents + 1 decision + 1 decision_missing = 4 entries"
        );
        // Outcome from aggregate_outcomes: any block_ip wins.
        assert_eq!(journey.outcome, "blocked");
        // Decision entry exists and references the right action.
        let has_block_decision = journey.entries.iter().any(|e| {
            e.kind == "decision"
                && e.data.get("action_type").and_then(|v| v.as_str()) == Some("block_ip")
        });
        assert!(has_block_decision);
        // The other incident (ti:1, no decision) gets a placeholder.
        let has_missing = journey.entries.iter().any(|e| {
            e.kind == "decision_missing"
                && e.data.get("incident_id").and_then(|v| v.as_str()) == Some("ti:1")
        });
        assert!(has_missing, "ti:1 must have decision_missing placeholder");
    }

    #[test]
    fn build_journey_from_sqlite_returns_none_when_subject_absent() {
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let date = "2026-04-29";
        insert_attacker_test_incident(
            &store,
            "ssh:1",
            "2026-04-29T01:00:00Z",
            "high",
            "brute",
            "203.0.113.10",
        );
        // Subject is a different IP — no incidents reference it.
        let journey = build_journey_from_sqlite(&store, date, PivotKind::Ip, "198.51.100.99", None);
        assert!(journey.is_none(), "no entries for absent subject");
    }

    #[tokio::test]
    async fn api_journey_falls_back_to_sqlite_when_kg_missing_subject() {
        // End-to-end: KG is empty (post-eviction state), SQLite has
        // incidents+decisions for the IP. The handler must return
        // those entries instead of an empty journey. This is the
        // exact scenario the operator hit on 197.243.0.62.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let today = chrono::Utc::now().date_naive().to_string();
        let ts = format!("{today}T01:00:00Z");
        insert_attacker_test_incident(&store, "ssh:1", &ts, "high", "brute", "203.0.113.10");
        insert_attacker_test_decision(
            &store,
            "ssh:1",
            &format!("{today}T01:00:01Z"),
            "block_ip",
            "203.0.113.10",
        );
        state.sqlite_store = Some(store);
        // KG stays empty.
        let q = JourneyQuery {
            subject_type: Some("ip".to_string()),
            subject: Some("203.0.113.10".to_string()),
            ip: None,
            date: None,
            severity_min: None,
            detector: None,
            window_seconds: None,
        };
        let Json(resp) = api_journey(State(state), Query(q)).await;
        assert!(
            !resp.entries.is_empty(),
            "SQLite fallback must surface incident+decision entries"
        );
        assert_eq!(resp.outcome, "blocked");
    }

    // ── Phase 3 anchors: block_state plumbing on the IP pivot ──────────
    //
    // Two anchors covering the new SQLite-handle threading. Without
    // these the spawn_blocking wrap on `api_journey` and the
    // `Some(block_state_for_ip(...))` branch of build_journey_from_graph
    // are unreachable from the test suite, which is the exact dead
    // surface that codecov/patch flags.

    #[test]
    fn build_journey_from_graph_ip_pivot_with_sqlite_populates_block_state() {
        // Real call path: build_journey_from_graph is given a real
        // SQLite store with a kernel-level block entry for the
        // subject IP. The journey response must surface
        // BlockState::BlockedNow (not None, not Open) so the front
        // end can render the kernel-evidence badge.
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("packet_flood", Some("198.51.100.77"));
        graph.ingest_incident(&inc);
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let now = chrono::Utc::now();
        let payload = serde_json::json!({
            "blocked_at_ms": now.timestamp_millis() - 60_000,
            "ttl_secs": 3600,
        });
        store
            .kv_set(
                "xdp_block_times",
                "198.51.100.77",
                &serde_json::to_vec(&payload).unwrap(),
            )
            .expect("kv_set");

        let filters = InvestigationFilters::from_query(None, None);
        let dir = TempDir::new().expect("tmpdir");
        let journey = build_journey_from_graph(
            &kg,
            dir.path(),
            &now.date_naive().to_string(),
            PivotKind::Ip,
            "198.51.100.77",
            &filters,
            None,
            Some(&store),
        );

        match journey.block_state {
            Some(crate::dashboard::threat_contract::BlockState::BlockedNow { .. }) => {}
            other => panic!("expected BlockedNow, got {other:?}"),
        }
    }

    #[test]
    fn build_journey_from_graph_detector_pivot_leaves_block_state_none() {
        // Detector pivot has no single IP to query against
        // xdp_block_times. block_state must stay None so the front
        // end does not render a kernel-evidence badge for the
        // detector group as a whole.
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("sigma", Some("198.51.100.77"));
        graph.ingest_incident(&inc);
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));

        let filters = InvestigationFilters::from_query(None, None);
        let dir = TempDir::new().expect("tmpdir");
        let journey = build_journey_from_graph(
            &kg,
            dir.path(),
            "2026-04-29",
            PivotKind::Detector,
            "sigma",
            &filters,
            None,
            Some(&store),
        );

        assert!(
            journey.block_state.is_none(),
            "detector pivot must not carry a block_state, got {:?}",
            journey.block_state
        );
    }

    #[tokio::test]
    async fn api_journey_async_handler_threads_sqlite_to_journey_builder() {
        // Anchors the api_journey -> spawn_blocking -> sqlite-threaded
        // build_journey_from_graph wiring end-to-end. Without this
        // test the new spawn_blocking wrapper, the sqlite_store clone,
        // and the date/subject fallback path are all unexercised
        // from the test suite (which codecov/patch flagged on
        // PR #335).
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::dashboard::state::test_dashboard_state(dir.path());

        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let inc = detector_test_incident("packet_flood", Some("198.51.100.99"));
        graph.ingest_incident(&inc);
        state.knowledge_graph = std::sync::Arc::new(std::sync::RwLock::new(graph));

        let q = JourneyQuery {
            subject_type: Some("ip".to_string()),
            subject: Some("198.51.100.99".to_string()),
            ip: None,
            date: None,
            severity_min: None,
            detector: None,
            window_seconds: None,
        };
        let Json(resp) = api_journey(State(state), Query(q)).await;
        assert_eq!(resp.subject_type, "ip");
        assert_eq!(resp.subject, "198.51.100.99");
        // sqlite_store is None on test_dashboard_state, so the IP
        // pivot block_state must resolve to Open (the no-store
        // fallback in block_state_for_ip).
        match resp.block_state {
            Some(crate::dashboard::threat_contract::BlockState::Open) => {}
            other => panic!("expected Some(Open) when no sqlite store, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_journey_async_handler_empty_subject_short_circuits() {
        // The subject.is_empty() branch in api_journey returns the
        // hand-built JourneyResponse before reaching spawn_blocking.
        // This anchor covers the new `block_state: None` field on
        // that early return so a future struct change cannot drop
        // the field silently.
        let dir = TempDir::new().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let q = JourneyQuery {
            subject_type: Some("ip".to_string()),
            subject: Some(String::new()),
            ip: None,
            date: None,
            severity_min: None,
            detector: None,
            window_seconds: None,
        };
        let Json(resp) = api_journey(State(state), Query(q)).await;
        assert_eq!(resp.subject, "");
        assert!(resp.block_state.is_none());
    }

    // ── Spec 037 Threats data contract ─────────────────────────────────
    //
    // Three regression anchors for the bundle (date scoping + entity
    // backfill + detector-pivot semantic alignment). Each test seeds a
    // graph with a known shape, calls the production code path, and
    // asserts on observable behavior from the operator's perspective.

    fn make_kg_with_two_dates(
    ) -> std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>> {
        // Two ssh_bruteforce incidents on different days. The pivot
        // builders MUST honour the requested date and only return the
        // matching one.
        use crate::knowledge_graph::types::*;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let day1 = chrono::DateTime::parse_from_rfc3339("2026-04-26T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let day2 = chrono::DateTime::parse_from_rfc3339("2026-04-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let ip_old = g.ensure_ip("203.0.113.99", day1);
        let inc_old = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:old".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "SSH brute force from 203.0.113.99".into(),
            summary: "".into(),
            ts: day1,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("203.0.113.99".into()),
            confidence: Some(0.9),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_old, ip_old, Relation::TriggeredBy, day1));

        let ip_new = g.ensure_ip("198.51.100.77", day2);
        let inc_new = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:new".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "SSH brute force from 198.51.100.77".into(),
            summary: "".into(),
            ts: day2,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("198.51.100.77".into()),
            confidence: Some(0.9),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc_new, ip_new, Relation::TriggeredBy, day2));

        std::sync::Arc::new(std::sync::RwLock::new(g))
    }

    #[test]
    fn build_pivots_from_graph_scopes_to_requested_date_only() {
        // Anchor for: "prod path with date errado não retorna incidentes
        // fora do dia". Graph has incidents on 2026-04-26 and 2026-04-28.
        // Asking for 2026-04-28 must return ONLY the 198.51.100.77 IP.
        let kg = make_kg_with_two_dates();
        let items = build_pivots_from_graph(
            &kg,
            PivotKind::Ip,
            100,
            &Default::default(),
            Some("2026-04-28"),
        );
        let ips: std::collections::HashSet<&str> = items.iter().map(|p| p.value.as_str()).collect();
        assert!(
            ips.contains("198.51.100.77"),
            "today's incident must appear, got: {ips:?}"
        );
        assert!(
            !ips.contains("203.0.113.99"),
            "yesterday's incident must NOT appear when date=2026-04-28, got: {ips:?}"
        );
    }

    #[test]
    fn ingest_incident_derives_implicit_entities_when_entities_empty() {
        // Anchor for: "incident sem entities mas com IP no incident_id/
        // title/summary cria IP node + edge". Driving the production
        // ingest path with an entities-empty incident must still
        // produce graph linkage so the IP pivot surfaces it.
        use crate::knowledge_graph::types::{Node, NodeType};
        use innerwarden_core::incident::Incident;
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let ts = chrono::DateTime::parse_from_rfc3339("2026-04-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let incident = Incident {
            incident_id: "port_scan:198.51.100.123:2026-04-28T12:00Z".to_string(),
            host: "h".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "Port scan detected".to_string(),
            summary: "Source IP 198.51.100.123 scanned 50 ports".to_string(),
            ts,
            entities: vec![],
            tags: vec![],
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
        };
        g.ingest_incident(&incident);

        // The IP node must have been created.
        let ip_label_present = g.nodes_of_type(NodeType::Ip).iter().any(
            |&id| matches!(g.get_node(id), Some(Node::Ip { addr, .. }) if addr == "198.51.100.123"),
        );
        assert!(
            ip_label_present,
            "expected derived IP node 198.51.100.123 to exist after ingest"
        );

        // The TriggeredBy edge from Incident to IP must exist so the
        // IP pivot can find it.
        let kg = std::sync::Arc::new(std::sync::RwLock::new(g));
        let items = build_pivots_from_graph(
            &kg,
            PivotKind::Ip,
            100,
            &Default::default(),
            Some("2026-04-28"),
        );
        let ips: std::collections::HashSet<&str> = items.iter().map(|p| p.value.as_str()).collect();
        assert!(
            ips.contains("198.51.100.123"),
            "derived IP must surface in IP pivot, got: {ips:?}"
        );
    }

    #[test]
    fn detector_pivot_and_ip_pivot_share_same_date_filter_subset() {
        // Anchor for: "detector pivot e IP pivot respeitam o mesmo
        // date/filter subset". Both pivots must agree on which
        // incidents qualify; the contradiction reported by the
        // operator was the Detector pivot listing items that the IP
        // pivot had filtered out.
        let kg = make_kg_with_two_dates();
        let ip_items = build_pivots_from_graph(
            &kg,
            PivotKind::Ip,
            100,
            &Default::default(),
            Some("2026-04-28"),
        );
        let det_items = build_pivots_from_graph(
            &kg,
            PivotKind::Detector,
            100,
            &Default::default(),
            Some("2026-04-28"),
        );
        // Both pivots are scoped to 2026-04-28 only. The two-date
        // fixture has exactly one incident per day, so both pivots
        // must report incident_count == 1 for the same single day.
        let total_ip_incidents: usize = ip_items.iter().map(|p| p.incident_count).sum();
        let total_det_incidents: usize = det_items.iter().map(|p| p.incident_count).sum();
        assert_eq!(
            total_ip_incidents, total_det_incidents,
            "Detector and IP pivots must agree on the qualifying-incident count for the same date+filter; got IP={total_ip_incidents}, Detector={total_det_incidents}"
        );
        assert_eq!(
            total_ip_incidents, 1,
            "fixture has exactly one incident on 2026-04-28; got {total_ip_incidents}"
        );
        // Detector pivot must derive outcome from decisions, not
        // hardcode "active". The 2026-04-28 incident has decision=block_ip.
        assert_eq!(
            det_items
                .iter()
                .find(|p| p.value == "ssh_bruteforce")
                .map(|p| p.outcome.as_str()),
            Some("blocked"),
            "Detector pivot outcome must reflect the underlying decision, got: {:?}",
            det_items
                .iter()
                .map(|p| (p.value.clone(), p.outcome.clone()))
                .collect::<Vec<_>>()
        );
    }

    // ── Spec 037 Threats UX hotfix ─────────────────────────────────────
    //
    // Regression anchors for the "page is empty after deploy" bug. The
    // operator hit an empty Threats tab because PR #327 made the date
    // filter mandatory (defaulted to today via `resolve_date`); on
    // hosts where today had only self-traffic incidents the page went
    // blank and switching the date didn't help because each switch
    // imposed a hard one-day filter. Fix: date is now an Option, with
    // None = no filter (show whole graph), Some = explicit YYYY-MM-DD.

    #[test]
    fn build_pivots_from_graph_with_none_date_returns_all_dates() {
        // Anchor for: "page must show data when no date is explicitly
        // selected". The two-date fixture has incidents on 2026-04-26
        // and 2026-04-28; with date=None both must surface.
        let kg = make_kg_with_two_dates();
        let items = build_pivots_from_graph(&kg, PivotKind::Ip, 100, &Default::default(), None);
        let ips: std::collections::HashSet<&str> = items.iter().map(|p| p.value.as_str()).collect();
        assert!(
            ips.contains("198.51.100.77"),
            "today's incident must appear, got: {ips:?}"
        );
        assert!(
            ips.contains("203.0.113.99"),
            "yesterday's incident must ALSO appear when date=None, got: {ips:?}"
        );
    }

    #[test]
    fn explicit_date_filter_rejects_empty_and_garbage() {
        // Anchor for the explicit-vs-resolved date split. Empty string,
        // missing param, and garbage all collapse to None so the
        // builder applies no filter. Only well-formed YYYY-MM-DD values
        // become Some.
        assert_eq!(explicit_date_filter(None), None, "missing -> None");
        assert_eq!(explicit_date_filter(Some("")), None, "empty -> None");
        assert_eq!(
            explicit_date_filter(Some("   ")),
            None,
            "whitespace -> None"
        );
        assert_eq!(
            explicit_date_filter(Some("not-a-date")),
            None,
            "garbage -> None"
        );
        assert_eq!(
            explicit_date_filter(Some("2026-13-99")),
            None,
            "out-of-range -> None"
        );
        assert_eq!(
            explicit_date_filter(Some("2026-04-28")),
            Some("2026-04-28"),
            "valid date passes through"
        );
    }

    #[test]
    fn graph_for_date_loads_historical_snapshot_when_date_differs_from_today() {
        // 2026-04-29: when an explicit date is not today, the helper
        // must read that day's snapshot from SQLite. Otherwise the
        // operator's date filter has no effect because the live
        // graph only contains today's incidents.
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        use innerwarden_core::event::Severity;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("open");

        // Seed a 2026-04-26 snapshot with one ssh_bruteforce incident.
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        let ts = chrono::DateTime::parse_from_rfc3339("2026-04-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ip = g.ensure_ip("203.0.113.42", ts);
        let inc = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:hist".into(),
            detector: "ssh_bruteforce".into(),
            severity: format!("{:?}", Severity::High),
            title: "historical".into(),
            summary: "".into(),
            ts,
            mitre_ids: vec![],
            decision: Some("block_ip".into()),
            decision_target: Some("203.0.113.42".into()),
            confidence: Some(0.9),
            decision_reason: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        g.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, ts));
        let snap = g.serialize_snapshot_bytes().expect("serialize");
        store
            .save_graph_snapshot(
                "2026-04-26",
                &snap.bytes,
                snap.nodes_count,
                snap.edges_count,
            )
            .expect("save");

        // Live graph holds a different date entirely (today's empty).
        let live = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let mut s = state.clone();
        s.knowledge_graph = live.clone();

        // Historical date -> snapshot loaded.
        let hist = graph_for_date(&s, Some("2026-04-26"));
        let hist_inc = hist
            .read()
            .unwrap()
            .nodes_of_type(crate::knowledge_graph::types::NodeType::Incident)
            .len();
        assert_eq!(hist_inc, 1, "historical date must load 2026-04-26 snapshot");

        // None -> live graph (empty).
        let live_used = graph_for_date(&s, None);
        let live_inc = live_used
            .read()
            .unwrap()
            .nodes_of_type(crate::knowledge_graph::types::NodeType::Incident)
            .len();
        assert_eq!(live_inc, 0, "None must reuse the (empty) live graph");
    }

    /// Diagnostic: load a real innerwarden.db (typically copied from
    /// prod) and run the production pivot builders against the latest
    /// available snapshot. Use to debug "page is empty in prod" without
    /// having to deploy.
    ///
    /// Run with:
    ///   INNERWARDEN_DIAG_DIR=/path/to/dir \
    ///     cargo test diagnose_prod_state -- --ignored --nocapture
    #[test]
    #[ignore]
    fn diagnose_prod_state() {
        let Ok(dir_path) = std::env::var("INNERWARDEN_DIAG_DIR") else {
            eprintln!("set INNERWARDEN_DIAG_DIR=/path/to/dir/with/innerwarden.db");
            return;
        };
        let parent = std::path::PathBuf::from(&dir_path);
        let store = innerwarden_store::Store::open(&parent).expect("open store");

        let conn = store.conn().expect("conn");
        let latest: String = conn
            .query_row(
                "SELECT date FROM graph_snapshots ORDER BY date DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("snapshot date");
        eprintln!("=== latest snapshot date: {latest} ===");

        // Discover available dates (last 7) so we can probe non-today behaviour.
        let mut stmt = conn
            .prepare("SELECT date FROM graph_snapshots ORDER BY date DESC LIMIT 7")
            .expect("snapshot dates");
        let dates: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        eprintln!("=== available dates: {:?} ===", dates);

        let graph =
            crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(&parent, &latest)
                .expect("graph loads");
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        // ── 1. Pivot backend behaviour by date ────────────────────────
        for date_arg in [
            None,
            Some(latest.as_str()),
            Some("2026-04-28"),
            Some("2026-05-29"),
        ] {
            for pivot in [PivotKind::Ip, PivotKind::User, PivotKind::Detector] {
                let items = build_pivots_from_graph(&kg, pivot, 500, &Default::default(), date_arg);
                eprintln!(
                    "[pivot] date={:?} pivot={} -> {} items",
                    date_arg,
                    pivot.as_str(),
                    items.len()
                );
            }
        }

        // ── 2. Check ALL Incident node dates in the graph ─────────────
        use crate::knowledge_graph::types::*;
        let g = kg.read().unwrap();
        let mut by_date: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut research_only_count = 0usize;
        let mut decision_buckets: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for id in g.nodes_of_type(NodeType::Incident) {
            if let Some(Node::Incident {
                ts,
                research_only,
                decision,
                ..
            }) = g.get_node(id)
            {
                *by_date
                    .entry(ts.naive_utc().date().to_string())
                    .or_default() += 1;
                if *research_only {
                    research_only_count += 1;
                }
                let key = decision.as_deref().unwrap_or("None").to_string();
                *decision_buckets.entry(key).or_default() += 1;
            }
        }
        eprintln!("[graph] incidents by_date: {:?}", by_date);
        eprintln!(
            "[graph] research_only={}, decision_buckets={:?}",
            research_only_count, decision_buckets
        );

        // ── 3. /api/clusters bug: is it date-scoped? ──────────────────
        // build_cluster_items_from_graph reads ALL Incident nodes
        // regardless of the query date. Confirm by checking total
        // cluster count vs total incidents.
        eprintln!(
            "[clusters] total Incident nodes regardless of date = {}",
            g.nodes_of_type(NodeType::Incident).len()
        );

        // ── 4. /api/threats/diagnostic shape ──────────────────────────
        // Replicate the same logic (no need to call the async fn).
        let det_for_diag = |date: Option<&str>| {
            build_pivots_from_graph(&kg, PivotKind::Detector, 500, &Default::default(), date)
                .iter()
                .map(|p| p.incident_count)
                .sum::<usize>()
        };
        for date_arg in [None, Some(latest.as_str()), Some("2026-05-29")] {
            eprintln!(
                "[diag] date={:?} incidents_in_scope={}",
                date_arg,
                det_for_diag(date_arg)
            );
        }

        // ── 5. Test loading historical day snapshots ─────────────────
        for d in &dates {
            if d == &latest {
                continue;
            }
            let yesterday_graph =
                crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(&parent, d);
            match yesterday_graph {
                Some(g) => {
                    let inc_count = g.nodes_of_type(NodeType::Incident).len();
                    let arc = std::sync::Arc::new(std::sync::RwLock::new(g));
                    let pivot_count = build_pivots_from_graph(
                        &arc,
                        PivotKind::Ip,
                        500,
                        &Default::default(),
                        Some(d.as_str()),
                    )
                    .len();
                    eprintln!(
                        "[hist] date={} loadable=YES incidents={} ip_pivot={}",
                        d, inc_count, pivot_count
                    );
                }
                None => eprintln!("[hist] date={} loadable=NO", d),
            }
        }

        // ── 6. Simulate api_entities flow (live -> graph_for_date swap) ──
        // Build a DashboardState-like wrapper. Easiest: replicate the
        // graph_for_date logic inline against the real data_dir.
        eprintln!("--- simulated api_entities/api_pivots flow ---");
        for date_arg in [
            None,
            Some(latest.as_str()),
            Some("2026-04-28"),
            Some("2026-04-25"),
        ] {
            let arc_for_request: std::sync::Arc<
                std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>,
            > = match date_arg {
                None => kg.clone(),
                Some(d) if d == latest => kg.clone(),
                Some(d) => {
                    match crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(
                        &parent, d,
                    ) {
                        Some(g) => std::sync::Arc::new(std::sync::RwLock::new(g)),
                        None => kg.clone(),
                    }
                }
            };
            let ip_count = build_pivots_from_graph(
                &arc_for_request,
                PivotKind::Ip,
                500,
                &Default::default(),
                date_arg,
            )
            .len();
            let det_count = build_pivots_from_graph(
                &arc_for_request,
                PivotKind::Detector,
                500,
                &Default::default(),
                date_arg,
            )
            .len();
            eprintln!(
                "[api-sim] date={:?} ip_pivot={} detector_pivot={}",
                date_arg, ip_count, det_count
            );
        }
    }

    // ─── PR #423 Wave 4c — journey honesty anchors ──────────────

    #[test]
    fn summary_references_agent_self_matches_killchain_self_comms() {
        // Anchor: every comm in `KILLCHAIN_SELF_EXCLUDED_COMMS` must
        // be detected by the journey-builder filter. If the killchain
        // list grows (e.g. a new agent thread name), this test
        // automatically covers it. If the journey filter starts using
        // a different list, this test will catch the divergence.
        for comm in crate::killchain_inline::KILLCHAIN_SELF_EXCLUDED_COMMS {
            let summary = format!("{} (pid=1234) reading /etc/ssh/sshd_config", comm);
            assert!(
                summary_references_agent_self(&summary, "file.read_access"),
                "self-comm {comm:?} must be filtered out of attacker IP journeys"
            );
        }

        // Negative: an attacker process named `sshd` reading the same
        // file must NOT be filtered. This is the "future post-pivot
        // attacker file IO" case the filter must not regress.
        assert!(!summary_references_agent_self(
            "sshd (pid=1234) reading /etc/passwd",
            "file.read_access"
        ));

        // Negative: a real network event from the attacker IP.
        assert!(!summary_references_agent_self(
            "nginx (PID 4150736) accepted incoming connection",
            "network.accept"
        ));
    }

    /// Helper for Wave 4c tests: build a minimal Incident with the
    /// supplied IP in `entities` so the journey filter accepts it.
    #[cfg(test)]
    fn make_test_incident(
        incident_id: &str,
        ts: chrono::DateTime<Utc>,
        ip: &str,
        title: &str,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts,
            host: "test".into(),
            incident_id: incident_id.into(),
            severity: innerwarden_core::event::Severity::Medium,
            title: title.into(),
            summary: format!("Possible event from {ip}"),
            evidence: serde_json::json!([]),
            tags: vec![],
            recommended_checks: vec![],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        }
    }

    #[test]
    fn build_journey_from_sqlite_emits_decision_missing_when_no_decision() {
        // Drives `build_journey_from_sqlite` against an SQLite store
        // with one incident and no associated decision. The journey
        // must emit a `decision_missing` placeholder so the operator
        // sees the audit gap explicitly. Mirrors the prod state for
        // the 13:46 / 13:53 SSH-login-attempts entries on 2026-05-03
        // in IP 164.90.237.71's journey.
        let dir = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open(dir.path()).expect("store opens"));

        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-03T13:46:53Z")
            .unwrap()
            .with_timezone(&Utc);
        let incident = make_test_incident(
            "ssh_bruteforce:1.2.3.4:t1",
            ts,
            "1.2.3.4",
            "SSH login attempts",
        );
        store.insert_incident(&incident).expect("insert incident");
        // Intentionally NO decision row.

        let journey =
            build_journey_from_sqlite(&store, "2026-05-03", PivotKind::Ip, "1.2.3.4", None)
                .expect("journey built");

        let kinds: Vec<&str> = journey.entries.iter().map(|e| e.kind.as_str()).collect();
        assert!(
            kinds.contains(&"decision_missing"),
            "expected decision_missing placeholder, got kinds: {kinds:?}"
        );
        assert!(
            kinds.contains(&"incident"),
            "incident must still be present: {kinds:?}"
        );

        // The placeholder carries the incident_id so the JS group-by
        // logic folds it under the same incident card.
        let dm = journey
            .entries
            .iter()
            .find(|e| e.kind == "decision_missing")
            .unwrap();
        assert_eq!(
            dm.data.get("incident_id").and_then(|v| v.as_str()),
            Some("ssh_bruteforce:1.2.3.4:t1")
        );
    }

    #[test]
    fn build_journey_from_sqlite_uses_real_execution_result() {
        // When a decision row carries `execution_result: "skipped: \
        // already blocked"`, the journey entry must surface that
        // string verbatim instead of deriving "ok" / "skipped" from
        // the auto_executed boolean.
        let dir = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open(dir.path()).expect("store opens"));

        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-03T14:37:38Z")
            .unwrap()
            .with_timezone(&Utc);
        let incident = make_test_incident(
            "ssh_bruteforce:1.2.3.4:t2",
            ts,
            "1.2.3.4",
            "SSH login attempts",
        );
        store.insert_incident(&incident).expect("insert incident");

        // Decision: auto_executed=1 but execution_result says skipped.
        // This is the "already blocked from prior incident" case the
        // user flagged on the dashboard.
        let decision_data = serde_json::json!({
            "execution_result": "skipped: already blocked",
            "action_type": "block_ip",
        })
        .to_string();
        store
            .insert_decision(&innerwarden_store::decisions::DecisionRow {
                ts: ts.to_rfc3339(),
                incident_id: "ssh_bruteforce:1.2.3.4:t2".into(),
                action_type: "block_ip".into(),
                target_ip: Some("1.2.3.4".into()),
                target_user: None,
                confidence: 0.95,
                auto_executed: true,
                reason: Some(
                    "Auto-blocked: ssh_bruteforce (rule-based, no AI needed, block 24h)".into(),
                ),
                data: decision_data,
            })
            .expect("insert decision");

        let journey =
            build_journey_from_sqlite(&store, "2026-05-03", PivotKind::Ip, "1.2.3.4", None)
                .expect("journey built");

        let dec = journey
            .entries
            .iter()
            .find(|e| e.kind == "decision")
            .expect("decision entry present");
        let er = dec
            .data
            .get("execution_result")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            er, "skipped: already blocked",
            "execution_result must come from decision JSON, not auto_executed"
        );
    }
}
