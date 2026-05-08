// Auto-extracted from mod.rs — dashboard intelligence handlers

use super::*;

// ── Attacker Intelligence & Monthly Reports ────────────────────────

/// `GET /api/attacker-profiles` - list attacker profiles sorted by risk.
///
/// 2026-05-08 (fix/profiles-cloud-provider-badge): every profile in the
/// response is enriched with a `cloud_provider` field — `Some(label)`
/// when the IP belongs to a known CDN / cloud / bulletproof-host range
/// (Cloudflare, AWS, Azure, GCP, OCI, DO, Hetzner, Akamai, Fastly,
/// CloudFront, …), `null` otherwise. The same predicate that gates
/// auto-blocks (`cloud_safelist::identify_provider`) is used here so
/// the dashboard view never disagrees with the autoblock gate. This
/// is purely additive — pre-fix consumers still get the legacy fields.
///
/// Operators can filter cloud-provider rows out of the list by passing
/// `?exclude_cloud=true`. Operator's prod 2026-05-08 audit found 99
/// "high-risk" profiles, several of which were Microsoft Azure /
/// AWS edge IPs surfaced by the inline-decision-vs-AI-router race
/// (PR #492 closed the write side; this PR closes the read side so
/// existing wrongly-credited rows stop dominating the page).
pub(super) async fn api_attacker_profiles(
    State(state): State<DashboardState>,
    Query(query): Query<AttackerProfilesQuery>,
) -> Json<serde_json::Value> {
    let limit = query.limit.unwrap_or(50).min(500);
    let offset = query.offset.unwrap_or(0);
    let min_risk = query.min_risk.unwrap_or(0);
    let sort = query.sort.as_deref().unwrap_or("risk_score");
    let exclude_cloud = query.exclude_cloud.unwrap_or(false);

    let profiles: Vec<serde_json::Value> = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("attacker_profiles").ok().flatten())
        .or_else(|| safe_read_data_file(&state.data_dir, "attacker-profiles.json"))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let consolidated = consolidate_geo_by_asn(profiles);
    let enriched = enrich_with_cloud_provider(consolidated);
    let mut filtered = sort_attacker_profiles(enriched, min_risk, sort);
    if exclude_cloud {
        filtered.retain(|p| p.get("cloud_provider").is_some_and(|v| v.is_null()));
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
    exclude_cloud: Option<bool>,
}

/// Override an outlier profile's `geo.country` / `geo.country_code`
/// when ≥3 profiles share an ASN AND ≥80% of them agree on a country
/// that disagrees with this profile's stored value.
///
/// 2026-05-08 (fix/profiles-asn-geo-consolidation): operator's prod
/// audit found `92.118.39.23` listed as US while its five siblings
/// `92.118.39.{195,196,197,235}` from the SAME `AS47890 Unmanaged LTD`
/// (Hosting24 NL bulletproof) listed as NL. Same ASN + same ISP +
/// different country = ip-api.com returned bad data for the outlier
/// at first-seen time, and the agent never re-queried (the
/// `backfill_enrichment` slow-loop only fills `geo.is_none()`
/// profiles, not stale ones).
///
/// The fix consolidates at READ time, not WRITE time — the
/// underlying `attacker-profiles.json` keeps the original lookup
/// for forensic record. Profiles whose country was overridden carry
/// `geo_consolidated_from_asn = true` so the dashboard / API
/// consumer can flag them.
///
/// Threshold of 80% agreement (with floor of 3 profiles) avoids
/// over-correction on multi-region ASNs (e.g. AWS / GCP) where a
/// real attacker IP genuinely lives in a different country than
/// the bulk of the ASN's profile set.
pub(super) fn consolidate_geo_by_asn(
    mut profiles: Vec<serde_json::Value>,
) -> Vec<serde_json::Value> {
    use std::collections::HashMap;

    // Pass 1: count countries per ASN. We key on the raw ASN string
    // because that's the only stable identifier the profile carries
    // (ASN labels include human text like "AS47890 UNMANAGED LTD").
    let mut asn_country_tally: HashMap<String, HashMap<String, usize>> = HashMap::new();
    for p in &profiles {
        let asn = p
            .get("geo")
            .and_then(|g| g.get("asn"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cc = p
            .get("geo")
            .and_then(|g| g.get("country_code"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if asn.is_empty() || cc.is_empty() {
            continue;
        }
        *asn_country_tally
            .entry(asn.to_string())
            .or_default()
            .entry(cc.to_string())
            .or_default() += 1;
    }

    // Pass 2: for each ASN with ≥3 profiles AND a clear majority
    // (≥80% agreement), record (majority_cc, majority_country_label).
    // The country label comes from any one profile that already
    // has the majority country, so the override carries a
    // human-readable "Netherlands" not just "NL".
    let mut asn_majority: HashMap<String, (String, String)> = HashMap::new();
    for (asn, counts) in &asn_country_tally {
        let total: usize = counts.values().sum();
        if total < 3 {
            continue;
        }
        if let Some((winner_cc, winner_count)) = counts.iter().max_by_key(|(_, n)| **n) {
            if *winner_count * 100 / total >= 80 {
                // Find a profile in this ASN that already has the
                // majority country, copy its country label.
                let label = profiles
                    .iter()
                    .find(|p| {
                        p.get("geo")
                            .and_then(|g| g.get("asn"))
                            .and_then(|v| v.as_str())
                            == Some(asn)
                            && p.get("geo")
                                .and_then(|g| g.get("country_code"))
                                .and_then(|v| v.as_str())
                                == Some(winner_cc)
                    })
                    .and_then(|p| p.get("geo"))
                    .and_then(|g| g.get("country"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                asn_majority.insert(asn.clone(), (winner_cc.clone(), label));
            }
        }
    }

    // Pass 3: rewrite outlier profiles in-place.
    for p in &mut profiles {
        let asn = p
            .get("geo")
            .and_then(|g| g.get("asn"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let cc = p
            .get("geo")
            .and_then(|g| g.get("country_code"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let Some((majority_cc, majority_label)) = asn_majority.get(&asn) else {
            continue;
        };
        if cc == *majority_cc {
            continue;
        }
        // Rewrite this profile's country to the ASN majority and
        // mark the override so consumers know.
        if let Some(geo) = p.get_mut("geo").and_then(|v| v.as_object_mut()) {
            geo.insert(
                "country_code".to_string(),
                serde_json::Value::String(majority_cc.clone()),
            );
            if !majority_label.is_empty() {
                geo.insert(
                    "country".to_string(),
                    serde_json::Value::String(majority_label.clone()),
                );
            }
        }
        if let Some(obj) = p.as_object_mut() {
            obj.insert(
                "geo_consolidated_from_asn".to_string(),
                serde_json::Value::Bool(true),
            );
        }
    }

    profiles
}

/// Add a `cloud_provider` field to every profile in `profiles`.
///
/// The value is `Some(provider_label)` when
/// `cloud_safelist::identify_provider` returns a label for the
/// profile's `ip` field, otherwise `null`. Pure-input → pure-output
/// helper kept separate from `api_attacker_profiles` so the contract
/// is unit-testable without a full dashboard state.
pub(super) fn enrich_with_cloud_provider(
    profiles: Vec<serde_json::Value>,
) -> Vec<serde_json::Value> {
    profiles
        .into_iter()
        .map(|mut p| {
            let provider = p
                .get("ip")
                .and_then(|v| v.as_str())
                .and_then(crate::cloud_safelist::identify_provider);
            if let Some(obj) = p.as_object_mut() {
                obj.insert(
                    "cloud_provider".to_string(),
                    match provider {
                        Some(label) => serde_json::Value::String(label.to_string()),
                        None => serde_json::Value::Null,
                    },
                );
            }
            p
        })
        .collect()
}

pub(super) fn sort_attacker_profiles(
    profiles: Vec<serde_json::Value>,
    min_risk: u8,
    sort_key: &str,
) -> Vec<serde_json::Value> {
    let mut filtered: Vec<serde_json::Value> = profiles
        .into_iter()
        .filter(|p| p["risk_score"].as_u64().unwrap_or(0) >= min_risk as u64)
        .collect();

    match sort_key {
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
    filtered
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
        Some(p) => {
            // Enrich with cloud_provider so the drill-down detail view
            // matches the list view's labelling (operator-honesty).
            let mut enriched = enrich_with_cloud_provider(vec![p]);
            Json(enriched.pop().unwrap_or(serde_json::Value::Null))
        }
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
    if !is_valid_month(&month) {
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
///
/// 2026-05-03 (Wave 5): the response is enriched with `user_classes`,
/// a `{username: "human"|"service"|"root"|"unknown"}` map covering every
/// user that appears in `user_login_hours`. The dashboard's "Who logs in,
/// when" heatmap uses it to default-hide daemon PAM sessions
/// (`snap_daemon`, `systemd-resolve`, `messagebus`, `_apt`, ...) which
/// share the SSH login plumbing but are not real human logins. Without
/// this filter the operator was reading the heatmap as "all these people
/// have logged in" when in reality only the Human-class entries are real
/// SSH sessions.
///
/// Classification reads `/etc/passwd` directly via
/// `environment_profile::parse_passwd_for_user_classes`. We do not pull
/// from the persisted `environment-profile.json` because that file is
/// only refreshed on the periodic census; reading the live file keeps
/// the dashboard honest if `useradd` ran since the last census tick.
pub(super) async fn api_baseline_status(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let mut baseline: serde_json::Value = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| sq.get_blob("baseline").ok().flatten())
        .or_else(|| safe_read_data_file(&state.data_dir, "baseline.json"))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({"mature": false, "training_days": 0}));

    let classes = enrich_user_classes_for_logins(&baseline);
    if let Some(obj) = baseline.as_object_mut() {
        obj.insert("user_classes".to_string(), classes);
    }
    Json(baseline)
}

/// Build the `user_classes` map for every user that appears in the
/// baseline's `user_login_hours`. Pure with respect to the baseline JSON
/// shape; `/etc/passwd` is the only side effect, isolated to
/// `read_passwd_for_classification` so tests can drive it via the inner
/// helper `build_user_classes_from_passwd`.
///
/// Returns an empty object when the baseline carries no logins or when
/// `/etc/passwd` is unreadable. The frontend treats "missing" the same
/// as "unknown" and shows the user, so a degraded path errs on the side
/// of operator visibility.
fn enrich_user_classes_for_logins(baseline: &serde_json::Value) -> serde_json::Value {
    let Some(logins) = baseline.get("user_login_hours").and_then(|v| v.as_object()) else {
        return serde_json::Value::Object(serde_json::Map::new());
    };
    if logins.is_empty() {
        return serde_json::Value::Object(serde_json::Map::new());
    }
    let passwd = read_passwd_for_classification();
    build_user_classes_from_passwd(logins.keys().map(|s| s.as_str()), passwd.as_deref())
}

fn read_passwd_for_classification() -> Option<String> {
    std::fs::read_to_string("/etc/passwd").ok()
}

/// Pure: given an iterator of usernames and the contents of `/etc/passwd`
/// (or `None` when the file is unreadable), return a JSON object
/// `{username: class_string}`. Class strings match `UserClass::as_str`
/// of the underlying enum so the frontend can switch on them without a
/// translation table.
///
/// Split out so tests can drive it without touching the real
/// `/etc/passwd`.
fn build_user_classes_from_passwd<'a>(
    usernames: impl IntoIterator<Item = &'a str>,
    passwd: Option<&str>,
) -> serde_json::Value {
    use std::collections::HashMap;
    let mut name_to_class: HashMap<String, &'static str> = HashMap::new();
    if let Some(content) = passwd {
        let scan = crate::environment_profile::parse_passwd_for_user_classes(content);
        for n in scan.human_user_names {
            name_to_class.insert(n, "human");
        }
        for n in scan.service_user_names {
            name_to_class.insert(n, "service");
        }
    }
    let mut out = serde_json::Map::new();
    for user in usernames {
        let class = if user == "root" {
            "root"
        } else {
            name_to_class.get(user).copied().unwrap_or("unknown")
        };
        out.insert(
            user.to_string(),
            serde_json::Value::String(class.to_string()),
        );
    }
    serde_json::Value::Object(out)
}

#[cfg(test)]
mod baseline_enrich_tests {
    use super::*;

    /// 2026-05-03 (Wave 5 anchor): exact case the operator hit. The
    /// baseline file shows logins for `ubuntu` (real SSH), `snap_daemon`
    /// (snap PAM session, daemon), `systemd-resolve` (DNS resolver),
    /// `messagebus` (dbus), and `root`. Only `ubuntu` and `root` are
    /// real human-or-elevated logins; the rest are daemon PAM sessions.
    /// The frontend keys off these class strings to default-hide
    /// services so the operator does not read the heatmap as "many
    /// users have SSH'd in".
    #[test]
    fn build_user_classes_marks_daemon_sessions_as_service() {
        let synthetic_passwd = "\
root:x:0:0::/root:/bin/bash\n\
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n\
messagebus:x:103:108::/nonexistent:/usr/sbin/nologin\n\
systemd-resolve:x:991:993::/run/systemd:/usr/sbin/nologin\n\
ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n\
snap_daemon:x:584788:584788::/nonexistent:/usr/bin/false\n\
";
        let users = [
            "ubuntu",
            "root",
            "snap_daemon",
            "systemd-resolve",
            "messagebus",
            "stranger_not_in_passwd",
        ];
        let result = build_user_classes_from_passwd(users.iter().copied(), Some(synthetic_passwd));
        let obj = result.as_object().expect("object shape");
        assert_eq!(obj.get("ubuntu").and_then(|v| v.as_str()), Some("human"));
        assert_eq!(obj.get("root").and_then(|v| v.as_str()), Some("root"));
        assert_eq!(
            obj.get("snap_daemon").and_then(|v| v.as_str()),
            Some("service"),
            "snap_daemon must be Service so the heatmap hides it by default"
        );
        assert_eq!(
            obj.get("systemd-resolve").and_then(|v| v.as_str()),
            Some("service")
        );
        assert_eq!(
            obj.get("messagebus").and_then(|v| v.as_str()),
            Some("service")
        );
        assert_eq!(
            obj.get("stranger_not_in_passwd").and_then(|v| v.as_str()),
            Some("unknown"),
            "users not in /etc/passwd fall through to Unknown — operator sees them by default"
        );
    }

    /// Degraded path: `/etc/passwd` unreadable. Endpoint must still
    /// return a well-formed object so the frontend's default-hide
    /// branch can run; every entry maps to "unknown" (visible by
    /// default) except literal "root".
    #[test]
    fn build_user_classes_falls_back_to_unknown_when_passwd_unreadable() {
        let users = ["ubuntu", "root", "snap_daemon"];
        let result = build_user_classes_from_passwd(users.iter().copied(), None);
        let obj = result.as_object().expect("object shape");
        assert_eq!(obj.get("ubuntu").and_then(|v| v.as_str()), Some("unknown"));
        assert_eq!(obj.get("root").and_then(|v| v.as_str()), Some("root"));
        assert_eq!(
            obj.get("snap_daemon").and_then(|v| v.as_str()),
            Some("unknown")
        );
    }

    #[test]
    fn enrich_returns_empty_when_no_logins_present() {
        let baseline = serde_json::json!({"mature": true, "training_days": 7});
        let result = enrich_user_classes_for_logins(&baseline);
        assert_eq!(result, serde_json::json!({}));
    }

    #[test]
    fn enrich_iterates_every_login_username() {
        let zeros: Vec<u8> = vec![0; 24];
        let baseline = serde_json::json!({
            "user_login_hours": {
                "ubuntu": zeros,
                "snap_daemon": vec![0u8; 24],
            }
        });
        let result = enrich_user_classes_for_logins(&baseline);
        let obj = result.as_object().expect("object");
        // Every key from user_login_hours is represented.
        assert!(obj.contains_key("ubuntu"));
        assert!(obj.contains_key("snap_daemon"));
    }
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

pub(super) fn is_valid_month(month: &str) -> bool {
    month.chars().all(|c| c.is_ascii_digit() || c == '-') && month.len() <= 7 && !month.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_attacker_profiles() {
        let profiles = vec![
            serde_json::json!({"ip": "1.1.1.1", "risk_score": 10, "total_incidents": 5, "last_seen": "2023-01-01"}),
            serde_json::json!({"ip": "2.2.2.2", "risk_score": 90, "total_incidents": 20, "last_seen": "2023-02-01"}),
            serde_json::json!({"ip": "3.3.3.3", "risk_score": 50, "total_incidents": 10, "last_seen": "2023-03-01"}),
        ];

        // test minimum risk filtering
        let filtered = sort_attacker_profiles(profiles.clone(), 50, "risk_score");
        assert_eq!(filtered.len(), 2);

        // test sort by risk score
        assert_eq!(filtered[0]["ip"], "2.2.2.2");

        // test sort by incidents
        let by_incidents = sort_attacker_profiles(profiles.clone(), 0, "incidents");
        assert_eq!(by_incidents[0]["ip"], "2.2.2.2");
        assert_eq!(by_incidents[1]["ip"], "3.3.3.3");

        // test sort by last_seen
        let by_last_seen = sort_attacker_profiles(profiles, 0, "last_seen");
        assert_eq!(by_last_seen[0]["ip"], "3.3.3.3");
    }

    #[test]
    fn test_is_valid_month_format() {
        assert!(is_valid_month("2023-01"));
        assert!(!is_valid_month("2023-01-01")); // too long
        assert!(!is_valid_month("2023/01"));
        assert!(!is_valid_month("../2023"));
        assert!(!is_valid_month(""));
    }

    /// 2026-05-08 anchor (fix/profiles-cloud-provider-badge): every
    /// profile in the Profiles tab must carry a `cloud_provider`
    /// label that matches what `cloud_safelist::identify_provider`
    /// would say for its IP. Pre-fix the dashboard listed Microsoft
    /// Azure / AWS edge IPs as "high-risk attacker" rows with no
    /// indication that the agent's own autoblock gate would have
    /// refused to block them. The mismatch made the page look
    /// paranoid (and the operator distrust every other row).
    ///
    /// The contract: the field is `Some(label)` for any IP in a
    /// known cloud range, `null` for unaffiliated IPs. The dashboard
    /// JS uses this to badge / filter / sort rows; even without UI
    /// changes the JSON consumer can grep for the label.
    #[test]
    fn enrich_with_cloud_provider_tags_known_clouds_and_leaves_others_null() {
        crate::cloud_safelist::init();
        let profiles = vec![
            // The exact prod IP from the 2026-05-08 audit (AWS Ireland).
            serde_json::json!({"ip": "34.253.181.30", "risk_score": 87}),
            // Microsoft Azure UK (the git-fetch FP).
            serde_json::json!({"ip": "20.26.156.215", "risk_score": 71}),
            // Cloudflare edge.
            serde_json::json!({"ip": "104.26.12.38", "risk_score": 60}),
            // Real attacker (TEST-NET-3, RFC 5737, never on a CDN).
            serde_json::json!({"ip": "203.0.113.42", "risk_score": 80}),
        ];
        let enriched = enrich_with_cloud_provider(profiles);
        assert_eq!(enriched[0]["cloud_provider"], "AWS");
        assert_eq!(enriched[1]["cloud_provider"], "Azure");
        assert_eq!(enriched[2]["cloud_provider"], "Cloudflare");
        assert!(
            enriched[3]["cloud_provider"].is_null(),
            "203.0.113.42 (real-attacker test net) must have null cloud_provider"
        );
    }

    /// 2026-05-08 anchor (fix/profiles-asn-geo-consolidation): the
    /// exact prod-audit scenario. AS47890 (Unmanaged LTD / Hosting24
    /// NL bulletproof) had five profiles on the operator's box —
    /// `92.118.39.{195,196,197,235}` correctly tagged NL, but
    /// `92.118.39.23` showed US (ip-api.com returned bad data at
    /// first-seen and the agent never re-queried). Pin the
    /// consolidation that overrides the outlier US to NL, sets
    /// `geo_consolidated_from_asn = true`, and leaves untouched
    /// profiles alone.
    #[test]
    fn consolidate_geo_by_asn_overrides_outlier_country_in_clear_majority_asn() {
        let profiles = vec![
            // Outlier — wrong country.
            serde_json::json!({
                "ip": "92.118.39.23",
                "geo": {"country": "United States", "country_code": "US",
                        "city": "?", "isp": "Unmanaged LTD",
                        "asn": "AS47890 UNMANAGED LTD"}
            }),
            // Four siblings agreeing on NL.
            serde_json::json!({
                "ip": "92.118.39.195",
                "geo": {"country": "Netherlands", "country_code": "NL",
                        "city": "Amsterdam", "isp": "Unmanaged LTD",
                        "asn": "AS47890 UNMANAGED LTD"}
            }),
            serde_json::json!({
                "ip": "92.118.39.196",
                "geo": {"country": "Netherlands", "country_code": "NL",
                        "city": "Amsterdam", "isp": "Unmanaged LTD",
                        "asn": "AS47890 UNMANAGED LTD"}
            }),
            serde_json::json!({
                "ip": "92.118.39.197",
                "geo": {"country": "Netherlands", "country_code": "NL",
                        "city": "Amsterdam", "isp": "Unmanaged LTD",
                        "asn": "AS47890 UNMANAGED LTD"}
            }),
            serde_json::json!({
                "ip": "92.118.39.235",
                "geo": {"country": "Netherlands", "country_code": "NL",
                        "city": "Amsterdam", "isp": "Unmanaged LTD",
                        "asn": "AS47890 UNMANAGED LTD"}
            }),
        ];
        let consolidated = consolidate_geo_by_asn(profiles);
        let outlier = consolidated
            .iter()
            .find(|p| p["ip"] == "92.118.39.23")
            .unwrap();
        assert_eq!(
            outlier["geo"]["country_code"], "NL",
            "outlier US must be overridden to ASN-majority NL"
        );
        assert_eq!(outlier["geo"]["country"], "Netherlands");
        assert_eq!(
            outlier["geo_consolidated_from_asn"], true,
            "overridden profile must carry the consolidation flag"
        );
        // Sibling profiles must NOT carry the flag (no override).
        let sibling = consolidated
            .iter()
            .find(|p| p["ip"] == "92.118.39.195")
            .unwrap();
        assert!(
            sibling.get("geo_consolidated_from_asn").is_none()
                || sibling["geo_consolidated_from_asn"] != true,
            "non-outlier profile must not carry consolidation flag"
        );
    }

    /// Anti-regression: an ASN with only 2 profiles is BELOW the
    /// `>=3` minimum and must NOT trigger consolidation. Pins the
    /// floor that prevents one-off lookups (e.g. a single outbound
    /// from a low-volume IP) from getting steamrolled by another
    /// IP that happens to share the ASN.
    #[test]
    fn consolidate_geo_by_asn_does_not_consolidate_below_threshold() {
        let profiles = vec![
            serde_json::json!({
                "ip": "1.2.3.4",
                "geo": {"country": "US", "country_code": "US",
                        "city": "?", "isp": "X", "asn": "AS1 X"}
            }),
            serde_json::json!({
                "ip": "1.2.3.5",
                "geo": {"country": "Netherlands", "country_code": "NL",
                        "city": "?", "isp": "X", "asn": "AS1 X"}
            }),
        ];
        let consolidated = consolidate_geo_by_asn(profiles);
        // Both profiles unchanged.
        assert_eq!(consolidated[0]["geo"]["country_code"], "US");
        assert_eq!(consolidated[1]["geo"]["country_code"], "NL");
        for p in &consolidated {
            assert!(
                p.get("geo_consolidated_from_asn").is_none()
                    || p["geo_consolidated_from_asn"] != true,
                "below-threshold ASN must not trigger consolidation"
            );
        }
    }

    /// Anti-regression: a multi-region ASN (e.g. AWS) with split
    /// 60/40 country mix must NOT be consolidated — the 80%
    /// agreement threshold prevents the override. Pins the
    /// over-correction guard for legitimate multi-country ASNs.
    #[test]
    fn consolidate_geo_by_asn_keeps_real_split_asns_intact() {
        let profiles = vec![
            // 3 NL + 2 US — 60% agreement, below the 80% floor.
            serde_json::json!({"ip": "1.1.1.1", "geo": {"country_code": "NL", "country": "NL", "asn": "AS9 SPLIT"}}),
            serde_json::json!({"ip": "1.1.1.2", "geo": {"country_code": "NL", "country": "NL", "asn": "AS9 SPLIT"}}),
            serde_json::json!({"ip": "1.1.1.3", "geo": {"country_code": "NL", "country": "NL", "asn": "AS9 SPLIT"}}),
            serde_json::json!({"ip": "1.1.1.4", "geo": {"country_code": "US", "country": "US", "asn": "AS9 SPLIT"}}),
            serde_json::json!({"ip": "1.1.1.5", "geo": {"country_code": "US", "country": "US", "asn": "AS9 SPLIT"}}),
        ];
        let consolidated = consolidate_geo_by_asn(profiles);
        let us_count = consolidated
            .iter()
            .filter(|p| p["geo"]["country_code"] == "US")
            .count();
        assert_eq!(us_count, 2, "60/40 split must NOT be consolidated");
    }

    /// Mirror anchor: when `?exclude_cloud=true` is passed, the API
    /// must drop every row with a non-null `cloud_provider`. Pins
    /// the operator-opt-in filter so the Profiles tab can render a
    /// clean "real attackers only" view without losing the data
    /// (the unfiltered view is still available by default).
    #[test]
    fn enrich_then_filter_exclude_cloud_drops_only_cloud_rows() {
        crate::cloud_safelist::init();
        let profiles = vec![
            serde_json::json!({"ip": "34.253.181.30", "risk_score": 87}),
            serde_json::json!({"ip": "203.0.113.42", "risk_score": 80}),
            serde_json::json!({"ip": "20.26.156.215", "risk_score": 71}),
            serde_json::json!({"ip": "203.0.113.99", "risk_score": 65}),
        ];
        let mut enriched = enrich_with_cloud_provider(profiles);
        enriched.retain(|p| p.get("cloud_provider").is_some_and(|v| v.is_null()));
        assert_eq!(enriched.len(), 2);
        assert_eq!(enriched[0]["ip"], "203.0.113.42");
        assert_eq!(enriched[1]["ip"], "203.0.113.99");
    }

    #[test]
    fn test_sort_attacker_profiles_missing_fields() {
        // Missing score fields default safely and still sort/filter deterministically.
        let profiles = vec![
            serde_json::json!({"ip": "1.1.1.1"}), // missing risk_score, defaults to 0
        ];
        let by_risk = sort_attacker_profiles(profiles.clone(), 0, "risk_score");
        assert_eq!(by_risk.len(), 1);

        let filtered = sort_attacker_profiles(profiles, 1, "risk_score");
        assert_eq!(filtered.len(), 0);
    }

    #[tokio::test]
    async fn test_api_attacker_profiles_empty() {
        use axum::extract::{Query, State};
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());

        let query = AttackerProfilesQuery {
            limit: None,
            offset: None,
            sort: None,
            min_risk: None,
            exclude_cloud: None,
        };
        let response = api_attacker_profiles(State(state), Query(query)).await;

        assert_eq!(response.0["total"].as_u64().unwrap(), 0);
        assert!(response.0["profiles"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_api_baseline_status_empty() {
        use axum::extract::State;
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());

        let response = api_baseline_status(State(state)).await;

        assert_eq!(response.0["mature"].as_bool().unwrap(), false);
        assert_eq!(response.0["training_days"].as_u64().unwrap(), 0);
        assert!(response.0["user_classes"].as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_api_deep_security() {
        use axum::extract::State;
        let tmp = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(tmp.path());

        let response = api_deep_security(State(state)).await;
        assert_eq!(response.0["killchain_pids_tracked"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_min_risk_100_filters_everything() {
        // min_risk=100 should filter all profiles below 100.
        let profiles = vec![
            serde_json::json!({"ip": "1.1.1.1", "risk_score": 99}),
            serde_json::json!({"ip": "2.2.2.2", "risk_score": 10}),
        ];
        let filtered = sort_attacker_profiles(profiles, 100, "risk_score");
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_sort_empty_list_does_not_panic() {
        // Sorting an empty profile list should be stable and panic-free.
        let filtered = sort_attacker_profiles(Vec::new(), 0, "risk_score");
        assert!(filtered.is_empty());
    }
}
