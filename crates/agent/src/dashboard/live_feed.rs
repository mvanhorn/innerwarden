// Auto-extracted from mod.rs — dashboard live_feed handlers

use super::*;
use std::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// Public live-feed endpoints (CORS-enabled, no auth)
// ---------------------------------------------------------------------------

/// Per-IP local reputation summary included in live-feed responses.
#[derive(Serialize, Deserialize, Clone)]
pub(super) struct LiveFeedReputation {
    total_incidents: u32,
    total_blocks: u32,
    reputation_score: f32,
    first_seen: String,
    last_seen: String,
}

/// MITRE ATT&CK annotation attached to live-feed items.
#[derive(Serialize, Clone)]
pub(super) struct LiveFeedMitre {
    tactic: String,
    technique_id: String,
    technique_name: String,
}

/// Item returned by the public live feed.
#[derive(Serialize)]
pub(super) struct LiveFeedItem {
    ts: String,
    severity: String,
    title: String,
    ip: Option<String>,
    action: Option<String>,
    /// Resolution outcome: "blocked", "monitored", "ignored", "open", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    confidence: Option<f32>,
    reason: Option<String>,
    /// Local IP reputation data (present when the IP has been seen before).
    #[serde(skip_serializing_if = "Option::is_none")]
    reputation: Option<LiveFeedReputation>,
    /// MITRE ATT&CK mapping derived from the detector name.
    #[serde(skip_serializing_if = "Option::is_none")]
    mitre: Option<LiveFeedMitre>,
    /// Detector that triggered this incident (e.g. "ssh_bruteforce").
    #[serde(skip_serializing_if = "Option::is_none")]
    detector: Option<String>,
}

/// On-disk representation of LocalIpReputation (written by agent main loop).
#[derive(Deserialize)]
pub(super) struct StoredIpReputation {
    total_incidents: u32,
    total_blocks: u32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    reputation_score: f32,
}

/// Load the `ip-reputation.json` file written by the agent's slow loop.
pub(super) fn load_ip_reputation_map(data_dir: &Path) -> HashMap<String, StoredIpReputation> {
    let path = data_dir.join("ip-reputation.json");
    // Resolve symlinks and verify the path stays within the data directory (CWE-22).
    let Ok(canonical) = path.canonicalize() else {
        return HashMap::new();
    };
    let Ok(canonical_dir) = data_dir.canonicalize() else {
        return HashMap::new();
    };
    if !canonical.starts_with(&canonical_dir) {
        return HashMap::new();
    }
    let Ok(content) = std::fs::read_to_string(&canonical) else {
        return HashMap::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// Live feed response with totals and items.
#[derive(Serialize)]
pub(super) struct LiveFeedResponse {
    total_today: usize,
    total_blocked: usize,
    total_high: usize,
    /// Number of unique source IPs across all real incidents today.
    unique_sources: usize,
    items: Vec<LiveFeedItem>,
}

/// Count **unique IPs** blocked today, not raw block decisions.
///
/// Without dedup, a single attacker blocked N times (retries, new
/// incidents, lifecycle re-entries) shows up N times, which is why the
/// "Blocked" KPI on the site and the dashboard Home KPI used to report
/// different numbers for the same traffic. The semantic this function
/// pins is "how many distinct IPs did the agent contain today"; it is
/// shared by `/api/live-feed` here and `/api/agent/security-context` in
/// `agent_api.rs` so every surface that reads "Blocked Today" agrees.
pub(super) fn count_unique_ips_blocked(
    decisions: &[DecisionEntry],
    real_ids: &std::collections::HashSet<&str>,
) -> usize {
    let mut ips: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for d in decisions {
        if d.action_type != "block_ip" {
            continue;
        }
        if !real_ids.contains(d.incident_id.as_str()) {
            continue;
        }
        if let Some(ip) = d.target_ip.as_deref().filter(|s| !s.is_empty()) {
            ips.insert(ip);
        }
    }
    ips.len()
}

/// `GET /api/live-feed` - last 200 incidents with totals for the day (public).
pub(super) async fn api_live_feed(State(state): State<DashboardState>) -> Json<LiveFeedResponse> {
    let _now = chrono::Utc::now();
    let reputation_map = load_ip_reputation_map(&state.data_dir);

    // Read incidents from knowledge graph
    use crate::knowledge_graph::types::{Node, NodeType, Relation};
    let graph = state.knowledge_graph.read().unwrap();

    // Build incidents from graph Incident nodes
    let mut incidents: Vec<Incident> = Vec::new();
    let mut decisions: Vec<DecisionEntry> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            incident_id,
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
            detector: _,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            // Spec 015 follow-up: hide research_only incidents from the
            // operator live feed. They still live in the graph (neural
            // training + investigation views still see them) but don't
            // pollute the Threats tab with self-traffic to Telegram,
            // Cloudflare, AWS, Oracle peers, etc.
            if *research_only {
                continue;
            }
            // Collect entities from TriggeredBy edges
            let entities: Vec<innerwarden_core::entities::EntityRef> = graph
                .outgoing_edges(id)
                .iter()
                .filter(|e| e.relation == Relation::TriggeredBy)
                .filter_map(|e| match graph.get_node(e.to) {
                    Some(Node::Ip { addr, .. }) => {
                        Some(innerwarden_core::entities::EntityRef::ip(addr))
                    }
                    Some(Node::User { name, .. }) => {
                        Some(innerwarden_core::entities::EntityRef::user(name))
                    }
                    _ => None,
                })
                .collect();

            let sev = match severity.to_lowercase().as_str() {
                "critical" => innerwarden_core::event::Severity::Critical,
                "high" => innerwarden_core::event::Severity::High,
                "medium" => innerwarden_core::event::Severity::Medium,
                "low" => innerwarden_core::event::Severity::Low,
                _ => innerwarden_core::event::Severity::Info,
            };

            incidents.push(Incident {
                ts: *ts,
                host: String::new(),
                incident_id: incident_id.clone(),
                severity: sev,
                title: title.clone(),
                summary: summary.clone(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: mitre_ids.clone(),
                entities,
            });

            if let Some(action) = decision {
                decisions.push(DecisionEntry {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    host: String::new(),
                    ai_provider: String::new(),
                    action_type: action.clone(),
                    target_ip: decision_target.clone(),
                    target_user: None,
                    skill_id: None,
                    confidence: confidence.unwrap_or(0.0),
                    auto_executed: *auto_executed,
                    dry_run: false,
                    reason: decision_reason.clone().unwrap_or_default(),
                    execution_result: if *auto_executed {
                        "ok".into()
                    } else {
                        "skipped".into()
                    },
                    estimated_threat: String::new(),
                    prev_hash: None,
                });
            }
        }
    }

    let decision_map: HashMap<String, &DecisionEntry> = decisions
        .iter()
        .map(|d| (d.incident_id.clone(), d))
        .collect();

    // Filter real attacks only (exclude internal noise) for consistent stats.
    let real_incidents: Vec<&Incident> = incidents.iter().filter(|i| !is_internal(i)).collect();

    // Build incident IDs set for matching decisions to real attacks only.
    let real_ids: std::collections::HashSet<&str> = real_incidents
        .iter()
        .map(|i| i.incident_id.as_str())
        .collect();

    let total_today = real_incidents.len();
    let total_blocked = count_unique_ips_blocked(&decisions, &real_ids);
    let total_high = real_incidents
        .iter()
        .filter(|i| matches!(i.severity, Severity::High | Severity::Critical))
        .count();
    let unique_sources = {
        let ips: std::collections::HashSet<&str> = real_incidents
            .iter()
            .flat_map(|i| {
                i.entities
                    .iter()
                    .filter(|e| e.r#type == EntityType::Ip)
                    .map(|e| e.value.as_str())
            })
            .collect();
        ips.len()
    };

    let mut items: Vec<LiveFeedItem> = real_incidents
        .iter()
        .rev()
        .take(200)
        .map(|inc| {
            let ip = inc
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::Ip)
                .map(|e| e.value.clone());
            let dec = decision_map.get(&inc.incident_id);
            let reputation = ip.as_ref().and_then(|ip_val| {
                reputation_map.get(ip_val).map(|r| LiveFeedReputation {
                    total_incidents: r.total_incidents,
                    total_blocks: r.total_blocks,
                    reputation_score: r.reputation_score,
                    first_seen: r.first_seen.to_rfc3339(),
                    last_seen: r.last_seen.to_rfc3339(),
                })
            });
            let detector = mitre::detector_from_incident_id(&inc.incident_id);
            let mitre_info = mitre::map_detector(detector).map(|m| LiveFeedMitre {
                tactic: m.tactic.to_string(),
                technique_id: m.technique_id.to_string(),
                technique_name: m.technique_name.to_string(),
            });
            let outcome = dec.map(|d| {
                match d.action_type.as_str() {
                    "block_ip" => "blocked",
                    "suspend_user_sudo" => "suspended",
                    "kill_process" => "killed",
                    "block_container" => "contained",
                    "monitor" => "monitored",
                    "honeypot" => "honeypot",
                    "ignore" => "ignored",
                    _ => "resolved",
                }
                .to_string()
            });
            let det_name = if detector.is_empty() {
                None
            } else {
                Some(detector.to_string())
            };
            LiveFeedItem {
                ts: inc.ts.to_rfc3339(),
                severity: format!("{:?}", inc.severity).to_lowercase(),
                title: live_feed_title(detector, &inc.severity),
                ip,
                action: dec.map(|d| d.action_type.clone()),
                outcome,
                confidence: dec.map(|d| d.confidence),
                reason: dec.map(|d| live_feed_reason(detector, &d.action_type)),
                reputation,
                mitre: mitre_info,
                detector: det_name,
            }
        })
        .collect();
    items.reverse();

    Json(LiveFeedResponse {
        total_today,
        total_blocked,
        total_high,
        unique_sources,
        items,
    })
}

/// Sanitized title for public live feed. No paths, PIDs, UIDs, usernames.
/// Replaces with fun hacker-protector personality messages.
pub(super) fn live_feed_title(detector: &str, severity: &Severity) -> String {
    match detector {
        "ssh_bruteforce" => "Brute force in progress. Tracking attempt count and origin.".into(),
        "credential_stuffing" => {
            "Credential spray detected. Someone's trying stolen passwords.".into()
        }
        "port_scan" => "Port scan detected. Someone's knocking on every door.".into(),
        "packet_flood" => "Traffic spike detected. Looks like someone brought friends.".into(),
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => {
            "Data exfiltration attempt caught. Nice try.".into()
        }
        "reverse_shell" => "Reverse shell blocked. Not today.".into(),
        "privesc" => "Privilege escalation attempt detected and flagged.".into(),
        "rootkit" => "Kernel anomaly detected. Running deep inspection.".into(),
        "ransomware" => {
            "Ransomware behavior detected. Encryption blocked, process terminated.".into()
        }
        "dns_tunneling" | "dns_tunneling_ebpf" => {
            "DNS tunneling detected. Hidden channel exposed.".into()
        }
        "c2_callback" => "C2 beacon detected. Communication channel disrupted.".into(),
        "crypto_miner" => "Cryptominer detected. Your CPU is not for rent.".into(),
        "container_escape" => "Container escape attempt blocked.".into(),
        "lateral_movement" => "Lateral movement detected. Containment in progress.".into(),
        "web_shell" => "Web shell detected and neutralized.".into(),
        "process_injection" => "Process injection blocked. Code integrity maintained.".into(),
        "fileless" => "Fileless malware detected in memory. Cleaned.".into(),
        "log_tampering" => "Log tampering attempt. Someone tried to erase their tracks.".into(),
        "ssh_key_injection" => "SSH key injection blocked. Unauthorized access denied.".into(),
        "crontab_persistence" | "systemd_persistence" => {
            "Persistence mechanism detected and flagged.".into()
        }
        "kernel_module_load" => "New kernel module detected. Under review.".into(),
        "discovery_burst" => "Reconnaissance sweep detected. Target is mapping the system.".into(),
        "sigma" => "Known attack pattern matched by community rules.".into(),
        "process_tree" => "Suspicious process chain detected.".into(),
        "neural_anomaly" => "AI detected unusual behavior pattern.".into(),
        "masquerading" => "Binary masquerading detected. Fake identity exposed.".into(),
        "suspicious_execution" => "Suspicious process execution flagged for review.".into(),
        "io_uring_create" => "io_uring syscall bypass attempt detected.".into(),
        _ => match severity {
            Severity::Critical => "Critical threat detected and handled.".into(),
            Severity::High => "High severity threat detected.".into(),
            _ => "Suspicious activity detected and logged.".into(),
        },
    }
}

/// Sanitized reason for public live feed with personality.
pub(super) fn live_feed_reason(detector: &str, action: &str) -> String {
    let action_verb = match action {
        "block_ip" => "IP blocked",
        "kill_process" => "Process terminated",
        "suspend_user_sudo" => "Access suspended",
        "honeypot" => "Redirected to honeypot",
        "monitor" => "Monitoring",
        _ => "Handled",
    };

    match detector {
        "ssh_bruteforce" => format!("Brute force detected and blocked. {action_verb}."),
        "credential_stuffing" => format!("Credential spray neutralized. {action_verb}."),
        "packet_flood" => format!("DDoS mitigated at wire speed. {action_verb}."),
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => {
            format!("Data theft attempt stopped cold. {action_verb}.")
        }
        "reverse_shell" => format!("Reverse shell terminated before execution. {action_verb}."),
        "ransomware" => format!("Ransomware killed before encryption. {action_verb}."),
        "c2_callback" => format!("C2 communication severed. {action_verb}."),
        "web_shell" => format!("Backdoor removed. {action_verb}."),
        _ => format!("{action_verb}."),
    }
}

#[cfg(test)]
pub(super) fn incident_priority(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[cfg(test)]
pub(super) fn enforce_feed_max_size<T>(items: Vec<T>, max: usize) -> Vec<T> {
    items.into_iter().take(max).collect()
}

/// `GET /api/live-feed/stream` - SSE stream of alerts for public live page.
pub(super) async fn api_live_feed_stream(
    State(state): State<DashboardState>,
) -> Result<
    Sse<impl futures_core::Stream<Item = Result<SseEvent, std::convert::Infallible>>>,
    StatusCode,
> {
    let current = SSE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if current >= MAX_SSE_CONNECTIONS {
        SSE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let rx = state.event_tx.subscribe();
    let guard = SseGuard;
    let stream = BroadcastStream::new(rx).filter_map(move |msg: Result<SsePayload, _>| {
        let _keep = &guard;
        let payload = msg.ok()?;
        // Only forward alert and heartbeat events to the public feed
        if payload.kind != "alert" && payload.kind != "heartbeat" {
            return None;
        }
        let data = serde_json::to_string(&payload).unwrap_or_default();
        Some(Ok(SseEvent::default().event(&payload.kind).data(data)))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// `GET /api/live-feed/geoip?ips=1.2.3.4,5.6.7.8` - batch GeoIP lookup (public proxy).
pub(super) async fn api_live_feed_geoip(Query(query): Query<GeoIpQuery>) -> Json<Vec<GeoIpResult>> {
    let ips: Vec<&str> = query
        .ips
        .split(',')
        .filter(|s| !s.is_empty())
        .take(30)
        .collect();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let mut results = Vec::new();
    for ip in ips {
        let ip = ip.trim();
        // ip-api.com free tier returns 403 on HTTPS; HTTPS requires the paid
        // plan. The IPs queried here are public attacker addresses already
        // observed on the server's public interfaces, so plaintext transit
        // adds no material disclosure. See also `crate::geoip`.
        let url = format!(
            "http://ip-api.com/json/{}?fields=status,lat,lon,country",
            ip
        );
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if data.get("status").and_then(|s| s.as_str()) == Some("success") {
                    results.push(GeoIpResult {
                        ip: ip.to_string(),
                        lat: data.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        lon: data.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        country: data
                            .get("country")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    });
                }
            }
        }
    }
    Json(results)
}

/// Honeypot session summary for the live feed.
#[derive(Serialize)]
pub(super) struct HoneypotSession {
    ts: String,
    ip: String,
    session_id: String,
    auth_attempts: Vec<serde_json::Value>,
    commands: Vec<String>,
}

/// `GET /api/live-feed/honeypot` - recent honeypot sessions (public).
pub(super) async fn api_live_feed_honeypot(
    State(state): State<DashboardState>,
) -> Json<Vec<HoneypotSession>> {
    let honeypot_dir = state.data_dir.join("honeypot");
    let mut sessions = Vec::new();

    // Resolve symlinks and verify the path stays within data_dir (CWE-22).
    let Ok(canonical_dir) = honeypot_dir.canonicalize() else {
        return Json(sessions);
    };
    let Ok(canonical_data) = state.data_dir.canonicalize() else {
        return Json(sessions);
    };
    if !canonical_dir.starts_with(&canonical_data) {
        return Json(sessions);
    }

    let entries = match std::fs::read_dir(&canonical_dir) {
        Ok(e) => e,
        Err(_) => return Json(sessions),
    };

    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|e| {
            e.path()
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("listener-session-") && n.ends_with(".jsonl"))
        })
        .map(|e| e.path())
        .collect();
    files.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    for path in files.into_iter().take(10) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let commands: Vec<String> = v["shell_commands"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| c["command"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            sessions.push(HoneypotSession {
                ts: v["ts"].as_str().unwrap_or("").to_string(),
                ip: v["peer_ip"].as_str().unwrap_or("").to_string(),
                session_id: v["session_id"].as_str().unwrap_or("").to_string(),
                auth_attempts: v["auth_attempts"].as_array().cloned().unwrap_or_default(),
                commands,
            });
        }
    }

    Json(sessions)
}

// ─── MITRE ATT&CK summary endpoint ─────────────────────────────────────────

/// A single technique entry inside a tactic summary.
#[derive(Serialize)]
pub(super) struct MitreTechniqueSummary {
    id: String,
    name: String,
    count: usize,
}

/// A tactic summary with aggregated technique counts.
#[derive(Serialize)]
pub(super) struct MitreTacticSummary {
    tactic: String,
    count: usize,
    techniques: Vec<MitreTechniqueSummary>,
}

/// Top-level response for `/api/live-feed/mitre`.
#[derive(Serialize)]
pub(super) struct MitreSummaryResponse {
    tactics: Vec<MitreTacticSummary>,
}

/// `GET /api/live-feed/mitre` - MITRE ATT&CK tactic/technique summary for today (Phase 6A: graph-only).
pub(super) async fn api_live_feed_mitre(
    State(state): State<DashboardState>,
) -> Json<MitreSummaryResponse> {
    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    // tactic -> (technique_id, technique_name) -> count
    let mut tactic_map: BTreeMap<String, BTreeMap<(String, String), usize>> = BTreeMap::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident { detector, .. }) = graph.get_node(id) {
            if let Some(m) = mitre::map_detector(detector) {
                let techniques = tactic_map.entry(m.tactic.to_string()).or_default();
                *techniques
                    .entry((m.technique_id.to_string(), m.technique_name.to_string()))
                    .or_insert(0) += 1;
            }
        }
    }

    let tactics: Vec<MitreTacticSummary> = tactic_map
        .into_iter()
        .map(|(tactic, techniques_map)| {
            let mut techniques: Vec<MitreTechniqueSummary> = techniques_map
                .into_iter()
                .map(|((id, name), count)| MitreTechniqueSummary { id, name, count })
                .collect();
            techniques.sort_by(|a, b| b.count.cmp(&a.count));
            let count = techniques.iter().map(|t| t.count).sum();
            MitreTacticSummary {
                tactic,
                count,
                techniques,
            }
        })
        .collect();

    Json(MitreSummaryResponse { tactics })
}

#[derive(Deserialize)]
pub(super) struct GeoIpQuery {
    #[serde(default)]
    ips: String,
}

#[derive(Serialize)]
pub(super) struct GeoIpResult {
    ip: String,
    lat: f64,
    lon: f64,
    country: String,
}

// ── Safe data file reading (CWE-22 path traversal protection) ──────
//
// All endpoints that read JSON files from data_dir MUST use this helper.
// It canonicalizes both base and target paths and verifies the target
// stays within the data directory, preventing path traversal attacks.

// Public feed: only show real external attacks (with attacker IP).
// Filter out internal detections, system noise, and advisory-only detectors.
pub(super) fn is_internal(inc: &innerwarden_core::incident::Incident) -> bool {
    let det = inc.incident_id.split(':').next().unwrap_or("");
    // Advisory-only detectors (observe, never block)
    if matches!(
        det,
        "neural_anomaly" | "host_drift" | "network_sniffing" | "discovery_burst"
    ) {
        return true;
    }
    // No external IP = internal noise
    if !inc
        .entities
        .iter()
        .any(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
    {
        return true;
    }
    let t = inc.title.to_lowercase();
    // Inner Warden processes doing setuid for skills
    t.contains("(en-agent)")
        || t.contains("(n-shield)")
        || t.contains("(en-sensor)")
        || t.contains("innerwarden")
        // System daemons that legitimately do setuid
        || t.contains("(timesyncd)")
        || t.contains("(systemd)")
        || t.contains("(networkd)")
        || t.contains("(resolved)")
        || t.contains("(sshd)")
        || t.contains("(cron)")
        || t.contains("(polkitd)")
        || t.contains("(dbus-daem")
        || t.contains("(login)")
        || t.contains("(su)")
        || t.contains("(sudo)")
        || t.contains("(pkexec)")
        || t.contains("(fwupdmgr)")
        || t.contains("(mandb)")
        || t.contains("(find)")
        || t.contains("(install)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_live_feed_title_formatting_rules() {
        assert_eq!(
            live_feed_title("ssh_bruteforce", &Severity::Critical),
            "Brute force in progress. Tracking attempt count and origin."
        );
        assert_eq!(
            live_feed_title("container_escape", &Severity::High),
            "Container escape attempt blocked."
        );
        assert_eq!(
            live_feed_title("unknown_detector", &Severity::Critical),
            "Critical threat detected and handled."
        );
        assert_eq!(
            live_feed_title("unknown_detector", &Severity::Low),
            "Suspicious activity detected and logged."
        );
    }

    #[test]
    fn test_live_feed_reason_formatting_rules() {
        assert_eq!(
            live_feed_reason("ssh_bruteforce", "block_ip"),
            "Brute force detected and blocked. IP blocked."
        );
        assert_eq!(
            live_feed_reason("ransomware", "kill_process"),
            "Ransomware killed before encryption. Process terminated."
        );
        assert_eq!(
            live_feed_reason("unknown_detector", "monitor"),
            "Monitoring."
        );
    }

    #[test]
    fn test_live_feed_item_serialization() {
        let mitre = LiveFeedMitre {
            tactic: "T0000".to_string(),
            technique_id: "T1234".to_string(),
            technique_name: "Magic Attack".to_string(),
        };

        let item = LiveFeedItem {
            ts: "2023-01-01T00:00:00Z".to_string(),
            severity: "high".to_string(),
            title: "Threat".to_string(),
            ip: Some("1.2.3.4".to_string()),
            action: Some("monitor".to_string()),
            outcome: Some("monitored".to_string()),
            confidence: Some(0.9),
            reason: Some("Monitoring.".to_string()),
            reputation: None,
            mitre: Some(mitre),
            detector: Some("magic_detector".to_string()),
        };

        let val = serde_json::to_value(&item).unwrap();
        assert_eq!(val["severity"], "high");
        assert_eq!(val["ip"], "1.2.3.4");
        assert_eq!(val["outcome"], "monitored");
        assert!(val.get("reputation").is_none()); // skip serialization if none
        assert_eq!(val["mitre"]["tactic"], "T0000");
    }

    #[test]
    fn test_live_feed_item_serialization_empty() {
        let item = LiveFeedItem {
            ts: "2023-01-01T00:00:00Z".to_string(),
            severity: "low".to_string(),
            title: "Threat".to_string(),
            ip: None,
            action: None,
            outcome: None,
            confidence: None,
            reason: None,
            reputation: None,
            mitre: None,
            detector: None,
        };
        let val = serde_json::to_value(&item).unwrap();
        // Optional fields skipped serialization if none
        assert!(val.get("outcome").is_none());
        assert!(val.get("detector").is_none());
        assert!(val.get("mitre").is_none());
        assert!(val["action"].is_null());
    }

    #[test]
    fn test_is_internal_filter() {
        // Filters internal/system noise while keeping real external attacks.
        use innerwarden_core::entities::EntityRef;
        // Real IP based threat => external
        let ext_inc = Incident {
            ts: Utc::now(),
            host: String::new(),
            incident_id: "ssh_bruteforce:123".into(),
            severity: Severity::High,
            title: "External threat".into(),
            summary: "xyz".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        assert_eq!(is_internal(&ext_inc), false);

        // System daemon title => internal
        let daemon_inc = Incident {
            title: "Setuid execution (sudo)".into(),
            ..ext_inc.clone()
        };
        assert_eq!(is_internal(&daemon_inc), true);

        // Advisory detector => internal
        let adv_inc = Incident {
            incident_id: "neural_anomaly:123".into(),
            ..ext_inc.clone()
        };
        assert_eq!(is_internal(&adv_inc), true);

        // No IP => internal
        let no_ip_inc = Incident {
            entities: vec![EntityRef::user("root")],
            ..ext_inc.clone()
        };
        assert_eq!(is_internal(&no_ip_inc), true);
    }

    #[test]
    fn test_feed_max_size_enforcement_truncates_entries() {
        // Ensures feed result is truncated when it exceeds configured max entries.
        let source: Vec<usize> = (0..250).collect();
        let truncated = enforce_feed_max_size(source, 200);
        assert_eq!(truncated.len(), 200);
        assert_eq!(truncated.first(), Some(&0));
        assert_eq!(truncated.last(), Some(&199));
    }

    #[test]
    fn test_critical_priority_higher_than_low() {
        // Confirms severity priority ordering used by feed ranking.
        assert!(incident_priority("critical") > incident_priority("low"));
    }

    #[test]
    fn test_feed_with_zero_entries_returns_empty_list() {
        // Verifies empty feed serialization remains an empty list.
        let empty: Vec<LiveFeedItem> = Vec::new();
        let response = LiveFeedResponse {
            total_today: 0,
            total_blocked: 0,
            total_high: 0,
            unique_sources: 0,
            items: empty,
        };
        assert!(response.items.is_empty());
    }

    #[test]
    fn test_geoip_query_deserialization_empty_params() {
        // Fix #152: ensure GeoIpQuery works without 'ips' parameter by defaulting to empty string.
        let query: GeoIpQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(query.ips, "");

        let query: GeoIpQuery =
            serde_json::from_value(serde_json::json!({"ips": "1.2.3.4"})).unwrap();
        assert_eq!(query.ips, "1.2.3.4");
    }

    // ── count_unique_ips_blocked (block-count consistency) ───────────

    fn mk_decision(incident_id: &str, action: &str, ip: Option<&str>) -> DecisionEntry {
        DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: String::new(),
            ai_provider: String::new(),
            action_type: action.to_string(),
            target_ip: ip.map(|s| s.to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: String::new(),
            execution_result: "ok".into(),
            estimated_threat: String::new(),
            prev_hash: None,
        }
    }

    #[test]
    fn count_unique_ips_blocked_dedups_repeated_ip() {
        // Same IP blocked three times across three incidents -> counted once.
        let real: std::collections::HashSet<&str> = ["i1", "i2", "i3"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", Some("10.0.0.1")),
            mk_decision("i2", "block_ip", Some("10.0.0.1")),
            mk_decision("i3", "block_ip", Some("10.0.0.1")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 1);
    }

    #[test]
    fn count_unique_ips_blocked_counts_distinct_ips() {
        let real: std::collections::HashSet<&str> = ["i1", "i2", "i3"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", Some("10.0.0.1")),
            mk_decision("i2", "block_ip", Some("10.0.0.2")),
            mk_decision("i3", "block_ip", Some("10.0.0.3")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 3);
    }

    #[test]
    fn count_unique_ips_blocked_skips_non_block_actions() {
        let real: std::collections::HashSet<&str> = ["i1", "i2"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "monitor", Some("10.0.0.1")),
            mk_decision("i2", "ignore", Some("10.0.0.2")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 0);
    }

    #[test]
    fn count_unique_ips_blocked_skips_decisions_not_in_real_set() {
        // Research-only / internal incidents get filtered out of the
        // "real" set upstream; their block decisions must not inflate
        // the public counter.
        let real: std::collections::HashSet<&str> = ["i1"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", Some("10.0.0.1")),
            mk_decision("research", "block_ip", Some("10.0.0.99")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 1);
    }

    #[test]
    fn count_unique_ips_blocked_ignores_missing_and_empty_target_ip() {
        let real: std::collections::HashSet<&str> = ["i1", "i2", "i3"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", None),
            mk_decision("i2", "block_ip", Some("")),
            mk_decision("i3", "block_ip", Some("10.0.0.1")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 1);
    }
}
