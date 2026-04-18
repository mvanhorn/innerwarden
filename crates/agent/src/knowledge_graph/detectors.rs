//! Graph-based detectors — run periodic queries on the knowledge graph
//! to detect attack patterns structurally instead of per-event matching.
//!
//! These run in parallel with sensor-side detectors (Phase 3 validation).
//! Each returns a Vec<Incident> that can be compared with sensor incidents.

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use std::collections::{HashMap, HashSet};

use super::graph::KnowledgeGraph;
use super::types::*;

/// Environment calibration context passed to graph detectors.
/// Enables cloud-aware suppression and operator UID awareness.
#[derive(Debug, Clone, Default)]
pub struct CalibrationContext {
    /// True if running on a cloud VM (auto-detected from environment profile).
    /// Reserved for future cloud-specific threshold adjustments (e.g.,
    /// timing anomaly sensitivity, network noise suppression).
    #[allow(dead_code)]
    pub is_cloud: bool,
    /// UIDs of human operators. Graph detectors use higher thresholds for these.
    pub human_uids: Vec<u32>,
}

/// Cooldown tracker to prevent duplicate graph-based alerts.
/// Also tracks recent graph detections for sensor dedup.
pub struct GraphDetectorState {
    cooldowns: HashMap<String, DateTime<Utc>>,
    #[allow(dead_code)]
    // seed value for new cooldowns; read by future detectors_custom_cooldown path
    default_cooldown_secs: i64,
    /// Tracks recent graph detections: "detector:entity" → timestamp.
    /// Used to suppress duplicate sensor incidents.
    recent_detections: HashMap<String, DateTime<Utc>>,
}

impl GraphDetectorState {
    pub fn new() -> Self {
        Self {
            cooldowns: HashMap::new(),
            default_cooldown_secs: 300,
            recent_detections: HashMap::new(),
        }
    }

    fn check_and_set(&mut self, key: &str, now: DateTime<Utc>, cooldown_secs: i64) -> bool {
        if let Some(last) = self.cooldowns.get(key) {
            if now - *last < Duration::seconds(cooldown_secs) {
                return false; // Still in cooldown
            }
        }
        self.cooldowns.insert(key.to_string(), now);
        true
    }

    /// Record that a graph detector fired for a specific detector+entity combination.
    fn record_detection(&mut self, detector: &str, entity: &str, now: DateTime<Utc>) {
        let key = format!("{}:{}", detector, entity);
        self.recent_detections.insert(key, now);
    }

    /// Check if a sensor incident should be suppressed because the graph already
    /// detected the same pattern for the same entity within 60s.
    pub fn should_suppress_sensor(
        &self,
        sensor_detector: &str,
        entity_value: &str,
        now: DateTime<Utc>,
    ) -> bool {
        // Map sensor detector names to their graph equivalents
        let graph_detector = match sensor_detector {
            "threat_intel" => "threat_intel",
            "lateral_movement" => "lateral_movement",
            "reverse_shell" => "reverse_shell",
            "fileless" => "fileless",
            "discovery_burst" => "discovery_burst",
            "data_exfiltration" | "data_exfil_cmd" => "data_exfil",
            "crontab_persistence" | "systemd_persistence" | "ssh_key_injection" => "persistence",
            "process_tree" => "process_tree",
            "kernel_module_load" | "kernel_module" => "kernel_module",
            "service_stop" => "service_stop",
            "container_escape" => "container_escape",
            "log_tampering" => "log_tampering",
            "crypto_miner" => "crypto_miner",
            "port_scan" => "port_scan",
            "credential_stuffing" => "credential_stuffing",
            "sudo_abuse" => "sudo_abuse",
            _ => return false, // No graph equivalent — don't suppress
        };

        let key = format!("{}:{}", graph_detector, entity_value);
        if let Some(ts) = self.recent_detections.get(&key) {
            return now - *ts < Duration::seconds(60);
        }
        false
    }

    /// Prune stale cooldowns and detections older than 1 hour.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.cooldowns
            .retain(|_, ts| now - *ts < Duration::hours(1));
        self.recent_detections
            .retain(|_, ts| now - *ts < Duration::seconds(120));
    }
}

/// Run all graph-based detectors with default calibration (no environment info).
/// Convenience wrapper for tests and backwards compatibility.
#[allow(dead_code)]
pub fn run_all(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    run_all_with_calibration(graph, state, host, now, &CalibrationContext::default())
}

/// Run all graph-based detectors with environment calibration context.
/// The calibration context enables cloud-aware suppression and operator
/// UID awareness to reduce false positives on fresh installs.
pub fn run_all_with_calibration(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();

    incidents.extend(detect_threat_intel(graph, state, host, now));
    incidents.extend(detect_lateral_movement(graph, state, host, now));
    incidents.extend(detect_process_tree_anomaly(graph, state, host, now));
    incidents.extend(detect_reverse_shell(graph, state, host, now));
    incidents.extend(detect_fileless(graph, state, host, now));
    incidents.extend(detect_discovery_burst_calibrated(
        graph, state, host, now, ctx,
    ));
    incidents.extend(detect_persistence(graph, state, host, now));
    incidents.extend(detect_data_exfil_calibrated(graph, state, host, now, ctx));

    // Phase 3A: easy graph detectors
    incidents.extend(detect_kernel_module(graph, state, host, now));
    incidents.extend(detect_service_stop(graph, state, host, now));
    incidents.extend(detect_container_escape(graph, state, host, now));
    incidents.extend(detect_log_tampering(graph, state, host, now));
    incidents.extend(detect_crypto_miner(graph, state, host, now));
    incidents.extend(detect_sensitive_write(graph, state, host, now));
    // Spec 015: detect_user_creation was removed. It was a pure presence
    // scan over `nodes_of_type(User)` that fired every 30min for every
    // non-system User node in the graph. Because User nodes are permanent
    // (graph.rs is_expired → `Node::User => false`), each attacker-supplied
    // username from SSH brute-force stayed in the graph forever and fired
    // the detector indefinitely — 3,954 false positives on prod snapshot
    // 2026-04-11. Real user creation continues to be detected by the
    // sensor-side `user_creation` detector (crates/sensor/src/detectors/
    // user_creation.rs), whose incidents are ingested via ingest_incident()
    // and still match the CL-012 "Multi-Persistence" correlation rule via
    // the stage pattern contains("user_creation").
    incidents.extend(detect_docker_anomaly(graph, state, host, now));
    incidents.extend(detect_scanner_ua(graph, state, host, now));
    incidents.extend(detect_c2_beacon(graph, state, host, now));

    incidents.extend(detect_cgroup_abuse(graph, state, host, now));

    // Phase 3B: aggregation detectors
    incidents.extend(detect_host_drift_calibrated(graph, state, host, now, ctx));
    incidents.extend(detect_proto_anomaly_aggregated(graph, state, host, now));
    incidents.extend(detect_port_scan(graph, state, host, now));
    incidents.extend(detect_credential_stuffing(graph, state, host, now));
    incidents.extend(detect_sudo_abuse(graph, state, host, now));
    incidents.extend(detect_network_sniffing(graph, state, host, now));
    incidents.extend(detect_dns_tunnel(graph, state, host, now));

    // Phase 3C: correlation rules as graph paths
    incidents.extend(detect_correlation_chains(graph, state, host, now));

    // Slow-and-low: 24h lookback for persistent low-rate C2 patterns
    incidents.extend(detect_slow_and_low(graph, state, host, now));

    // Record detections for sensor dedup
    for inc in &incidents {
        let detector = inc.incident_id.split(':').next().unwrap_or("");
        // Strip "graph_" prefix to match sensor names
        let detector_base = detector.strip_prefix("graph_").unwrap_or(detector);
        let entity = inc.entities.first().map(|e| e.value.as_str()).unwrap_or("");
        state.record_detection(detector_base, entity, now);
    }

    // Periodic prune
    state.prune(now);

    incidents
}

// ── 1. Threat Intel via Graph ───────────────────────────────────────────
// Replaces: threat_intel detector (per-event IP checking)
// Graph query: all Process→ConnectedTo→Ip where Ip.datasets is non-empty

fn detect_threat_intel(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let hits = graph.threat_intel_hits();

    for (proc_id, ip_id, dataset) in hits {
        let key = format!("graph_ti:{}:{}", ip_id, dataset);
        if !state.check_and_set(&key, now, 300) {
            continue;
        }

        let proc_label = graph
            .get_node(proc_id)
            .map(|n| n.label())
            .unwrap_or_default();
        let ip_addr = match graph.get_node(ip_id) {
            Some(Node::Ip { addr, .. }) => addr.clone(),
            _ => continue,
        };

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_threat_intel:{}:{}", ip_addr, now.timestamp()),
            severity: Severity::High,
            title: format!(
                "Threat intel match: {} → {} ({})",
                proc_label, ip_addr, dataset
            ),
            summary: format!(
                "Process {} connected to IP {} which is in threat dataset '{}'.",
                proc_label, ip_addr, dataset
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_threat_intel",
                "process": proc_label,
                "ip": ip_addr,
                "dataset": dataset,
            }),
            recommended_checks: vec![
                format!("Check process {}", proc_label),
                format!("Investigate IP {} in threat feeds", ip_addr),
            ],
            tags: vec!["T1071".to_string()],
            entities: vec![EntityRef::ip(&ip_addr)],
        });
    }

    incidents
}

// ── 2. Lateral Movement via Graph ───────────────────────────────────────
// Replaces: lateral_movement detector (per-event outbound connect to internal)
// Graph query: Process→ConnectedTo→Ip(internal) where same Process connects to 3+ internal IPs on port 22

fn detect_lateral_movement(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(300);

    // Group: Process → set of internal IPs connected on port 22
    let mut ssh_scans: HashMap<NodeId, HashSet<String>> = HashMap::new();
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        for edge in graph.outgoing_edges(proc_id) {
            if edge.relation != Relation::ConnectedTo || edge.ts < cutoff {
                continue;
            }
            let port = edge
                .properties
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            if port != 22 {
                continue;
            }
            if let Some(Node::Ip {
                addr,
                is_internal: true,
                ..
            }) = graph.get_node(edge.to)
            {
                ssh_scans.entry(proc_id).or_default().insert(addr.clone());
            }
        }
    }

    for (proc_id, ips) in ssh_scans {
        if ips.len() < 3 {
            continue;
        }
        let key = format!("graph_lateral:{}", proc_id);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let proc_label = graph
            .get_node(proc_id)
            .map(|n| n.label())
            .unwrap_or_default();
        let ip_list: Vec<String> = ips.into_iter().collect();

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_lateral_movement:{}:{}", proc_id, now.timestamp()),
            severity: Severity::High,
            title: format!(
                "Lateral movement: {} SSH scanning {} internal IPs",
                proc_label,
                ip_list.len()
            ),
            summary: format!(
                "Process {} connected via SSH (port 22) to {} internal IPs in 5 minutes: {}",
                proc_label,
                ip_list.len(),
                ip_list.join(", ")
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_lateral_movement",
                "process": proc_label,
                "internal_ips": ip_list,
            }),
            recommended_checks: vec!["Check for compromised credentials".to_string()],
            tags: vec!["T1021.004".to_string()],
            entities: ip_list.iter().map(EntityRef::ip).collect(),
        });
    }

    incidents
}

// ── 3. Process Tree Anomaly via Graph ───────────────────────────────────
// Replaces: process_tree detector (parent→child pattern matching)
// Graph query: ancestors() with suspicious parent comm

fn detect_process_tree_anomaly(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let suspicious_parents = [
        "nginx", "apache", "apache2", "httpd", "mysqld", "postgres", "java", "node", "php-fpm",
        "uwsgi", "gunicorn", "mongod",
    ];
    let shell_comms = ["bash", "sh", "dash", "zsh", "ash", "fish", "csh"];

    for proc_id in graph.nodes_of_type(NodeType::Process) {
        let (pid, comm) = match graph.get_node(proc_id) {
            Some(Node::Process { pid, comm, .. }) => (*pid, comm.clone()),
            _ => continue,
        };

        // Only check shell processes
        if !shell_comms.iter().any(|s| comm == *s) {
            continue;
        }

        let ancestors = graph.ancestors(pid);
        if ancestors.is_empty() {
            continue;
        }

        // Check if any ancestor is a suspicious parent
        for anc_id in &ancestors {
            let anc_comm = match graph.get_node(*anc_id) {
                Some(Node::Process { comm, .. }) => comm.clone(),
                _ => continue,
            };

            if suspicious_parents.iter().any(|s| anc_comm.contains(s)) {
                let key = format!("graph_ptree:{}:{}", anc_comm, pid);
                if !state.check_and_set(&key, now, 600) {
                    continue;
                }

                let chain: Vec<String> = std::iter::once(proc_id)
                    .chain(ancestors.iter().copied())
                    .filter_map(|id| graph.get_node(id).map(|n| n.label()))
                    .collect();

                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!(
                        "graph_process_tree:{}:{}:{}",
                        anc_comm,
                        pid,
                        now.timestamp()
                    ),
                    severity: Severity::High,
                    title: format!("Suspicious process tree: {} spawned shell", anc_comm),
                    summary: format!("Process chain: {}", chain.join(" → ")),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_process_tree",
                        "chain": chain,
                        "suspicious_parent": anc_comm,
                    }),
                    recommended_checks: vec![
                        format!("Check if {} was exploited", anc_comm),
                        "Review process tree for web shell or RCE".to_string(),
                    ],
                    tags: vec!["T1059.004".to_string()],
                    entities: vec![],
                });
                break; // One alert per process
            }
        }
    }

    incidents
}

// ── 4. Reverse Shell via Graph ──────────────────────────────────────────
// Replaces: reverse_shell detector (eBPF fd_redirect + connect sequence)
// Graph query: Process with RedirectedFd(fd=0|1) AND ConnectedTo(external Ip)

fn detect_reverse_shell(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(30);
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        let edges = graph.outgoing_edges(proc_id);

        // Check for fd redirect (fd 0, 1, or 2)
        let has_fd_redirect = edges.iter().any(|e| {
            e.relation == Relation::RedirectedFd
                && e.ts >= cutoff
                && e.properties
                    .get("old_fd")
                    .and_then(|v| v.as_i64())
                    .is_some_and(|fd| fd <= 2)
        });

        if !has_fd_redirect {
            continue;
        }

        // Check for outbound connection to external IP
        let external_ip = edges.iter().find_map(|e| {
            if e.relation == Relation::ConnectedTo && e.ts >= cutoff {
                match graph.get_node(e.to) {
                    Some(Node::Ip {
                        addr,
                        is_internal: false,
                        ..
                    }) => Some(addr.clone()),
                    _ => None,
                }
            } else {
                None
            }
        });

        if let Some(ip) = external_ip {
            let pid = match graph.get_node(proc_id) {
                Some(Node::Process { pid, .. }) => *pid,
                _ => continue,
            };
            let key = format!("graph_revshell:{}", pid);
            if !state.check_and_set(&key, now, 300) {
                continue;
            }

            let label = graph
                .get_node(proc_id)
                .map(|n| n.label())
                .unwrap_or_default();

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_reverse_shell:{}:{}", pid, now.timestamp()),
                severity: Severity::Critical,
                title: format!("Reverse shell: {} → {}", label, ip),
                summary: format!(
                    "Process {} redirected stdin/stdout to socket connected to external IP {}",
                    label, ip
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_reverse_shell",
                    "process": label,
                    "pid": pid,
                    "dst_ip": ip,
                }),
                recommended_checks: vec![format!("Kill PID {}", pid), format!("Block IP {}", ip)],
                tags: vec!["T1059.004".to_string()],
                entities: vec![EntityRef::ip(&ip)],
            });
        }
    }

    incidents
}

// ── 5. Fileless Malware via Graph ───────────────────────────────────────
// Replaces: fileless detector (memfd_create + mprotect + connect)
// Graph query: Process with CreatedMemfd AND MprotectExec AND ConnectedTo(external)

fn detect_fileless(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(60);
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        let edges = graph.outgoing_edges(proc_id);

        let has_memfd = edges
            .iter()
            .any(|e| e.relation == Relation::CreatedMemfd && e.ts >= cutoff);
        let has_mprotect = edges
            .iter()
            .any(|e| e.relation == Relation::MprotectExec && e.ts >= cutoff);
        let has_external = edges.iter().any(|e| {
            e.relation == Relation::ConnectedTo
                && e.ts >= cutoff
                && graph.get_node(e.to).is_some_and(|n| {
                    matches!(
                        n,
                        Node::Ip {
                            is_internal: false,
                            ..
                        }
                    )
                })
        });

        if has_memfd && has_mprotect && has_external {
            let pid = match graph.get_node(proc_id) {
                Some(Node::Process { pid, .. }) => *pid,
                _ => continue,
            };
            let key = format!("graph_fileless:{}", pid);
            if !state.check_and_set(&key, now, 300) {
                continue;
            }

            let label = graph
                .get_node(proc_id)
                .map(|n| n.label())
                .unwrap_or_default();

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_fileless:{}:{}", pid, now.timestamp()),
                severity: Severity::Critical,
                title: format!("Fileless malware: {}", label),
                summary: format!(
                    "Process {} created memfd + made memory executable + connected to external IP (CL-006 pattern)",
                    label
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_fileless",
                    "process": label,
                    "pid": pid,
                }),
                recommended_checks: vec![format!("Kill PID {} immediately", pid)],
                tags: vec!["T1055.009".to_string()],
                entities: vec![],
            });
        }
    }

    incidents
}

// ── 6. Discovery Burst via Graph ────────────────────────────────────────
// Replaces: discovery_burst detector (counting recon commands per user)
// Graph query: User with >5 Read edges to sensitive files in <60s

fn detect_discovery_burst_calibrated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(60);
    let threshold = 5;

    // Group: User → count of processes that executed in window
    for user_id in graph.nodes_of_type(NodeType::User) {
        let user_name = match graph.get_node(user_id) {
            Some(Node::User { name, .. }) => name.clone(),
            _ => continue,
        };

        // Count processes that have RunAs edge to this user in the window
        let recent_procs: Vec<NodeId> = graph
            .incoming_edges(user_id)
            .iter()
            .filter(|e| e.relation == Relation::RunAs && e.ts >= cutoff)
            .map(|e| e.from)
            .collect();

        // Count Read edges to sensitive files from those processes
        let mut sensitive_reads = 0;
        for &proc_id in &recent_procs {
            for edge in graph.outgoing_edges(proc_id) {
                if edge.relation == Relation::Read && edge.ts >= cutoff {
                    if let Some(Node::File {
                        is_sensitive: true, ..
                    }) = graph.get_node(edge.to)
                    {
                        sensitive_reads += 1;
                    }
                }
            }
        }

        // Also count Executed edges (process spawns = discovery commands)
        let exec_count = recent_procs.len();

        let total = sensitive_reads + exec_count;

        // Apply 3x threshold for root AND trusted operator UIDs.
        // Operators doing their job (deploying, debugging) routinely
        // hit discovery thresholds. This is structural suppression:
        // the UID is declared or auto-detected, not observed.
        let is_trusted_user =
            user_name == "root" || is_trusted_graph_user(&user_name, &ctx.human_uids);
        let adjusted_threshold = if is_trusted_user {
            threshold * 3
        } else {
            threshold
        };

        if total >= adjusted_threshold {
            let key = format!("graph_discovery:{}", user_name);
            if !state.check_and_set(&key, now, 1800) {
                continue;
            }

            let severity = if total >= adjusted_threshold * 2 {
                Severity::High
            } else {
                Severity::Medium
            };

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_discovery_burst:{}:{}", user_name, now.timestamp()),
                severity,
                title: format!("Discovery burst: user {} ({} actions in 60s)", user_name, total),
                summary: format!(
                    "User {} performed {} process executions and {} sensitive file reads in 60 seconds",
                    user_name, exec_count, sensitive_reads
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_discovery_burst",
                    "user": user_name,
                    "exec_count": exec_count,
                    "sensitive_reads": sensitive_reads,
                }),
                recommended_checks: vec!["Check for reconnaissance activity".to_string()],
                tags: vec!["T1087".to_string()],
                entities: vec![EntityRef::user(&user_name)],
            });
        }
    }

    incidents
}

/// Check if a graph user name (which can be "root", "ubuntu", "uid:1001", etc.)
/// corresponds to a trusted operator UID from the calibration context.
fn is_trusted_graph_user(user_name: &str, human_uids: &[u32]) -> bool {
    // Graph user names can be actual usernames or "uid:NNNN" format
    if let Some(uid_str) = user_name.strip_prefix("uid:") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            return human_uids.contains(&uid);
        }
    }
    // For named users, check if any human UID resolves to this name.
    // Since we don't have a reverse map, we check if the user has a UID >= 1000
    // pattern (human UIDs are >= 1000 by convention).
    false
}

// ── 7. Persistence via Graph ────────────────────────────────────────────
// Replaces: crontab_persistence + systemd_persistence + ssh_key_injection
// Graph query: Process→Wrote→File where File.path matches persistence locations

fn detect_persistence(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(300);
    let active = graph.active_nodes_since(cutoff);

    let persistence_patterns: &[(&str, &str, &str)] = &[
        ("/etc/cron", "crontab_persistence", "T1053.003"),
        ("/var/spool/cron", "crontab_persistence", "T1053.003"),
        ("/etc/systemd/", "systemd_persistence", "T1543.002"),
        ("/usr/lib/systemd/", "systemd_persistence", "T1543.002"),
        ("authorized_keys", "ssh_key_injection", "T1098.004"),
    ];

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        for edge in graph.outgoing_edges(proc_id) {
            if edge.relation != Relation::Wrote || edge.ts < cutoff {
                continue;
            }

            let file_path = match graph.get_node(edge.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            };

            for &(pattern, detector_name, mitre) in persistence_patterns {
                if !file_path.contains(pattern) {
                    continue;
                }

                let key = format!("graph_persist:{}:{}", detector_name, proc_id);
                if !state.check_and_set(&key, now, 600) {
                    continue;
                }

                let proc_label = graph
                    .get_node(proc_id)
                    .map(|n| n.label())
                    .unwrap_or_default();

                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_{}:{}:{}", detector_name, proc_id, now.timestamp()),
                    severity: Severity::High,
                    title: format!("Persistence: {} wrote to {}", proc_label, file_path),
                    summary: format!(
                        "Process {} wrote to persistence location {}",
                        proc_label, file_path
                    ),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": format!("graph_{}", detector_name),
                        "process": proc_label,
                        "path": file_path,
                    }),
                    recommended_checks: vec![
                        format!("Inspect {}", file_path),
                        format!("Check process tree of {}", proc_label),
                    ],
                    tags: vec![mitre.to_string()],
                    entities: vec![EntityRef::path(&file_path)],
                });
                break; // One match per file
            }
        }
    }

    incidents
}

// ── 8. Data Exfiltration via Graph ──────────────────────────────────────
// Replaces: data_exfiltration + data_exfil_ebpf
// Graph query: Process that Read(sensitive file) AND ConnectedTo(external Ip) in <60s

fn detect_data_exfil_calibrated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    _ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(60);
    let active = graph.active_nodes_since(cutoff);

    for &proc_id in &active {
        if !matches!(graph.get_node(proc_id), Some(Node::Process { .. })) {
            continue;
        }
        let edges = graph.outgoing_edges(proc_id);

        // Check if process read a sensitive file recently
        let sensitive_read = edges.iter().find(|e| {
            e.relation == Relation::Read
                && e.ts >= cutoff
                && graph.get_node(e.to).is_some_and(|n| n.is_sensitive_file())
        });

        let read_file = match sensitive_read {
            Some(e) => match graph.get_node(e.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            },
            None => continue,
        };

        // Check if same process connected to external IP
        let external_conn = edges.iter().find(|e| {
            e.relation == Relation::ConnectedTo
                && e.ts >= cutoff
                && graph.get_node(e.to).is_some_and(|n| {
                    matches!(
                        n,
                        Node::Ip {
                            is_internal: false,
                            ..
                        }
                    )
                })
        });

        if let Some(conn_edge) = external_conn {
            let dst_ip = match graph.get_node(conn_edge.to) {
                Some(Node::Ip { addr, .. }) => addr.clone(),
                _ => continue,
            };

            // Suppress data exfil to cloud provider IPs and self-traffic
            // destinations (Telegram, GeoIP endpoints, Ubuntu archives, etc.).
            // The agent routinely reads /etc/passwd (NSS resolution) and
            // connects to cloud APIs — that's self-traffic, not exfil.
            if crate::cloud_safelist::is_self_traffic_ip(&dst_ip) {
                continue;
            }

            let (pid, comm, uid) = match graph.get_node(proc_id) {
                Some(Node::Process { pid, comm, uid, .. }) => (*pid, comm.clone(), *uid),
                _ => continue,
            };

            // Infrastructure processes that legitimately read sensitive files
            // and connect to external IPs are NOT data exfiltration.
            // Filter by process name — not IP — so new IPs are covered.
            const INFRA_COMMS: &[&str] = &[
                "crowdsec",          // CrowdSec threat intel
                "innerwarden",       // InnerWarden agent
                "tokio-rt-worker",   // InnerWarden agent runtime threads
                "innerwarden-agent", // Agent binary name
                "innerwarden-senso", // Sensor binary name (truncated to 16 chars)
                "fail2ban",          // Fail2ban
                "telegraf",          // Telegraf monitoring
                "prometheus",        // Prometheus
                "node_exporter",     // Node exporter
                "apt",               // Package manager
                "dpkg",              // Package manager
                "unattended-upgr",   // Unattended upgrades
                "cscli",             // CrowdSec CLI
            ];
            let comm_lower = comm.to_lowercase();
            if INFRA_COMMS.iter().any(|&c| comm_lower.starts_with(c)) {
                continue;
            }
            // Also skip InnerWarden UID (typically 998)
            if uid == 998 {
                continue;
            }

            let key = format!("graph_exfil:{}:{}", pid, dst_ip);
            if !state.check_and_set(&key, now, 300) {
                continue;
            }

            let label = graph
                .get_node(proc_id)
                .map(|n| n.label())
                .unwrap_or_default();

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_data_exfil:{}:{}:{}", pid, dst_ip, now.timestamp()),
                severity: Severity::High,
                title: format!("Data exfiltration: {} read {} → connected to {}", label, read_file, dst_ip),
                summary: format!(
                    "Process {} read sensitive file {} and connected to external IP {} within 60 seconds (CL-008 pattern)",
                    label, read_file, dst_ip
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_data_exfil",
                    "process": label,
                    "pid": pid,
                    "file": read_file,
                    "dst_ip": dst_ip,
                }),
                recommended_checks: vec![
                    format!("Block IP {}", dst_ip),
                    format!("Kill PID {}", pid),
                    "Check for credential theft".to_string(),
                ],
                tags: vec!["T1041".to_string()],
                entities: vec![EntityRef::ip(&dst_ip), EntityRef::path(&read_file)],
            });
        }
    }

    incidents
}

// 24. Network sniffing — processes running capture tools
fn detect_network_sniffing(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let sniffer_tools = [
        "tcpdump",
        "tshark",
        "wireshark",
        "ngrep",
        "ettercap",
        "bettercap",
        "dsniff",
        "arpspoof",
        "mitmproxy",
    ];
    // Spec 015: processes spawned by the agent itself must not trigger this
    // detector. The dashboard pcap_capture module spawns tcpdump for ~60s
    // bursts whenever a High/Critical incident fires, and the old presence
    // scan was counting each of those bursts as a new sniffing event —
    // contributing 67 graph_network_sniffing false positives on the prod
    // snapshot from 2026-04-11.
    let agent_ancestors = ["innerwarden-agent", "innerwarden-sensor"];

    // Only consider processes that actually started recently. This matches
    // the signal we care about ("someone just launched tcpdump") and stops
    // the presence-scan behavior where a stale Process node kept firing the
    // detector once per cooldown window forever.
    let window = Duration::seconds(300);

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let (pid, comm, start_ts) = match graph.get_node(pid_id) {
            Some(Node::Process {
                pid,
                comm,
                start_ts,
                ..
            }) => (*pid, comm.clone(), *start_ts),
            _ => continue,
        };
        if !sniffer_tools.iter().any(|t| comm == *t) {
            continue;
        }
        if now - start_ts > window {
            continue; // stale node — not a fresh launch
        }

        // Walk ancestors; if any is the agent/sensor itself, this sniffer
        // was spawned by InnerWarden's own pcap_capture and is not an alert.
        let spawned_by_agent = graph.ancestors(pid).iter().any(|&anc| {
            matches!(
                graph.get_node(anc),
                Some(Node::Process { comm: ac, .. }) if agent_ancestors.iter().any(|a| ac == a)
            )
        });
        if spawned_by_agent {
            continue;
        }

        // Fallback: if the ancestor walk couldn't find the parent (eBPF
        // event arrived with pid=0 or ppid not ingested), check the Process
        // node's own uid. The agent runs as uid 998 (innerwarden); tcpdump
        // spawned by pcap_capture inherits this uid. Observed 2026-04-12:
        // the ancestor walk returns empty when the graph doesn't have the
        // parent Process node, so the uid check is the safety net.
        if let Some(Node::Process { uid, .. }) = graph.get_node(pid_id) {
            if *uid == 998 {
                // innerwarden UID — this sniffer is our own pcap_capture
                continue;
            }
        }

        let key = format!("graph_sniff:{}:{}", comm, pid_id);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_network_sniffing:{}:{}", comm, now.timestamp()),
            severity: Severity::High,
            title: format!("Network sniffing tool detected: {}", comm),
            summary: format!(
                "Process '{}' is a known network capture tool. May indicate credential harvesting or traffic interception.",
                comm
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_network_sniffing",
                "process": comm,
            }),
            recommended_checks: vec![
                format!("Check process: ps aux | grep {}", comm),
                "Review CAP_NET_RAW: getpcaps $(pgrep tcpdump)".to_string(),
            ],
            tags: vec!["T1040".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// 25. DNS tunneling — high query volume or high-entropy domains
fn detect_dns_tunnel(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(60);

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        // Count DNS resolutions in window
        let dns_edges = graph.edges_in_window(pid_id, Relation::Resolved, now, window);
        if dns_edges.len() < 50 {
            continue; // Normal DNS volume
        }

        // Check for high-entropy domains (long labels = likely tunneling)
        let long_domains = dns_edges
            .iter()
            .filter(|e| {
                graph
                    .get_node(e.to)
                    .map(|n| n.label().len() > 50)
                    .unwrap_or(false)
            })
            .count();

        let is_tunnel = long_domains > 10 || dns_edges.len() > 100;
        if !is_tunnel {
            continue;
        }

        let key = format!("graph_dnstunnel:{}", comm);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let sample_domains: Vec<String> = dns_edges
            .iter()
            .take(5)
            .filter_map(|e| graph.get_node(e.to).map(|n| n.label().to_string()))
            .collect();

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_dns_tunnel:{}:{}", comm, now.timestamp()),
            severity: Severity::High,
            title: format!("DNS tunneling: {} ({} queries, {} long domains in 1m)", comm, dns_edges.len(), long_domains),
            summary: format!(
                "Process '{}' resolved {} domains in 1 minute ({} with labels >50 chars). Pattern consistent with DNS tunneling/exfiltration.",
                comm, dns_edges.len(), long_domains
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_dns_tunnel",
                "process": comm,
                "query_count": dns_edges.len(),
                "long_domain_count": long_domains,
                "sample_domains": sample_domains,
            }),
            recommended_checks: vec![
                format!("Check DNS: dig +short any suspicious domain"),
                format!("Block process: kill $(pgrep {})", comm),
            ],
            tags: vec!["T1071.004".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// ── Phase 3A: Easy Graph Detectors ─────────────────────────────────────

// 9. Kernel module loading (insmod/modprobe/rmmod)
fn detect_kernel_module(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let module_cmds = ["insmod", "modprobe", "rmmod"];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if !module_cmds.iter().any(|c| comm == *c) {
            continue;
        }
        // Find what file was executed/loaded
        let target = graph
            .outgoing_edges(pid_id)
            .iter()
            .find(|e| e.relation == Relation::Executed || e.relation == Relation::LoadedModule)
            .and_then(|e| graph.get_node(e.to).map(|n| n.label().to_string()))
            .unwrap_or_else(|| comm.clone());

        let key = format!("graph_km:{}", target);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_kernel_module:{}:{}", target, now.timestamp()),
            severity: Severity::High,
            title: format!("Kernel module operation: {} {}", comm, target),
            summary: format!(
                "Process '{}' loaded/unloaded kernel module '{}'. Kernel module operations can indicate rootkit installation or system tampering.",
                comm, target
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_kernel_module",
                "process": comm,
                "module": target,
            }),
            recommended_checks: vec![
                format!("Verify module {} is expected", target),
                "Check lsmod for unknown modules".to_string(),
            ],
            tags: vec!["T1547.006".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// 10. Security service stopped (systemctl stop innerwarden/fail2ban/auditd/etc)
fn detect_service_stop(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let security_services = [
        "innerwarden",
        "fail2ban",
        "auditd",
        "rsyslog",
        "syslog",
        "iptables",
        "nftables",
        "ufw",
        "firewalld",
        "apparmor",
        "selinux",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if comm != "systemctl" && comm != "service" {
            continue;
        }
        // Get args from edge properties (summary field or event details)
        let args_str = graph
            .outgoing_edges(pid_id)
            .iter()
            .filter_map(|e| e.properties.get("summary").and_then(|v| v.as_str()))
            .next()
            .unwrap_or("")
            .to_lowercase();
        if !args_str.contains("stop") && !args_str.contains("disable") {
            continue;
        }
        let stopped = security_services.iter().find(|s| args_str.contains(**s));
        let Some(svc) = stopped else { continue };

        let key = format!("graph_svc_stop:{}", svc);
        if !state.check_and_set(&key, now, 300) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_service_stop:{}:{}", svc, now.timestamp()),
            severity: Severity::Critical,
            title: format!("Security service stopped: {}", svc),
            summary: format!(
                "Process '{}' stopped security service '{}'. This may indicate defense evasion.",
                comm, svc
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_service_stop",
                "process": comm,
                "service": svc,
                "args": args_str,
            }),
            recommended_checks: vec![
                format!(
                    "Check if {} is still running: systemctl status {}",
                    svc, svc
                ),
                "Review who initiated the stop".to_string(),
            ],
            tags: vec!["T1562.001".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// 11. Container escape attempts (docker.sock access, /proc/1 reads)
fn detect_container_escape(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let escape_paths = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/proc/1/root",
        "/proc/1/ns/mnt",
        "/proc/1/ns/pid",
        "/proc/1/ns/net",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::Read && edge.relation != Relation::Wrote {
                continue;
            }
            let file_path = match graph.get_node(edge.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            };
            if !escape_paths.iter().any(|p| file_path.starts_with(p)) {
                continue;
            }

            let key = format!("graph_escape:{}:{}", pid_id, file_path);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_container_escape:{}:{}", comm, now.timestamp()),
                severity: Severity::Critical,
                title: format!("Container escape attempt: {} accessed {}", comm, file_path),
                summary: format!(
                    "Process '{}' accessed '{}' which may indicate a container escape attempt.",
                    comm, file_path
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_container_escape",
                    "process": comm,
                    "file": file_path,
                }),
                recommended_checks: vec![
                    "Check if process is running inside a container".to_string(),
                    format!("Investigate why {} needs access to {}", comm, file_path),
                ],
                tags: vec!["T1611".to_string()],
                entities: vec![],
            });
        }
    }
    incidents
}

// 12. Log tampering (non-standard processes writing to /var/log)
fn detect_log_tampering(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let log_writers = [
        "rsyslog",
        "syslog-ng",
        "journald",
        "systemd-journal",
        "logrotate",
        "systemd",
        "auditd",
        "innerwarden-sensor",
        "innerwarden-agent",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if log_writers.iter().any(|w| comm == *w) {
            continue;
        }

        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::Wrote
                && edge.relation != Relation::Deleted
                && edge.relation != Relation::Truncated
            {
                continue;
            }
            let file_path = match graph.get_node(edge.to) {
                Some(Node::File { path, .. }) => path.clone(),
                _ => continue,
            };
            if !file_path.starts_with("/var/log/") {
                continue;
            }

            let key = format!("graph_logtamp:{}:{}", comm, file_path);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_log_tampering:{}:{}", comm, now.timestamp()),
                severity: Severity::High,
                title: format!("Log tampering: {} modified {}", comm, file_path),
                summary: format!(
                    "Non-standard process '{}' modified log file '{}'. This may indicate log tampering to cover tracks.",
                    comm, file_path
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_log_tampering",
                    "process": comm,
                    "file": file_path,
                    "action": format!("{:?}", edge.relation),
                }),
                recommended_checks: vec![
                    format!("Check integrity of {}", file_path),
                    format!("Investigate process {}", comm),
                ],
                tags: vec!["T1070.002".to_string()],
                entities: vec![],
            });
        }
    }
    incidents
}

// 13. Crypto miner detection (connections to mining pools)
fn detect_crypto_miner(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let miner_comms = [
        "xmrig",
        "minerd",
        "cpuminer",
        "ethminer",
        "cgminer",
        "bfgminer",
        "ccminer",
        "nbminer",
        "t-rex",
        "phoenixminer",
        "lolminer",
    ];
    let mining_ports: HashSet<u16> = [3333, 4444, 5555, 8333, 14444, 14433, 45700]
        .iter()
        .copied()
        .collect();

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        // Check by process name
        let name_match = miner_comms.iter().any(|m| comm.to_lowercase().contains(m));

        // Check by connection to mining ports
        let port_match = graph.outgoing_edges(pid_id).iter().any(|e| {
            if e.relation != Relation::ConnectedTo {
                return false;
            }
            e.properties
                .get("port")
                .and_then(|p| p.as_u64())
                .map(|p| mining_ports.contains(&(p as u16)))
                .unwrap_or(false)
        });

        if !name_match && !port_match {
            continue;
        }

        let key = format!("graph_miner:{}", comm);
        if !state.check_and_set(&key, now, 1800) {
            continue;
        }

        // Extract pid and uid from the graph node so the incident can be
        // linked back to the originating process via the evidence-array
        // ingestion path (ingestion.rs Phase 014-D). Without pid/uid the
        // incident ends up with no TriggeredBy edge, so the Threats tab
        // cannot pivot to it. The let-else is defensive: `pid_id` was
        // produced from `nodes_of_type(NodeType::Process)` above, so the
        // node is always Process — but if the graph was mutated between
        // the two calls, skipping this iteration is safer than emitting
        // a bogus incident with pid=0.
        let Some(Node::Process { pid, uid, .. }) = graph.get_node(pid_id) else {
            continue;
        };
        let (pid, uid) = (*pid, *uid);

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_crypto_miner:{}:{}", comm, now.timestamp()),
            severity: Severity::High,
            title: format!("Crypto miner detected: {}", comm),
            summary: format!(
                "Process '{}' matches crypto mining patterns (process name or mining pool connection).",
                comm
            ),
            evidence: serde_json::json!([{
                "source": "knowledge_graph",
                "detector": "graph_crypto_miner",
                "process": comm,
                "pid": pid,
                "comm": comm,
                "uid": uid,
                "name_match": name_match,
                "port_match": port_match,
            }]),
            recommended_checks: vec![
                format!("Kill process: kill -9 $(pgrep {})", comm),
                "Check CPU usage: top -bn1 | head -20".to_string(),
            ],
            tags: vec!["T1496".to_string()],
            entities: vec![EntityRef::path(format!("service:{comm}"))],
        });
    }
    incidents
}

// 14. Sensitive file writes by unexpected processes
fn detect_sensitive_write(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let trusted_writers = [
        "apt",
        "dpkg",
        "yum",
        "rpm",
        "pacman",
        "systemd",
        "systemctl",
        "useradd",
        "usermod",
        "groupadd",
        "passwd",
        "chpasswd",
        "innerwarden-sensor",
        "innerwarden-agent",
    ];

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };
        if trusted_writers.iter().any(|w| comm == *w) {
            continue;
        }

        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::Wrote {
                continue;
            }
            let (file_path, is_sensitive) = match graph.get_node(edge.to) {
                Some(Node::File {
                    path, is_sensitive, ..
                }) => (path.clone(), *is_sensitive),
                _ => continue,
            };
            if !is_sensitive {
                continue;
            }

            let key = format!("graph_senswrite:{}:{}", comm, file_path);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_sensitive_write:{}:{}", comm, now.timestamp()),
                severity: Severity::High,
                title: format!("Sensitive file modified: {} wrote {}", comm, file_path),
                summary: format!(
                    "Unexpected process '{}' wrote to sensitive file '{}'. This may indicate unauthorized system modification.",
                    comm, file_path
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_sensitive_write",
                    "process": comm,
                    "file": file_path,
                }),
                recommended_checks: vec![
                    format!("Check file integrity: stat {}", file_path),
                    format!("Review process: ps aux | grep {}", comm),
                ],
                tags: vec!["T1222".to_string()],
                entities: vec![EntityRef::path(&file_path)],
            });
        }
    }
    incidents
}

// ── Phase 3C: Correlation Rules as Graph Paths ─────────────────────────

struct CorrelationRule {
    id: &'static str,
    name: &'static str,
    /// Detector slug patterns for each stage. Supports glob-like prefix match.
    stages: &'static [&'static [&'static str]],
    window_secs: i64,
    /// If true, stages must share the same entity (IP or User).
    entity_must_match: bool,
    severity: Severity,
    mitre: &'static str,
}

const CORRELATION_RULES: &[CorrelationRule] = &[
    CorrelationRule {
        id: "CL-002",
        name: "Recon to Exfiltration",
        stages: &[
            &["port_scan", "web_scan", "user_agent_scanner"],
            &["ssh_bruteforce", "credential_stuffing"],
            &["data_exfiltration", "data_exfil", "outbound_anomaly"],
        ],
        window_secs: 1800,
        entity_must_match: true,
        severity: Severity::Critical,
        mitre: "TA0010",
    },
    CorrelationRule {
        id: "CL-003",
        name: "Honeypot to Real Attack",
        stages: &[
            &["honeypot"],
            &["ssh_bruteforce", "credential_stuffing", "proto_anomaly"],
        ],
        window_secs: 3600,
        entity_must_match: true,
        severity: Severity::High,
        mitre: "TA0001",
    },
    CorrelationRule {
        id: "CL-005",
        name: "Container Escape to Host",
        stages: &[
            &["container_escape", "container_drift"],
            &["shell", "execution_guard", "suspicious_execution"],
            &["privilege", "escalat"],
        ],
        window_secs: 600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "T1611",
    },
    CorrelationRule {
        id: "CL-010",
        name: "Multi-Low Severity Elevation",
        stages: &[&["__multi_low__"]], // Special handling below
        window_secs: 600,
        entity_must_match: true,
        severity: Severity::High,
        mitre: "TA0001",
    },
    CorrelationRule {
        id: "CL-011",
        name: "Credential Theft to Lateral Movement",
        stages: &[
            &["credential_harvest", "credential_stuffing"],
            &["lateral_movement", "ssh_key_injection"],
        ],
        window_secs: 1800,
        entity_must_match: true,
        severity: Severity::Critical,
        mitre: "TA0008",
    },
    CorrelationRule {
        id: "CL-012",
        name: "Multi-Persistence",
        stages: &[
            &["crontab_persistence", "systemd_persistence"],
            &["ssh_key_injection", "user_creation"],
        ],
        window_secs: 3600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "TA0003",
    },
    CorrelationRule {
        id: "CL-014",
        name: "Cryptominer Deployment",
        stages: &[
            &["shell", "outbound_connect", "execution"],
            &["crypto_miner", "cgroup"],
        ],
        window_secs: 600,
        entity_must_match: false,
        severity: Severity::High,
        mitre: "T1496",
    },
    CorrelationRule {
        id: "CL-015",
        name: "Post-Compromise Log Tampering",
        stages: &[
            &["privilege", "reverse_shell", "ssh_bruteforce"],
            &["log_tampering"],
        ],
        window_secs: 600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "T1070",
    },
    CorrelationRule {
        id: "CL-024",
        name: "Fast Web Exploit to Exfil",
        stages: &[
            &["port_scan", "web_scan", "user_agent_scanner"],
            &["web_shell", "reverse_shell"],
            &["data_exfil", "dns_tunnel", "outbound_anomaly"],
        ],
        window_secs: 300,
        entity_must_match: true,
        severity: Severity::Critical,
        mitre: "TA0010",
    },
    CorrelationRule {
        id: "CL-029",
        name: "Multi-Persistence Attempt",
        stages: &[
            &["crontab", "systemd_persistence"],
            &["ssh_key", "authorized_keys"],
        ],
        window_secs: 3600,
        entity_must_match: false,
        severity: Severity::Critical,
        mitre: "TA0003",
    },
];

/// Run all correlation rules against the graph.
/// For each entity (IP/User) that has Incident nodes, check if the incident
/// detectors match the rule's stage pattern within the time window.
fn detect_correlation_chains(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();

    // Collect all Incident nodes with their entity connections
    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    if incident_nodes.len() < 2 {
        return incidents; // Need at least 2 incidents for correlation
    }

    // Build entity→incidents map: for each IP/User, list connected incidents
    let mut entity_incidents: HashMap<NodeId, Vec<(String, DateTime<Utc>, NodeId)>> =
        HashMap::new();

    for &inc_id in &incident_nodes {
        let (detector, ts) = match graph.get_node(inc_id) {
            Some(Node::Incident { detector, ts, .. }) => (detector.clone(), *ts),
            _ => continue,
        };

        // Find connected entities via TriggeredBy edges
        for edge in graph.outgoing_edges(inc_id) {
            if edge.relation != Relation::TriggeredBy {
                continue;
            }
            let entity_type = graph.get_node(edge.to).map(|n| n.node_type());
            if matches!(entity_type, Some(NodeType::Ip) | Some(NodeType::User)) {
                entity_incidents
                    .entry(edge.to)
                    .or_default()
                    .push((detector.clone(), ts, inc_id));
            }
        }
    }

    // Check each rule against each entity's incidents
    for rule in CORRELATION_RULES {
        // Special handling: CL-010 Multi-Low Elevation
        if rule.id == "CL-010" {
            for (entity_id, inc_list) in &entity_incidents {
                let window = Duration::seconds(rule.window_secs);
                let recent: Vec<&str> = inc_list
                    .iter()
                    .filter(|(_, ts, _)| now - *ts < window)
                    .map(|(det, _, _)| det.as_str())
                    .collect();

                let unique_detectors: HashSet<&str> = recent.iter().copied().collect();
                if unique_detectors.len() < 3 {
                    continue;
                }

                let entity_label = graph
                    .get_node(*entity_id)
                    .map(|n| n.label().to_string())
                    .unwrap_or_default();
                let key = format!("graph_corr:CL-010:{}", entity_label);
                if !state.check_and_set(&key, now, 600) {
                    continue;
                }

                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_correlation:CL-010:{}:{}", entity_label, now.timestamp()),
                    severity: rule.severity.clone(),
                    title: format!(
                        "Multi-detector elevation: {} triggered {} detectors",
                        entity_label,
                        unique_detectors.len()
                    ),
                    summary: format!(
                        "Entity {} triggered {} distinct detectors in {}s: {}. Multiple low-severity indicators elevate to high.",
                        entity_label,
                        unique_detectors.len(),
                        rule.window_secs,
                        unique_detectors.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_correlation",
                        "rule": rule.id,
                        "rule_name": rule.name,
                        "entity": entity_label,
                        "detectors": recent,
                    }),
                    recommended_checks: vec![
                        format!("Investigate entity: {}", entity_label),
                    ],
                    tags: vec![rule.mitre.to_string()],
                    entities: vec![],
                });
            }
            continue;
        }

        // Standard multi-stage rules: the entity-matched path below walks
        // `entity_incidents` directly; non-entity-match rules walk the global
        // incident list built elsewhere in the same tick. We no longer stage a
        // combined "check_entities" vector since it was unused by the matcher.

        // For entity-matched rules: check each entity
        if rule.entity_must_match {
            for (entity_id, inc_list) in &entity_incidents {
                if let Some(incident) =
                    check_rule_stages(graph, state, rule, inc_list, *entity_id, host, now)
                {
                    incidents.push(incident);
                }
            }
        } else {
            // For non-entity rules: merge all incidents and check globally
            let all_incs: Vec<(String, DateTime<Utc>, NodeId)> = entity_incidents
                .values()
                .flat_map(|v| v.iter().cloned())
                .collect();
            if let Some(incident) = check_rule_stages(graph, state, rule, &all_incs, 0, host, now) {
                incidents.push(incident);
            }
        }
    }

    incidents
}

/// Check if a set of incidents matches all stages of a correlation rule.
fn check_rule_stages(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    rule: &CorrelationRule,
    inc_list: &[(String, DateTime<Utc>, NodeId)],
    entity_id: NodeId,
    host: &str,
    now: DateTime<Utc>,
) -> Option<Incident> {
    let window = Duration::seconds(rule.window_secs);

    // For each stage, find at least one matching incident within the window
    let mut stage_matches: Vec<Option<(&str, DateTime<Utc>)>> = Vec::new();

    for stage_patterns in rule.stages {
        let matched = inc_list.iter().find(|(det, ts, _)| {
            now - *ts < window
                && stage_patterns
                    .iter()
                    .any(|pattern| det.starts_with(pattern) || det.contains(pattern))
        });
        stage_matches.push(matched.map(|(det, ts, _)| (det.as_str(), *ts)));
    }

    // All stages must have a match
    if stage_matches.iter().any(|m| m.is_none()) {
        return None;
    }

    // Verify ordering: each stage's timestamp must be >= previous stage
    let timestamps: Vec<DateTime<Utc>> = stage_matches.iter().map(|m| m.unwrap().1).collect();
    for pair in timestamps.windows(2) {
        if pair[1] < pair[0] {
            return None; // Wrong order
        }
    }

    let entity_label = if entity_id > 0 {
        graph
            .get_node(entity_id)
            .map(|n| n.label().to_string())
            .unwrap_or_default()
    } else {
        "global".to_string()
    };

    let key = format!("graph_corr:{}:{}", rule.id, entity_label);
    if !state.check_and_set(&key, now, 600) {
        return None;
    }

    let matched_detectors: Vec<&str> = stage_matches.iter().map(|m| m.unwrap().0).collect();

    Some(Incident {
        ts: now,
        host: host.to_string(),
        incident_id: format!("graph_correlation:{}:{}:{}", rule.id, entity_label, now.timestamp()),
        severity: rule.severity.clone(),
        title: format!("{}: {} ({})", rule.id, rule.name, entity_label),
        summary: format!(
            "Multi-stage attack chain detected ({}): {} stages matched for entity '{}' within {}s. Stages: {}.",
            rule.name,
            rule.stages.len(),
            entity_label,
            rule.window_secs,
            matched_detectors.join(" → ")
        ),
        evidence: serde_json::json!({
            "source": "knowledge_graph",
            "detector": "graph_correlation",
            "rule": rule.id,
            "rule_name": rule.name,
            "entity": entity_label,
            "stages_matched": matched_detectors,
            "window_secs": rule.window_secs,
        }),
        recommended_checks: vec![
            format!("Investigate attack chain for {}", entity_label),
            format!("Check timeline: /api/graph/timeline?node_id={}", entity_id),
        ],
        tags: vec![rule.mitre.to_string()],
        entities: vec![],
    })
}

// ── Phase 3B: Aggregation Detectors ────────────────────────────────────

// 19. Host drift — aggregated: instead of 1 incident per unknown process,
// group by user and fire 1 incident with count. Unknown binaries in /tmp always fire individually.
fn detect_host_drift_calibrated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
    ctx: &CalibrationContext,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let system_binaries = [
        "apt",
        "apt-get",
        "dpkg",
        "yum",
        "rpm",
        "pacman",
        "snap",
        "systemctl",
        "service",
        "journalctl",
        "logrotate",
        "cron",
        "sshd",
        "bash",
        "sh",
        "zsh",
        "dash",
        "login",
        "su",
        "sudo",
        "grep",
        "find",
        "ls",
        "cat",
        "head",
        "tail",
        "awk",
        "sed",
        "ps",
        "top",
        "htop",
        "free",
        "df",
        "du",
        "mount",
        "umount",
        "ip",
        "ss",
        "netstat",
        "ping",
        "curl",
        "wget",
        "ssh",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "chmod",
        "chown",
        "tar",
        "gzip",
        "make",
        "cargo",
        "rustc",
        "gcc",
        "python3",
        "pip",
        "node",
        "npm",
        "git",
        "rsync",
        "docker",
        "containerd",
        "runc",
        "innerwarden-sensor",
        "innerwarden-agent",
        "innerwarden-watchdog",
        "date",
        "who",
        "w",
        "id",
        "uname",
        "hostname",
        "env",
        "touch",
        "tee",
        "sort",
        "uniq",
        "wc",
        "cut",
        "tr",
        "xargs",
        "readlink",
        "dirname",
        "basename",
        "stat",
        "file",
        "which",
        "locale",
        "stty",
        "tput",
        "clear",
        "less",
        "more",
        "vi",
        "vim",
        "nano",
    ];

    // Group unusual executions by user
    let mut user_drifts: HashMap<String, Vec<String>> = HashMap::new();

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let (comm, uid, start_ts) = match graph.get_node(pid_id) {
            Some(Node::Process {
                comm,
                uid,
                start_ts,
                ..
            }) => (comm.clone(), *uid, *start_ts),
            _ => continue,
        };
        if now - start_ts > window {
            continue;
        }
        if system_binaries.iter().any(|b| comm == *b) {
            continue;
        }

        // Check if exe path is suspicious (/tmp, /dev/shm, /var/tmp)
        let exe_suspicious = graph.outgoing_edges(pid_id).iter().any(|e| {
            e.relation == Relation::Executed
                && graph
                    .get_node(e.to)
                    .map(|n| {
                        let label = n.label();
                        label.starts_with("/tmp/")
                            || label.starts_with("/dev/shm/")
                            || label.starts_with("/var/tmp/")
                    })
                    .unwrap_or(false)
        });

        if exe_suspicious {
            // Suspicious path — fire individually (never aggregate these)
            let key = format!("graph_drift_sus:{}:{}", comm, pid_id);
            if state.check_and_set(&key, now, 300) {
                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_host_drift:{}:{}", comm, now.timestamp()),
                    severity: Severity::High,
                    title: format!("Suspicious execution: {} from temp directory", comm),
                    summary: format!(
                        "Process '{}' executed from suspicious path (/tmp, /dev/shm, /var/tmp).",
                        comm
                    ),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_host_drift",
                        "process": comm,
                        "suspicious_path": true,
                    }),
                    recommended_checks: vec![format!(
                        "Check process: ls -la /proc/{}/exe 2>/dev/null || echo 'process exited'",
                        pid_id
                    )],
                    tags: vec!["T1059".to_string()],
                    entities: vec![],
                });
            }
            continue;
        }

        // Normal drift — aggregate by user
        let user_name = format!("uid:{}", uid);
        user_drifts.entry(user_name).or_default().push(comm);
    }

    // Fire aggregated incidents per user
    for (user, procs) in &user_drifts {
        // Trusted operators (root + human UIDs from calibration) get a
        // higher threshold. Operators building software, deploying, or
        // debugging legitimately run many non-standard binaries.
        let is_trusted = user == "uid:0" || is_trusted_graph_user(user, &ctx.human_uids);
        let threshold = if is_trusted { 30 } else { 15 };
        if procs.len() < threshold {
            continue;
        }
        let key = format!("graph_drift_agg:{}", user);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }
        let unique: HashSet<&String> = procs.iter().collect();
        let sample: Vec<&str> = unique.iter().take(10).map(|s| s.as_str()).collect();
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_host_drift:{}:{}", user, now.timestamp()),
            severity: Severity::Medium,
            title: format!("Host drift: {} unusual executions by {} in 5m", procs.len(), user),
            summary: format!(
                "User {} ran {} non-standard processes in 5 minutes. Sample: {}. May indicate admin activity or compromise.",
                user, procs.len(), sample.join(", ")
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_host_drift",
                "user": user,
                "count": procs.len(),
                "unique_count": unique.len(),
                "sample": sample,
            }),
            recommended_checks: vec![
                format!("Check recent activity for {}", user),
            ],
            tags: vec!["T1059".to_string()],
            entities: vec![EntityRef::user(user)],
        });
    }
    incidents
}

// 20. Proto anomaly — aggregated by source IP
fn detect_proto_anomaly_aggregated(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let threshold = 5;

    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let (addr, is_internal) = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => (addr.clone(), *is_internal),
            _ => continue,
        };
        if is_internal {
            continue;
        }

        // Count anomalous connections in window (edges with "malformed" or "anomaly" in properties)
        let anomaly_count = graph
            .edges_in_window(ip_id, Relation::ConnectedTo, now, window)
            .iter()
            .filter(|e| {
                e.properties
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        s.contains("malformed") || s.contains("anomal") || s.contains("invalid")
                    })
                    .unwrap_or(false)
            })
            .count();

        // Also count all connections (fan-out detection)
        let total_conn = graph.count_edges_in_window(ip_id, Relation::ConnectedTo, now, window);

        if anomaly_count < threshold && total_conn < 20 {
            continue;
        }

        let key = format!("graph_proto_agg:{}", addr);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let severity = if anomaly_count >= 10 {
            Severity::High
        } else {
            Severity::Medium
        };
        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_proto_anomaly:{}:{}", addr, now.timestamp()),
            severity,
            title: format!("Protocol anomaly: {} from {} ({} connections in 5m)", anomaly_count, addr, total_conn),
            summary: format!(
                "IP {} sent {} anomalous connections ({} total) in 5 minutes. May indicate scanning or exploitation attempts.",
                addr, anomaly_count, total_conn
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_proto_anomaly",
                "ip": addr,
                "anomaly_count": anomaly_count,
                "total_connections": total_conn,
            }),
            recommended_checks: vec![
                format!("Check connections: ss -tn | grep {}", addr),
            ],
            tags: vec!["T1190".to_string()],
            entities: vec![EntityRef::ip(&addr)],
        });
    }
    incidents
}

// 21. Port scan — count distinct ports per source IP
fn detect_port_scan(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(60);
    let threshold = 10; // 10+ distinct ports in 1 minute

    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let (addr, is_internal) = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => (addr.clone(), *is_internal),
            _ => continue,
        };
        if is_internal {
            continue;
        }

        let distinct_ports =
            graph.count_distinct_targets_in_window(ip_id, Relation::ScannedPort, now, window);
        if distinct_ports < threshold {
            continue;
        }

        let key = format!("graph_portscan:{}", addr);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_port_scan:{}:{}", addr, now.timestamp()),
            severity: Severity::Medium,
            title: format!("Port scan: {} probed {} ports in 1m", addr, distinct_ports),
            summary: format!(
                "IP {} probed {} distinct ports in 1 minute. Indicates network reconnaissance.",
                addr, distinct_ports
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_port_scan",
                "ip": addr,
                "distinct_ports": distinct_ports,
            }),
            recommended_checks: vec![format!("Block scanner: innerwarden block-ip {}", addr)],
            tags: vec!["T1046".to_string()],
            entities: vec![EntityRef::ip(&addr)],
        });
    }
    incidents
}

// 22. Credential stuffing — many distinct usernames from same IP
fn detect_credential_stuffing(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let threshold = 5; // 5+ distinct users tried from same IP

    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let (addr, is_internal) = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => (addr.clone(), *is_internal),
            _ => continue,
        };
        if is_internal {
            continue;
        }

        // Count distinct users with LoggedInFrom edges from this IP
        let auth_edges = graph.incoming_edges(ip_id);
        let distinct_users: HashSet<NodeId> = auth_edges
            .iter()
            .filter(|e| e.relation == Relation::LoggedInFrom && now - e.ts < window)
            .map(|e| e.from)
            .collect();

        if distinct_users.len() < threshold {
            continue;
        }

        let key = format!("graph_credstuff:{}", addr);
        if !state.check_and_set(&key, now, 600) {
            continue;
        }

        let user_names: Vec<String> = distinct_users
            .iter()
            .filter_map(|&uid| graph.get_node(uid).map(|n| n.label().to_string()))
            .take(10)
            .collect();

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_credential_stuffing:{}:{}", addr, now.timestamp()),
            severity: Severity::High,
            title: format!("Credential stuffing: {} tried {} users in 5m", addr, distinct_users.len()),
            summary: format!(
                "IP {} attempted login as {} distinct users in 5 minutes: {}. Indicates credential stuffing attack.",
                addr, distinct_users.len(), user_names.join(", ")
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_credential_stuffing",
                "ip": addr,
                "distinct_users": distinct_users.len(),
                "usernames": user_names,
            }),
            recommended_checks: vec![
                format!("Block attacker: innerwarden block-ip {}", addr),
            ],
            tags: vec!["T1110.004".to_string()],
            entities: vec![EntityRef::ip(&addr)],
        });
    }
    incidents
}

// 23. Sudo abuse — burst of sudo commands from one user
fn detect_sudo_abuse(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(60);
    let threshold = 10;

    for &uid in graph.nodes_of_type(NodeType::User).iter() {
        let name = match graph.get_node(uid) {
            Some(Node::User { name, .. }) => name.clone(),
            _ => continue,
        };
        if name == "root" {
            continue; // root doesn't need sudo
        }

        // SudoAs edges go Process→User, so look at incoming edges on User
        let sudo_count = graph
            .incoming_edges(uid)
            .iter()
            .filter(|e| e.relation == Relation::SudoAs && now - e.ts < window)
            .count();

        if sudo_count < threshold {
            continue;
        }

        let key = format!("graph_sudoabuse:{}", name);
        if !state.check_and_set(&key, now, 1800) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_sudo_abuse:{}:{}", name, now.timestamp()),
            severity: Severity::High,
            title: format!("Sudo abuse: {} ran {} sudo commands in 1m", name, sudo_count),
            summary: format!(
                "User '{}' executed {} sudo commands in 1 minute. May indicate privilege abuse or automated exploitation.",
                name, sudo_count
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_sudo_abuse",
                "user": name,
                "sudo_count": sudo_count,
            }),
            recommended_checks: vec![
                format!("Check sudo log: journalctl _COMM=sudo | grep {}", name),
                format!("Suspend user: innerwarden suspend-user {}", name),
            ],
            tags: vec!["T1548.003".to_string()],
            entities: vec![EntityRef::user(&name)],
        });
    }
    incidents
}

// 15. User creation — new user accounts appearing (privilege escalation vector)
// Spec 015: `detect_user_creation` was removed as a presence-scan
// anti-pattern. See the comment in `run_all` above for the rationale.
// Real user-creation signal is preserved via the sensor-side
// `user_creation` detector, whose incidents reach the graph via
// `ingest_incident` and continue to feed correlation rules.

// 16. Docker anomaly — container rapid restarts or OOM kills
fn detect_docker_anomaly(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);

    for &cid in graph.nodes_of_type(NodeType::Container).iter() {
        let (container_id, name, oom_killed) = match graph.get_node(cid) {
            Some(Node::Container {
                container_id,
                name,
                oom_killed,
                ..
            }) => (
                container_id.clone(),
                name.clone().unwrap_or_default(),
                *oom_killed,
            ),
            _ => continue,
        };

        // Count restart events (DiedOn + StartedOn pairs) in window
        let restart_count = graph
            .all_edges(cid)
            .iter()
            .filter(|e| {
                matches!(e.relation, Relation::DiedOn | Relation::StartedOn) && now - e.ts < window
            })
            .count();

        if oom_killed {
            let key = format!("graph_docker_oom:{}", container_id);
            if state.check_and_set(&key, now, 600) {
                let label = if name.is_empty() {
                    &container_id
                } else {
                    &name
                };
                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_docker_oom:{}:{}", container_id, now.timestamp()),
                    severity: Severity::Medium,
                    title: format!("Container OOM killed: {}", label),
                    summary: format!("Container '{}' was killed by OOM. May indicate resource exhaustion attack or crypto mining.", label),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_docker_anomaly",
                        "container_id": container_id,
                        "name": name,
                        "event": "oom_killed",
                    }),
                    recommended_checks: vec![
                        format!("Check container: docker inspect {}", container_id),
                    ],
                    tags: vec!["T1496".to_string()],
                    entities: vec![],
                });
            }
        }

        if restart_count >= 6 {
            // 3+ restarts (each = died + started)
            let key = format!("graph_docker_restart:{}", container_id);
            if state.check_and_set(&key, now, 600) {
                let label = if name.is_empty() {
                    &container_id
                } else {
                    &name
                };
                incidents.push(Incident {
                    ts: now,
                    host: host.to_string(),
                    incident_id: format!("graph_docker_restart:{}:{}", container_id, now.timestamp()),
                    severity: Severity::Medium,
                    title: format!("Container rapid restarts: {} ({} events in 5m)", label, restart_count),
                    summary: format!("Container '{}' has {} start/stop events in 5 minutes. May indicate crash loop or instability.", label, restart_count),
                    evidence: serde_json::json!({
                        "source": "knowledge_graph",
                        "detector": "graph_docker_anomaly",
                        "container_id": container_id,
                        "restart_events": restart_count,
                    }),
                    recommended_checks: vec![
                        format!("Check logs: docker logs {}", container_id),
                    ],
                    tags: vec!["T1610".to_string()],
                    entities: vec![],
                });
            }
        }
    }
    incidents
}

// 17. Scanner User-Agent detection (known security scanners probing the server)
fn detect_scanner_ua(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let scanner_patterns = [
        "nmap",
        "nikto",
        "sqlmap",
        "zap",
        "burp",
        "gobuster",
        "dirbuster",
        "wfuzz",
        "ffuf",
        "nuclei",
        "whatweb",
        "masscan",
        "acunetix",
    ];

    // Check all Ip nodes for HttpRequestTo edges with scanner UA
    for &ip_id in graph.nodes_of_type(NodeType::Ip).iter() {
        let addr = match graph.get_node(ip_id) {
            Some(Node::Ip {
                addr, is_internal, ..
            }) => {
                if *is_internal {
                    continue;
                }
                addr.clone()
            }
            _ => continue,
        };

        for edge in graph.outgoing_edges(ip_id) {
            if edge.relation != Relation::HttpRequestTo {
                continue;
            }
            let ua = edge
                .properties
                .get("user_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ua_lower = ua.to_lowercase();
            let matched = scanner_patterns.iter().find(|p| ua_lower.contains(**p));
            let Some(scanner) = matched else { continue };

            let key = format!("graph_scanner:{}:{}", addr, scanner);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_scanner_ua:{}:{}", addr, now.timestamp()),
                severity: Severity::Medium,
                title: format!("Security scanner detected: {} from {}", scanner, addr),
                summary: format!(
                    "IP {} sent HTTP requests with security scanner User-Agent matching '{}'. Indicates active reconnaissance.",
                    addr, scanner
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_scanner_ua",
                    "ip": addr,
                    "scanner": scanner,
                    "user_agent": ua,
                }),
                recommended_checks: vec![
                    format!("Check access logs for IP {}", addr),
                ],
                tags: vec!["T1595.002".to_string()],
                entities: vec![EntityRef::ip(&addr)],
            });
        }
    }
    incidents
}

// 18. C2 beacon detection (periodic outbound connections at regular intervals)
fn detect_c2_beacon(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(300);
    let min_connections = 5;
    let max_jitter_pct = 0.15; // 15% jitter tolerance

    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        // Group outbound connections by destination IP
        let mut ip_times: HashMap<NodeId, Vec<i64>> = HashMap::new();
        for edge in graph.outgoing_edges(pid_id) {
            if edge.relation != Relation::ConnectedTo {
                continue;
            }
            if now - edge.ts > window {
                continue;
            }
            // Only external IPs
            if let Some(Node::Ip { is_internal, .. }) = graph.get_node(edge.to) {
                if *is_internal {
                    continue;
                }
            }
            ip_times
                .entry(edge.to)
                .or_default()
                .push(edge.ts.timestamp());
        }

        for (ip_id, mut times) in ip_times {
            if times.len() < min_connections {
                continue;
            }
            times.sort();

            // Calculate intervals between consecutive connections
            let intervals: Vec<i64> = times.windows(2).map(|w| w[1] - w[0]).collect();
            if intervals.is_empty() {
                continue;
            }

            let avg_interval = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
            if avg_interval < 5.0 {
                continue; // Too fast, likely normal traffic not beaconing
            }

            // Check jitter: all intervals within ±15% of average
            let is_periodic = intervals.iter().all(|&i| {
                let deviation = (i as f64 - avg_interval).abs() / avg_interval;
                deviation <= max_jitter_pct
            });

            if !is_periodic {
                continue;
            }

            let ip_addr = match graph.get_node(ip_id) {
                Some(Node::Ip { addr, .. }) => addr.clone(),
                _ => continue,
            };

            let key = format!("graph_c2:{}:{}", comm, ip_addr);
            if !state.check_and_set(&key, now, 600) {
                continue;
            }

            incidents.push(Incident {
                ts: now,
                host: host.to_string(),
                incident_id: format!("graph_c2_beacon:{}:{}:{}", comm, ip_addr, now.timestamp()),
                severity: Severity::High,
                title: format!("C2 beacon pattern: {} → {} (every ~{}s)", comm, ip_addr, avg_interval as i64),
                summary: format!(
                    "Process '{}' shows periodic outbound connections to {} every ~{}s ({} connections in 5m, {:.0}% jitter). This pattern is consistent with command-and-control beaconing.",
                    comm, ip_addr, avg_interval as i64, times.len(), max_jitter_pct * 100.0
                ),
                evidence: serde_json::json!({
                    "source": "knowledge_graph",
                    "detector": "graph_c2_beacon",
                    "process": comm,
                    "ip": ip_addr,
                    "connection_count": times.len(),
                    "avg_interval_secs": avg_interval as i64,
                    "intervals": intervals,
                }),
                recommended_checks: vec![
                    format!("Check process: ps aux | grep {}", comm),
                    format!("Check destination: whois {}", ip_addr),
                    format!("Block IP: innerwarden block-ip {}", ip_addr),
                ],
                tags: vec!["T1071".to_string(), "T1573".to_string()],
                entities: vec![EntityRef::ip(&ip_addr)],
            });
        }
    }
    incidents
}

// ── Phase 3A (T009): Cgroup Abuse ──────────────────────────────────────
// Detects processes with excessive CPU/memory usage based on cgroup monitoring
// events. Fires when a process appears in multiple cgroup-related events
// within a window (sustained resource abuse, e.g. cryptominer).

fn detect_cgroup_abuse(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let window = Duration::seconds(120); // 2+ ticks (60s each)

    // Count cgroup-related edges per process in recent window
    for &pid_id in graph.nodes_of_type(NodeType::Process).iter() {
        let comm = match graph.get_node(pid_id) {
            Some(Node::Process { comm, .. }) => comm.clone(),
            _ => continue,
        };

        // Count edges with cgroup properties in window
        let cgroup_events: usize = graph
            .outgoing_edges(pid_id)
            .iter()
            .filter(|e| {
                now - e.ts < window
                    && e.properties
                        .get("cgroup_cpu_pct")
                        .and_then(|v| v.as_f64())
                        .map(|pct| pct > 90.0)
                        .unwrap_or(false)
            })
            .count();

        if cgroup_events < 2 {
            continue; // Need sustained abuse (2+ observations)
        }

        let key = format!("graph_cgroup:{}:{}", comm, pid_id);
        if !state.check_and_set(&key, now, 1800) {
            continue;
        }

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_cgroup_abuse:{}:{}", comm, now.timestamp()),
            severity: Severity::Medium,
            title: format!("Cgroup abuse: {} sustained high CPU", comm),
            summary: format!(
                "Process '{}' shows sustained CPU usage >90% across {} observations in {}s. May indicate cryptominer or resource abuse.",
                comm, cgroup_events, window.num_seconds()
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_cgroup_abuse",
                "process": comm,
                "observations": cgroup_events,
                "window_secs": window.num_seconds(),
            }),
            recommended_checks: vec![
                format!("Check CPU: top -p $(pgrep -f {})", comm),
                format!("Check cgroup: cat /sys/fs/cgroup/system.slice/*/cpu.stat"),
            ],
            tags: vec!["T1496".to_string()],
            entities: vec![],
        });
    }
    incidents
}

// ── Slow-and-low detector ──────────────────────────────────────────────
// Detects persistent low-rate C2 communication over 24h+.
// Complements the sensor's beaconing detector (5min window) by catching
// attackers who spread connections over hours/days with irregular intervals.

fn detect_slow_and_low(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::hours(6); // 6h lookback (graph retains ~6h of edges)
    let min_connections = 4;
    let min_span_hours = 2;

    // Group: (process_id, external IP) → edge timestamps
    let mut patterns: std::collections::HashMap<(NodeId, String), Vec<DateTime<Utc>>> =
        std::collections::HashMap::new();

    for &proc_id in &graph.active_nodes_since(cutoff) {
        let (comm, uid) = match graph.get_node(proc_id) {
            Some(Node::Process { comm, uid, .. }) => (comm.clone(), *uid),
            _ => continue,
        };

        // Skip infra processes (same list as data exfil)
        const INFRA: &[&str] = &[
            "crowdsec",
            "innerwarden",
            "tokio-rt-worker",
            "innerwarden-agent",
            "innerwarden-senso",
            "fail2ban",
            "telegraf",
            "prometheus",
            "node_exporter",
            "apt",
            "dpkg",
            "cscli",
        ];
        let comm_lower = comm.to_lowercase();
        if INFRA.iter().any(|&c| comm_lower.starts_with(c)) || uid == 998 {
            continue;
        }

        for edge in graph.outgoing_edges(proc_id) {
            if edge.relation != Relation::ConnectedTo || edge.ts < cutoff {
                continue;
            }
            if let Some(Node::Ip {
                addr,
                is_internal: false,
                ..
            }) = graph.get_node(edge.to)
            {
                if crate::cloud_safelist::is_self_traffic_ip(addr) {
                    continue;
                }
                patterns
                    .entry((proc_id, addr.clone()))
                    .or_default()
                    .push(edge.ts);
            }
        }
    }

    for ((proc_id, ip), mut timestamps) in patterns {
        if timestamps.len() < min_connections {
            continue;
        }
        timestamps.sort();

        let first = timestamps.first().copied().unwrap();
        let last = timestamps.last().copied().unwrap();
        let span = last - first;
        if span < Duration::hours(min_span_hours) {
            continue;
        }

        // Check irregularity: coefficient of variation of intervals
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]).num_seconds() as f64)
            .collect();
        if intervals.is_empty() {
            continue;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < 1.0 {
            continue;
        }
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let cv = variance.sqrt() / mean;

        // CV < 0.3 = regular beaconing (caught by sensor c2_callback).
        // CV >= 0.3 = irregular slow-and-low.
        if cv < 0.3 {
            continue;
        }

        let key = format!("graph_slow_low:{}:{}", proc_id, ip);
        if !state.check_and_set(&key, now, 3600) {
            continue;
        }

        let label = graph
            .get_node(proc_id)
            .map(|n| n.label())
            .unwrap_or_default();
        let hours = span.num_hours().max(1);

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_slow_low:{}:{}:{}", proc_id, ip, now.timestamp()),
            severity: Severity::High,
            title: format!(
                "Slow-and-low C2: {} → {} ({} connections over {}h)",
                label,
                ip,
                timestamps.len(),
                hours
            ),
            summary: format!(
                "Process {} made {} connections to external IP {} over {} hours with irregular \
                 intervals (CV={:.2}). This pattern evades short-window detectors and suggests \
                 intentional C2 communication.",
                label,
                timestamps.len(),
                ip,
                hours,
                cv
            ),
            evidence: serde_json::json!({
                "source": "knowledge_graph",
                "detector": "graph_slow_low",
                "process": label,
                "ip": ip,
                "connections": timestamps.len(),
                "span_hours": hours,
                "coefficient_of_variation": cv,
            }),
            recommended_checks: vec![
                format!("Investigate {} for C2 implant or backdoor", label),
                format!("Check {} on AbuseIPDB/VirusTotal", ip),
                "Review process ancestry for initial compromise".to_string(),
            ],
            tags: vec!["T1071".to_string(), "slow_and_low".to_string()],
            entities: vec![EntityRef::ip(&ip)],
        });
    }

    incidents
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1700000000 + secs, 0).unwrap()
    }

    #[test]
    fn test_threat_intel_detection() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1, 0, "wget", 0, ts(0));
        let ip_id = g.add_node(Node::Ip {
            addr: "93.1.1.1".into(),
            is_internal: false,
            datasets: vec!["sslbl".into()],
            risk_score: 80,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(1)));

        let mut state = GraphDetectorState::new();
        let incidents = detect_threat_intel(&g, &mut state, "test", ts(2));
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("sslbl"));

        // Cooldown should prevent duplicate
        let incidents2 = detect_threat_intel(&g, &mut state, "test", ts(3));
        assert_eq!(incidents2.len(), 0);
    }

    #[test]
    fn test_lateral_movement_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "ssh", 0, ts(0));

        // Connect to 4 internal IPs on port 22
        for i in 1..=4 {
            let ip = g.ensure_ip(&format!("192.168.1.{}", i), now);
            g.add_edge(
                Edge::new(proc_id, ip, Relation::ConnectedTo, now)
                    .with_prop("port", serde_json::Value::from(22u16)),
            );
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_lateral_movement(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("SSH scanning"));
    }

    #[test]
    fn test_process_tree_anomaly() {
        let mut g = KnowledgeGraph::new();
        let nginx = g.ensure_process(100, 1, "nginx", 33, ts(0));
        let bash = g.ensure_process(200, 100, "bash", 33, ts(1));
        g.add_edge(Edge::new(bash, nginx, Relation::SpawnedBy, ts(1)));

        let mut state = GraphDetectorState::new();
        let incidents = detect_process_tree_anomaly(&g, &mut state, "test", ts(2));
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("nginx"));
    }

    #[test]
    fn test_reverse_shell_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "bash", 0, now);
        let ip_id = g.ensure_ip("93.1.1.1", now);

        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::RedirectedFd, now)
                .with_prop("old_fd", serde_json::Value::from(0)),
        );
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_reverse_shell(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
    }

    #[test]
    fn test_fileless_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "malware", 0, now);
        let ip_id = g.ensure_ip("93.1.1.1", now);

        g.add_edge(Edge::new(proc_id, proc_id, Relation::CreatedMemfd, now));
        g.add_edge(Edge::new(proc_id, proc_id, Relation::MprotectExec, now));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_fileless(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
    }

    #[test]
    fn test_persistence_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "payload", 0, now);
        let file_id = g.ensure_file("/etc/cron.d/backdoor");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_persistence(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("Persistence"));
    }

    #[test]
    fn test_data_exfil_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "payload", 0, now);
        let file_id = g.ensure_file("/etc/shadow");
        let ip_id = g.ensure_ip("93.1.1.1", now);

        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, now));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_data_exfil_calibrated(
            &g,
            &mut state,
            "test",
            now,
            &CalibrationContext::default(),
        );
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("exfiltration"));
    }

    #[test]
    fn test_cooldown_prune() {
        let mut state = GraphDetectorState::new();
        state.cooldowns.insert("old_key".into(), ts(0));
        state.cooldowns.insert("new_key".into(), ts(3601));
        state.prune(ts(7200)); // ~2h later, new_key is 3599s old (< 1h)
        assert_eq!(state.cooldowns.len(), 1);
        assert!(state.cooldowns.contains_key("new_key"));
    }

    // ── Phase 3A tests ────────────────────────────────────────────────

    #[test]
    fn test_kernel_module_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "insmod", 0, now);
        let file_id = g.ensure_file("/lib/modules/evil.ko");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Executed, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_kernel_module(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("Kernel module"));
    }

    #[test]
    fn test_service_stop_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "systemctl", 0, now);
        // Add an edge with summary containing "stop innerwarden"
        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::Executed, now).with_prop(
                "summary",
                serde_json::Value::from("systemctl stop innerwarden-sensor"),
            ),
        );

        let mut state = GraphDetectorState::new();
        let incidents = detect_service_stop(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].severity == Severity::Critical);
    }

    #[test]
    fn test_container_escape_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "runc", 0, now);
        let file_id = g.ensure_file("/var/run/docker.sock");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_container_escape(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].severity == Severity::Critical);
    }

    #[test]
    fn test_log_tampering_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "evil", 0, now);
        let file_id = g.ensure_file("/var/log/auth.log");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_log_tampering(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("Log tampering"));
    }

    #[test]
    fn test_log_tampering_allows_rsyslog() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "rsyslog", 0, now);
        let file_id = g.ensure_file("/var/log/syslog");
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_log_tampering(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 0); // rsyslog is a trusted writer
    }

    #[test]
    fn test_network_sniffing_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        g.ensure_process(1234, 0, "tcpdump", 0, now);

        let mut state = GraphDetectorState::new();
        let incidents = detect_network_sniffing(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("tcpdump"));
    }

    #[test]
    fn test_network_sniffing_skips_agent_spawned_tcpdump() {
        // Spec 015: pcap_capture spawns tcpdump via the agent. Those
        // invocations must not fire graph_network_sniffing.
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        // agent → tcpdump chain
        let agent = g.ensure_process(42, 1, "innerwarden-agent", 0, now);
        let tcpdump = g.ensure_process(1234, 42, "tcpdump", 0, now);
        g.add_edge(Edge::new(tcpdump, agent, Relation::SpawnedBy, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_network_sniffing(&g, &mut state, "test", now);
        assert!(
            incidents.is_empty(),
            "tcpdump spawned by the agent itself must not alert"
        );
    }

    #[test]
    fn test_network_sniffing_skips_stale_processes() {
        // Spec 015: the pre-fix detector re-fired every 10 minutes for the
        // lifetime of any Process node with comm=tcpdump, even after the
        // process exited, because it was a pure presence scan. The fixed
        // version only considers Process nodes started in the last 5min.
        let mut g = KnowledgeGraph::new();
        g.ensure_process(1234, 0, "tcpdump", 0, ts(0));

        let mut state = GraphDetectorState::new();
        let incidents = detect_network_sniffing(&g, &mut state, "test", ts(1_000));
        assert!(
            incidents.is_empty(),
            "stale tcpdump node (>5min old) must not fire the detector"
        );
    }

    #[test]
    fn test_sensitive_write_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "evil", 0, now);
        let file_id = g.add_node(Node::File {
            path: "/etc/shadow".to_string(),
            sha256: None,
            size: None,
            entropy: None,
            is_sensitive: true,
            yara_matches: vec![],
        });
        g.add_edge(Edge::new(proc_id, file_id, Relation::Wrote, now));

        let mut state = GraphDetectorState::new();
        let incidents = detect_sensitive_write(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
    }

    // ── Phase 3B tests ────────────────────────────────────────────────

    #[test]
    fn test_port_scan_detection() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let ip_id = g.ensure_ip("1.2.3.4", now);

        // Scan 15 distinct ports
        for port in 1..=15 {
            let port_id = g.ensure_port(port, "tcp");
            g.add_edge(Edge::new(ip_id, port_id, Relation::ScannedPort, now));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_port_scan(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("15 ports"));
    }

    #[test]
    fn test_port_scan_below_threshold() {
        let mut g = KnowledgeGraph::new();
        let now = ts(100);
        let ip_id = g.ensure_ip("1.2.3.4", now);

        // Only 3 ports — below threshold
        for port in 1..=3 {
            let port_id = g.ensure_port(port, "tcp");
            g.add_edge(Edge::new(ip_id, port_id, Relation::ScannedPort, now));
        }

        let mut state = GraphDetectorState::new();
        let incidents = detect_port_scan(&g, &mut state, "test", now);
        assert_eq!(incidents.len(), 0);
    }

    // ── Phase 3D tests ────────────────────────────────────────────────

    #[test]
    fn test_dedup_suppresses_sensor() {
        let mut state = GraphDetectorState::new();
        let now = ts(100);

        // Graph detected threat_intel for IP 1.2.3.4
        state.record_detection("threat_intel", "1.2.3.4", now);

        // Sensor fires 30s later — should be suppressed
        assert!(state.should_suppress_sensor("threat_intel", "1.2.3.4", ts(130)));

        // Different IP — should NOT be suppressed
        assert!(!state.should_suppress_sensor("threat_intel", "5.6.7.8", ts(130)));

        // After 60s — should NOT be suppressed (expired)
        assert!(!state.should_suppress_sensor("threat_intel", "1.2.3.4", ts(161)));
    }

    #[test]
    fn test_dedup_maps_sensor_to_graph() {
        let mut state = GraphDetectorState::new();
        let now = ts(100);

        state.record_detection("data_exfil", "1.2.3.4", now);

        // Sensor uses different name but maps to same graph detector
        assert!(state.should_suppress_sensor("data_exfiltration", "1.2.3.4", ts(110)));
        assert!(state.should_suppress_sensor("data_exfil_cmd", "1.2.3.4", ts(110)));

        // Unknown sensor detector — never suppress
        assert!(!state.should_suppress_sensor("yara_scan", "1.2.3.4", ts(110)));
    }

    // ── Phase 3A missing tests ───────────────────────────────────────────

    #[test]
    fn test_crypto_miner_detection() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(100, 1, "xmrig", 0, ts(0));
        let ip_id = g.add_node(Node::Ip {
            addr: "pool.minexmr.com".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        g.add_edge(
            Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(10)).with_prop("port", 3333u16),
        );

        let mut state = GraphDetectorState::new();
        let result = detect_crypto_miner(&g, &mut state, "test", ts(20));
        assert!(
            !result.is_empty(),
            "xmrig connecting to port 3333 should trigger"
        );
    }

    // Spec 015: test_user_creation_detection was removed alongside the
    // detector. The anti-pattern it verified (emit per non-system User
    // node) is precisely the behavior we deleted. Real user-creation
    // coverage stays on the sensor side (crates/sensor/src/detectors/
    // user_creation.rs tests) and the CL-012 correlation-rule path.

    #[test]
    fn test_scanner_ua_detection() {
        let mut g = KnowledgeGraph::new();
        let ip_id = g.add_node(Node::Ip {
            addr: "10.0.0.99".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        let sys_id = g.ensure_system("test-host");
        g.add_edge(
            Edge::new(ip_id, sys_id, Relation::HttpRequestTo, ts(5))
                .with_prop("user_agent", "Nikto/2.1.6"),
        );

        let mut state = GraphDetectorState::new();
        let result = detect_scanner_ua(&g, &mut state, "test", ts(10));
        assert!(
            !result.is_empty(),
            "Nikto UA should trigger scanner detection"
        );
    }

    #[test]
    fn test_docker_anomaly_restart_detection() {
        let mut g = KnowledgeGraph::new();
        let cid = g.ensure_container("abc123");
        let sys_id = g.ensure_system("test-host");
        // Simulate 4 restarts in 5 minutes
        for i in 0..4 {
            g.add_edge(Edge::new(cid, sys_id, Relation::StartedOn, ts(i * 60)));
            g.add_edge(Edge::new(cid, sys_id, Relation::DiedOn, ts(i * 60 + 30)));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_docker_anomaly(&g, &mut state, "test", ts(250));
        assert!(
            !result.is_empty(),
            "4 container restarts in 5 min should trigger"
        );
    }

    #[test]
    fn test_host_drift_suspicious_path() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(999, 1, "payload", 0, ts(5));
        let file_id = g.add_node(Node::File {
            path: "/tmp/payload".into(),
            sha256: None,
            size: None,
            entropy: None,
            is_sensitive: false,
            yara_matches: vec![],
        });
        g.add_edge(Edge::new(proc_id, file_id, Relation::Executed, ts(5)));

        let mut state = GraphDetectorState::new();
        let result = detect_host_drift_calibrated(
            &g,
            &mut state,
            "test",
            ts(10),
            &CalibrationContext::default(),
        );
        assert!(
            !result.is_empty(),
            "/tmp execution should fire individually as suspicious"
        );
        assert!(result[0].severity == Severity::High);
    }

    #[test]
    fn test_credential_stuffing_detection() {
        let mut g = KnowledgeGraph::new();
        let ip_id = g.add_node(Node::Ip {
            addr: "185.0.0.1".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        // 5 distinct users with failed auth from same IP
        for i in 0..5 {
            let user_id = g.ensure_user(&format!("user{}", i));
            g.add_edge(
                Edge::new(user_id, ip_id, Relation::LoggedInFrom, ts(i * 10))
                    .with_prop("success", false),
            );
        }

        let mut state = GraphDetectorState::new();
        let result = detect_credential_stuffing(&g, &mut state, "test", ts(60));
        assert!(
            !result.is_empty(),
            "5 distinct users from same IP should trigger credential stuffing"
        );
    }

    #[test]
    fn test_sudo_abuse_detection() {
        let mut g = KnowledgeGraph::new();
        let user_id = g.ensure_user("attacker");
        // 10 sudo commands in 50s (all within 60s window of ts(55))
        for i in 0..10 {
            let proc_id = g.ensure_process(100 + i, 1, "sudo", 0, ts(i as i64 * 5));
            g.add_edge(
                Edge::new(proc_id, user_id, Relation::SudoAs, ts(i as i64 * 5))
                    .with_prop("command", format!("cat /etc/shadow_{}", i)),
            );
        }

        let mut state = GraphDetectorState::new();
        let result = detect_sudo_abuse(&g, &mut state, "test", ts(55));
        assert!(!result.is_empty(), "10 sudo commands in 60s should trigger");
    }

    #[test]
    fn test_dns_tunnel_high_entropy() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(50, 1, "dnscat2", 0, ts(0));
        // Create 60 Resolved edges to long domains (>50 chars) — triggers dns tunnel
        for i in 0..60 {
            let long_name = format!(
                "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBkb21h{:03}.evil.com",
                i
            );
            let dom_id = g.add_node(Node::Domain {
                name: long_name,
                datasets: vec![],
                is_dga: Some(true),
                entropy: Some(5.2),
            });
            g.add_edge(Edge::new(proc_id, dom_id, Relation::Resolved, ts(i)));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_dns_tunnel(&g, &mut state, "test", ts(65));
        assert!(
            !result.is_empty(),
            "60 DNS resolutions to long domains should trigger DNS tunnel detection"
        );
    }

    #[test]
    fn test_correlation_multi_low_elevation() {
        let mut g = KnowledgeGraph::new();
        let ip_id = g.add_node(Node::Ip {
            addr: "10.0.0.50".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        // Create 3 incidents from different detectors all connected to same IP
        for (i, det) in ["port_scan", "user_agent_scanner", "discovery_burst"]
            .iter()
            .enumerate()
        {
            let inc_id = g.add_node(Node::Incident {
                incident_id: format!("{}:test:{}", det, i),
                detector: det.to_string(),
                severity: "low".into(),
                title: format!("{} test", det),
                summary: String::new(),
                ts: ts(i as i64 * 30),
                mitre_ids: vec![],
                decision: None,
                confidence: None,
                decision_reason: None,
                decision_target: None,
                auto_executed: false,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            g.add_edge(Edge::new(
                inc_id,
                ip_id,
                Relation::TriggeredBy,
                ts(i as i64 * 30),
            ));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_correlation_chains(&g, &mut state, "test", ts(100));
        assert!(
            !result.is_empty(),
            "3 distinct low-severity detectors from same IP should escalate to HIGH"
        );
        assert!(result[0].incident_id.contains("CL-010"));
    }

    #[test]
    fn test_c2_beacon_periodic_connections() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(42, 1, "backdoor", 0, ts(0));
        let ip_id = g.add_node(Node::Ip {
            addr: "93.184.216.34".into(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
            attempted_usernames: Vec::new(),
        });
        // 6 connections at regular 30s intervals (within 15% jitter)
        for i in 0..6 {
            g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(i * 30)));
        }

        let mut state = GraphDetectorState::new();
        let result = detect_c2_beacon(&g, &mut state, "test", ts(180));
        assert!(
            !result.is_empty(),
            "6 periodic connections at 30s intervals should trigger C2 beacon"
        );
    }
}
