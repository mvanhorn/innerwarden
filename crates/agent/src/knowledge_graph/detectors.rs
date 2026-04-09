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

/// Cooldown tracker to prevent duplicate graph-based alerts.
pub struct GraphDetectorState {
    cooldowns: HashMap<String, DateTime<Utc>>,
    default_cooldown_secs: i64,
}

impl GraphDetectorState {
    pub fn new() -> Self {
        Self {
            cooldowns: HashMap::new(),
            default_cooldown_secs: 300,
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

    /// Prune stale cooldowns older than 1 hour.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.cooldowns
            .retain(|_, ts| now - *ts < Duration::hours(1));
    }
}

/// Run all graph-based detectors. Called every slow-loop tick (30s).
pub fn run_all(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();

    incidents.extend(detect_threat_intel(graph, state, host, now));
    incidents.extend(detect_lateral_movement(graph, state, host, now));
    incidents.extend(detect_process_tree_anomaly(graph, state, host, now));
    incidents.extend(detect_reverse_shell(graph, state, host, now));
    incidents.extend(detect_fileless(graph, state, host, now));
    incidents.extend(detect_discovery_burst(graph, state, host, now));
    incidents.extend(detect_persistence(graph, state, host, now));
    incidents.extend(detect_data_exfil(graph, state, host, now));

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

        let proc_label = graph.get_node(proc_id).map(|n| n.label()).unwrap_or_default();
        let ip_addr = match graph.get_node(ip_id) {
            Some(Node::Ip { addr, .. }) => addr.clone(),
            _ => continue,
        };

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_threat_intel:{}:{}", ip_addr, now.timestamp()),
            severity: Severity::High,
            title: format!("Threat intel match: {} → {} ({})", proc_label, ip_addr, dataset),
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

    for proc_id in graph.nodes_of_type(NodeType::Process) {
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
            if let Some(Node::Ip { addr, is_internal: true, .. }) = graph.get_node(edge.to) {
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

        let proc_label = graph.get_node(proc_id).map(|n| n.label()).unwrap_or_default();
        let ip_list: Vec<String> = ips.into_iter().collect();

        incidents.push(Incident {
            ts: now,
            host: host.to_string(),
            incident_id: format!("graph_lateral_movement:{}:{}", proc_id, now.timestamp()),
            severity: Severity::High,
            title: format!("Lateral movement: {} SSH scanning {} internal IPs", proc_label, ip_list.len()),
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
            entities: ip_list.iter().map(|ip| EntityRef::ip(ip)).collect(),
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
        "nginx", "apache", "apache2", "httpd", "mysqld", "postgres",
        "java", "node", "php-fpm", "uwsgi", "gunicorn", "mongod",
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
                    incident_id: format!("graph_process_tree:{}:{}:{}", anc_comm, pid, now.timestamp()),
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

    for proc_id in graph.nodes_of_type(NodeType::Process) {
        let edges = graph.outgoing_edges(proc_id);

        // Check for fd redirect (fd 0, 1, or 2)
        let has_fd_redirect = edges.iter().any(|e| {
            e.relation == Relation::RedirectedFd
                && e.ts >= cutoff
                && e.properties
                    .get("old_fd")
                    .and_then(|v| v.as_i64())
                    .map_or(false, |fd| fd <= 2)
        });

        if !has_fd_redirect {
            continue;
        }

        // Check for outbound connection to external IP
        let external_ip = edges.iter().find_map(|e| {
            if e.relation == Relation::ConnectedTo && e.ts >= cutoff {
                match graph.get_node(e.to) {
                    Some(Node::Ip { addr, is_internal: false, .. }) => Some(addr.clone()),
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

            let label = graph.get_node(proc_id).map(|n| n.label()).unwrap_or_default();

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
                recommended_checks: vec![
                    format!("Kill PID {}", pid),
                    format!("Block IP {}", ip),
                ],
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

    for proc_id in graph.nodes_of_type(NodeType::Process) {
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
                && graph
                    .get_node(e.to)
                    .map_or(false, |n| matches!(n, Node::Ip { is_internal: false, .. }))
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

            let label = graph.get_node(proc_id).map(|n| n.label()).unwrap_or_default();

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

fn detect_discovery_burst(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
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
                    if let Some(Node::File { is_sensitive: true, .. }) = graph.get_node(edge.to) {
                        sensitive_reads += 1;
                    }
                }
            }
        }

        // Also count Executed edges (process spawns = discovery commands)
        let exec_count = recent_procs.len();

        let total = sensitive_reads + exec_count;
        let adjusted_threshold = if user_name == "root" { threshold * 3 } else { threshold };

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

    let persistence_patterns: &[(&str, &str, &str)] = &[
        ("/etc/cron", "crontab_persistence", "T1053.003"),
        ("/var/spool/cron", "crontab_persistence", "T1053.003"),
        ("/etc/systemd/", "systemd_persistence", "T1543.002"),
        ("/usr/lib/systemd/", "systemd_persistence", "T1543.002"),
        ("authorized_keys", "ssh_key_injection", "T1098.004"),
    ];

    for proc_id in graph.nodes_of_type(NodeType::Process) {
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

                let proc_label = graph.get_node(proc_id).map(|n| n.label()).unwrap_or_default();

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

fn detect_data_exfil(
    graph: &KnowledgeGraph,
    state: &mut GraphDetectorState,
    host: &str,
    now: DateTime<Utc>,
) -> Vec<Incident> {
    let mut incidents = Vec::new();
    let cutoff = now - Duration::seconds(60);

    for proc_id in graph.nodes_of_type(NodeType::Process) {
        let edges = graph.outgoing_edges(proc_id);

        // Check if process read a sensitive file recently
        let sensitive_read = edges.iter().find(|e| {
            e.relation == Relation::Read
                && e.ts >= cutoff
                && graph
                    .get_node(e.to)
                    .map_or(false, |n| n.is_sensitive_file())
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
                && graph
                    .get_node(e.to)
                    .map_or(false, |n| matches!(n, Node::Ip { is_internal: false, .. }))
        });

        if let Some(conn_edge) = external_conn {
            let dst_ip = match graph.get_node(conn_edge.to) {
                Some(Node::Ip { addr, .. }) => addr.clone(),
                _ => continue,
            };

            let pid = match graph.get_node(proc_id) {
                Some(Node::Process { pid, .. }) => *pid,
                _ => continue,
            };

            let key = format!("graph_exfil:{}:{}", pid, dst_ip);
            if !state.check_and_set(&key, now, 300) {
                continue;
            }

            let label = graph.get_node(proc_id).map(|n| n.label()).unwrap_or_default();

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
        let incidents = detect_data_exfil(&g, &mut state, "test", now);
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
}
