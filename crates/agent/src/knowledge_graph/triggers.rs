//! Real-time critical detectors — fire on edge insertion, not 30s tick.
//! Each trigger does O(1) index lookups. No graph traversal.
//!
//! These share cooldown keys with the 30s detectors in detectors.rs,
//! so the tick version gets suppressed when the trigger fires first.

use chrono::{Duration, Utc};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

use super::graph::KnowledgeGraph;
use super::types::*;

/// Escape paths for container escape detection.
const ESCAPE_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc/1/root",
    "/proc/1/ns/mnt",
    "/proc/1/ns/pid",
    "/proc/1/ns/net",
];

/// Security services for service stop detection.
const SECURITY_SERVICES: &[&str] = &[
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
];

/// Called from add_edge() for every new edge. Must be fast.
/// Checks 4 critical patterns and pushes incidents to graph.trigger_incidents.
pub fn check_critical_triggers(
    graph: &mut KnowledgeGraph,
    relation: Relation,
    from: NodeId,
    to: NodeId,
    now: chrono::DateTime<Utc>,
    properties: &std::collections::HashMap<
        crate::knowledge_graph::types::PropKey,
        serde_json::Value,
    >,
) {
    match relation {
        Relation::RedirectedFd => {
            trigger_reverse_shell_from_fd(graph, from, now, properties);
        }
        Relation::ConnectedTo => {
            trigger_reverse_shell_from_connect(graph, from, to, now);
            trigger_fileless_from_connect(graph, from, to, now);
        }
        Relation::MprotectExec => {
            trigger_fileless_from_mprotect(graph, from, now);
        }
        Relation::Read | Relation::Wrote => {
            trigger_container_escape(graph, from, to, now);
        }
        Relation::Executed => {
            trigger_service_stop(graph, from, now, properties);
        }
        _ => {}
    }
}

// ── Reverse Shell ──────────────────────────────────────────────────────
// Pattern: Process has RedirectedFd(fd 0,1,2) AND ConnectedTo(external IP) within 30s

fn trigger_reverse_shell_from_fd(
    graph: &mut KnowledgeGraph,
    proc_id: NodeId,
    now: chrono::DateTime<Utc>,
    properties: &std::collections::HashMap<
        crate::knowledge_graph::types::PropKey,
        serde_json::Value,
    >,
) {
    let fd = properties
        .get("old_fd")
        .and_then(|v| v.as_u64())
        .unwrap_or(99);
    if fd > 2 {
        return;
    } // Only stdin/stdout/stderr

    // Check if this process has ConnectedTo(external) in last 30s
    let window = Duration::seconds(30);
    let has_external_connect = graph
        .outgoing
        .get(&proc_id)
        .map(|idxs| {
            idxs.iter().any(|&i| {
                let e = &graph.edges[i];
                e.relation == Relation::ConnectedTo
                    && now - e.ts < window
                    && !e.is_snapshot()
                    && graph
                        .get_node(e.to)
                        .map(|n| {
                            matches!(
                                n,
                                Node::Ip {
                                    is_internal: false,
                                    ..
                                }
                            )
                        })
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    if !has_external_connect {
        return;
    }
    emit_reverse_shell(graph, proc_id, now);
}

fn trigger_reverse_shell_from_connect(
    graph: &mut KnowledgeGraph,
    proc_id: NodeId,
    ip_id: NodeId,
    now: chrono::DateTime<Utc>,
) {
    // Only external IPs
    if let Some(Node::Ip {
        is_internal: true, ..
    }) = graph.get_node(ip_id)
    {
        return;
    }

    // Check if this process has RedirectedFd(fd 0,1,2) in last 30s
    let window = Duration::seconds(30);
    let has_fd_redirect = graph
        .outgoing
        .get(&proc_id)
        .map(|idxs| {
            idxs.iter().any(|&i| {
                let e = &graph.edges[i];
                e.relation == Relation::RedirectedFd
                    && now - e.ts < window
                    && !e.is_snapshot()
                    && e.properties
                        .get("old_fd")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(99)
                        <= 2
            })
        })
        .unwrap_or(false);

    if !has_fd_redirect {
        return;
    }
    emit_reverse_shell(graph, proc_id, now);
}

fn emit_reverse_shell(graph: &mut KnowledgeGraph, proc_id: NodeId, now: chrono::DateTime<Utc>) {
    let comm = graph
        .get_node(proc_id)
        .map(|n| n.label())
        .unwrap_or_default();
    let _key = format!("graph_reverse_shell:{}", proc_id);

    // Use a simple dedup: check if we already emitted for this process recently
    // (can't use GraphDetectorState here since we only have &mut KnowledgeGraph)
    // Use trigger_incidents as dedup: check last 10 incidents
    if graph.trigger_incidents.iter().any(|i| {
        i.incident_id
            .contains(&format!("trigger_reverse_shell:{}", proc_id))
    }) {
        return;
    }

    let host = graph.trigger_host.clone();
    graph.trigger_incidents.push(Incident {
        ts: now,
        host,
        incident_id: format!("trigger_reverse_shell:{}:{}", proc_id, now.timestamp()),
        severity: Severity::Critical,
        title: format!("REAL-TIME: Reverse shell detected — {}", comm),
        summary: format!(
            "Process '{}' (PID area {}) redirected fd 0/1/2 and connected to external IP. Reverse shell confirmed.",
            comm, proc_id
        ),
        evidence: serde_json::json!({
            "source": "knowledge_graph_trigger",
            "detector": "trigger_reverse_shell",
            "process": comm,
            "realtime": true,
        }),
        recommended_checks: vec![
            format!("IMMEDIATE: kill -9 {}", proc_id),
            "Check for persistence: crontab -l, ~/.bashrc, systemctl list-units".to_string(),
        ],
        tags: vec!["T1059.004".to_string()],
        entities: vec![],
    });
}

// ── Fileless Execution ─────────────────────────────────────────────────
// Pattern: Process has CreatedMemfd AND MprotectExec AND ConnectedTo(external) within 60s

fn trigger_fileless_from_mprotect(
    graph: &mut KnowledgeGraph,
    proc_id: NodeId,
    now: chrono::DateTime<Utc>,
) {
    check_fileless_complete(graph, proc_id, now);
}

fn trigger_fileless_from_connect(
    graph: &mut KnowledgeGraph,
    proc_id: NodeId,
    ip_id: NodeId,
    now: chrono::DateTime<Utc>,
) {
    if let Some(Node::Ip {
        is_internal: true, ..
    }) = graph.get_node(ip_id)
    {
        return;
    }
    check_fileless_complete(graph, proc_id, now);
}

fn check_fileless_complete(
    graph: &mut KnowledgeGraph,
    proc_id: NodeId,
    now: chrono::DateTime<Utc>,
) {
    let window = Duration::seconds(60);
    let edges = graph.outgoing.get(&proc_id);
    let Some(idxs) = edges else { return };

    let mut has_memfd = false;
    let mut has_mprotect = false;
    let mut has_external = false;

    for &i in idxs {
        let e = &graph.edges[i];
        if e.is_snapshot() || now - e.ts > window {
            continue;
        }
        match e.relation {
            Relation::CreatedMemfd => has_memfd = true,
            Relation::MprotectExec => has_mprotect = true,
            Relation::ConnectedTo
                if graph
                    .get_node(e.to)
                    .map(|n| {
                        matches!(
                            n,
                            Node::Ip {
                                is_internal: false,
                                ..
                            }
                        )
                    })
                    .unwrap_or(false) =>
            {
                has_external = true;
            }
            _ => {}
        }
    }

    if !has_memfd || !has_mprotect || !has_external {
        return;
    }

    // Dedup
    if graph.trigger_incidents.iter().any(|i| {
        i.incident_id
            .contains(&format!("trigger_fileless:{}", proc_id))
    }) {
        return;
    }

    let comm = graph
        .get_node(proc_id)
        .map(|n| n.label())
        .unwrap_or_default();
    let host = graph.trigger_host.clone();
    graph.trigger_incidents.push(Incident {
        ts: now,
        host,
        incident_id: format!("trigger_fileless:{}:{}", proc_id, now.timestamp()),
        severity: Severity::Critical,
        title: format!("REAL-TIME: Fileless execution — {}", comm),
        summary: format!(
            "Process '{}' created memfd + set executable permissions + connected to external IP. In-memory malware execution confirmed.",
            comm
        ),
        evidence: serde_json::json!({
            "source": "knowledge_graph_trigger",
            "detector": "trigger_fileless",
            "process": comm,
            "realtime": true,
        }),
        recommended_checks: vec![
            format!("IMMEDIATE: kill -9 {}", proc_id),
            "Dump memory: /proc/PID/maps, /proc/PID/mem".to_string(),
        ],
        tags: vec!["T1055.009".to_string()],
        entities: vec![],
    });
}

// ── Container Escape ───────────────────────────────────────────────────
// Pattern: Any process reading/writing container escape paths

fn trigger_container_escape(
    graph: &mut KnowledgeGraph,
    proc_id: NodeId,
    file_id: NodeId,
    now: chrono::DateTime<Utc>,
) {
    let file_path = match graph.get_node(file_id) {
        Some(Node::File { path, .. }) => path.clone(),
        _ => return,
    };

    if !ESCAPE_PATHS.iter().any(|p| file_path.starts_with(p)) {
        return;
    }

    // Dedup
    if graph.trigger_incidents.iter().any(|i| {
        i.incident_id
            .contains(&format!("trigger_escape:{}:{}", proc_id, file_path))
    }) {
        return;
    }

    let comm = graph
        .get_node(proc_id)
        .map(|n| n.label())
        .unwrap_or_default();
    let host = graph.trigger_host.clone();
    graph.trigger_incidents.push(Incident {
        ts: now,
        host,
        incident_id: format!(
            "trigger_escape:{}:{}:{}",
            proc_id,
            file_path,
            now.timestamp()
        ),
        severity: Severity::Critical,
        title: format!(
            "REAL-TIME: Container escape — {} accessed {}",
            comm, file_path
        ),
        summary: format!(
            "Process '{}' accessed '{}'. Container escape attempt detected in real-time.",
            comm, file_path
        ),
        evidence: serde_json::json!({
            "source": "knowledge_graph_trigger",
            "detector": "trigger_container_escape",
            "process": comm,
            "file": file_path,
            "realtime": true,
        }),
        recommended_checks: vec![
            "Check if running in container: cat /proc/1/cgroup".to_string(),
            format!("Kill process and investigate: kill -9 {}", proc_id),
        ],
        tags: vec!["T1611".to_string()],
        entities: vec![],
    });
}

// ── Service Stop ───────────────────────────────────────────────────────
// Pattern: systemctl/service executing stop on security service

fn trigger_service_stop(
    graph: &mut KnowledgeGraph,
    proc_id: NodeId,
    now: chrono::DateTime<Utc>,
    properties: &std::collections::HashMap<
        crate::knowledge_graph::types::PropKey,
        serde_json::Value,
    >,
) {
    let comm = match graph.get_node(proc_id) {
        Some(Node::Process { comm, .. }) if comm == "systemctl" || comm == "service" => {
            comm.clone()
        }
        _ => return,
    };

    let summary = properties
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let summary_lower = summary.to_lowercase();

    if !summary_lower.contains("stop") && !summary_lower.contains("disable") {
        return;
    }

    let stopped_service = SECURITY_SERVICES
        .iter()
        .find(|s| summary_lower.contains(**s));
    let Some(svc) = stopped_service else { return };

    // Dedup
    if graph
        .trigger_incidents
        .iter()
        .any(|i| i.incident_id.contains(&format!("trigger_svcstop:{}", svc)))
    {
        return;
    }

    let host = graph.trigger_host.clone();
    graph.trigger_incidents.push(Incident {
        ts: now,
        host,
        incident_id: format!("trigger_svcstop:{}:{}", svc, now.timestamp()),
        severity: Severity::Critical,
        title: format!("REAL-TIME: Security service stopped — {}", svc),
        summary: format!(
            "Process '{}' stopped security service '{}'. Defense evasion detected in real-time.",
            comm, svc
        ),
        evidence: serde_json::json!({
            "source": "knowledge_graph_trigger",
            "detector": "trigger_service_stop",
            "process": comm,
            "service": svc,
            "realtime": true,
        }),
        recommended_checks: vec![
            format!("IMMEDIATE: systemctl start {}", svc),
            "Check who initiated: journalctl -u {} -n 20".to_string(),
        ],
        tags: vec!["T1562.001".to_string()],
        entities: vec![],
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::graph::KnowledgeGraph;

    fn ts(secs: i64) -> chrono::DateTime<Utc> {
        chrono::DateTime::from_timestamp(1700000000 + secs, 0).unwrap()
    }

    #[test]
    fn test_trigger_reverse_shell_from_fd() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "bash", 0, now);
        let ip_id = g.ensure_ip("93.1.1.1", now);

        // First: external connection
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));
        assert_eq!(g.trigger_incidents.len(), 0); // No fd redirect yet

        // Then: fd redirect → trigger fires
        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::RedirectedFd, now)
                .with_prop("old_fd", serde_json::Value::from(0)),
        );
        assert_eq!(g.trigger_incidents.len(), 1);
        assert!(g.trigger_incidents[0].title.contains("Reverse shell"));
        assert_eq!(g.trigger_incidents[0].severity, Severity::Critical);
    }

    #[test]
    fn test_trigger_reverse_shell_from_connect() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "bash", 0, now);

        // First: fd redirect
        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::RedirectedFd, now)
                .with_prop("old_fd", serde_json::Value::from(1)),
        );
        assert_eq!(g.trigger_incidents.len(), 0); // No connection yet

        // Then: external connection → trigger fires
        let ip_id = g.ensure_ip("93.1.1.1", now);
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));
        assert_eq!(g.trigger_incidents.len(), 1);
    }

    #[test]
    fn test_trigger_reverse_shell_internal_ip_no_fire() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "bash", 0, now);

        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::RedirectedFd, now)
                .with_prop("old_fd", serde_json::Value::from(0)),
        );
        // Internal IP — should NOT fire
        let ip_id = g.ensure_ip("192.168.1.1", now);
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));
        assert_eq!(g.trigger_incidents.len(), 0);
    }

    #[test]
    fn test_trigger_fileless() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "malware", 0, now);

        g.add_edge(Edge::new(proc_id, proc_id, Relation::CreatedMemfd, now));
        assert_eq!(g.trigger_incidents.len(), 0);

        g.add_edge(Edge::new(proc_id, proc_id, Relation::MprotectExec, now));
        assert_eq!(g.trigger_incidents.len(), 0); // Need external connect too

        let ip_id = g.ensure_ip("93.1.1.1", now);
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, now));
        assert_eq!(g.trigger_incidents.len(), 1);
        assert!(g.trigger_incidents[0].title.contains("Fileless"));
    }

    #[test]
    fn test_trigger_container_escape() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "runc", 0, now);
        let file_id = g.ensure_file("/var/run/docker.sock");

        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, now));
        assert_eq!(g.trigger_incidents.len(), 1);
        assert!(g.trigger_incidents[0].title.contains("Container escape"));
    }

    #[test]
    fn test_trigger_container_escape_normal_file() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "cat", 0, now);
        let file_id = g.ensure_file("/etc/passwd");

        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, now));
        assert_eq!(g.trigger_incidents.len(), 0); // Not an escape path
    }

    #[test]
    fn test_trigger_service_stop() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "systemctl", 0, now);

        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::Executed, now).with_prop(
                "summary",
                serde_json::Value::from("systemctl stop innerwarden-sensor"),
            ),
        );
        assert_eq!(g.trigger_incidents.len(), 1);
        assert!(g.trigger_incidents[0].severity == Severity::Critical);
    }

    #[test]
    fn test_trigger_service_stop_normal_service() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "systemctl", 0, now);

        g.add_edge(
            Edge::new(proc_id, proc_id, Relation::Executed, now)
                .with_prop("summary", serde_json::Value::from("systemctl stop nginx")),
        );
        assert_eq!(g.trigger_incidents.len(), 0); // nginx is not a security service
    }

    #[test]
    fn test_trigger_dedup() {
        let mut g = KnowledgeGraph::new();
        g.set_trigger_host("test");
        let now = ts(100);
        let proc_id = g.ensure_process(1234, 0, "runc", 0, now);
        let file_id = g.ensure_file("/var/run/docker.sock");

        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, now));
        assert_eq!(g.trigger_incidents.len(), 1);

        // Second read — should be deduped
        g.add_edge(Edge::new(proc_id, file_id, Relation::Read, ts(101)));
        assert_eq!(g.trigger_incidents.len(), 1); // Still 1
    }
}
