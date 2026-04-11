//! One-shot migrations for the knowledge graph.
//!
//! Each migration is implemented as a standalone function that takes a
//! mutable [`KnowledgeGraph`] reference and returns a report describing
//! what was removed. Migrations are triggered by CLI flags on the agent
//! binary (see `main.rs`) — never run automatically — so operators have
//! full control of destructive cleanups.
//!
//! When a migration has been deployed everywhere, its module here and the
//! corresponding CLI flag can be deleted together.

use super::graph::KnowledgeGraph;
use super::types::{Node, NodeId, NodeType, Relation};

/// Report returned by [`cleanup_015_graph_signal_quality`].
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Cleanup015Report {
    /// Incident nodes deleted because their `incident_id` or `detector`
    /// belongs to the removed `graph_user_creation` detector.
    pub graph_user_creation_incidents_removed: usize,
    /// User nodes deleted because every `LoggedInFrom` edge they had was a
    /// failed auth (SSH brute-force pollution). Real users — those with at
    /// least one successful login, a `RunAs`/`SudoAs`/`EscalatedTo` edge,
    /// or any other structural reference — are preserved.
    pub brute_force_user_nodes_removed: usize,
    /// Names of the deleted User nodes (for audit in the migration output).
    pub removed_user_names: Vec<String>,
    /// Total nodes in the graph before cleanup.
    pub nodes_before: usize,
    /// Total nodes in the graph after cleanup.
    pub nodes_after: usize,
}

/// Spec 015: remove the 3,954 `graph_user_creation` false-positive
/// incidents and the brute-force User nodes that accumulated while the
/// buggy `detect_user_creation` presence scan was running.
///
/// Safe to run multiple times — if the graph has already been cleaned,
/// the report will show zero removals.
///
/// The cleanup is conservative: a User node is only deleted when **all**
/// of its `LoggedInFrom` edges carry `success == false` (or it has no
/// `LoggedInFrom` edge but is otherwise isolated). Any User that has a
/// successful login, `RunAs` edge, `SudoAs` edge, or `EscalatedTo` edge
/// is preserved. Real local users, `uid:N` fallback nodes created by
/// privilege-escalation ingestion, and `root` are never removed.
pub fn cleanup_015_graph_signal_quality(graph: &mut KnowledgeGraph) -> Cleanup015Report {
    let mut report = Cleanup015Report {
        nodes_before: graph.node_count(),
        ..Default::default()
    };

    // ── 1. Remove graph_user_creation Incident nodes ────────────────────
    //
    // Any Incident whose `incident_id` starts with `graph_user_creation:`
    // is false-positive noise. The `detector` field is redundant (set from
    // the incident_id prefix in `ingest_incident`) but we check both for
    // robustness against older snapshots that may have mismatched values.
    let incident_victims: Vec<NodeId> = graph
        .nodes_of_type(NodeType::Incident)
        .into_iter()
        .filter(|&id| {
            matches!(
                graph.get_node(id),
                Some(Node::Incident {
                    incident_id,
                    detector,
                    ..
                }) if incident_id.starts_with("graph_user_creation:")
                    || detector == "graph_user_creation"
            )
        })
        .collect();

    for id in &incident_victims {
        graph.remove_node(*id);
    }
    report.graph_user_creation_incidents_removed = incident_victims.len();

    // ── 2. Remove brute-force User nodes ─────────────────────────────────
    //
    // A User node is a brute-force artifact iff it has at least one
    // `LoggedInFrom` edge AND every such edge has `success == false`
    // (attacker username that never successfully logged in), AND it has no
    // `RunAs`, `SudoAs`, or `EscalatedTo` edge (otherwise it's a real
    // local user or a uid:N fallback we want to keep).
    let mut user_victims: Vec<(NodeId, String)> = Vec::new();
    for &user_id in graph.nodes_of_type(NodeType::User).iter() {
        let name = match graph.get_node(user_id) {
            Some(Node::User { name, .. }) => name.clone(),
            _ => continue,
        };

        // Preserve system singletons and uid:N fallbacks unconditionally.
        if name == "root" || name.starts_with("uid:") {
            continue;
        }

        // Look at every edge touching this user.
        let mut has_logged_in = false;
        let mut all_failed = true;
        let mut has_privilege_edge = false;
        for edge in graph
            .outgoing_edges(user_id)
            .iter()
            .chain(graph.incoming_edges(user_id).iter())
        {
            match edge.relation {
                Relation::LoggedInFrom => {
                    has_logged_in = true;
                    let success = edge
                        .properties
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if success {
                        all_failed = false;
                    }
                }
                Relation::RunAs | Relation::SudoAs | Relation::EscalatedTo => {
                    has_privilege_edge = true;
                }
                _ => {}
            }
        }

        if has_privilege_edge {
            continue; // real user
        }
        if !has_logged_in {
            continue; // not SSH-sourced pollution — leave alone
        }
        if !all_failed {
            continue; // at least one successful login → real user
        }

        user_victims.push((user_id, name));
    }

    for (id, name) in &user_victims {
        graph.remove_node(*id);
        report.removed_user_names.push(name.clone());
    }
    report.brute_force_user_nodes_removed = user_victims.len();

    report.nodes_after = graph.node_count();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::Edge;
    use chrono::{TimeZone, Utc};

    fn ts(s: i64) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 11, 0, 0, s as u32).unwrap()
    }

    #[test]
    fn cleanup_removes_graph_user_creation_incidents() {
        let mut g = KnowledgeGraph::new();
        let user = g.ensure_user("admin");
        let inc = g.add_node(Node::Incident {
            incident_id: "graph_user_creation:admin:12345".to_string(),
            detector: "graph_user_creation".to_string(),
            severity: "medium".to_string(),
            title: "New user account: admin".to_string(),
            summary: String::new(),
            ts: ts(0),
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
        });
        g.add_edge(Edge::new(inc, user, Relation::TriggeredBy, ts(0)));

        let report = cleanup_015_graph_signal_quality(&mut g);
        assert_eq!(report.graph_user_creation_incidents_removed, 1);
        assert!(g.get_node(inc).is_none(), "incident should be deleted");
    }

    #[test]
    fn cleanup_removes_brute_force_user_only_failed_logins() {
        let mut g = KnowledgeGraph::new();
        let ip = g.ensure_ip("185.1.1.1", ts(0));
        let admin = g.ensure_user("admin"); // attacker username
        let root = g.ensure_user("root"); // real user — preserved
        let alice = g.ensure_user("alice"); // real user with success

        // admin: 3 failed logins, zero success → delete
        for i in 0..3 {
            let edge =
                Edge::new(admin, ip, Relation::LoggedInFrom, ts(i)).with_prop("success", false);
            g.add_edge(edge);
        }
        // alice: 1 failed + 1 success → preserve
        g.add_edge(Edge::new(alice, ip, Relation::LoggedInFrom, ts(5)).with_prop("success", false));
        g.add_edge(Edge::new(alice, ip, Relation::LoggedInFrom, ts(6)).with_prop("success", true));
        // root: only failed but the migration preserves root unconditionally.
        g.add_edge(Edge::new(root, ip, Relation::LoggedInFrom, ts(10)).with_prop("success", false));

        let report = cleanup_015_graph_signal_quality(&mut g);
        assert_eq!(report.brute_force_user_nodes_removed, 1);
        assert_eq!(report.removed_user_names, vec!["admin".to_string()]);
        assert!(g.find_by_user("admin").is_none());
        assert!(g.find_by_user("alice").is_some());
        assert!(g.find_by_user("root").is_some());
    }

    #[test]
    fn cleanup_preserves_uid_fallback_users() {
        let mut g = KnowledgeGraph::new();
        let ip = g.ensure_ip("185.1.1.1", ts(0));
        let uid_user = g.ensure_user("uid:1001");
        // Even if the only edges are failed LoggedInFrom, the uid:N prefix
        // is always preserved.
        g.add_edge(
            Edge::new(uid_user, ip, Relation::LoggedInFrom, ts(0)).with_prop("success", false),
        );

        let report = cleanup_015_graph_signal_quality(&mut g);
        assert_eq!(report.brute_force_user_nodes_removed, 0);
        assert!(g.find_by_user("uid:1001").is_some());
    }

    #[test]
    fn cleanup_preserves_user_with_privilege_edge() {
        let mut g = KnowledgeGraph::new();
        let user = g.ensure_user("deploy");
        let proc_id = g.ensure_process(1234, 0, "sudo", 0, ts(0));
        let ip = g.ensure_ip("185.1.1.1", ts(0));

        // Only failed logins via SSH, but a SudoAs edge exists →
        // user is real, preserve.
        g.add_edge(Edge::new(user, ip, Relation::LoggedInFrom, ts(0)).with_prop("success", false));
        g.add_edge(Edge::new(proc_id, user, Relation::SudoAs, ts(1)));

        let report = cleanup_015_graph_signal_quality(&mut g);
        assert_eq!(report.brute_force_user_nodes_removed, 0);
        assert!(g.find_by_user("deploy").is_some());
    }

    #[test]
    fn cleanup_is_idempotent() {
        let mut g = KnowledgeGraph::new();
        let ip = g.ensure_ip("185.1.1.1", ts(0));
        let admin = g.ensure_user("admin");
        g.add_edge(Edge::new(admin, ip, Relation::LoggedInFrom, ts(0)).with_prop("success", false));

        let first = cleanup_015_graph_signal_quality(&mut g);
        let second = cleanup_015_graph_signal_quality(&mut g);
        assert_eq!(first.brute_force_user_nodes_removed, 1);
        assert_eq!(second.brute_force_user_nodes_removed, 0);
    }
}
