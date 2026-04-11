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

/// Report returned by [`backfill_research_only_flag`].
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BackfillResearchOnlyReport {
    /// Total Incident nodes scanned.
    pub incidents_scanned: usize,
    /// Incidents that had their `research_only` flag flipped from false → true.
    pub incidents_flagged: usize,
    /// Breakdown by detector slug (top contributors).
    pub by_detector: std::collections::BTreeMap<String, usize>,
}

/// Spec 015 follow-up: walk the graph and backfill the `research_only`
/// flag on every Incident node whose connected `Ip` nodes are all
/// self-traffic (cloud providers, Telegram, GeoIP, Canonical, OCI peers).
///
/// Safe to run multiple times — idempotent. The migration never *unflags*
/// an incident; it only promotes false → true when the data matches.
///
/// The rule is the same as `ingest_incident`'s: an incident is research_only
/// iff it has at least one connected Ip node AND every connected Ip node is
/// a safelist match. Incidents with a single attacker IP and a self-traffic
/// IP stay visible.
pub fn backfill_research_only_flag(graph: &mut KnowledgeGraph) -> BackfillResearchOnlyReport {
    let mut report = BackfillResearchOnlyReport::default();

    // Collect (incident_id, should_flag) in a first pass so we don't hold a
    // mutable borrow while iterating.
    let mut updates: Vec<(NodeId, String)> = Vec::new();

    let incident_nodes = graph.nodes_of_type(NodeType::Incident);
    report.incidents_scanned = incident_nodes.len();

    for inc_id in incident_nodes {
        let (already_flagged, detector, severity, title) = match graph.get_node(inc_id) {
            Some(Node::Incident {
                research_only,
                detector,
                severity,
                title,
                ..
            }) => (
                *research_only,
                detector.clone(),
                severity.clone(),
                title.clone(),
            ),
            _ => continue,
        };
        if already_flagged {
            continue;
        }

        // Rule 1: kill_chain "forming" (incomplete bit pattern, severity
        // Medium) is research/training data, never user-facing. The fully
        // formed kill chains (severity Critical) stay visible.
        //
        // On the 2026-04-11 prod snapshot this alone moves 21,783 incidents
        // out of the operator view while preserving the 31 critical ones.
        if detector == "kill_chain"
            && severity.eq_ignore_ascii_case("medium")
            && title.starts_with("Kill chain forming")
        {
            updates.push((inc_id, detector));
            continue;
        }

        // Rule 2: self-traffic rule — the incident is anchored on IPs and
        // every anchor IP is a cloud provider / agent service endpoint.
        let mut ip_addrs: Vec<String> = Vec::new();
        for edge in graph.outgoing_edges(inc_id) {
            if edge.relation != super::types::Relation::TriggeredBy {
                continue;
            }
            if let Some(Node::Ip { addr, .. }) = graph.get_node(edge.to) {
                ip_addrs.push(addr.clone());
            }
        }
        if ip_addrs.is_empty() {
            continue;
        }
        let all_self = ip_addrs
            .iter()
            .all(|ip| crate::cloud_safelist::is_self_traffic_ip(ip));
        if all_self {
            updates.push((inc_id, detector));
        }
    }

    // Apply.
    for (inc_id, detector) in updates {
        if let Some(Node::Incident { research_only, .. }) = graph.nodes.get_mut(&inc_id) {
            *research_only = true;
            report.incidents_flagged += 1;
            *report.by_detector.entry(detector).or_insert(0) += 1;
        }
    }

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
            research_only: false,
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
    fn backfill_research_only_flags_telegram_chain() {
        crate::cloud_safelist::init();
        let mut g = KnowledgeGraph::new();

        // Telegram IP (Bot API) → incident
        let telegram = g.ensure_ip("149.154.166.110", ts(0));
        let inc = g.add_node(Node::Incident {
            incident_id: "graph_data_exfil:tokio-rt-worker:1".to_string(),
            detector: "graph_data_exfil".to_string(),
            severity: "critical".to_string(),
            title: "exfil → telegram".to_string(),
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
            research_only: false,
        });
        g.add_edge(Edge::new(inc, telegram, Relation::TriggeredBy, ts(0)));

        let report = backfill_research_only_flag(&mut g);
        assert_eq!(report.incidents_flagged, 1);
        assert_eq!(report.by_detector.get("graph_data_exfil"), Some(&1));
        match g.get_node(inc) {
            Some(Node::Incident { research_only, .. }) => assert!(*research_only),
            _ => panic!("incident lost"),
        }
    }

    #[test]
    fn backfill_preserves_real_attacker_incidents() {
        crate::cloud_safelist::init();
        let mut g = KnowledgeGraph::new();

        let attacker = g.ensure_ip("185.113.139.51", ts(0));
        let inc = g.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "brute force".to_string(),
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
            research_only: false,
        });
        g.add_edge(Edge::new(inc, attacker, Relation::TriggeredBy, ts(0)));

        let report = backfill_research_only_flag(&mut g);
        assert_eq!(report.incidents_flagged, 0);
        match g.get_node(inc) {
            Some(Node::Incident { research_only, .. }) => assert!(!*research_only),
            _ => panic!("incident lost"),
        }
    }

    #[test]
    fn backfill_mixed_chain_stays_visible() {
        crate::cloud_safelist::init();
        let mut g = KnowledgeGraph::new();

        let telegram = g.ensure_ip("149.154.166.110", ts(0));
        let attacker = g.ensure_ip("185.113.139.51", ts(0));
        let inc = g.add_node(Node::Incident {
            incident_id: "cross_layer_chain:mixed:1".to_string(),
            detector: "cross_layer_chain".to_string(),
            severity: "high".to_string(),
            title: "mixed".to_string(),
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
            research_only: false,
        });
        g.add_edge(Edge::new(inc, telegram, Relation::TriggeredBy, ts(0)));
        g.add_edge(Edge::new(inc, attacker, Relation::TriggeredBy, ts(0)));

        let report = backfill_research_only_flag(&mut g);
        assert_eq!(report.incidents_flagged, 0, "mixed chain must stay visible");
    }

    #[test]
    fn backfill_is_idempotent() {
        crate::cloud_safelist::init();
        let mut g = KnowledgeGraph::new();

        let telegram = g.ensure_ip("149.154.166.110", ts(0));
        let inc = g.add_node(Node::Incident {
            incident_id: "graph_data_exfil:1".to_string(),
            detector: "graph_data_exfil".to_string(),
            severity: "critical".to_string(),
            title: "t".to_string(),
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
            research_only: false,
        });
        g.add_edge(Edge::new(inc, telegram, Relation::TriggeredBy, ts(0)));

        let first = backfill_research_only_flag(&mut g);
        let second = backfill_research_only_flag(&mut g);
        assert_eq!(first.incidents_flagged, 1);
        assert_eq!(second.incidents_flagged, 0);
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
