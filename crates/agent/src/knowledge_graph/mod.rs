//! Knowledge Graph — in-memory directed graph for attack context.
//!
//! Replaces JSONL flat file as the primary data structure for:
//! - Detector queries (threat_intel, lateral_movement, process_tree, etc.)
//! - AI triage context (attack narrative with full subgraph)
//! - Dashboard visualization (interactive graph)
//! - Correlation engine (graph path queries)
//!
//! ## Architecture
//!
//! The graph runs in parallel with JSONL (Phase 1). Events from the sensor
//! feed both JSONL sinks and the graph via `graph.ingest(event)` in the
//! fast loop. The slow loop handles TTL cleanup and periodic snapshots.
//!
//! ## Node types (11)
//!
//! Process, Ip, File, User, Domain, Port, Container, Device, System,
//! Incident, Campaign.
//!
//! ## Memory
//!
//! Estimated 10-24 MB for a typical 24h window. Hard cap at 50 MB with
//! LRU pruning.

pub mod buckets;
pub mod detectors;
pub mod graph;
pub mod ingestion;
pub mod migrations;
pub mod narrative;
pub mod persistence;
pub mod triggers;
pub mod types;

pub use graph::KnowledgeGraph;
pub use types::*;

impl KnowledgeGraph {
    /// Extract structural features for the neural autoencoder.
    pub fn extract_neural_features(&self) -> crate::neural_lifecycle::GraphFeatures {
        use crate::neural_lifecycle::GraphFeatures;

        let process_nodes = self.nodes_of_type(NodeType::Process);
        let ip_nodes = self.nodes_of_type(NodeType::Ip);

        // Average degree of process nodes
        let avg_process_degree = if process_nodes.is_empty() {
            0.0
        } else {
            let total: usize = process_nodes
                .iter()
                .map(|&id| self.all_edges(id).len())
                .sum();
            total as f32 / process_nodes.len() as f32
        };

        // Max process tree depth
        let max_depth = process_nodes
            .iter()
            .filter_map(|&id| {
                if let Some(Node::Process { pid, .. }) = self.get_node(id) {
                    Some(self.ancestors(*pid).len() as u32)
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(0);

        // Threat intel IP count
        let ti_count = ip_nodes
            .iter()
            .filter(|&&id| {
                matches!(self.get_node(id), Some(Node::Ip { datasets, .. }) if !datasets.is_empty())
            })
            .count() as u32;

        // Writes to sensitive paths
        let writes_sensitive = self
            .edges_slice()
            .iter()
            .filter(|e| {
                e.relation == Relation::Wrote
                    && self.get_node(e.to).is_some_and(|n| n.is_sensitive_file())
            })
            .count() as u32;

        // Process/IP ratio
        let process_ip_ratio = if ip_nodes.is_empty() {
            0.0
        } else {
            process_nodes.len() as f32 / ip_nodes.len() as f32
        };

        // High-degree nodes (>10 edges)
        let high_degree = self
            .nodes()
            .keys()
            .filter(|&&id| self.all_edges(id).len() > 10)
            .count() as u32;

        // Incident count
        let incident_count = self.nodes_of_type(NodeType::Incident).len() as u32;

        // Active sessions (LoggedInFrom with success in last 5min)
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(5);
        let active_sessions = self
            .edges_slice()
            .iter()
            .filter(|e| {
                e.relation == Relation::LoggedInFrom
                    && e.ts >= cutoff
                    && e.properties
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
            })
            .count() as u32;

        // Connected components via union-find
        let connected_components = self.count_connected_components();

        GraphFeatures {
            avg_process_degree,
            max_process_tree_depth: max_depth,
            threat_intel_ip_count: ti_count,
            writes_to_sensitive: writes_sensitive,
            connected_components,
            process_ip_ratio,
            high_degree_nodes: high_degree,
            incident_count,
            total_edges: self.edge_count() as u32,
            active_sessions,
        }
    }

    /// Count connected components using union-find.
    /// Useful for detecting isolated attack clusters vs connected attack paths.
    fn count_connected_components(&self) -> u32 {
        if self.nodes.is_empty() {
            return 0;
        }

        let node_ids: Vec<NodeId> = self.nodes.keys().copied().collect();
        let mut parent: std::collections::HashMap<NodeId, NodeId> =
            node_ids.iter().map(|&id| (id, id)).collect();

        fn find(parent: &mut std::collections::HashMap<NodeId, NodeId>, x: NodeId) -> NodeId {
            let mut root = x;
            while parent[&root] != root {
                root = parent[&root];
            }
            // Path compression
            let mut cur = x;
            while cur != root {
                let next = parent[&cur];
                parent.insert(cur, root);
                cur = next;
            }
            root
        }

        for edge in &self.edges {
            if edge.is_snapshot() {
                continue;
            }
            if !parent.contains_key(&edge.from) || !parent.contains_key(&edge.to) {
                continue;
            }
            let ra = find(&mut parent, edge.from);
            let rb = find(&mut parent, edge.to);
            if ra != rb {
                parent.insert(ra, rb);
            }
        }

        // Count distinct roots
        let roots: std::collections::HashSet<NodeId> =
            node_ids.iter().map(|&id| find(&mut parent, id)).collect();
        roots.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn count_connected_components_returns_zero_for_empty_graph() {
        // Covers empty-graph path to avoid regressions in component counting bootstrap behavior.
        let graph = KnowledgeGraph::new();
        assert_eq!(graph.count_connected_components(), 0);
    }

    #[test]
    fn count_connected_components_splits_disconnected_clusters() {
        // Ensures union-find correctly reports separate attack clusters as distinct components.
        let mut graph = KnowledgeGraph::new();
        let now = Utc::now();

        let p1 = graph.ensure_process(1001, 1, "bash", 0, now);
        let ip1 = graph.ensure_ip("1.2.3.4", now);
        graph.add_edge(Edge::new(p1, ip1, Relation::ConnectedTo, now));

        let p2 = graph.ensure_process(2001, 1, "python", 0, now);
        let ip2 = graph.ensure_ip("5.6.7.8", now);
        graph.add_edge(Edge::new(p2, ip2, Relation::ConnectedTo, now));

        assert_eq!(graph.count_connected_components(), 2);
    }

    #[test]
    fn extract_neural_features_tracks_sensitive_writes_and_active_sessions() {
        // Verifies feature extraction emits expected counters used by the neural lifecycle model.
        let mut graph = KnowledgeGraph::new();
        let now = Utc::now();

        let proc = graph.ensure_process(3001, 1, "curl", 0, now);
        let sensitive = graph.ensure_file("/etc/shadow");
        let user = graph.ensure_user("root");
        let ip = graph.ensure_ip("9.9.9.9", now);
        let incident = graph.add_node(Node::Incident {
            incident_id: "inc-1".to_string(),
            detector: "test".to_string(),
            severity: "high".to_string(),
            title: "t".to_string(),
            summary: "s".to_string(),
            ts: now,
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

        graph.add_edge(Edge::new(proc, sensitive, Relation::Wrote, now));
        let mut login = Edge::new(user, ip, Relation::LoggedInFrom, now - Duration::minutes(1));
        login
            .properties
            .insert("success".to_string(), serde_json::json!(true));
        graph.add_edge(login);
        graph.add_edge(Edge::new(proc, incident, Relation::TriggeredBy, now));

        let features = graph.extract_neural_features();
        assert_eq!(features.writes_to_sensitive, 1);
        assert_eq!(features.active_sessions, 1);
        assert_eq!(features.incident_count, 1);
        assert!(features.total_edges >= 3);
    }
}
