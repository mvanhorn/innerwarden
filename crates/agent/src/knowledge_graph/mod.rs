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

pub mod detectors;
pub mod graph;
pub mod ingestion;
pub mod narrative;
pub mod persistence;
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
            let total: usize = process_nodes.iter().map(|&id| self.all_edges(id).len()).sum();
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
                    && self
                        .get_node(e.to)
                        .map_or(false, |n| n.is_sensitive_file())
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

        GraphFeatures {
            avg_process_degree,
            max_process_tree_depth: max_depth,
            threat_intel_ip_count: ti_count,
            writes_to_sensitive: writes_sensitive,
            connected_components: 0, // TODO: implement if needed
            process_ip_ratio,
            high_degree_nodes: high_degree,
            incident_count,
            total_edges: self.edge_count() as u32,
            active_sessions,
        }
    }
}
