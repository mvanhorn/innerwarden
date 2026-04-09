use std::collections::HashMap;
use std::path::Path;

use super::graph::KnowledgeGraph;
use super::types::*;
use tracing::warn;

/// Serializable snapshot of the graph for persistence.
#[derive(serde::Serialize, serde::Deserialize)]
struct GraphSnapshot {
    nodes: HashMap<NodeId, Node>,
    edges: Vec<Edge>,
    next_id: NodeId,
}

impl KnowledgeGraph {
    /// Save the graph to a JSON file.
    pub fn save_snapshot(&self, path: &Path) -> anyhow::Result<()> {
        let snapshot = GraphSnapshot {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
            next_id: self.next_id,
        };

        let data = serde_json::to_vec(&snapshot)?;
        std::fs::write(path, &data)?;

        tracing::info!(
            "Knowledge graph snapshot saved: {} nodes, {} edges, {} bytes",
            snapshot.nodes.len(),
            snapshot.edges.len(),
            data.len()
        );

        Ok(())
    }

    /// Load the graph from a snapshot file. Returns empty graph on error.
    pub fn load_snapshot(path: &Path) -> Self {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Knowledge graph snapshot not found: {}", e);
                return Self::new();
            }
        };

        let snapshot: GraphSnapshot = match serde_json::from_slice(&data) {
            Ok(s) => s,
            Err(e) => {
                warn!("Knowledge graph snapshot corrupted, starting fresh: {}", e);
                return Self::new();
            }
        };

        let mut graph = Self::new();
        graph.next_id = snapshot.next_id;

        // Restore nodes and rebuild indexes
        for (&id, node) in &snapshot.nodes {
            graph.index_node(id, node);
            graph.memory_estimate += Self::estimate_node_size(node);
        }
        graph.nodes = snapshot.nodes;

        // Restore edges and rebuild adjacency lists
        for (idx, edge) in snapshot.edges.iter().enumerate() {
            graph.outgoing.entry(edge.from).or_default().push(idx);
            graph.incoming.entry(edge.to).or_default().push(idx);
            graph.memory_estimate += Self::estimate_edge_size(edge);
        }
        graph.edges = snapshot.edges;

        tracing::info!(
            "Knowledge graph restored: {} nodes, {} edges, ~{} KB",
            graph.node_count(),
            graph.edge_count(),
            graph.memory_estimate / 1024
        );

        graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::tempdir;

    #[test]
    fn test_save_and_load_snapshot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("graph-snapshot.json");

        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1234, 800, "bash", 0, Utc::now());
        let ip_id = g.ensure_ip("1.2.3.4", Utc::now());
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, Utc::now()));

        g.save_snapshot(&path).unwrap();

        let g2 = KnowledgeGraph::load_snapshot(&path);
        assert_eq!(g2.node_count(), g.node_count());
        assert_eq!(g2.edge_count(), g.edge_count());
        assert!(g2.find_by_pid(1234).is_some());
        assert!(g2.find_by_ip("1.2.3.4").is_some());
    }

    #[test]
    fn test_load_missing_file() {
        let g = KnowledgeGraph::load_snapshot(Path::new("/nonexistent/path.json"));
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn test_load_corrupted_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"not json").unwrap();

        let g = KnowledgeGraph::load_snapshot(&path);
        assert_eq!(g.node_count(), 0);
    }
}
