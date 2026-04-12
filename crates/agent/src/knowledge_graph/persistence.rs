use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::graph::KnowledgeGraph;
use super::types::*;
use tracing::warn;

/// Serializable snapshot of the graph for persistence.
#[derive(serde::Serialize, serde::Deserialize)]
struct GraphSnapshot {
    nodes: HashMap<NodeId, Node>,
    edges: Vec<Edge>,
    next_id: NodeId,
    /// Event telemetry counters (added Phase 6A — persisted so Sensors tab works after restart)
    #[serde(default)]
    source_counts: HashMap<String, usize>,
    #[serde(default)]
    kind_counts: HashMap<String, usize>,
    #[serde(default)]
    event_timeline: std::collections::BTreeMap<String, HashMap<String, usize>>,
    #[serde(default)]
    total_events_ingested: usize,
}

impl KnowledgeGraph {
    /// Save the graph to a JSON file with rotation (T029: keep last 3 snapshots).
    pub fn save_snapshot(&self, path: &Path) -> anyhow::Result<()> {
        let snapshot = GraphSnapshot {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
            next_id: self.next_id,
            source_counts: self.source_counts.clone(),
            kind_counts: self.kind_counts.clone(),
            event_timeline: self.event_timeline.clone(),
            total_events_ingested: self.total_events_ingested,
        };

        let data = serde_json::to_vec(&snapshot)?;

        // T029: rotate previous snapshots before writing new one
        rotate_snapshots(path, 3);

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
    /// T027: verifies integrity after load (node/edge count consistency).
    /// T030: on corruption, attempts rebuild from today's JSONL files.
    pub fn load_snapshot(path: &Path) -> Self {
        match Self::try_load_snapshot(path) {
            Some(graph) => graph,
            None => {
                // T030: try rotated backups before giving up
                for i in 1..=3 {
                    let backup = path.with_extension(format!("json.{i}"));
                    if let Some(graph) = Self::try_load_snapshot(&backup) {
                        tracing::warn!(
                            backup = %backup.display(),
                            "Knowledge graph loaded from backup snapshot"
                        );
                        return graph;
                    }
                }
                tracing::warn!("No valid graph snapshot found, starting fresh");
                Self::new()
            }
        }
    }

    // ── Phase 7 (spec 013): Dated snapshot API ───────────────────────────

    /// Path for today's dated snapshot.
    pub fn dated_snapshot_path(data_dir: &Path) -> PathBuf {
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        data_dir.join(format!("graph-snapshot-{today}.json"))
    }

    /// Save a dated snapshot: `graph-snapshot-YYYY-MM-DD.json` with rotation.
    pub fn save_dated_snapshot(&self, data_dir: &Path) -> anyhow::Result<()> {
        let path = Self::dated_snapshot_path(data_dir);
        self.save_snapshot(&path)
    }

    /// Load today's dated snapshot (with fallback to legacy `graph-snapshot.json`).
    pub fn load_today_snapshot(data_dir: &Path) -> Self {
        let dated = Self::dated_snapshot_path(data_dir);
        if dated.exists() {
            let g = Self::load_snapshot(&dated);
            if g.node_count() > 0 {
                return g;
            }
        }
        // Fallback: legacy non-dated snapshot (one-time migration)
        let legacy = data_dir.join("graph-snapshot.json");
        if legacy.exists() {
            let g = Self::load_snapshot(&legacy);
            if g.node_count() > 0 {
                tracing::info!("Migrated from legacy graph-snapshot.json to dated snapshots");
                return g;
            }
        }
        tracing::warn!("No graph snapshot found, starting fresh");
        Self::new()
    }

    /// Load a historical dated snapshot for a specific date string (e.g. "2026-04-10").
    /// Returns None if the snapshot doesn't exist or is corrupt.
    pub fn load_dated(data_dir: &Path, date: &str) -> Option<Self> {
        let path = data_dir.join(format!("graph-snapshot-{date}.json"));
        Self::try_load_snapshot(&path)
    }

    /// Delete dated snapshots older than `keep_days` days.
    pub fn cleanup_old_snapshots(data_dir: &Path, keep_days: u32) {
        let cutoff = chrono::Local::now().date_naive() - chrono::Duration::days(keep_days as i64);
        let pattern = "graph-snapshot-";
        let entries = match std::fs::read_dir(data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(pattern) || !name.ends_with(".json") {
                continue;
            }
            // Extract date from "graph-snapshot-YYYY-MM-DD.json"
            let date_part = &name[pattern.len()..name.len() - 5]; // strip prefix and .json
            if date_part.contains('.') {
                // This is a rotation backup like "graph-snapshot-2026-04-10.json.1"
                // handled separately
                continue;
            }
            if let Ok(date) = chrono::NaiveDate::parse_from_str(date_part, "%Y-%m-%d") {
                if date < cutoff {
                    let _ = std::fs::remove_file(entry.path());
                    // Also remove rotation backups
                    for i in 1..=3 {
                        let backup = entry.path().with_extension(format!("json.{i}"));
                        let _ = std::fs::remove_file(&backup);
                    }
                    tracing::info!(date = %date_part, "Deleted old graph snapshot");
                }
            }
        }
    }

    fn try_load_snapshot(path: &Path) -> Option<Self> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return None,
        };

        let snapshot: GraphSnapshot = match serde_json::from_slice(&data) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "Knowledge graph snapshot corrupted"
                );
                return None;
            }
        };

        Self::reconstruct_from_snapshot(snapshot)
    }

    // ── SQLite-backed snapshot API (spec 016) ────────────────────────────

    /// Save graph snapshot to the unified SQLite store.
    pub fn save_to_store(&self, store: &innerwarden_store::Store) -> anyhow::Result<()> {
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d").to_string();
        let snapshot = GraphSnapshot {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
            next_id: self.next_id,
            source_counts: self.source_counts.clone(),
            kind_counts: self.kind_counts.clone(),
            event_timeline: self.event_timeline.clone(),
            total_events_ingested: self.total_events_ingested,
        };
        let data = serde_json::to_vec(&snapshot)?;
        store.save_graph_snapshot(&today, &data, self.node_count(), self.edge_count())?;
        tracing::info!(
            "Graph snapshot saved to SQLite: {} nodes, {} edges",
            self.node_count(),
            self.edge_count()
        );
        Ok(())
    }

    /// Load the latest graph snapshot from the unified SQLite store.
    pub fn load_from_store(store: &innerwarden_store::Store) -> Option<Self> {
        let (date, data) = store.load_latest_graph_snapshot().ok()??;
        let snapshot: GraphSnapshot = serde_json::from_slice(&data).ok()?;
        let graph = Self::reconstruct_from_snapshot(snapshot)?;
        tracing::info!(date = %date, "Graph loaded from SQLite store");
        Some(graph)
    }

    /// Delete SQLite graph snapshots older than `keep_days` days.
    pub fn cleanup_store_snapshots(store: &innerwarden_store::Store, keep_days: u32) {
        let cutoff = (chrono::Local::now().date_naive()
            - chrono::Duration::days(keep_days as i64))
        .format("%Y-%m-%d")
        .to_string();
        if let Err(e) = store.delete_graph_snapshots_before(&cutoff) {
            tracing::warn!("SQLite snapshot cleanup failed: {e:#}");
        }
    }

    /// Reconstruct a `KnowledgeGraph` from a deserialized snapshot.
    /// Shared by `try_load_snapshot` (file) and `load_from_store` (SQLite).
    fn reconstruct_from_snapshot(snapshot: GraphSnapshot) -> Option<Self> {
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

        // Restore event telemetry counters (Phase 6A: Sensors tab needs these after restart)
        graph.source_counts = snapshot.source_counts;
        graph.kind_counts = snapshot.kind_counts;
        graph.event_timeline = snapshot.event_timeline;
        graph.total_events_ingested = snapshot.total_events_ingested;

        // T027: integrity check — verify indexes are consistent
        let node_count = graph.nodes.len();
        let _edge_count = graph.edges.len();
        let indexed_nodes = graph.pid_index.len()
            + graph.ip_index.len()
            + graph.file_index.len()
            + graph.user_index.len()
            + graph.domain_index.len()
            + graph.port_index.len()
            + graph.container_index.len()
            + graph.device_index.len()
            + graph.incident_index.len()
            + graph.campaign_index.len()
            + graph.system_node.iter().count();

        if indexed_nodes == 0 && node_count > 0 {
            warn!(
                "Knowledge graph integrity check failed: {} nodes but 0 indexed — possible corruption",
                node_count
            );
            return None;
        }

        // Verify all edge references point to existing nodes
        let mut dangling = 0usize;
        for edge in &graph.edges {
            if !graph.nodes.contains_key(&edge.from) || !graph.nodes.contains_key(&edge.to) {
                dangling += 1;
            }
        }
        if dangling > 0 {
            warn!(
                dangling,
                "Knowledge graph has dangling edge references — pruning"
            );
            graph
                .edges
                .retain(|e| graph.nodes.contains_key(&e.from) && graph.nodes.contains_key(&e.to));
            // Rebuild adjacency after pruning
            graph.outgoing.clear();
            graph.incoming.clear();
            for (idx, edge) in graph.edges.iter().enumerate() {
                graph.outgoing.entry(edge.from).or_default().push(idx);
                graph.incoming.entry(edge.to).or_default().push(idx);
            }
        }

        tracing::info!(
            "Knowledge graph restored: {} nodes, {} edges, ~{} KB",
            graph.node_count(),
            graph.edge_count(),
            graph.memory_estimate / 1024
        );

        Some(graph)
    }
}

/// T029: Rotate snapshot files — keep last `max_backups` copies.
/// graph-snapshot.json → .json.1 → .json.2 → .json.3 (oldest deleted)
fn rotate_snapshots(path: &Path, max_backups: u32) {
    // Delete oldest backup
    let oldest = path.with_extension(format!("json.{max_backups}"));
    let _ = std::fs::remove_file(&oldest);

    // Shift backups: .2 → .3, .1 → .2
    for i in (1..max_backups).rev() {
        let from = path.with_extension(format!("json.{i}"));
        let to = path.with_extension(format!("json.{}", i + 1));
        let _ = std::fs::rename(&from, &to);
    }

    // Current → .1
    let backup = path.with_extension("json.1");
    let _ = std::fs::rename(path, &backup);
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

    #[test]
    fn test_snapshot_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("graph-snapshot.json");

        let mut g = KnowledgeGraph::new();
        g.ensure_ip("1.1.1.1", Utc::now());
        g.save_snapshot(&path).unwrap();

        // Second save should rotate first to .1
        g.ensure_ip("2.2.2.2", Utc::now());
        g.save_snapshot(&path).unwrap();

        assert!(path.exists());
        assert!(path.with_extension("json.1").exists());

        // Load from .1 backup should have 1 node (first save)
        let backup = KnowledgeGraph::try_load_snapshot(&path.with_extension("json.1")).unwrap();
        assert_eq!(backup.node_count(), 1);
    }

    #[test]
    fn test_corrupted_falls_back_to_backup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("graph-snapshot.json");

        // First save: creates main snapshot
        let mut g = KnowledgeGraph::new();
        g.ensure_ip("10.0.0.1", Utc::now());
        g.save_snapshot(&path).unwrap();

        // Second save: rotates main → .1 (backup), writes new main
        g.save_snapshot(&path).unwrap();
        assert!(path.with_extension("json.1").exists());

        // Corrupt the main snapshot
        std::fs::write(&path, b"corrupted!!!").unwrap();

        // Load should fall back to .1
        let loaded = KnowledgeGraph::load_snapshot(&path);
        assert!(loaded.node_count() > 0);
        assert!(loaded.find_by_ip("10.0.0.1").is_some());
    }
}
