use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::graph::KnowledgeGraph;
use super::types::*;
use tracing::warn;

/// Gzip magic bytes — the first two bytes of any RFC 1952 gzip stream.
/// Used to distinguish compressed snapshots (written by agents from the
/// 2026-04-23 fix onwards) from legacy uncompressed JSON (which always
/// starts with `{`).
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Default gzip compression level. 6 is flate2's default — a sweet spot
/// for typical JSON payloads (graph snapshots compress 6-10x). Bumping
/// to 9 saves ~5% more space at significant CPU cost; 1 is barely worth
/// running. Tuning here affects the slow_loop tick latency, not just disk.
const SNAPSHOT_GZIP_LEVEL: flate2::Compression = flate2::Compression::new(6);

/// Compress a JSON-bytes snapshot into gzip. Returns the original bytes
/// on compression error so the caller can still persist the snapshot
/// (correctness over efficiency under degraded conditions).
fn gzip_snapshot_bytes(json: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::with_capacity(json.len() / 4), SNAPSHOT_GZIP_LEVEL);
    if encoder.write_all(json).is_err() {
        return json.to_vec();
    }
    encoder.finish().unwrap_or_else(|_| json.to_vec())
}

/// Decompress a snapshot blob if it carries the gzip magic header,
/// otherwise return the bytes unchanged. Pre-2026-04-23 snapshots were
/// stored as raw JSON starting with `{`; the magic-byte check makes the
/// reader back-compat with both schemes without a separate version
/// column. On a corrupted gzip stream the reader yields `None` so the
/// caller falls through to the same "snapshot corrupted" path used for
/// invalid JSON.
fn maybe_decompress(blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() >= 2 && blob[0] == GZIP_MAGIC[0] && blob[1] == GZIP_MAGIC[1] {
        let mut decoder = flate2::read::GzDecoder::new(blob);
        let mut out = Vec::with_capacity(blob.len() * 6); // conservative pre-allocation
        decoder.read_to_end(&mut out).ok()?;
        Some(out)
    } else {
        Some(blob.to_vec())
    }
}

/// Owned snapshot used by load (deserialize moves into KnowledgeGraph).
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

/// Borrowed view for serialization. Avoids cloning the entire graph
/// state every save (272 MB transient allocation per slow_loop tick on
/// the production agent at 1354-profile baseline). Wire format is
/// identical to `GraphSnapshot`, so saves written via this struct round-
/// trip through `GraphSnapshot::deserialize` unchanged.
#[derive(serde::Serialize)]
struct GraphSnapshotRef<'a> {
    nodes: &'a HashMap<NodeId, Node>,
    edges: &'a Vec<Edge>,
    next_id: NodeId,
    source_counts: &'a HashMap<String, usize>,
    kind_counts: &'a HashMap<String, usize>,
    event_timeline: &'a std::collections::BTreeMap<String, HashMap<String, usize>>,
    total_events_ingested: usize,
}

impl<'a> GraphSnapshotRef<'a> {
    fn from_graph(g: &'a KnowledgeGraph) -> Self {
        Self {
            nodes: &g.nodes,
            edges: &g.edges,
            next_id: g.next_id,
            source_counts: &g.source_counts,
            kind_counts: &g.kind_counts,
            event_timeline: &g.event_timeline,
            total_events_ingested: g.total_events_ingested,
        }
    }
}

impl KnowledgeGraph {
    /// Save the graph to a JSON file with rotation (T029: keep last 3 snapshots).
    ///
    /// Bytes are gzip-compressed before write (typical JSON payload shrinks
    /// 6-10× — 47 MB → ~5 MB on the prod baseline at 14k nodes / 145k edges).
    /// Reader detects the format via the gzip magic header so legacy
    /// uncompressed snapshots still load.
    pub fn save_snapshot(&self, path: &Path) -> anyhow::Result<()> {
        let snapshot = GraphSnapshotRef::from_graph(self);
        let json = serde_json::to_vec(&snapshot)?;
        let data = gzip_snapshot_bytes(&json);

        // T029: rotate previous snapshots before writing new one
        rotate_snapshots(path, 3);

        std::fs::write(path, &data)?;

        tracing::info!(
            nodes = self.nodes.len(),
            edges = self.edges.len(),
            bytes_on_disk = data.len(),
            bytes_uncompressed = json.len(),
            "Knowledge graph snapshot saved"
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
        let raw = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return None,
        };

        let data = match maybe_decompress(&raw) {
            Some(d) => d,
            None => {
                warn!(
                    path = %path.display(),
                    "Knowledge graph snapshot has gzip header but failed to decompress"
                );
                return None;
            }
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
    ///
    /// Bytes are gzip-compressed before bind. SQLite's `bind_blob` copies
    /// the slice into its internal buffer, so the smaller the BLOB the
    /// less memory the slow_loop allocates per tick (the prod baseline
    /// at 14k nodes / 145k edges shrinks from ~47 MB JSON to ~5 MB gzip).
    pub fn save_to_store(&self, store: &innerwarden_store::Store) -> anyhow::Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let snapshot = GraphSnapshotRef::from_graph(self);
        let json = serde_json::to_vec(&snapshot)?;
        let data = gzip_snapshot_bytes(&json);
        store.save_graph_snapshot(&today, &data, self.node_count(), self.edge_count())?;
        tracing::info!(
            nodes = self.node_count(),
            edges = self.edge_count(),
            bytes_in_blob = data.len(),
            bytes_uncompressed = json.len(),
            "Graph snapshot saved to SQLite"
        );
        Ok(())
    }

    /// Load the latest graph snapshot from the unified SQLite store.
    pub fn load_from_store(store: &innerwarden_store::Store) -> Option<Self> {
        let (date, raw) = store.load_latest_graph_snapshot().ok()??;
        let data = maybe_decompress(&raw)?;
        let snapshot: GraphSnapshot = serde_json::from_slice(&data).ok()?;
        let graph = Self::reconstruct_from_snapshot(snapshot)?;
        tracing::info!(date = %date, "Graph loaded from SQLite store");
        Some(graph)
    }

    /// Load a graph snapshot for a specific date from the unified SQLite store.
    pub fn load_dated_from_store(store: &innerwarden_store::Store, date: &str) -> Option<Self> {
        let raw = store.load_graph_snapshot(date).ok()??;
        let data = maybe_decompress(&raw)?;
        let snapshot: GraphSnapshot = serde_json::from_slice(&data).ok()?;
        let graph = Self::reconstruct_from_snapshot(snapshot)?;
        tracing::debug!(date = %date, "Graph loaded from SQLite store for date");
        Some(graph)
    }

    /// Delete SQLite graph snapshots older than `keep_days` days.
    pub fn cleanup_store_snapshots(store: &innerwarden_store::Store, keep_days: u32) {
        let cutoff = (chrono::Local::now().date_naive() - chrono::Duration::days(keep_days as i64))
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

        // Restore edges and rebuild adjacency lists. Also rebuild the
        // `last_edge_ts` LRU index used by `enforce_memory_limit`. The index
        // is derived from `edges` and not part of the wire format, so old
        // snapshots load unchanged — same precedent as `outgoing`/`incoming`.
        for (idx, edge) in snapshot.edges.iter().enumerate() {
            graph.outgoing.entry(edge.from).or_default().push(idx);
            graph.incoming.entry(edge.to).or_default().push(idx);
            graph.memory_estimate += Self::estimate_edge_size(edge);
            let edge_ts = edge.ts;
            graph
                .last_edge_ts
                .entry(edge.from)
                .and_modify(|t| {
                    if edge_ts > *t {
                        *t = edge_ts;
                    }
                })
                .or_insert(edge_ts);
            if edge.to != edge.from {
                graph
                    .last_edge_ts
                    .entry(edge.to)
                    .and_modify(|t| {
                        if edge_ts > *t {
                            *t = edge_ts;
                        }
                    })
                    .or_insert(edge_ts);
            }
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
    fn save_to_store_and_load_from_store_roundtrip() {
        // Covers the SQLite-backed persistence path. Equivalent to
        // `test_save_and_load_snapshot` but for `save_to_store` /
        // `load_from_store`, which were only exercised in production
        // before this test (slow_loop calls them every tick).
        let store = innerwarden_store::Store::open_memory().expect("memory store");

        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(4321, 1, "redis-server", 0, Utc::now());
        let ip_id = g.ensure_ip("203.0.113.7", Utc::now());
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, Utc::now()));

        g.save_to_store(&store).expect("save_to_store");

        let g2 = KnowledgeGraph::load_from_store(&store).expect("load_from_store");
        assert_eq!(g2.node_count(), g.node_count());
        assert_eq!(g2.edge_count(), g.edge_count());
        assert!(g2.find_by_pid(4321).is_some());
        assert!(g2.find_by_ip("203.0.113.7").is_some());
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

    // ── gzip snapshot tests ──────────────────────────────────────────
    //
    // Anchors for the size reduction shipped 2026-04-23. The wire format
    // changed from raw JSON to gzip-wrapped JSON. The reader uses a
    // magic-byte sniff so legacy uncompressed snapshots still load —
    // these tests pin both directions of that contract.

    #[test]
    fn save_snapshot_writes_gzip_compressed_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("snap.json");
        let mut g = KnowledgeGraph::new();
        // Make the graph non-trivial so compression actually engages.
        for i in 0..50 {
            g.ensure_ip(&format!("203.0.113.{i}"), Utc::now());
        }
        g.save_snapshot(&path).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b,
            "snapshot must start with gzip magic bytes"
        );
    }

    #[test]
    fn load_snapshot_reads_gzip_compressed_bytes_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("snap.json");
        let mut g = KnowledgeGraph::new();
        let p = g.ensure_process(7777, 1, "redis", 0, Utc::now());
        let ip = g.ensure_ip("198.51.100.42", Utc::now());
        g.add_edge(Edge::new(p, ip, Relation::ConnectedTo, Utc::now()));
        g.save_snapshot(&path).unwrap();

        let loaded = KnowledgeGraph::load_snapshot(&path);
        assert_eq!(loaded.node_count(), g.node_count());
        assert_eq!(loaded.edge_count(), g.edge_count());
        assert!(loaded.find_by_pid(7777).is_some());
        assert!(loaded.find_by_ip("198.51.100.42").is_some());
    }

    #[test]
    fn load_snapshot_back_compat_reads_legacy_uncompressed_json() {
        // Simulates a snapshot written by an agent BEFORE the gzip change.
        // Reader must detect "no gzip magic" and parse as raw JSON.
        let dir = tempdir().unwrap();
        let path = dir.path().join("snap.json");

        let mut g = KnowledgeGraph::new();
        g.ensure_ip("10.0.0.99", Utc::now());

        // Write the snapshot the OLD way: raw JSON, no gzip wrapping.
        let snap_ref = GraphSnapshotRef::from_graph(&g);
        let raw_json = serde_json::to_vec(&snap_ref).unwrap();
        assert_eq!(
            raw_json[0], b'{',
            "test fixture must look like legacy raw JSON"
        );
        std::fs::write(&path, &raw_json).unwrap();

        let loaded = KnowledgeGraph::load_snapshot(&path);
        assert!(
            loaded.find_by_ip("10.0.0.99").is_some(),
            "legacy uncompressed snapshot must still load (back-compat)"
        );
    }

    #[test]
    fn maybe_decompress_passes_through_non_gzip_bytes() {
        // Defensive unit test for the reader helper.
        let raw = b"{\"nodes\":{},\"edges\":[]}".to_vec();
        let out = maybe_decompress(&raw).expect("non-gzip bytes return unchanged");
        assert_eq!(out, raw);
    }

    #[test]
    fn maybe_decompress_round_trips_gzip_bytes() {
        let original = b"hello inner warden compression check 12345".repeat(10);
        let compressed = gzip_snapshot_bytes(&original);
        // Compression with non-trivial input must produce different bytes.
        assert_ne!(compressed, original);
        assert!(
            compressed.len() >= 2 && compressed[0] == 0x1f && compressed[1] == 0x8b,
            "compressor output must carry gzip magic"
        );
        let decoded = maybe_decompress(&compressed).expect("gzip round-trip");
        assert_eq!(decoded, original);
    }

    #[test]
    fn maybe_decompress_handles_corrupt_gzip_gracefully() {
        // Magic bytes present but the rest is garbage — must return None,
        // not panic, so the caller can fall through to its "snapshot
        // corrupted" branch.
        let mut bad = vec![0x1f, 0x8b];
        bad.extend_from_slice(&[0u8; 32]);
        assert!(maybe_decompress(&bad).is_none());
    }

    #[test]
    fn save_to_store_writes_gzip_and_load_round_trips() {
        // SQLite path equivalent of the file-snapshot test.
        let store = innerwarden_store::Store::open_memory().expect("memory store");

        let mut g = KnowledgeGraph::new();
        for i in 0..20 {
            g.ensure_ip(&format!("198.51.100.{i}"), Utc::now());
        }
        g.save_to_store(&store).unwrap();

        // The blob in the store must be gzip-compressed.
        let (_date, raw_blob) = store
            .load_latest_graph_snapshot()
            .expect("load_latest succeeds")
            .expect("latest blob exists");
        assert!(
            raw_blob.len() >= 2 && raw_blob[0] == 0x1f && raw_blob[1] == 0x8b,
            "SQLite blob must be gzip-compressed"
        );

        // Round-trip via the public load API.
        let loaded = KnowledgeGraph::load_from_store(&store).expect("load_from_store");
        for i in 0..20 {
            assert!(loaded.find_by_ip(&format!("198.51.100.{i}")).is_some());
        }
    }
}
