use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::graph::KnowledgeGraph;
use super::types::*;
use tracing::warn;

// ── Observability counters for `load_dated_sqlite_first` ──────────────
//
// Exposed via `/metrics` under `innerwarden_kg_dated_load_total{source=...}`
// so operators can tell whether dated KG reads are being served from the
// SQLite canonical source, the JSON fallback, or neither. These are
// process-local (reset on agent restart); the Prometheus scraper
// already handles that semantics for counter types.
//
// Labels are mutually exclusive — every call increments exactly one.
static KG_DATED_LOAD_SQLITE: AtomicU64 = AtomicU64::new(0);
static KG_DATED_LOAD_JSON: AtomicU64 = AtomicU64::new(0);
static KG_DATED_LOAD_MISS: AtomicU64 = AtomicU64::new(0);
static KG_DATED_LOAD_ERROR: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the four `load_dated_sqlite_first` counters for the
/// `/metrics` endpoint. Returned as a fixed-order array so the render
/// site does not need to know about the `static` layout.
pub(crate) fn load_dated_metrics_snapshot() -> [(&'static str, u64); 4] {
    [
        ("sqlite", KG_DATED_LOAD_SQLITE.load(Ordering::Relaxed)),
        ("json", KG_DATED_LOAD_JSON.load(Ordering::Relaxed)),
        ("miss", KG_DATED_LOAD_MISS.load(Ordering::Relaxed)),
        ("error", KG_DATED_LOAD_ERROR.load(Ordering::Relaxed)),
    ]
}

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

/// Strict shape predicate for a date-string used as a filesystem path
/// component or SQL parameter. Accepts only the canonical
/// `YYYY-MM-DD` form: exactly 10 ASCII chars, digits and dashes in
/// fixed positions. Rejects loose variants chrono would otherwise
/// accept (`2026-4-23`, `2026-04-23T00`, etc.) so the on-disk filename
/// is always canonical and predictable.
fn has_canonical_iso_date_shape(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| match i {
        4 | 7 => b == b'-',
        _ => b.is_ascii_digit(),
    })
}

/// Parse a date-string and return a SAFE filename component for the
/// snapshot store. The user-controlled `date: &str` flows from the
/// `/api/report?date=...` HTTP query into a `data_dir.join(...)` call;
/// without this guard a request like `?date=../../etc/passwd` would
/// attempt to read outside `data_dir`.
///
/// Three layered defenses:
///
/// 1. **Shape check**: `has_canonical_iso_date_shape` rejects any
///    string that is not exactly 10 ASCII chars in `YYYY-MM-DD` form,
///    short-circuiting the path-traversal payloads that CodeQL flagged.
/// 2. **Calendar validation**: `chrono::NaiveDate::parse_from_str`
///    rejects shape-passing-but-impossible dates (`2026-13-01`,
///    `2026-02-30`).
/// 3. **Taint break**: the filename is **reconstructed** from the typed
///    `(year, month, day)` primitives, NOT from the original `&str`.
///    CodeQL's path-traversal taint analysis follows string flow; passing
///    `date` through `parse → reformat` produces a fresh string whose
///    contents are provably ASCII digits + dashes in fixed positions,
///    breaking the taint chain at the function boundary.
///
/// Returns the safe filename (e.g. `"graph-snapshot-2026-04-23.json"`)
/// or `None` if the input fails any of the three checks.
pub(crate) fn safe_snapshot_filename(date: &str) -> Option<String> {
    use chrono::Datelike;
    if !has_canonical_iso_date_shape(date) {
        return None;
    }
    let parsed = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    Some(format!(
        "graph-snapshot-{:04}-{:02}-{:02}.json",
        parsed.year(),
        parsed.month(),
        parsed.day(),
    ))
}

/// Like `safe_snapshot_filename` but returns the raw `YYYY-MM-DD` form,
/// used by `load_dated_from_store` where the date is bound as a SQL
/// parameter (no path component). The taint break is the same: parse +
/// reformat from typed primitives, never the original string.
pub(crate) fn safe_date_string(date: &str) -> Option<String> {
    use chrono::Datelike;
    if !has_canonical_iso_date_shape(date) {
        return None;
    }
    let parsed = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}",
        parsed.year(),
        parsed.month(),
        parsed.day(),
    ))
}

fn safe_snapshot_file_name(name: &str) -> Option<String> {
    let (base, backup_suffix) = match name.rsplit_once(".json.") {
        Some((base, suffix)) if matches!(suffix, "1" | "2" | "3") => {
            (format!("{base}.json"), Some(suffix))
        }
        _ => (name.to_string(), None),
    };

    let safe_base = if base == "graph-snapshot.json" {
        "graph-snapshot.json".to_string()
    } else {
        match base
            .strip_prefix("graph-snapshot-")
            .and_then(|value| value.strip_suffix(".json"))
        {
            Some(date) => safe_snapshot_filename(date)?,
            None => safe_simple_snapshot_file_name(&base)?,
        }
    };

    Some(match backup_suffix {
        Some(suffix) => format!("{safe_base}.{suffix}"),
        None => safe_base,
    })
}

fn safe_simple_snapshot_file_name(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".json")?;
    if stem.is_empty() || stem.starts_with('.') || name.contains("..") {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    Some(name.to_string())
}

fn read_snapshot_bytes(path: &Path) -> Option<Vec<u8>> {
    let safe_name = safe_snapshot_file_name(path.file_name()?.to_str()?)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = parent.canonicalize().ok()?;
    let target = base.join(safe_name);
    let canonical = target.canonicalize().ok()?;
    if !canonical.starts_with(&base) {
        return None;
    }
    std::fs::read(canonical).ok()
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

/// Serialised + gzipped snapshot ready for I/O. Returned by
/// `KnowledgeGraph::serialize_snapshot_bytes` so the caller can drop
/// the read lock before doing any disk or SQLite work — see slow_loop
/// for the rationale.
pub struct SerializedSnapshot {
    pub bytes: Vec<u8>,
    pub uncompressed_size: usize,
    pub nodes_count: usize,
    pub edges_count: usize,
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
    /// Serialize + gzip the graph snapshot into a `Vec<u8>` ready for
    /// `std::fs::write` or `Store::save_graph_snapshot`. Holds **no
    /// locks** — the caller is expected to be inside a `read()` guard
    /// when invoking this; it returns owned bytes so the lock can drop
    /// before any I/O happens.
    ///
    /// Pre-2026-04-23 the slow_loop held a `write()` guard for the
    /// whole save (cleanup → compact → enforce → fs::write → sqlite
    /// bind), blocking every dashboard request for hundreds of ms each
    /// 60s tick. Splitting "make bytes" from "write bytes" lets the
    /// caller release the lock before any disk/SQLite work.
    pub fn serialize_snapshot_bytes(&self) -> anyhow::Result<SerializedSnapshot> {
        let snapshot = GraphSnapshotRef::from_graph(self);
        let json = serde_json::to_vec(&snapshot)?;
        let data = gzip_snapshot_bytes(&json);
        Ok(SerializedSnapshot {
            bytes: data,
            uncompressed_size: json.len(),
            nodes_count: self.nodes.len(),
            edges_count: self.edges.len(),
        })
    }

    /// Save the graph to a JSON file with rotation (T029: keep last 3 snapshots).
    ///
    /// Bytes are gzip-compressed before write (typical JSON payload shrinks
    /// 6-10× — 47 MB → ~5 MB on the prod baseline at 14k nodes / 145k edges).
    /// Reader detects the format via the gzip magic header so legacy
    /// uncompressed snapshots still load.
    ///
    /// Convenience wrapper around `serialize_snapshot_bytes` for callers
    /// that don't need to release the read lock between serialize and
    /// write (test code, one-shot CLI). Hot-path callers should serialize
    /// under a read lock and write outside it — see slow_loop.
    pub fn save_snapshot(&self, path: &Path) -> anyhow::Result<()> {
        let snap = self.serialize_snapshot_bytes()?;
        Self::write_snapshot_bytes(path, &snap)
    }

    /// Write pre-serialized snapshot bytes to disk with rotation.
    /// Holds no graph lock — pair with `serialize_snapshot_bytes` from
    /// inside a read guard, then call this after the guard drops.
    pub fn write_snapshot_bytes(path: &Path, snap: &SerializedSnapshot) -> anyhow::Result<()> {
        rotate_snapshots(path, 3);
        std::fs::write(path, &snap.bytes)?;
        tracing::info!(
            nodes = snap.nodes_count,
            edges = snap.edges_count,
            bytes_on_disk = snap.bytes.len(),
            bytes_uncompressed = snap.uncompressed_size,
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
    /// Convenience wrapper retained for one-shot callers (CLI, tests). The
    /// agent slow_loop uses `serialize_snapshot_bytes` + `write_snapshot_bytes`
    /// directly so it can drop the read lock before the disk write.
    #[allow(dead_code)]
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
    /// Returns None if the snapshot doesn't exist, is corrupt, or the
    /// date string fails strict `YYYY-MM-DD` parsing. The filename is
    /// reconstructed from typed `(year, month, day)` primitives via
    /// `safe_snapshot_filename`, breaking the path-traversal taint chain
    /// for `?date=../../etc/passwd`-style HTTP query payloads.
    pub fn load_dated(data_dir: &Path, date: &str) -> Option<Self> {
        let safe_name = safe_snapshot_filename(date)?;
        let path = data_dir.join(safe_name);
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
                    // Spec 037 I-13 PR-7 (K-class): best-effort cleanup.
                    // The dated snapshot may have been removed by a
                    // prior run, by an external operator, or via the
                    // rotation chain. Failure modes: NotFound (common
                    // — pre-existing absence) or PermissionDenied
                    // (rare). Either way the file lingers harmlessly
                    // and the next cleanup run retries; the surrounding
                    // `info!` below logs success on the dated row.
                    let _ = std::fs::remove_file(entry.path());
                    // Same K-class rationale: rotation backups
                    // `.json.{1,2,3}` are absent on most days
                    // (rotation only fills slots when snapshots are
                    // saved repeatedly within a day). NotFound is the
                    // expected steady-state outcome for the majority
                    // of these calls — converting to debug! would
                    // spam every cleanup tick without diagnostic
                    // value.
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
        let raw = read_snapshot_bytes(path)?;

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
    ///
    /// Convenience wrapper around `serialize_snapshot_bytes`. Hot-path
    /// callers (slow_loop) should serialize under read lock and call
    /// `Self::store_snapshot_bytes` after the lock drops.
    #[allow(dead_code)]
    pub fn save_to_store(&self, store: &innerwarden_store::Store) -> anyhow::Result<()> {
        let snap = self.serialize_snapshot_bytes()?;
        Self::store_snapshot_bytes(store, &snap)
    }

    /// Push pre-serialized snapshot bytes to the SQLite store. Holds no
    /// graph lock — pair with `serialize_snapshot_bytes`.
    pub fn store_snapshot_bytes(
        store: &innerwarden_store::Store,
        snap: &SerializedSnapshot,
    ) -> anyhow::Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        store.save_graph_snapshot(&today, &snap.bytes, snap.nodes_count, snap.edges_count)?;
        tracing::info!(
            nodes = snap.nodes_count,
            edges = snap.edges_count,
            bytes_in_blob = snap.bytes.len(),
            bytes_uncompressed = snap.uncompressed_size,
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
    /// Date is parsed via `safe_date_string` — the SQL path is parameter-bound
    /// so SQL injection is not the risk; the parse-and-reformat just keeps
    /// the API surface uniform with `load_dated` and means the SQL parameter
    /// is always the canonical reformatted form, not whatever the user
    /// originally typed.
    pub fn load_dated_from_store(store: &innerwarden_store::Store, date: &str) -> Option<Self> {
        let safe_date = safe_date_string(date)?;
        let raw = store.load_graph_snapshot(&safe_date).ok()??;
        let data = maybe_decompress(&raw)?;
        let snapshot: GraphSnapshot = serde_json::from_slice(&data).ok()?;
        let graph = Self::reconstruct_from_snapshot(snapshot)?;
        tracing::debug!(date = %date, "Graph loaded from SQLite store for date");
        Some(graph)
    }

    /// SQLite-first loader with JSON fallback. Opens a short-lived `Store`
    /// against `data_dir/innerwarden.db`, tries the SQLite blob first, falls
    /// back to the dated JSON snapshot on miss. Callers that already hold a
    /// live store should call `load_dated_from_store` directly.
    ///
    /// Priority matches the rule "if both sinks hold a snapshot for `date`,
    /// SQLite wins and the JSON file is never consulted" — the fallback
    /// cannot mask drift between the two.
    ///
    /// Each call increments exactly one counter in [`load_dated_metrics_snapshot`]:
    ///   - `sqlite` — SQLite hit (silent, no log).
    ///   - `json` — SQLite miss (for any reason), JSON hit. INFO log so
    ///     operators can see whether the dual-write is still load-bearing.
    ///   - `miss` — neither sink has the snapshot (normal when the date
    ///     falls outside the 7-day retention window).
    ///   - `error` — `Store::open` failed AND JSON also missed. The agent
    ///     cannot read either sink for this date — WARN so it surfaces.
    pub fn load_dated_sqlite_first(data_dir: &Path, date: &str) -> Option<Self> {
        let (store_opened, store_err) = match innerwarden_store::Store::open(data_dir) {
            Ok(store) => {
                if let Some(g) = Self::load_dated_from_store(&store, date) {
                    KG_DATED_LOAD_SQLITE.fetch_add(1, Ordering::Relaxed);
                    return Some(g);
                }
                (true, None)
            }
            Err(e) => (false, Some(format!("{e}"))),
        };

        match Self::load_dated(data_dir, date) {
            Some(g) => {
                KG_DATED_LOAD_JSON.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    date = %date,
                    store_opened,
                    "load_dated_sqlite_first: SQLite miss, served from JSON fallback"
                );
                Some(g)
            }
            None => {
                if let Some(err) = store_err {
                    KG_DATED_LOAD_ERROR.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        date = %date,
                        error = %err,
                        "load_dated_sqlite_first: Store::open failed and JSON missing"
                    );
                } else {
                    KG_DATED_LOAD_MISS.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        date = %date,
                        "load_dated_sqlite_first: neither sink had a snapshot for this date"
                    );
                }
                None
            }
        }
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
    fn reconstruct_from_snapshot(mut snapshot: GraphSnapshot) -> Option<Self> {
        let mut graph = Self::new();
        graph.next_id = snapshot.next_id;

        // Restore nodes and rebuild indexes
        for (&id, node) in &snapshot.nodes {
            graph.index_node(id, node);
            graph.memory_estimate += Self::estimate_node_size(node);
        }
        graph.nodes = snapshot.nodes;

        // Re-intern property keys: serde produces a fresh `Arc<str>`
        // per deserialized key, defeating the interner that
        // `add_edge` relies on at insert time. Walk every edge once
        // and swap each key for the canonical `Arc<str>` so the in-
        // memory graph immediately benefits from deduplication.
        for edge in snapshot.edges.iter_mut() {
            if edge.properties.is_empty() {
                continue;
            }
            let old = std::mem::take(&mut edge.properties);
            edge.properties = old
                .into_iter()
                .map(|(k, v)| (super::intern::intern(&k), v))
                .collect();
        }

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

/// Atomically rename a snapshot file inside the rotation chain,
/// surfacing real failures via `warn!` while staying silent on the
/// expected case where the source does not yet exist (Spec 037 I-13
/// PR-5).
///
/// Why the existence pre-check: `rotate_snapshots` walks the rotation
/// chain unconditionally on every call. A fresh agent has only the
/// current `graph-snapshot.json` on disk — the `.json.{1,2,3}`
/// backups do not exist yet. Naively warning on every rename failure
/// would emit ~3 spurious warns per rotation until the chain fills,
/// which would itself become noise that drowns out genuine failures
/// (permission denied, cross-device rename, FS corruption).
///
/// The pre-check filters `ErrorKind::NotFound` cleanly: if `from`
/// does not exist, the rename is a no-op and stays silent. The warn
/// arm only fires when `from` exists but the rename still fails —
/// which is unambiguously a real failure that breaks the rotation
/// chain invariant and the operator should see.
///
/// Failure mode: the rename did not happen. The chain is left in
/// whatever state the partial rotation produced — the caller does
/// not retry (matches the prior `let _ =` behaviour exactly).
fn rename_snapshot_or_warn(from: &Path, to: &Path) {
    if !from.exists() {
        return;
    }
    if let Err(e) = std::fs::rename(from, to) {
        warn!(
            from = %from.display(),
            to = %to.display(),
            error = %e,
            "snapshot rotation rename failed (rotation chain may be inconsistent)"
        );
    }
}

/// T029: Rotate snapshot files — keep last `max_backups` copies.
/// graph-snapshot.json → .json.1 → .json.2 → .json.3 (oldest deleted)
fn rotate_snapshots(path: &Path, max_backups: u32) {
    // Delete oldest backup. Spec 037 I-13 PR-7 (K-class):
    // best-effort cleanup. On a fresh chain (rotation slot
    // `.json.{max_backups}` not yet populated), `remove_file`
    // returns NotFound — that is the expected case until the
    // rotation has cycled `max_backups` times. PermissionDenied
    // would also be silent here, but `rotate_snapshots` is now
    // off the hot path post spec 037 PR-3 (called only by
    // operator-triggered CLI migrations) so any real failure is
    // visible in the migration command output one way or another.
    let oldest = path.with_extension(format!("json.{max_backups}"));
    let _ = std::fs::remove_file(&oldest);

    // Shift backups: .2 → .3, .1 → .2
    for i in (1..max_backups).rev() {
        let from = path.with_extension(format!("json.{i}"));
        let to = path.with_extension(format!("json.{}", i + 1));
        rename_snapshot_or_warn(&from, &to);
    }

    // Current → .1
    let backup = path.with_extension("json.1");
    rename_snapshot_or_warn(path, &backup);
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

    /// 2026-05-03 (Wave 5b PR-4 anchor): pre-save compaction must
    /// remove tombstoned edges so reload does NOT see them as
    /// dangling. Pinned the operator-visible WARN
    /// "Knowledge graph has dangling edge references — pruning
    /// dangling=30157" that fired every save cycle in prod for days.
    /// The bug class: `enforce_memory_limit` removes nodes (which
    /// tombstones edges) AFTER the gated `compact_edges` runs. Without
    /// `compact_edges_force` between the two, tombstones from
    /// `enforce_memory_limit` leaked into the persisted blob.
    #[test]
    fn snapshot_after_node_eviction_carries_no_dangling_edges() {
        use crate::knowledge_graph::types::Relation;

        let mut g = KnowledgeGraph::new();
        // Build a small graph: 5 IPs each connected to a Process.
        let proc_id = g.ensure_process(1234, 800, "bash", 0, Utc::now());
        let mut ip_ids = Vec::new();
        for n in 1..=5 {
            let ip = g.ensure_ip(&format!("10.0.0.{n}"), Utc::now());
            g.add_edge(Edge::new(proc_id, ip, Relation::ConnectedTo, Utc::now()));
            ip_ids.push(ip);
        }
        let edges_before = g.edge_count();
        assert_eq!(edges_before, 5);

        // Simulate `enforce_memory_limit` removing 3 nodes: tombstones
        // 3 edges but does NOT remove them from `self.edges`.
        for &id in &ip_ids[..3] {
            g.remove_node(id);
        }
        // Pre-fix path: gated `compact_edges` would NOT run because
        // tombstone ratio is 3/5 = 60% which DOES exceed 20%, but the
        // operator's prod showed the inverse (large graph + small
        // batch eviction = sub-20% ratio). Force the case here by
        // construction: the unconditional path must always sweep.
        // Force-compact mirrors the pre-serialise call.
        g.compact_edges_force();

        // Round-trip via the file path (covers `try_load_snapshot`
        // → `reconstruct_from_snapshot` → dangling check).
        let dir = tempdir().unwrap();
        let path = dir.path().join("post-eviction.json");
        g.save_snapshot(&path).unwrap();
        let reloaded = KnowledgeGraph::load_snapshot(&path);

        // Every reloaded edge must have both endpoints in the node
        // map — no dangling references survived the round-trip.
        // `KnowledgeGraph` does not expose `edges()` directly (only
        // `nodes()` and per-node `all_edges(NodeId)`), so we walk
        // through every node and check its outgoing edges.
        let nodes_map = reloaded.nodes();
        for &id in nodes_map.keys() {
            for edge in reloaded.all_edges(id) {
                assert!(
                    nodes_map.contains_key(&edge.from) && nodes_map.contains_key(&edge.to),
                    "dangling edge in reloaded snapshot: {:?} → {:?}",
                    edge.from,
                    edge.to
                );
            }
        }
        // And the count is right: 2 live edges (the IPs we kept).
        assert_eq!(reloaded.edge_count(), 2);
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

    // ── path-traversal guard tests ───────────────────────────────────
    //
    // CodeQL flagged `try_load_snapshot` as a path-traversal sink because
    // `load_dated`'s `date: &str` flows from the `/api/report?date=...`
    // HTTP query into a `data_dir.join(...)` call. The fix:
    // `safe_snapshot_filename` parses the input to typed primitives and
    // reconstructs the filename from those, breaking the taint chain.
    // These tests pin both the accept/reject set AND the round-trip
    // shape of the reconstructed filename.

    #[test]
    fn safe_snapshot_filename_returns_canonical_form_for_valid_dates() {
        assert_eq!(
            safe_snapshot_filename("2026-04-23").as_deref(),
            Some("graph-snapshot-2026-04-23.json")
        );
        assert_eq!(
            safe_snapshot_filename("0001-01-01").as_deref(),
            Some("graph-snapshot-0001-01-01.json")
        );
        assert_eq!(
            safe_snapshot_filename("9999-12-31").as_deref(),
            Some("graph-snapshot-9999-12-31.json")
        );
    }

    #[test]
    fn safe_snapshot_filename_rejects_path_traversal_payloads() {
        // The exact attack payload from the CodeQL alert.
        assert_eq!(safe_snapshot_filename("../../etc/passwd"), None);
        // Variants that could slip past a naive contains-check.
        assert_eq!(safe_snapshot_filename(".."), None);
        assert_eq!(safe_snapshot_filename("/etc"), None);
        assert_eq!(safe_snapshot_filename("2026-04-23/.."), None);
        assert_eq!(safe_snapshot_filename("2026-04-23\0evil"), None);
        assert_eq!(safe_snapshot_filename("2026-04-23\n"), None);
        assert_eq!(safe_snapshot_filename("2026/04/23"), None);
        assert_eq!(safe_snapshot_filename(""), None);
        // Length 10 but non-digit content
        assert_eq!(safe_snapshot_filename("aaaa-bb-cc"), None);
        // Off-by-one length
        assert_eq!(safe_snapshot_filename("2026-4-23"), None);
        assert_eq!(safe_snapshot_filename("2026-04-2"), None);
        assert_eq!(safe_snapshot_filename("2026-04-233"), None);
        // Out-of-range months/days that pass shape but fail calendar
        assert_eq!(safe_snapshot_filename("2026-13-01"), None);
        assert_eq!(safe_snapshot_filename("2026-02-30"), None);
        assert_eq!(safe_snapshot_filename("2026-00-15"), None);
    }

    #[test]
    fn safe_snapshot_filename_output_has_no_path_separators() {
        // The whole point of the parse-and-reconstruct dance is that
        // the output cannot contain a path separator. Belt-and-braces:
        // assert it directly on a permissive set of inputs.
        for date in ["2026-04-23", "0001-01-01", "9999-12-31"] {
            let f = safe_snapshot_filename(date).unwrap();
            assert!(!f.contains('/'), "filename must not contain '/': {f:?}");
            assert!(!f.contains('\\'), "filename must not contain '\\\\': {f:?}");
            assert!(
                !f.contains(".."),
                "filename must not contain parent-traversal: {f:?}"
            );
        }
    }

    #[test]
    fn safe_date_string_round_trips_canonical_form() {
        assert_eq!(
            safe_date_string("2026-04-23").as_deref(),
            Some("2026-04-23")
        );
        assert_eq!(safe_date_string("../etc"), None);
        assert_eq!(safe_date_string(""), None);
    }

    #[test]
    fn load_dated_returns_none_for_path_traversal_payload() {
        let dir = tempdir().unwrap();
        // Plant a file outside `data_dir` that the attacker would target.
        let outside = dir.path().join("..").join("evil.json");
        let _ = std::fs::write(&outside, br#"{"nodes":{},"edges":[]}"#);

        // The attacker payload — even if `outside` exists, `load_dated`
        // must return None because the date string fails parsing.
        assert!(KnowledgeGraph::load_dated(dir.path(), "../evil").is_none());
        assert!(KnowledgeGraph::load_dated(dir.path(), "../../etc/passwd").is_none());
    }

    #[test]
    fn load_dated_from_store_returns_none_for_path_traversal_payload() {
        // SQL path is already parameter-bound. Parsing keeps the API
        // uniform and means the parameter is always the canonical form.
        let store = innerwarden_store::Store::open_memory().unwrap();
        assert!(KnowledgeGraph::load_dated_from_store(&store, "../etc/passwd").is_none());
        assert!(KnowledgeGraph::load_dated_from_store(&store, "").is_none());
    }

    // ── spec 037 slice 5 PR-1: JSON ↔ SQLite equivalence anchors ─────
    //
    // Before migrating any consumer of `load_dated` to the SQLite-first
    // pattern, we need evidence that `load_dated_from_store` and
    // `load_dated` produce structurally equivalent graphs for the same
    // date. These anchors pin that equivalence so later PRs can migrate
    // readers without risk of a silent shape mismatch.

    fn seed_graph_with_mixed_nodes() -> KnowledgeGraph {
        let mut g = KnowledgeGraph::new();
        let now = Utc::now();
        // Distinct node types so equivalence checks exercise multiple
        // indexes (ip_index, pid_index, file_index, ...).
        for i in 0..5 {
            g.ensure_ip(&format!("203.0.113.{i}"), now);
        }
        let p1 = g.ensure_process(8801, 1, "nginx", 0, now);
        let p2 = g.ensure_process(8802, 8801, "redis", 0, now);
        let ip = g.ensure_ip("198.51.100.42", now);
        // Two edges so adjacency reconstruction must run on load.
        g.add_edge(Edge::new(p1, ip, Relation::ConnectedTo, now));
        g.add_edge(Edge::new(p2, p1, Relation::SpawnedBy, now));
        g
    }

    /// Returns a snapshot summary usable for structural equivalence
    /// assertions across the two load paths. Stable field set, no
    /// dependency on serde `Value` field ordering.
    fn graph_summary(g: &KnowledgeGraph) -> (usize, usize, bool, bool, bool, bool) {
        (
            g.node_count(),
            g.edge_count(),
            g.find_by_ip("198.51.100.42").is_some(),
            g.find_by_ip("203.0.113.3").is_some(),
            g.find_by_pid(8801).is_some(),
            g.find_by_pid(8802).is_some(),
        )
    }

    #[test]
    fn load_dated_from_store_matches_load_dated_when_both_present() {
        // Arrange: serialize one graph and write identical bytes to both
        // sinks for the same date. This eliminates "different input"
        // as an explanation for any divergence the assertion might
        // surface — any mismatch would be a real load-path bug.
        let dir = tempdir().unwrap();
        let store = innerwarden_store::Store::open_memory().unwrap();
        let date = "2026-04-20";

        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().expect("serialize");

        // JSON sink: write at the canonical dated filename.
        let safe_name = safe_snapshot_filename(date).expect("safe name");
        let json_path = dir.path().join(safe_name);
        KnowledgeGraph::write_snapshot_bytes(&json_path, &snap).expect("write file");

        // SQLite sink: same bytes, same date.
        store
            .save_graph_snapshot(date, &snap.bytes, snap.nodes_count, snap.edges_count)
            .expect("save to store");

        let from_json = KnowledgeGraph::load_dated(dir.path(), date).expect("json loads");
        let from_sqlite =
            KnowledgeGraph::load_dated_from_store(&store, date).expect("sqlite loads");

        assert_eq!(
            graph_summary(&from_json),
            graph_summary(&from_sqlite),
            "load_dated and load_dated_from_store must produce structurally equivalent graphs"
        );
        assert_eq!(from_json.node_count(), g.node_count());
        assert_eq!(from_json.edge_count(), g.edge_count());
    }

    #[test]
    fn load_dated_from_store_returns_none_when_date_missing() {
        // Fresh store + valid-shape date that was never persisted.
        let store = innerwarden_store::Store::open_memory().unwrap();
        assert!(
            KnowledgeGraph::load_dated_from_store(&store, "2026-04-20").is_none(),
            "valid-shape date with no row must return None (not a panic)"
        );
    }

    #[test]
    fn load_dated_from_store_handles_gzip_and_raw_json() {
        // Wire-format compatibility: the reader uses a magic-byte sniff
        // in `maybe_decompress`, so historical raw-JSON blobs (pre-gzip
        // deploy, 2026-04-23) still load. The SQLite load path goes
        // through the same helper — assert both paths here so a future
        // refactor cannot silently drop one of them.
        let store = innerwarden_store::Store::open_memory().unwrap();

        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().expect("serialize");
        assert!(
            snap.bytes.len() >= 2 && snap.bytes[0] == 0x1f && snap.bytes[1] == 0x8b,
            "serialize_snapshot_bytes must emit gzip today — test premise"
        );

        // Gzip date: write the gzip bytes as-is.
        store
            .save_graph_snapshot(
                "2026-04-21",
                &snap.bytes,
                snap.nodes_count,
                snap.edges_count,
            )
            .expect("save gzip");

        // Raw-JSON date: re-encode the same snapshot without gzip
        // wrapping, mimicking a pre-2026-04-23 blob sitting in the
        // store after an upgrade.
        let raw_bytes =
            serde_json::to_vec(&GraphSnapshotRef::from_graph(&g)).expect("raw serialize");
        assert_eq!(raw_bytes[0], b'{', "fixture must look like raw JSON");
        store
            .save_graph_snapshot("2026-04-22", &raw_bytes, snap.nodes_count, snap.edges_count)
            .expect("save raw");

        let from_gzip =
            KnowledgeGraph::load_dated_from_store(&store, "2026-04-21").expect("gzip blob loads");
        let from_raw =
            KnowledgeGraph::load_dated_from_store(&store, "2026-04-22").expect("raw blob loads");

        // Both must decode to the same graph — same source, different wire wrap.
        assert_eq!(graph_summary(&from_gzip), graph_summary(&from_raw));
        assert_eq!(from_gzip.node_count(), g.node_count());
    }

    /// Cross-check helper returned as a test-module utility. Mirrors the
    /// shape of the compliance cross-check added in slice 4 PR-2: pure
    /// diagnostic, no hard failure. Useful as a building block if we
    /// later expose a compliance-tab field for KG drift; here it is
    /// only wired to the equivalence anchor below so we have a single
    /// call site that exercises it.
    #[derive(Debug, PartialEq, Eq)]
    struct DatedSnapshotCrossCheck {
        json_present: bool,
        sqlite_present: bool,
        json_summary: Option<(usize, usize, bool, bool, bool, bool)>,
        sqlite_summary: Option<(usize, usize, bool, bool, bool, bool)>,
    }

    impl DatedSnapshotCrossCheck {
        fn run(data_dir: &std::path::Path, store: &innerwarden_store::Store, date: &str) -> Self {
            let json = KnowledgeGraph::load_dated(data_dir, date);
            let sqlite = KnowledgeGraph::load_dated_from_store(store, date);
            Self {
                json_present: json.is_some(),
                sqlite_present: sqlite.is_some(),
                json_summary: json.as_ref().map(graph_summary),
                sqlite_summary: sqlite.as_ref().map(graph_summary),
            }
        }

        fn agrees(&self) -> bool {
            self.json_present == self.sqlite_present && self.json_summary == self.sqlite_summary
        }
    }

    #[test]
    fn cross_check_reports_agreement_when_both_sinks_hold_same_date() {
        let dir = tempdir().unwrap();
        let store = innerwarden_store::Store::open_memory().unwrap();
        let date = "2026-04-20";

        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().unwrap();
        let safe_name = safe_snapshot_filename(date).unwrap();
        KnowledgeGraph::write_snapshot_bytes(&dir.path().join(safe_name), &snap).unwrap();
        store
            .save_graph_snapshot(date, &snap.bytes, snap.nodes_count, snap.edges_count)
            .unwrap();

        let check = DatedSnapshotCrossCheck::run(dir.path(), &store, date);
        assert!(check.json_present);
        assert!(check.sqlite_present);
        assert!(
            check.agrees(),
            "both sinks hold the same bytes for the same date; cross-check must agree: {check:?}"
        );
    }

    // ── spec 037 slice 5 PR-2: load_dated_sqlite_first anchors ──────
    //
    // The helper is the idiom the 6 migrated callsites now use
    // (neural_lifecycle × 3, report.rs × 2, threat_report.rs × 1).
    // Four invariants matter:
    //   1. SQLite populated, JSON missing → loads from SQLite.
    //   2. JSON populated, SQLite empty → loads from JSON fallback.
    //   3. Both present and identical → loads something; either
    //      source is fine because they agree (PR-1 equivalence anchor
    //      already proves structural equality for the same bytes).
    //   4. Divergence: SQLite wins, JSON fallback does NOT run. This
    //      is the load-bearing property — consumers that migrated
    //      must see the canonical source, not stale JSON.

    #[test]
    fn load_dated_sqlite_first_reads_sqlite_when_json_missing() {
        let dir = tempdir().unwrap();
        let store = innerwarden_store::Store::open(dir.path()).expect("store");
        let date = "2026-04-20";

        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().expect("serialize");
        store
            .save_graph_snapshot(date, &snap.bytes, snap.nodes_count, snap.edges_count)
            .expect("save to store");
        // No JSON file written.

        let loaded = KnowledgeGraph::load_dated_sqlite_first(dir.path(), date)
            .expect("sqlite-only must load");
        assert_eq!(graph_summary(&loaded), graph_summary(&g));
    }

    #[test]
    fn load_dated_sqlite_first_falls_back_to_json_when_sqlite_missing() {
        let dir = tempdir().unwrap();
        // Open+close a store so the innerwarden.db file exists but has no row.
        {
            let _ = innerwarden_store::Store::open(dir.path()).expect("store open");
        }
        let date = "2026-04-20";

        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().expect("serialize");
        let safe_name = safe_snapshot_filename(date).unwrap();
        KnowledgeGraph::write_snapshot_bytes(&dir.path().join(safe_name), &snap)
            .expect("write json");
        // No SQLite row for this date.

        let loaded = KnowledgeGraph::load_dated_sqlite_first(dir.path(), date)
            .expect("json fallback must load");
        assert_eq!(graph_summary(&loaded), graph_summary(&g));
    }

    #[test]
    fn load_dated_sqlite_first_prefers_sqlite_when_both_present_and_diverge() {
        // Plant deliberately different graphs in the two sinks. The
        // helper must return the SQLite graph — if the JSON fallback
        // ever runs when SQLite had an answer, migrated consumers
        // would silently read the wrong source.
        let dir = tempdir().unwrap();
        let store = innerwarden_store::Store::open(dir.path()).expect("store");
        let date = "2026-04-20";

        let mut sqlite_graph = KnowledgeGraph::new();
        sqlite_graph.ensure_ip("203.0.113.77", Utc::now()); // unique to SQLite

        let mut json_graph = KnowledgeGraph::new();
        json_graph.ensure_ip("198.51.100.88", Utc::now()); // unique to JSON

        let sq_snap = sqlite_graph.serialize_snapshot_bytes().unwrap();
        store
            .save_graph_snapshot(
                date,
                &sq_snap.bytes,
                sq_snap.nodes_count,
                sq_snap.edges_count,
            )
            .expect("save sqlite");

        let json_snap = json_graph.serialize_snapshot_bytes().unwrap();
        let safe_name = safe_snapshot_filename(date).unwrap();
        KnowledgeGraph::write_snapshot_bytes(&dir.path().join(safe_name), &json_snap)
            .expect("write json");

        let loaded = KnowledgeGraph::load_dated_sqlite_first(dir.path(), date)
            .expect("one of the two must load");
        assert!(
            loaded.find_by_ip("203.0.113.77").is_some(),
            "SQLite IP must be present — SQLite wins"
        );
        assert!(
            loaded.find_by_ip("198.51.100.88").is_none(),
            "JSON IP must NOT be present — fallback was masked by SQLite hit"
        );
    }

    #[test]
    fn load_dated_sqlite_first_returns_none_when_neither_sink_has_date() {
        let dir = tempdir().unwrap();
        let _store = innerwarden_store::Store::open(dir.path()).expect("store");
        // Empty store, no JSON file.

        assert!(
            KnowledgeGraph::load_dated_sqlite_first(dir.path(), "2026-04-20").is_none(),
            "no data in either sink must return None, not panic"
        );
    }

    // ── spec 037 slice 5 PR-2.5: load_dated metrics anchors ─────────
    //
    // Verifies each invocation of `load_dated_sqlite_first` bumps
    // exactly one of the four `innerwarden_kg_dated_load_total` counters
    // (sqlite / json / miss / error). Tests use a module-local mutex
    // so parallel test execution cannot race on the process-global
    // static counters. Each test captures deltas, not absolute values,
    // so the order tests run in does not matter.

    static METRICS_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Copy, Clone)]
    struct MetricsSnap {
        sqlite: u64,
        json: u64,
        miss: u64,
        error: u64,
    }

    fn snap_metrics() -> MetricsSnap {
        let s = load_dated_metrics_snapshot();
        MetricsSnap {
            sqlite: s[0].1,
            json: s[1].1,
            miss: s[2].1,
            error: s[3].1,
        }
    }

    #[allow(dead_code)] // retained for future tighter assertions if tests get serialized
    fn delta(before: MetricsSnap, after: MetricsSnap) -> (u64, u64, u64, u64) {
        (
            after.sqlite - before.sqlite,
            after.json - before.json,
            after.miss - before.miss,
            after.error - before.error,
        )
    }

    #[test]
    fn load_dated_metric_sqlite_increments_on_sqlite_hit() {
        let _guard = METRICS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let before = snap_metrics();

        let dir = tempdir().unwrap();
        let store = innerwarden_store::Store::open(dir.path()).expect("store");
        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().unwrap();
        store
            .save_graph_snapshot(
                "2026-04-20",
                &snap.bytes,
                snap.nodes_count,
                snap.edges_count,
            )
            .unwrap();

        assert!(KnowledgeGraph::load_dated_sqlite_first(dir.path(), "2026-04-20").is_some());

        let after = snap_metrics();
        // Assertions are `>` rather than `==` because other tests across
        // the workspace (neural_lifecycle, report, threat_report) call
        // `load_dated_sqlite_first` in parallel and bump the same
        // process-global counters. Mutual exclusivity of the 4 labels
        // is proven by the structure of `load_dated_sqlite_first` itself
        // (one `match` arm bumps exactly one counter per call); the test
        // proves attribution (the expected label fired for this path).
        assert!(
            after.sqlite > before.sqlite,
            "SQLite hit path must bump the sqlite counter (before={before:?} after={after:?})",
            before = before.sqlite,
            after = after.sqlite,
        );
    }

    #[test]
    fn load_dated_metric_json_increments_on_fallback() {
        let _guard = METRICS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let before = snap_metrics();

        let dir = tempdir().unwrap();
        let _store = innerwarden_store::Store::open(dir.path()).expect("store");
        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().unwrap();
        let safe_name = safe_snapshot_filename("2026-04-20").unwrap();
        KnowledgeGraph::write_snapshot_bytes(&dir.path().join(safe_name), &snap).unwrap();
        // No SQLite row.

        assert!(KnowledgeGraph::load_dated_sqlite_first(dir.path(), "2026-04-20").is_some());

        let after = snap_metrics();
        assert!(
            after.json > before.json,
            "JSON fallback path must bump the json counter (before={} after={})",
            before.json,
            after.json,
        );
    }

    #[test]
    fn load_dated_metric_miss_increments_when_neither_sink_has_date() {
        let _guard = METRICS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let before = snap_metrics();

        let dir = tempdir().unwrap();
        let _store = innerwarden_store::Store::open(dir.path()).expect("store");
        // Empty store, no JSON file.

        assert!(KnowledgeGraph::load_dated_sqlite_first(dir.path(), "2026-04-20").is_none());

        let after = snap_metrics();
        assert!(
            after.miss > before.miss,
            "neither-sink path must bump the miss counter (before={} after={})",
            before.miss,
            after.miss,
        );
    }

    #[test]
    fn load_dated_metric_error_increments_when_store_open_fails_and_json_missing() {
        // `Store::open` against a path that cannot host a SQLite DB file
        // (a regular file instead of a directory) fails with I/O error.
        // JSON lookup then also fails (no directory to read from).
        // The helper must bump `error`, not `miss` — they are distinct
        // operational signals.
        let _guard = METRICS_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let before = snap_metrics();

        let tmp_parent = tempdir().unwrap();
        let file_path = tmp_parent.path().join("not-a-directory");
        std::fs::write(&file_path, b"I am a regular file, not a directory").unwrap();

        assert!(
            KnowledgeGraph::load_dated_sqlite_first(&file_path, "2026-04-20").is_none(),
            "bad data_dir must return None"
        );

        let after = snap_metrics();
        assert!(
            after.error > before.error,
            "Store::open error path must bump the error counter (before={} after={})",
            before.error,
            after.error,
        );
    }

    #[test]
    fn load_dated_metrics_snapshot_returns_expected_labels_in_order() {
        let s = load_dated_metrics_snapshot();
        assert_eq!(s[0].0, "sqlite");
        assert_eq!(s[1].0, "json");
        assert_eq!(s[2].0, "miss");
        assert_eq!(s[3].0, "error");
    }

    #[test]
    fn cross_check_reports_disagreement_when_only_one_sink_populated() {
        // Exactly the state a data dir lands in after PR-1 ships but
        // before PR-2 migrates consumers: writer touches both sinks,
        // but a freshly-restored backup (or the very first boot after
        // the migration) could have only one side populated.
        let dir = tempdir().unwrap();
        let store = innerwarden_store::Store::open_memory().unwrap();
        let date = "2026-04-20";

        let g = seed_graph_with_mixed_nodes();
        let snap = g.serialize_snapshot_bytes().unwrap();
        let safe_name = safe_snapshot_filename(date).unwrap();
        KnowledgeGraph::write_snapshot_bytes(&dir.path().join(safe_name), &snap).unwrap();
        // SQLite intentionally untouched.

        let check = DatedSnapshotCrossCheck::run(dir.path(), &store, date);
        assert!(check.json_present);
        assert!(!check.sqlite_present);
        assert!(
            !check.agrees(),
            "only-JSON side populated MUST be flagged as disagreement"
        );
    }

    // ── lock-scope split tests ───────────────────────────────────────
    //
    // Anchors for the slow_loop refactor: serialize_snapshot_bytes runs
    // under a read lock and returns owned bytes; write_snapshot_bytes
    // and store_snapshot_bytes consume those bytes WITHOUT touching the
    // graph. The pair must round-trip identically to the legacy
    // `save_snapshot` / `save_to_store` convenience wrappers so external
    // callers (tests, CLI) keep working.

    #[test]
    fn serialize_snapshot_bytes_round_trips_via_write_snapshot_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("snap.json");

        let mut g = KnowledgeGraph::new();
        let p = g.ensure_process(101, 1, "redis", 0, Utc::now());
        let ip = g.ensure_ip("203.0.113.42", Utc::now());
        g.add_edge(Edge::new(p, ip, Relation::ConnectedTo, Utc::now()));

        let snap = g.serialize_snapshot_bytes().expect("serialize");
        assert_eq!(snap.nodes_count, g.node_count());
        assert_eq!(snap.edges_count, g.edge_count());
        assert!(snap.bytes.len() > 0);
        assert!(
            snap.uncompressed_size > snap.bytes.len(),
            "gzip should shrink"
        );
        // Magic byte sniff — proves it's compressed before write.
        assert_eq!(&snap.bytes[0..2], &[0x1f, 0x8b]);

        KnowledgeGraph::write_snapshot_bytes(&path, &snap).expect("write");

        let loaded = KnowledgeGraph::load_snapshot(&path);
        assert_eq!(loaded.node_count(), g.node_count());
        assert_eq!(loaded.edge_count(), g.edge_count());
        assert!(loaded.find_by_pid(101).is_some());
        assert!(loaded.find_by_ip("203.0.113.42").is_some());
    }

    #[test]
    fn serialize_then_store_snapshot_bytes_round_trips_through_sqlite() {
        let store = innerwarden_store::Store::open_memory().expect("memory store");

        let mut g = KnowledgeGraph::new();
        for i in 0..10 {
            g.ensure_ip(&format!("198.51.100.{i}"), Utc::now());
        }

        let snap = g.serialize_snapshot_bytes().expect("serialize");
        KnowledgeGraph::store_snapshot_bytes(&store, &snap).expect("store");

        let loaded = KnowledgeGraph::load_from_store(&store).expect("load");
        for i in 0..10 {
            assert!(loaded.find_by_ip(&format!("198.51.100.{i}")).is_some());
        }
    }

    #[test]
    fn legacy_save_snapshot_still_round_trips() {
        // Convenience wrapper kept for tests / CLI must keep working
        // with the new split-API plumbing.
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.json");

        let mut g = KnowledgeGraph::new();
        g.ensure_ip("10.0.0.1", Utc::now());

        g.save_snapshot(&path).expect("legacy save_snapshot");

        let loaded = KnowledgeGraph::load_snapshot(&path);
        assert!(loaded.find_by_ip("10.0.0.1").is_some());
    }

    // ── Spec 037 I-13 PR-5 — rotation rename warn anchors ─────────
    //
    // PR-5 of I-13 converts the two `let _ = std::fs::rename(..)`
    // sites in `rotate_snapshots` into a `warn!`-on-failure pattern
    // via the `rename_snapshot_or_warn` helper. The rotation chain
    // is the back-compat read fallback — silent rename failure breaks
    // the chain invariant so a future restore picks the wrong file.
    //
    // The helper carries a load-bearing pre-check: NotFound is the
    // *expected* common case during the first few rotations before
    // `.json.{1,2,3}` are populated. A naive warn on every rename
    // failure would emit ~3 spurious warns per rotation on a fresh
    // agent. The pre-check filters that case so the warn arm fires
    // only on genuine failures (permission denied, cross-device,
    // corrupt FS).
    //
    // Tests pin three contracts:
    //   1. Source missing → no rename, no warn (fresh-rotation case).
    //   2. Source exists + target unwritable → warn fires with
    //      from + to + error.
    //   3. Source exists + target writable → rename succeeds,
    //      no warn.

    // Capture is via `crate::test_util` (global subscriber +
    // thread-local buffer). Tests pin three contracts: silent on
    // missing source (fresh-rotation NotFound case), warn on real
    // failure, silent rename on happy path.

    #[test]
    fn rename_snapshot_or_warn_is_silent_when_source_missing() {
        let _guard = crate::test_util::arm_capture();

        // Fresh-agent case: rotation walks a chain that doesn't exist
        // yet. Each call must be a no-op AND must not emit a warn so
        // the boot-time logs stay clean.
        let dir = tempdir().expect("tempdir");
        let from = dir.path().join("graph-snapshot.json.2");
        let to = dir.path().join("graph-snapshot.json.3");
        // `from` deliberately not created — the no-existence path.

        rename_snapshot_or_warn(&from, &to);

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("snapshot rotation rename failed"),
            "missing source MUST NOT emit a warn (NotFound is the expected fresh-rotation case) — got: {captured_str}"
        );
        // Target also must not have been created.
        assert!(
            !to.exists(),
            "no-op path must not somehow create the target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rename_snapshot_or_warn_emits_warn_on_real_failure() {
        // Real failure case: `from` exists but the rename can't
        // complete. Force the failure by making the target
        // directory unwritable (chmod 0o500 = read+exec but no
        // write). The rename returns PermissionDenied, the helper
        // emits a warn carrying from + to + error, and the file
        // is left where it was.
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::test_util::arm_capture();

        let dir = tempdir().expect("tempdir");
        let target_dir = dir.path().join("locked");
        std::fs::create_dir(&target_dir).expect("create locked dir");

        let from = dir.path().join("graph-snapshot.json.1");
        std::fs::write(&from, b"placeholder").expect("seed from");

        // Move into the locked dir to force PermissionDenied. Save
        // the previous mode so we can restore it before tempdir drop
        // (otherwise cleanup itself fails with PermissionDenied).
        let original_mode = std::fs::metadata(&target_dir)
            .expect("stat target_dir")
            .permissions()
            .mode()
            & 0o7777;
        std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o500))
            .expect("chmod 500");

        let to = target_dir.join("graph-snapshot.json.2");

        rename_snapshot_or_warn(&from, &to);

        // Restore writable mode so TempDir::drop can clean up.
        std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(original_mode))
            .expect("restore mode");

        let captured_str = crate::test_util::drain_capture();

        assert!(
            captured_str.contains("snapshot rotation rename failed"),
            "warn message missing on real rename failure — got: {captured_str}"
        );
        // Both endpoints must be present so the operator can
        // identify which rotation step broke.
        assert!(
            captured_str.contains("graph-snapshot.json.1"),
            "from field missing — got: {captured_str}"
        );
        assert!(
            captured_str.contains("graph-snapshot.json.2"),
            "to field missing — got: {captured_str}"
        );
        assert!(
            captured_str.contains("error="),
            "error field missing — got: {captured_str}"
        );
        // The original file must still be where it was — the helper
        // never claims to roll back a partial state, but the rename
        // failed so `from` should still exist.
        assert!(
            from.exists(),
            "from must remain on disk after a failed rename"
        );
    }

    #[test]
    fn rename_snapshot_or_warn_performs_rename_silently_on_happy_path() {
        let _guard = crate::test_util::arm_capture();

        // Happy path: source exists, target writable. Helper must
        // perform the rename AND NOT emit a warn.
        let dir = tempdir().expect("tempdir");
        let from = dir.path().join("graph-snapshot.json.1");
        let to = dir.path().join("graph-snapshot.json.2");
        let payload = b"placeholder-bytes";
        std::fs::write(&from, payload).expect("seed from");

        rename_snapshot_or_warn(&from, &to);

        // Side effect: the rename actually moved the bytes.
        assert!(
            !from.exists(),
            "from must be gone after a successful rename"
        );
        let moved = std::fs::read(&to).expect("read target");
        assert_eq!(
            moved.as_slice(),
            payload,
            "bytes must arrive at target intact"
        );

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("snapshot rotation rename failed"),
            "successful rename must not emit the failure warn — got: {captured_str}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Spec 035 PR-A2 phase 2 — save_to_store heap-budget anchor
// ─────────────────────────────────────────────────────────────────────
//
// Standing gate for the per-call allocation cost of KG snapshot
// persistence. Historically the hottest allocator path in the slow_loop
// (see `.claude-local/SESSION_LOG.md` 2026-04-22/23 entries about
// `save_to_store` transients and gzip compression). A regression here
// tends to show up as steadily-climbing agent RSS in production; this
// anchor catches it at CI time.
//
// **What is measured**: `dhat::HeapStats::total_bytes` delta across a
// single `save_to_store` call on a fixture graph (1000 IP nodes + 1000
// Process nodes + 2000 ConnectedTo edges). This is *cumulative bytes
// allocated during the window*, not live RSS. It is allocator-agnostic
// and independent of runner hardware — the same code produces the same
// delta on any machine.
//
// **What the budget means**: a *trend* gate. The constant is baselined
// from the first green run + 10% headroom. DHAT numbers are not directly
// comparable to production jemalloc RSS; they measure allocation churn.
// A deliberate raise requires updating `BUDGET_TOTAL_BYTES` here AND the
// matching line in `.claude-local/IMPACT.md` "Memory layout" with the
// reason, in the same PR — enforced by operator review, not the test.
//
// **Why `total_bytes` not `max_bytes`**: `max_bytes` is peak live heap
// at any single instant (sensitive to allocator interleaving with other
// work running in the same test process). `total_bytes` is cumulative
// new allocations in the window, which is the actual signal we care
// about: "how many bytes did this call touch the allocator for?" It is
// also monotonically reproducible across runs.
//
// **Fixture size**: 1000+1000 nodes / 2000 edges is ~7% of the prod
// baseline (14k/145k). Proportional fixtures let the budget stay small
// (single-test run finishes in <1 s under DHAT instrumentation, which
// is ~10x slower than jemalloc) while still exercising the serialize →
// gzip → sqlite-bind pipeline that carries the real regression risk.
//
// **Thread-safety / mandatory `--test-threads=1`**: DHAT's
// `HeapStats::get()` reads a *process-global* allocation counter, not a
// per-thread one. When other tests in the same binary run concurrently
// under the DHAT allocator, their allocations leak into this test's
// delta and the measurement becomes meaningless (empirically: standalone
// 2.47 MiB → concurrent 5.56 MiB on the same fixture). Any invocation
// that enables `--features dhat-heap` MUST also pass `--test-threads=1`
// to force serial execution. The phase-5 CI job (still pending) will
// encode this; the verification protocol today is:
//
//   cargo test -p innerwarden-agent --features dhat-heap \
//       -- --test-threads=1
//
// Running without `--test-threads=1` may spuriously fail this test and
// is a build-system bug, not a regression in `save_to_store`.

#[cfg(all(test, feature = "dhat-heap"))]
mod heap_budget {
    use super::*;
    use chrono::Utc;

    /// Baselined on 2026-04-24 against the fixture below.
    ///
    /// First-run measurement: **2_589_677 bytes (2.47 MiB)** cumulative
    /// new allocations per `save_to_store` call (measured after the
    /// warm-up call; fresh fixture graph of 2000 nodes + 2000 edges;
    /// `cargo test --features dhat-heap` on Apple Silicon, dev profile).
    ///
    /// Budget = ceil(measurement × 1.10 / 100 KiB) × 100 KiB
    ///        = ceil(2_848_645 / 102_400) × 102_400
    ///        = 28 × 102_400
    ///        = 2_867_200 bytes (2.73 MiB, ~10.7 % headroom over baseline).
    ///
    /// A deliberate raise MUST update this constant AND the matching
    /// line in `.claude-local/IMPACT.md` "Memory layout" in the same
    /// PR, with the reason (e.g. "added N-byte field to Node, fixture
    /// size × N = +M bytes, justified because …"). This is a trend
    /// gate, not a prod-RSS target — DHAT's `total_bytes` metric is
    /// cumulative allocation churn, not live heap. See the module-level
    /// comment above for the full rationale.
    const BUDGET_TOTAL_BYTES: u64 = 2_867_200;

    fn build_fixture_graph() -> KnowledgeGraph {
        let ts = Utc::now();
        let mut g = KnowledgeGraph::new();

        // 1000 IP nodes — a realistic prod mix includes attackers + local
        // peers + cloud egress targets. Addresses span the RFC 5737
        // documentation range 203.0.x.y so they can never collide with
        // any real routable block.
        let mut ip_ids = Vec::with_capacity(1000);
        for i in 0..1000u32 {
            let addr = format!("203.0.{}.{}", i / 256, i % 256);
            ip_ids.push(g.ensure_ip(&addr, ts));
        }

        // 1000 Process nodes — varying comm strings to stress
        // string-allocation paths in the serializer.
        let mut proc_ids = Vec::with_capacity(1000);
        for i in 0..1000u32 {
            let comm = match i % 7 {
                0 => "nginx",
                1 => "sshd",
                2 => "redis-server",
                3 => "postgres",
                4 => "python3.11",
                5 => "innerwarden-agent",
                _ => "bash",
            };
            proc_ids.push(g.ensure_process(i + 1000, 1, comm, 0, ts));
        }

        // 2000 ConnectedTo edges — every process talks to 2 IPs, wrapping.
        for (i, &pid) in proc_ids.iter().enumerate() {
            let ip_a = ip_ids[i % ip_ids.len()];
            let ip_b = ip_ids[(i + 7) % ip_ids.len()];
            g.add_edge(Edge::new(pid, ip_a, Relation::ConnectedTo, ts));
            g.add_edge(Edge::new(pid, ip_b, Relation::ConnectedTo, ts));
        }

        g
    }

    #[test]
    fn save_to_store_allocates_under_budget() {
        // DHAT profiler — only one can be active per process. Test is
        // the sole consumer in this binary (we gate on --features
        // dhat-heap which also disables jemalloc, so other tests run
        // against dhat::Alloc but don't instantiate their own Profiler).
        let _profiler = dhat::Profiler::builder().testing().build();

        let graph = build_fixture_graph();
        let store = innerwarden_store::Store::open_memory().expect("memory store");

        // Warm-up call: first save allocates sqlite statement cache,
        // JSON serializer scratch, gzip dictionaries, etc. — those are
        // amortised across the lifetime of the process and not the
        // regression signal we want to anchor.
        graph.save_to_store(&store).expect("warm-up save_to_store");

        let before = dhat::HeapStats::get();
        graph.save_to_store(&store).expect("measured save_to_store");
        let after = dhat::HeapStats::get();

        let delta_total = after.total_bytes - before.total_bytes;
        let delta_max = after.max_bytes.saturating_sub(before.max_bytes);
        eprintln!(
            "save_to_store heap budget — total_bytes delta: {delta_total} bytes ({:.2} MiB), \
             max_bytes delta: {delta_max} bytes ({:.2} MiB), nodes: {}, edges: {}",
            delta_total as f64 / (1024.0 * 1024.0),
            delta_max as f64 / (1024.0 * 1024.0),
            graph.node_count(),
            graph.edge_count(),
        );

        assert!(
            delta_total <= BUDGET_TOTAL_BYTES,
            "save_to_store allocated {delta_total} bytes per call ({:.2} MiB), \
             budget is {BUDGET_TOTAL_BYTES} bytes ({:.2} MiB). \
             If this is a deliberate raise, update BUDGET_TOTAL_BYTES here AND \
             the matching line in .claude-local/IMPACT.md \"Memory layout\" in \
             the same PR, with the reason.",
            delta_total as f64 / (1024.0 * 1024.0),
            BUDGET_TOTAL_BYTES as f64 / (1024.0 * 1024.0),
        );
    }
}
