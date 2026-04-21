//! Database maintenance operations.
//!
//! Implements the 14 mandatory maintenance tasks from spec 016:
//! - VACUUM, WAL checkpoint, graph cleanup, cache validation, KV cleanup,
//!   schema migrations, hash chain verify, integrity check, disk monitoring,
//!   task counter, threat intel staleness, API key health, pool exhaustion,
//!   WAL size alerts.

use chrono::Datelike;
use rusqlite::params;
use tracing::{info, warn};

use crate::error::Result;
use crate::Store;

/// Result of a retention cleanup.
#[derive(Debug, Default)]
pub struct RetentionResult {
    pub events_deleted: u64,
    pub incidents_deleted: u64,
    pub decisions_deleted: u64,
    pub graph_snapshots_deleted: u64,
}

/// Database statistics.
#[derive(Debug)]
pub struct StoreStats {
    pub db_size_bytes: u64,
    pub wal_size_bytes: u64,
    pub events_count: u64,
    pub incidents_count: u64,
    pub decisions_count: u64,
    pub kv_count: u64,
    pub graph_snapshots_count: u64,
    pub schema_version: i64,
}

impl Store {
    /// Run a WAL checkpoint (TRUNCATE mode — reclaims WAL space).
    pub fn wal_checkpoint(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    /// Run incremental vacuum (reclaim N free pages).
    pub fn incremental_vacuum(&self, pages: u32) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(&format!("PRAGMA incremental_vacuum({pages})"), [])?;
        Ok(())
    }

    /// Run a full VACUUM (rewrites entire database — slow for large DBs).
    pub fn vacuum(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch("VACUUM")?;
        info!("VACUUM complete");
        Ok(())
    }

    /// Ratio of free (unused) pages to total pages. Spec 030: used by
    /// the weekly VACUUM gate so we only rebuild the file when there
    /// is meaningful slack to reclaim. Returns 0.0 for an empty or
    /// fresh database.
    pub fn free_page_ratio(&self) -> Result<f64> {
        let conn = self.conn()?;
        let free: i64 = conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
        let total: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
        if total <= 0 {
            return Ok(0.0);
        }
        Ok(free as f64 / total as f64)
    }

    /// Run SQLite integrity check. Returns "ok" if healthy.
    pub fn integrity_check(&self) -> Result<String> {
        let conn = self.conn()?;
        let result: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result != "ok" {
            warn!(result = %result, "integrity check failed");
        }
        Ok(result)
    }

    /// Get WAL file size in bytes (0 if file doesn't exist).
    pub fn wal_size_bytes(&self) -> Result<u64> {
        let wal_path = self.data_dir.join("innerwarden.db-wal");
        match std::fs::metadata(&wal_path) {
            Ok(m) => Ok(m.len()),
            Err(_) => Ok(0),
        }
    }

    /// Run retention cleanup: delete data older than specified days.
    pub fn run_retention(
        &self,
        events_days: u32,
        incidents_days: u32,
        decisions_days: u32,
        graph_snapshot_days: u32,
    ) -> Result<RetentionResult> {
        let now = chrono::Utc::now();
        let mut result = RetentionResult::default();

        if events_days > 0 {
            let cutoff = (now - chrono::Duration::days(events_days as i64)).to_rfc3339();
            result.events_deleted = self.delete_events_before(&cutoff)?;
        }

        if incidents_days > 0 {
            let cutoff = (now - chrono::Duration::days(incidents_days as i64)).to_rfc3339();
            result.incidents_deleted = self.delete_incidents_before(&cutoff)?;
        }

        if decisions_days > 0 {
            let cutoff = (now - chrono::Duration::days(decisions_days as i64)).to_rfc3339();
            let conn = self.conn()?;
            let deleted = conn.execute("DELETE FROM decisions WHERE ts < ?1", params![cutoff])?;
            result.decisions_deleted = deleted as u64;
        }

        if graph_snapshot_days > 0 {
            let cutoff_date = (now - chrono::Duration::days(graph_snapshot_days as i64))
                .format("%Y-%m-%d")
                .to_string();
            result.graph_snapshots_deleted = self.delete_graph_snapshots_before(&cutoff_date)?;
        }

        if result.events_deleted > 0 || result.incidents_deleted > 0 || result.decisions_deleted > 0
        {
            info!(
                events = result.events_deleted,
                incidents = result.incidents_deleted,
                decisions = result.decisions_deleted,
                snapshots = result.graph_snapshots_deleted,
                "retention cleanup complete"
            );
        }

        Ok(result)
    }

    /// Get a metrics counter value.
    pub fn metric_get(&self, name: &str) -> Result<i64> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT value FROM metrics_counters WHERE name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0);
        Ok(result)
    }

    /// Increment a metrics counter.
    pub fn metric_inc(&self, name: &str, delta: i64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO metrics_counters (name, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO UPDATE SET
                value = value + ?2,
                updated_at = ?3",
            params![name, delta, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Set a metrics counter to an absolute value.
    pub fn metric_set(&self, name: &str, value: i64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO metrics_counters (name, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at",
            params![name, value, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Collect database statistics.
    pub fn stats(&self) -> Result<StoreStats> {
        Ok(StoreStats {
            db_size_bytes: self.db_size_bytes()?,
            wal_size_bytes: self.wal_size_bytes()?,
            events_count: self.events_count()?,
            incidents_count: self.incidents_count()?,
            decisions_count: self.decisions_count()?,
            kv_count: {
                let conn = self.conn()?;
                conn.query_row("SELECT COUNT(*) FROM kv_state", [], |row| {
                    row.get::<_, i64>(0)
                })? as u64
            },
            graph_snapshots_count: self.list_graph_snapshots()?.len() as u64,
            schema_version: self.schema_version()?,
        })
    }
}

// ─── MaintenanceScheduler ─────────────────────────────────────────────

/// Time-gated scheduler for periodic SQLite maintenance tasks.
///
/// Called every slow-loop tick (~30s) from the agent. Internally gates
/// tasks into 5-minute, hourly, and daily buckets so the caller does
/// not need its own timers.
pub struct MaintenanceScheduler {
    last_5min: std::time::Instant,
    last_hourly: std::time::Instant,
    last_daily: Option<chrono::NaiveDate>,
    last_weekly: Option<chrono::IsoWeek>,
}

impl Default for MaintenanceScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl MaintenanceScheduler {
    pub fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            last_5min: now,
            last_hourly: now,
            last_daily: None,
            last_weekly: None,
        }
    }

    /// Called every slow-loop tick (~30s). Runs time-gated maintenance tasks.
    /// Returns a list of security alerts (integrity violations) that the caller
    /// should forward to Telegram/notifications.
    pub fn tick(&mut self, store: &Store) -> Vec<String> {
        let now = std::time::Instant::now();
        let mut alerts = Vec::new();

        // 5-minute tasks
        if now.duration_since(self.last_5min).as_secs() >= 300 {
            self.last_5min = now;
            self.tick_5min(store);
        }

        // Hourly tasks
        if now.duration_since(self.last_hourly).as_secs() >= 3600 {
            self.last_hourly = now;
            alerts.extend(self.tick_hourly(store));
        }

        // Daily tasks (first tick of a new calendar day)
        let today = chrono::Local::now().date_naive();
        if self.last_daily != Some(today) {
            self.last_daily = Some(today);
            self.tick_daily(store);
        }

        // Weekly tasks (first tick of a new ISO week)
        let this_week = chrono::Local::now().date_naive().iso_week();
        if self.last_weekly != Some(this_week) {
            self.last_weekly = Some(this_week);
            self.tick_weekly(store);
        }

        alerts
    }

    // ── 5-minute bucket ───────────────────────────────────────────────

    fn tick_5min(&self, store: &Store) {
        // WAL checkpoint
        if let Err(e) = store.wal_checkpoint() {
            warn!("maintenance: wal_checkpoint failed: {e:#}");
        }

        // KV expired cleanup
        match store.kv_cleanup_expired() {
            Ok(n) if n > 0 => info!(deleted = n, "maintenance: kv expired cleanup"),
            Err(e) => warn!("maintenance: kv_cleanup_expired failed: {e:#}"),
            _ => {}
        }

        // WAL size check
        match store.wal_size_bytes() {
            Ok(bytes) if bytes > 200 * 1024 * 1024 => {
                warn!(
                    bytes,
                    mb = bytes / (1024 * 1024),
                    "maintenance: WAL file exceeds 200 MB"
                );
            }
            Err(e) => warn!("maintenance: wal_size_bytes failed: {e:#}"),
            _ => {}
        }

        // DB size metric update
        match store.db_size_bytes() {
            Ok(bytes) => {
                if let Err(e) = store.metric_set("db_size_bytes", bytes as i64) {
                    warn!("maintenance: metric_set db_size_bytes failed: {e:#}");
                }
            }
            Err(e) => warn!("maintenance: db_size_bytes failed: {e:#}"),
        }
    }

    // ── Hourly bucket ─────────────────────────────────────────────────

    fn tick_hourly(&self, store: &Store) -> Vec<String> {
        let mut alerts = Vec::new();

        // Incremental vacuum (1000 pages)
        if let Err(e) = store.incremental_vacuum(1000) {
            warn!("maintenance: incremental_vacuum(1000) failed: {e:#}");
        }

        // KV trim for bounded namespaces
        match store.kv_trim("ip_reputations", 10_000) {
            Ok(n) if n > 0 => info!(deleted = n, "maintenance: trimmed ip_reputations"),
            Err(e) => warn!("maintenance: kv_trim ip_reputations failed: {e:#}"),
            _ => {}
        }

        match store.kv_trim("attacker_profiles", 10_000) {
            Ok(n) if n > 0 => info!(deleted = n, "maintenance: trimmed attacker_profiles"),
            Err(e) => warn!("maintenance: kv_trim attacker_profiles failed: {e:#}"),
            _ => {}
        }

        // ── Security: database integrity checks (every hour) ─────────
        // Detects corruption from disk errors, external tampering, or bugs.

        // SQLite PRAGMA integrity_check
        match store.integrity_check() {
            Ok(ref s) if s == "ok" => {}
            Ok(ref s) => {
                let msg = format!("DATABASE INTEGRITY VIOLATION: {s}");
                warn!("{msg}");
                alerts.push(msg);
            }
            Err(e) => warn!("maintenance: integrity_check failed: {e:#}"),
        }

        // Decision hash chain verification
        match store.verify_hash_chain() {
            Ok(result) => {
                if result.intact {
                    info!(verified = result.verified, "maintenance: hash chain intact");
                } else {
                    let msg = format!(
                        "HASH CHAIN BROKEN — audit trail tampered. {} verified, broken at: {:?}",
                        result.verified, result.broken_at,
                    );
                    warn!("{msg}");
                    alerts.push(msg);
                }
            }
            Err(e) => warn!("maintenance: verify_hash_chain failed: {e:#}"),
        }

        // Self-heal world-readable files in data_dir. The agent/sensor only
        // hold security-sensitive artefacts here (incidents, decisions,
        // attacker profiles, DB, graph snapshots). We strip the world-read
        // bit on every hourly tick instead of only alerting, so existing
        // deployments are fixed in place without operator intervention.
        // New installs are already protected by UMask=0007 in the systemd
        // units; this path only matters for files rotated in or created
        // before that change landed.
        #[cfg(unix)]
        {
            let healed = heal_world_readable(&store.data_dir);
            if healed > 0 {
                info!(
                    files = healed,
                    dir = %store.data_dir.display(),
                    "maintenance: stripped world-read bit from data files"
                );
            }
        }

        alerts
    }

    // ── Daily bucket ──────────────────────────────────────────────────

    fn tick_daily(&self, store: &Store) {
        // Full retention cleanup
        match store.run_retention(2, 30, 90, 7) {
            Ok(r) => {
                if r.events_deleted > 0
                    || r.incidents_deleted > 0
                    || r.decisions_deleted > 0
                    || r.graph_snapshots_deleted > 0
                {
                    info!(
                        events = r.events_deleted,
                        incidents = r.incidents_deleted,
                        decisions = r.decisions_deleted,
                        snapshots = r.graph_snapshots_deleted,
                        "maintenance: daily retention cleanup"
                    );
                }
            }
            Err(e) => warn!("maintenance: run_retention failed: {e:#}"),
        }

        // Hash chain + integrity checks moved to hourly bucket for faster
        // tamper detection. Daily still runs vacuum and retention.

        // Conditional vacuum if DB > 500 MB
        match store.db_size_bytes() {
            Ok(bytes) if bytes > 500 * 1024 * 1024 => {
                info!(
                    mb = bytes / (1024 * 1024),
                    "maintenance: DB > 500 MB, running incremental_vacuum(5000)"
                );
                if let Err(e) = store.incremental_vacuum(5000) {
                    warn!("maintenance: incremental_vacuum(5000) failed: {e:#}");
                }
            }
            Err(e) => warn!("maintenance: db_size_bytes check failed: {e:#}"),
            _ => {}
        }
    }

    // ── Weekly bucket ─────────────────────────────────────────────────
    //
    // Spec 030: `incremental_vacuum` (hourly + daily) returns pages to
    // the freelist but does not shrink the sqlite file. Free space
    // piles up until `VACUUM` rebuilds the file. Run VACUUM at most
    // once per ISO week, and only when the freelist exceeds 20% of the
    // database — skip the rebuild when the file is already dense.
    fn tick_weekly(&self, store: &Store) {
        let ratio = match store.free_page_ratio() {
            Ok(r) => r,
            Err(e) => {
                warn!("maintenance: free_page_ratio failed: {e:#}");
                return;
            }
        };
        if ratio < 0.20 {
            info!(
                free_ratio = format!("{:.2}", ratio),
                "maintenance: weekly VACUUM skipped (free page ratio below 20%)"
            );
            return;
        }
        let before = store.db_size_bytes().unwrap_or(0);
        let t0 = std::time::Instant::now();
        if let Err(e) = store.vacuum() {
            warn!("maintenance: weekly VACUUM failed: {e:#}");
            return;
        }
        let after = store.db_size_bytes().unwrap_or(0);
        let elapsed_ms = t0.elapsed().as_millis() as u64;
        info!(
            before_mb = before / (1024 * 1024),
            after_mb = after / (1024 * 1024),
            reclaimed_mb = before.saturating_sub(after) / (1024 * 1024),
            elapsed_ms,
            "maintenance: weekly VACUUM complete"
        );
        if let Err(e) = store.metric_set(
            "vacuum_last_reclaimed_bytes",
            before.saturating_sub(after) as i64,
        ) {
            warn!("maintenance: metric_set vacuum_last_reclaimed_bytes failed: {e:#}");
        }
    }
}

/// Walk `dir` one level deep, stripping the world-read bit on any regular
/// file whose mode has `0o004` set. Returns the number of files healed.
///
/// Non-recursive and fail-silent: any `io::Error` on a single entry is
/// swallowed so a transient permission issue doesn't block the rest of
/// the hourly maintenance tick. The caller logs the aggregate count.
#[cfg(unix)]
fn heal_world_readable(dir: &std::path::Path) -> usize {
    use std::os::unix::fs::PermissionsExt;

    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut healed = 0;
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o004 != 0 {
            let new_mode = mode & !0o007;
            if std::fs::set_permissions(&path, std::fs::Permissions::from_mode(new_mode)).is_ok() {
                healed += 1;
            }
        }
    }
    healed
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::event::{Event, Severity};

    #[cfg(unix)]
    #[test]
    fn heal_world_readable_strips_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let loose = tmp.path().join("loose.json");
        std::fs::write(&loose, b"x").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        let tight = tmp.path().join("tight.json");
        std::fs::write(&tight, b"x").unwrap();
        std::fs::set_permissions(&tight, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert_eq!(heal_world_readable(tmp.path()), 1);
        assert_eq!(
            std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::metadata(&tight).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn test_wal_checkpoint() {
        let store = Store::open_memory().unwrap();
        store.wal_checkpoint().unwrap();
    }

    #[test]
    fn test_integrity_check() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.integrity_check().unwrap(), "ok");
    }

    #[test]
    fn test_metrics() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 0);

        store.metric_inc("test_counter", 5).unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 5);

        store.metric_inc("test_counter", 3).unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 8);

        store.metric_set("test_counter", 100).unwrap();
        assert_eq!(store.metric_get("test_counter").unwrap(), 100);
    }

    #[test]
    fn test_retention() {
        let store = Store::open_memory().unwrap();
        // Insert some data
        let event = Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "test".into(),
            kind: "test".into(),
            severity: Severity::Low,
            summary: "test".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        store.insert_event(&event).unwrap();

        // Retention with 0 days = delete everything
        // But we need a far-future cutoff since we just inserted
        let result = store.run_retention(0, 0, 0, 0).unwrap();
        assert_eq!(result.events_deleted, 0); // 0 days means skip

        // Use 1 day — events are from now, so nothing deleted
        let result = store.run_retention(1, 1, 1, 1).unwrap();
        assert_eq!(result.events_deleted, 0);
    }

    #[test]
    fn test_stats() {
        let store = Store::open_memory().unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(stats.events_count, 0);
        assert_eq!(stats.incidents_count, 0);
        assert_eq!(stats.schema_version, 1);
    }

    #[test]
    fn test_scheduler_new() {
        let sched = MaintenanceScheduler::new();
        assert!(sched.last_daily.is_none());
    }

    #[test]
    fn test_scheduler_tick_does_not_panic() {
        let store = Store::open_memory().unwrap();
        let mut sched = MaintenanceScheduler::new();
        // First tick should run daily (last_daily is None).
        // 5-min and hourly gates will not fire yet (just created).
        sched.tick(&store);
        assert!(sched.last_daily.is_some());
        // Spec 030: weekly bucket should also fire on first tick.
        assert!(sched.last_weekly.is_some());
    }

    // ── Spec 030: free_page_ratio + weekly VACUUM ─────────────────────

    #[test]
    fn free_page_ratio_on_empty_db_is_non_negative() {
        let store = Store::open_memory().unwrap();
        let ratio = store.free_page_ratio().unwrap();
        assert!((0.0..=1.0).contains(&ratio));
    }

    #[test]
    fn weekly_tick_does_not_run_twice_in_same_week() {
        let store = Store::open_memory().unwrap();
        let mut sched = MaintenanceScheduler::new();
        sched.tick(&store);
        let first_week = sched.last_weekly;
        assert!(first_week.is_some());

        // Second tick in the same wall-clock second: weekly bucket
        // should not re-fire. We assert the state is unchanged (same
        // ISO week stored).
        sched.tick(&store);
        assert_eq!(sched.last_weekly, first_week);
    }

    #[test]
    fn weekly_tick_skips_vacuum_when_freelist_below_threshold() {
        // Fresh DB has a near-zero freelist (just the empty schema
        // pages). The weekly tick must observe ratio < 0.20 and skip
        // the VACUUM call. We assert by verifying the file size does
        // not churn and that tick_weekly runs without error.
        let td = tempfile::TempDir::new().unwrap();
        let store = Store::open(td.path()).unwrap();
        let mut sched = MaintenanceScheduler::new();
        let before = store.db_size_bytes().unwrap();
        // Drive the weekly tick directly so the wall-clock gate does
        // not interfere.
        sched.tick_weekly(&store);
        let after = store.db_size_bytes().unwrap();
        // File size is unchanged (no VACUUM happened).
        assert_eq!(before, after);
    }

    #[test]
    fn weekly_tick_runs_vacuum_when_freelist_above_threshold() {
        // Populate, bulk-delete, then drive tick_weekly. Expected:
        // freelist ratio crosses 0.20 so the tick fires VACUUM and
        // `vacuum_last_reclaimed_bytes` metric gets set.
        let td = tempfile::TempDir::new().unwrap();
        let store = Store::open(td.path()).unwrap();

        for i in 0..400 {
            let ev = Event {
                ts: Utc::now(),
                host: format!("h-{i}"),
                source: "test".into(),
                kind: "test.weekly".into(),
                severity: Severity::Low,
                summary: format!("e-{i}"),
                details: serde_json::json!({ "pad": "x".repeat(4096) }),
                tags: vec![],
                entities: vec![],
            };
            store.insert_event(&ev).unwrap();
        }
        store.wal_checkpoint().unwrap();
        let conn = store.conn().unwrap();
        conn.execute("DELETE FROM events", []).unwrap();
        drop(conn);
        store.wal_checkpoint().unwrap();
        assert!(store.free_page_ratio().unwrap() > 0.20);

        let mut sched = MaintenanceScheduler::new();
        sched.tick_weekly(&store);

        // VACUUM ran. Freelist should be near zero. The
        // `vacuum_last_reclaimed_bytes` metric is populated by
        // `tick_weekly`; on small test datasets the byte count can
        // legitimately be zero (page-aligned file size unchanged)
        // so we only assert the freelist drained.
        assert!(store.free_page_ratio().unwrap() < 0.05);
    }

    #[test]
    fn free_page_ratio_drops_after_delete_and_vacuum() {
        use tempfile::TempDir;

        let td = TempDir::new().unwrap();
        let store = Store::open(td.path()).unwrap();

        // Pad enough rows to force multiple pages past the schema floor.
        // Each row carries a 4 KB blob in `details` so ~400 rows reliably
        // occupy > 1 MB before compression.
        for i in 0..400 {
            let ev = Event {
                ts: Utc::now(),
                host: format!("h-{i}"),
                source: "test".into(),
                kind: "test.vacuum".into(),
                severity: Severity::Low,
                summary: format!("filler event {i}"),
                details: serde_json::json!({ "i": i, "pad": "x".repeat(4096) }),
                tags: vec!["vacuum".into()],
                entities: vec![],
            };
            store.insert_event(&ev).unwrap();
        }
        store.wal_checkpoint().unwrap();

        let conn = store.conn().unwrap();
        conn.execute("DELETE FROM events", []).unwrap();
        drop(conn);
        store.wal_checkpoint().unwrap();

        // After bulk delete, a large fraction of pages is on the freelist.
        let ratio_before = store.free_page_ratio().unwrap();
        assert!(
            ratio_before > 0.05,
            "expected freelist > 5% after bulk delete, got {ratio_before:.3}"
        );

        store.vacuum().unwrap();

        // VACUUM rebuilds the file and drops the freelist back to ~0.
        let ratio_after = store.free_page_ratio().unwrap();
        assert!(
            ratio_after < 0.01,
            "VACUUM must drain freelist, got {ratio_after:.3}"
        );
    }

    #[test]
    fn test_scheduler_5min_tasks() {
        let store = Store::open_memory().unwrap();
        let sched = MaintenanceScheduler::new();
        // Directly call tick_5min — should not panic on empty DB
        sched.tick_5min(&store);
    }

    #[test]
    fn test_scheduler_hourly_tasks() {
        let store = Store::open_memory().unwrap();
        let sched = MaintenanceScheduler::new();
        sched.tick_hourly(&store);
    }

    #[test]
    fn test_scheduler_daily_tasks() {
        let store = Store::open_memory().unwrap();
        let sched = MaintenanceScheduler::new();
        sched.tick_daily(&store);
    }
}
