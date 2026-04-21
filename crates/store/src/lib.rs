//! Unified SQLite storage backend for InnerWarden.
//!
//! Replaces JSONL files, redb, and JSON snapshots with a single
//! `innerwarden.db` SQLite database. Used by both sensor (sync)
//! and agent (async via `spawn_blocking`).
//!
//! WAL mode enables concurrent reads from agent while sensor writes.

pub mod cursors;
pub mod decisions;
pub mod error;
pub mod events;
pub mod graph;
pub mod incidents;
pub mod kv;
pub mod maintenance;
pub mod migration;
pub mod schema;
pub mod state_blobs;

use std::path::{Path, PathBuf};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tracing::info;

use crate::error::{Result, StoreError};

/// Unified storage backend backed by SQLite.
///
/// Thread-safe via r2d2 connection pool. WAL mode enables concurrent
/// reader/writer access across sensor and agent processes.
pub struct Store {
    pool: Pool<SqliteConnectionManager>,
    data_dir: PathBuf,
}

impl Store {
    /// Open or create the database at `data_dir/innerwarden.db`.
    ///
    /// Runs schema migrations if needed. Configures WAL mode and
    /// performance-oriented PRAGMAs.
    pub fn open(data_dir: &Path) -> Result<Self> {
        // Canonicalize data_dir to prevent path traversal attacks.
        let data_dir = std::fs::canonicalize(data_dir).map_err(StoreError::Io)?;
        if !data_dir.is_dir() {
            return Err(StoreError::Other("data_dir is not a directory".into()));
        }
        let db_path = data_dir.join("innerwarden.db");

        // Pre-create the DB file with group-writable permissions (0660) so that
        // both sensor (root:innerwarden) and agent (innerwarden:innerwarden) can
        // write. NOT world-readable — contains security-sensitive data (incidents,
        // decisions, attacker profiles). SQLite's internal open() uses 0644,
        // ignoring the process UMask.
        if !db_path.exists() {
            if let Ok(f) = std::fs::File::create(&db_path) {
                drop(f);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o660));
                }
            }
        }

        // Spec 030: apply PRAGMAs via `with_init` so every pooled
        // connection (not just the first fetched) gets the same
        // runtime configuration. Without this, connections lazily
        // created after the first `pool.get()` used sqlite defaults
        // for per-connection PRAGMAs (cache_size, mmap_size,
        // temp_store, etc.) which contributed silently to the RSS
        // growth this spec targets.
        let manager = SqliteConnectionManager::file(&db_path)
            .with_init(|conn| conn.execute_batch(PRAGMA_SETUP));
        let pool = Pool::builder()
            .max_size(4)
            .build(manager)
            .map_err(StoreError::Pool)?;

        // Ensure the schema on one connection after the pool is up.
        {
            let conn = pool.get().map_err(StoreError::Pool)?;
            schema::ensure_schema(&conn)?;
        }

        info!(path = %db_path.display(), "store opened (sqlite WAL)");

        Ok(Self { pool, data_dir })
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self> {
        let manager =
            SqliteConnectionManager::memory().with_init(|conn| conn.execute_batch(PRAGMA_SETUP));
        let pool = Pool::builder()
            .max_size(1) // memory DB is single-connection
            .build(manager)
            .map_err(StoreError::Pool)?;

        {
            let conn = pool.get().map_err(StoreError::Pool)?;
            schema::ensure_schema(&conn)?;
        }

        Ok(Self {
            pool,
            data_dir: PathBuf::from(":memory:"),
        })
    }

    /// Get a pooled connection.
    pub fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool.get().map_err(StoreError::Pool)
    }

    /// Return the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Return the database file size in bytes (0 for in-memory).
    pub fn db_size_bytes(&self) -> Result<u64> {
        let db_path = self.data_dir.join("innerwarden.db");
        match std::fs::metadata(&db_path) {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// Return current schema version.
    pub fn schema_version(&self) -> Result<i64> {
        let conn = self.conn()?;
        schema::schema_version(&conn)
    }
}

/// Per-connection PRAGMA script. Applied via
/// `SqliteConnectionManager::with_init` so every connection the
/// r2d2 pool creates gets the same configuration.
///
/// Spec 030 tuning (replaces the earlier `cache_size = -8000` + no
/// `mmap_size` + implicit `temp_store`):
/// - `cache_size = -2000` holds the per-connection page cache at
///   2 MB. With a pool of four, that caps the sqlite-owned page
///   cache in the agent at ~8 MB instead of the previous ~32 MB
///   (four × 8 MB). The OS page cache still serves hot pages for
///   reads, so the miss cost is negligible for our workload.
/// - `mmap_size = 0` disables sqlite's internal memory-mapped IO
///   so reads go through `read()` and the OS page cache. Without
///   this, sqlite can map hundreds of MB of the db into the
///   process address space, which inflates RSS even though the
///   data is shared with the OS cache.
/// - `temp_store = FILE` keeps temporary tables on disk instead of
///   in RAM. Our queries rarely touch temp tables (no big sorts)
///   so the disk cost is invisible; the RAM savings are real on
///   the odd large query.
const PRAGMA_SETUP: &str = "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA cache_size = -2000;
         PRAGMA mmap_size = 0;
         PRAGMA temp_store = 1;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA auto_vacuum = INCREMENTAL;";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::CURRENT_VERSION);
    }

    // Spec 030: verify the tuned PRAGMAs apply to every pooled
    // connection. The earlier code path ran the PRAGMA batch on one
    // fetched connection and relied on the pool returning the same
    // one - which only held for the first `pool.get()` call. The
    // `with_init` migration guarantees all connections are
    // configured, so we assert on freshly fetched connections.
    fn read_pragma(conn: &rusqlite::Connection, name: &str) -> i64 {
        let sql = format!("PRAGMA {name}");
        conn.query_row(&sql, [], |r| r.get::<_, i64>(0))
            .unwrap_or_else(|e| panic!("PRAGMA {name} query failed: {e:?}"))
    }

    #[test]
    fn pragmas_are_set_on_every_pool_connection_memory() {
        // Memory DBs do not support mmap, so `PRAGMA mmap_size` returns
        // no row on them. Skip that assertion and focus on the
        // per-connection runtime values that do apply to in-memory.
        let store = Store::open_memory().unwrap();
        let conn = store.conn().unwrap();
        assert_eq!(read_pragma(&conn, "cache_size"), -2000);
        assert_eq!(read_pragma(&conn, "temp_store"), 1);
        assert_eq!(read_pragma(&conn, "synchronous"), 1);
    }

    #[test]
    fn pragmas_apply_to_file_pool_across_fetches() {
        use tempfile::TempDir;
        let td = TempDir::new().unwrap();
        let store = Store::open(td.path()).unwrap();

        // Cycle through a few pool fetches to exercise connections
        // beyond the first one. Each returned conn must have the
        // full spec-030 tuning applied, including mmap_size which
        // is only meaningful on file-backed databases.
        for _ in 0..8 {
            let conn = store.conn().unwrap();
            assert_eq!(read_pragma(&conn, "cache_size"), -2000);
            assert_eq!(read_pragma(&conn, "mmap_size"), 0);
            assert_eq!(read_pragma(&conn, "temp_store"), 1);
            assert_eq!(read_pragma(&conn, "synchronous"), 1);
        }
    }

    #[test]
    fn test_open_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::CURRENT_VERSION);
        assert!(store.db_size_bytes().unwrap() > 0);
    }

    #[test]
    fn test_reopen_preserves_schema() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _store = Store::open(dir.path()).unwrap();
        }
        // Reopen — should not fail or re-migrate
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::CURRENT_VERSION);
    }
}
