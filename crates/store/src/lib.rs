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

        let manager = SqliteConnectionManager::file(&db_path);
        let pool = Pool::builder()
            .max_size(4)
            .build(manager)
            .map_err(StoreError::Pool)?;

        // Configure PRAGMAs and ensure schema on one connection
        {
            let conn = pool.get().map_err(StoreError::Pool)?;
            configure_connection(&conn)?;
            schema::ensure_schema(&conn)?;
        }

        info!(path = %db_path.display(), "store opened (sqlite WAL)");

        Ok(Self { pool, data_dir })
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1) // memory DB is single-connection
            .build(manager)
            .map_err(StoreError::Pool)?;

        {
            let conn = pool.get().map_err(StoreError::Pool)?;
            configure_connection(&conn)?;
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

/// Apply performance PRAGMAs to a connection.
fn configure_connection(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA cache_size = -8000;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA auto_vacuum = INCREMENTAL;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::CURRENT_VERSION);
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
