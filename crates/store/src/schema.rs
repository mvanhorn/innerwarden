//! Schema definitions and migrations for the unified SQLite store.

use rusqlite::Connection;
use tracing::info;

use crate::error::{Result, StoreError};

/// Current schema version.
///
/// History:
/// - v1: initial sqlite migration from JSONL+redb (spec 016).
/// - v2: events.src_ip column. Replaces a per-row JSON re-parse in
///   `events_for_training` with an indexed column lookup
///   (`RECURRING_BUGS.md` "events_for_training reparses full JSON to
///   extract src_ip"). Includes a one-time backfill of existing rows.
pub const CURRENT_VERSION: i64 = 2;

/// Initial DDL for schema v1.
const SCHEMA_V1: &str = r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    migrated_at TEXT NOT NULL,
    notes       TEXT
);

-- ============================================================
-- STREAMS (replace events/incidents/decisions JSONL)
-- ============================================================

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    host        TEXT NOT NULL,
    source      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    summary     TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    host        TEXT NOT NULL,
    incident_id TEXT NOT NULL UNIQUE,
    severity    TEXT NOT NULL,
    detector    TEXT NOT NULL,
    title       TEXT NOT NULL,
    summary     TEXT,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(ts);
CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE TABLE IF NOT EXISTS decisions (
    id              INTEGER PRIMARY KEY,
    ts              TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    action_type     TEXT NOT NULL,
    target_ip       TEXT,
    target_user     TEXT,
    confidence      REAL,
    auto_executed   INTEGER NOT NULL,
    reason          TEXT,
    prev_hash       TEXT,
    row_hash        TEXT NOT NULL,
    data            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS idx_decisions_incident ON decisions(incident_id);
CREATE INDEX IF NOT EXISTS idx_decisions_action ON decisions(action_type);

-- ============================================================
-- GRAPH SNAPSHOTS (replace graph-snapshot-*.json)
-- ============================================================

CREATE TABLE IF NOT EXISTS graph_snapshots (
    id          INTEGER PRIMARY KEY,
    date        TEXT NOT NULL UNIQUE,
    snapshot    BLOB NOT NULL,
    nodes_count INTEGER NOT NULL,
    edges_count INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);

-- ============================================================
-- KV STATE (replace redb tables)
-- ============================================================

CREATE TABLE IF NOT EXISTS kv_state (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       BLOB NOT NULL,
    expires_at  TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_kv_expires ON kv_state(expires_at)
    WHERE expires_at IS NOT NULL;

-- ============================================================
-- STATE BLOBS (replace JSON state files)
-- ============================================================

CREATE TABLE IF NOT EXISTS state_blobs (
    name        TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- ============================================================
-- CURSORS
-- ============================================================

CREATE TABLE IF NOT EXISTS agent_cursors (
    name        TEXT PRIMARY KEY,
    last_id     INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sensor_cursors (
    collector   TEXT PRIMARY KEY,
    cursor_data TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- ============================================================
-- METRICS
-- ============================================================

CREATE TABLE IF NOT EXISTS metrics_counters (
    name        TEXT PRIMARY KEY,
    value       INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL
);
"#;

/// Ensure the database schema is up to date.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    // Check if schema_version table exists
    let has_schema: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
            [],
            |row| row.get(0),
        )
        .map(|count: i64| count > 0)
        .unwrap_or(false);

    if !has_schema {
        // Fresh database — apply v1 schema, record version, then fall
        // through to the migration loop so a fresh DB ends up at
        // CURRENT_VERSION via the same code path as an upgraded one.
        conn.execute_batch(SCHEMA_V1)?;
        conn.execute(
            "INSERT INTO schema_version (version, migrated_at, notes) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                1_i64,
                chrono::Utc::now().to_rfc3339(),
                "initial sqlite migration from JSONL+redb"
            ],
        )?;
        info!(version = 1, "v1 schema initialized");
    }

    // Check current version
    let current: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current < CURRENT_VERSION {
        run_migrations(conn, current)?;
    }

    Ok(())
}

fn run_migrations(conn: &Connection, from_version: i64) -> Result<()> {
    if from_version < 2 {
        apply_v2(conn)?;
    }

    info!(
        from = from_version,
        to = CURRENT_VERSION,
        "schema migrations complete"
    );
    Ok(())
}

/// v2 migration: add `events.src_ip` column + index, then record the
/// schema version. **The backfill is NOT part of the migration** — it
/// runs as a background task in the slow_loop (`backfill_events_src_ip`)
/// so a large table on an upgraded database cannot block `Store::open`.
///
/// Pre-2026-04-23 the migration inlined the backfill as 800k+ individual
/// UPDATE statements. On production with the sensor concurrently writing
/// to the same database, the loop never completed within the
/// `busy_timeout` window, so the `INSERT schema_version` at the end
/// never ran. Result: every `Store::open` re-attempted v2 migration,
/// every attempt hit the same contention, and `state.sqlite_store`
/// stayed `None` for the entire agent process lifetime.
///
/// The new split:
///   - **Migration** (this function): column + index + version row,
///     all idempotent. Takes milliseconds. Runs on every `Store::open`
///     (fast path when already applied).
///   - **Backfill** (`backfill_events_src_ip`): walk rows where
///     `src_ip IS NULL`, extract from JSON, wrap each batch in a
///     single explicit transaction. Progress is implicit via the
///     `src_ip IS NULL` WHERE clause — no state to persist. Can be
///     safely interrupted and resumed. Runs asynchronously from
///     agent slow_loop.
///
/// Readers (`events_for_training`) already handle NULL `src_ip`
/// gracefully, so the agent remains functional during the backfill
/// window. Only the nightly training's historical-row coverage is
/// gradual until the backfill completes.
fn apply_v2(conn: &Connection) -> Result<()> {
    // Column may already exist if a partial migration was attempted —
    // tolerate "duplicate column name" by checking pragma_table_info.
    let already_present: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'src_ip'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);
    if !already_present {
        conn.execute("ALTER TABLE events ADD COLUMN src_ip TEXT", [])?;
    }
    // Index creation is idempotent (IF NOT EXISTS) and cheap.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip) WHERE src_ip IS NOT NULL",
        [],
    )?;

    conn.execute(
        "INSERT INTO schema_version (version, migrated_at, notes) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            2_i64,
            chrono::Utc::now().to_rfc3339(),
            "events.src_ip column + index (backfill runs separately)"
        ],
    )?;

    Ok(())
}

/// Return the current schema version, or 0 if not initialized.
pub fn schema_version(conn: &Connection) -> Result<i64> {
    let has_table: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .map_err(StoreError::Sqlite)?;

    if !has_table {
        return Ok(0);
    }

    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )
    .map_err(StoreError::Sqlite)
}
