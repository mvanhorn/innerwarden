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

/// v2 migration: add `events.src_ip` column + index, then backfill the
/// new column for any existing rows by extracting `details.src_ip`
/// (preferred) or `details.ip` (fallback) from the JSON payload. The
/// backfill is a one-time scan; on a fresh database it runs over zero
/// rows. On an upgraded production database it runs once and the column
/// becomes the canonical source for `events_for_training`.
fn apply_v2(conn: &Connection) -> Result<()> {
    use rusqlite::params;

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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip) WHERE src_ip IS NOT NULL",
            [],
        )?;
    }

    // Backfill: scan rows where src_ip IS NULL, extract from data, update.
    // Done in batches to avoid loading the entire table into memory on
    // upgrade. Uses prepared statements so the per-row cost is parse +
    // bind, not query compile.
    let mut select =
        conn.prepare("SELECT id, data FROM events WHERE src_ip IS NULL ORDER BY id LIMIT 1000")?;
    let mut update = conn.prepare("UPDATE events SET src_ip = ?1 WHERE id = ?2")?;
    loop {
        let mut rows = select.query([])?;
        let mut updated_in_batch = 0;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let data: String = row.get(1)?;
            let ip = serde_json::from_str::<serde_json::Value>(&data)
                .ok()
                .and_then(|v| {
                    v.get("details").and_then(|d| {
                        d.get("src_ip")
                            .or_else(|| d.get("ip"))
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string())
                    })
                });
            // Always update to mark the row as "scanned" — without this
            // the loop would never terminate on rows where src_ip is
            // genuinely absent (they would re-match the WHERE clause
            // forever). Use empty string as the "scanned but no IP"
            // marker, then convert empty back to NULL.
            update.execute(params![ip.as_deref().unwrap_or(""), id])?;
            updated_in_batch += 1;
        }
        if updated_in_batch == 0 {
            break;
        }
    }
    // Convert the empty-string sentinel back to NULL so query semantics
    // match the post-migration writers (which insert NULL when no IP).
    conn.execute("UPDATE events SET src_ip = NULL WHERE src_ip = ''", [])?;

    conn.execute(
        "INSERT INTO schema_version (version, migrated_at, notes) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            2_i64,
            chrono::Utc::now().to_rfc3339(),
            "events.src_ip column + backfill"
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
