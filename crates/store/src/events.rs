//! Event storage operations.

use innerwarden_core::event::Event;
use rusqlite::params;

use crate::error::Result;
use crate::Store;

/// Extract the `src_ip` (preferred) or `ip` (fallback) string from an
/// event's `details` payload. Used by both `insert_event` and the schema
/// v2 backfill — keeping the lookup in one place ensures the column
/// values written at insert time match what the backfill computed for
/// pre-v2 rows.
pub(crate) fn event_src_ip(event: &Event) -> Option<String> {
    let details = &event.details;
    details
        .get("src_ip")
        .or_else(|| details.get("ip"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

impl Store {
    /// Insert an event. Returns the rowid (monotonic cursor).
    pub fn insert_event(&self, event: &Event) -> Result<i64> {
        let conn = self.conn()?;
        let data = serde_json::to_string(event)?;
        let src_ip = event_src_ip(event);
        conn.execute(
            "INSERT INTO events (ts, host, source, kind, severity, summary, data, src_ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.ts.to_rfc3339(),
                event.host,
                event.source,
                event.kind,
                format!("{:?}", event.severity).to_lowercase(),
                event.summary,
                data,
                src_ip,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Insert a batch of events in a single transaction.
    pub fn insert_events_batch(&self, events: &[Event]) -> Result<()> {
        let conn = self.conn()?;
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (ts, host, source, kind, severity, summary, data, src_ip)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for event in events {
                let data = serde_json::to_string(event)?;
                let src_ip = event_src_ip(event);
                stmt.execute(params![
                    event.ts.to_rfc3339(),
                    event.host,
                    event.source,
                    event.kind,
                    format!("{:?}", event.severity).to_lowercase(),
                    event.summary,
                    data,
                    src_ip,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Stream event `(kind, src_ip)` tuples since `since_ts_iso`, up to `limit`,
    /// in ascending `ts` order. Used by nightly autoencoder training — the
    /// full `Event` payload is never needed there, so we return the two fields
    /// that matter (kind for feature index, ip for blocked-IP filtering) and
    /// avoid deserialising the rest.
    ///
    /// Pre-2026-04-23 this function read the `data` column and re-parsed each
    /// row's full JSON payload to extract `details.src_ip` — millions of
    /// allocations per nightly run on a busy host. Schema v2 added a
    /// dedicated `src_ip` column populated at insert (and backfilled on
    /// upgrade), so the parse happens once at write time, not once per
    /// training query. See `RECURRING_BUGS.md` "events_for_training reparses
    /// full JSON to extract src_ip".
    pub fn events_for_training(
        &self,
        since_ts_iso: &str,
        limit: usize,
    ) -> Result<Vec<(String, Option<String>)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT kind, src_ip FROM events WHERE ts >= ?1 ORDER BY ts LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since_ts_iso, limit as i64], |row| {
            // Normalize the backfill's empty-string sentinel ("scanned, no IP
            // in JSON") back to None so callers see uniform NULL/missing
            // semantics regardless of whether the row was inserted post-v2
            // or backfilled from a legacy JSON-only payload.
            let ip = row.get::<_, Option<String>>(1)?.filter(|s| !s.is_empty());
            Ok((row.get::<_, String>(0)?, ip))
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Backfill `events.src_ip` for one batch of legacy rows where the
    /// column is NULL. Returns the number of rows updated. Returns 0
    /// when no NULL rows remain — caller can stop scheduling.
    ///
    /// Wrapped in a single explicit transaction so the batch lands as
    /// one WAL frame instead of `batch_size` individual auto-commits.
    /// Critical when running concurrently with the sensor's writes:
    /// pre-fix the per-row auto-commit pattern lost the busy-timeout
    /// race over and over and the migration never finished. The batch
    /// transaction acquires RESERVED → COMMIT once.
    ///
    /// Idempotent and resumable: progress is implicit in the
    /// `src_ip IS NULL` predicate. Rows whose JSON has no extractable
    /// IP get the empty-string sentinel `''` so the next batch's
    /// WHERE clause stops matching them — without this the loop would
    /// spin forever on the same NULL rows. Readers normalize `''` back
    /// to `None` (see `events_for_training`).
    pub fn backfill_events_src_ip(&self, batch_size: usize) -> Result<usize> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let mut updated = 0usize;
        {
            let mut select = tx
                .prepare("SELECT id, data FROM events WHERE src_ip IS NULL ORDER BY id LIMIT ?1")?;
            let mut update = tx.prepare("UPDATE events SET src_ip = ?1 WHERE id = ?2")?;
            let mut rows = select.query(params![batch_size as i64])?;
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
                // Empty-string sentinel marks "scanned but no IP" so the
                // WHERE clause stops matching the row on subsequent
                // batches. Persisted; readers normalize `''` to `None`.
                update.execute(params![ip.as_deref().unwrap_or(""), id])?;
                updated += 1;
            }
        }
        tx.commit()?;
        Ok(updated)
    }

    /// Number of events still awaiting `src_ip` backfill. Used by the
    /// agent slow_loop to decide whether to schedule another batch and
    /// to surface progress in dashboards. Counts only rows where
    /// `src_ip IS NULL` — the empty-string sentinel from a completed
    /// scan is excluded.
    pub fn events_pending_src_ip_backfill(&self) -> Result<u64> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE src_ip IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// Read events with rowid > `after_id`, up to `limit`.
    /// Returns `(rowid, Event)` pairs for cursor tracking.
    pub fn events_since(&self, after_id: i64, limit: usize) -> Result<Vec<(i64, Event)>> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare_cached("SELECT id, data FROM events WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![after_id, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (id, data) = row?;
            match serde_json::from_str::<Event>(&data) {
                Ok(event) => results.push((id, event)),
                Err(e) => {
                    tracing::warn!(id, error = %e, "skipping malformed event row");
                }
            }
        }
        Ok(results)
    }

    /// Count total events.
    pub fn events_count(&self) -> Result<u64> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Delete events with ts < `before_ts` (ISO 8601). Returns rows deleted.
    pub fn delete_events_before(&self, before_ts: &str) -> Result<u64> {
        let conn = self.conn()?;
        let deleted = conn.execute("DELETE FROM events WHERE ts < ?1", params![before_ts])?;
        Ok(deleted as u64)
    }

    /// Get the maximum rowid in the events table (0 if empty).
    pub fn events_max_id(&self) -> Result<i64> {
        let conn = self.conn()?;
        let max: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
            row.get(0)
        })?;
        Ok(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::event::Severity;

    fn sample_event(kind: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test-host".into(),
            source: "test".into(),
            kind: kind.into(),
            severity: Severity::Medium,
            summary: "test event".into(),
            details: serde_json::json!({"key": "value"}),
            tags: vec!["test".into()],
            entities: vec![],
        }
    }

    #[test]
    fn test_insert_and_query() {
        let store = Store::open_memory().unwrap();
        let id1 = store.insert_event(&sample_event("ssh_bruteforce")).unwrap();
        let id2 = store.insert_event(&sample_event("port_scan")).unwrap();
        assert!(id2 > id1);

        let events = store.events_since(0, 100).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].1.kind, "ssh_bruteforce");
        assert_eq!(events[1].1.kind, "port_scan");

        // Cursor: only events after id1
        let events = store.events_since(id1, 100).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1.kind, "port_scan");
    }

    #[test]
    fn test_batch_insert() {
        let store = Store::open_memory().unwrap();
        let events: Vec<Event> = (0..100)
            .map(|i| sample_event(&format!("kind_{i}")))
            .collect();
        store.insert_events_batch(&events).unwrap();
        assert_eq!(store.events_count().unwrap(), 100);
    }

    #[test]
    fn test_delete_before() {
        let store = Store::open_memory().unwrap();
        store.insert_event(&sample_event("old")).unwrap();
        // Delete everything before far future
        let deleted = store.delete_events_before("2099-01-01T00:00:00Z").unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.events_count().unwrap(), 0);
    }

    #[test]
    fn test_events_for_training_streams_kind_and_ip() {
        let store = Store::open_memory().unwrap();
        let mut ev = sample_event("ssh.login_failed");
        ev.details = serde_json::json!({"src_ip": "1.2.3.4", "user": "root"});
        store.insert_event(&ev).unwrap();
        let mut ev2 = sample_event("http.request");
        ev2.details = serde_json::json!({"ip": "5.6.7.8"});
        store.insert_event(&ev2).unwrap();
        let mut ev3 = sample_event("file.read_access");
        ev3.details = serde_json::json!({"path": "/etc/passwd"});
        store.insert_event(&ev3).unwrap();

        let rows = store
            .events_for_training("1970-01-01T00:00:00Z", 100)
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], ("ssh.login_failed".into(), Some("1.2.3.4".into())));
        assert_eq!(rows[1], ("http.request".into(), Some("5.6.7.8".into())));
        assert_eq!(rows[2].0, "file.read_access");
        assert_eq!(rows[2].1, None);
    }

    #[test]
    fn test_events_for_training_respects_window_cutoff() {
        let store = Store::open_memory().unwrap();
        store.insert_event(&sample_event("a")).unwrap();
        let far_future = "2099-01-01T00:00:00Z";
        let rows = store.events_for_training(far_future, 100).unwrap();
        assert!(rows.is_empty(), "events older than cutoff must be skipped");
    }

    #[test]
    fn test_events_max_id() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.events_max_id().unwrap(), 0);
        store.insert_event(&sample_event("a")).unwrap();
        let max = store.events_max_id().unwrap();
        assert!(max > 0);
    }

    // ── schema v2: events.src_ip column + backfill ────────────────────
    //
    // Anchors for `RECURRING_BUGS.md` "events_for_training reparses full
    // JSON to extract src_ip". The column must:
    //   1. Be populated at insert time (no re-parse during training).
    //   2. Be backfilled for rows inserted before the migration.
    //   3. Survive the `details.src_ip` vs legacy `details.ip` ambiguity.

    #[test]
    fn insert_event_populates_src_ip_column_from_details_src_ip() {
        let store = Store::open_memory().unwrap();
        let mut ev = sample_event("ssh.login_failed");
        ev.details = serde_json::json!({"src_ip": "203.0.113.10", "user": "root"});
        store.insert_event(&ev).unwrap();

        let conn = store.conn().unwrap();
        let ip: Option<String> = conn
            .query_row("SELECT src_ip FROM events LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ip.as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn insert_event_falls_back_to_details_ip_legacy_field() {
        let store = Store::open_memory().unwrap();
        let mut ev = sample_event("http.request");
        ev.details = serde_json::json!({"ip": "198.51.100.5"});
        store.insert_event(&ev).unwrap();

        let conn = store.conn().unwrap();
        let ip: Option<String> = conn
            .query_row("SELECT src_ip FROM events LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ip.as_deref(), Some("198.51.100.5"));
    }

    #[test]
    fn insert_event_writes_null_when_no_ip_in_details() {
        let store = Store::open_memory().unwrap();
        let mut ev = sample_event("file.read_access");
        ev.details = serde_json::json!({"path": "/etc/passwd"});
        store.insert_event(&ev).unwrap();

        let conn = store.conn().unwrap();
        let ip: Option<String> = conn
            .query_row("SELECT src_ip FROM events LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ip, None);
    }

    #[test]
    fn events_for_training_uses_indexed_column_no_json_reparse() {
        // Drop the `data` column visibility for this test — if the
        // implementation reverts to parsing it, the test still passes
        // *now*, but the perf invariant we're anchoring is "no JSON
        // parse per training row". The lighter test we can do without
        // mocking is: the column must be readable directly by the query.
        let store = Store::open_memory().unwrap();
        let mut ev = sample_event("ssh.login_failed");
        ev.details = serde_json::json!({"src_ip": "203.0.113.99"});
        store.insert_event(&ev).unwrap();

        let rows = store
            .events_for_training("1970-01-01T00:00:00Z", 10)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "ssh.login_failed");
        assert_eq!(rows[0].1.as_deref(), Some("203.0.113.99"));
    }

    /// Helper for the v2-upgrade tests: rebuild a v1-shaped table on
    /// the open store. Drops the v2 index + column + schema_version
    /// row so the next `ensure_schema` re-runs the migration. Returns
    /// the connection so the caller can keep inserting v1-shape rows.
    fn rollback_to_v1_schema(store: &Store) {
        let conn = store.conn().unwrap();
        conn.execute("DROP INDEX IF EXISTS idx_events_src_ip", [])
            .unwrap();
        conn.execute("ALTER TABLE events DROP COLUMN src_ip", [])
            .unwrap();
        conn.execute("DELETE FROM schema_version WHERE version >= 2", [])
            .unwrap();
    }

    fn insert_v1_event(store: &Store, kind: &str, details: serde_json::Value) {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = store.conn().unwrap();
        conn.execute(
            "INSERT INTO events (ts, host, source, kind, severity, summary, data) \
             VALUES (?1, 'h', 's', ?2, 'low', 'sum', ?3)",
            rusqlite::params![now, kind, details.to_string()],
        )
        .unwrap();
    }

    #[test]
    fn schema_v2_migration_does_not_backfill_inline() {
        // The v2 migration must NOT do the row backfill itself — it
        // must only add the column + index + version row. The backfill
        // is driven asynchronously by the agent slow_loop. This is the
        // anchor that prevents a regression to PR #262's behavior
        // where an 800k+ row inline backfill blocked `Store::open` and
        // caused the boot-time `database is locked` race.
        use crate::schema::{ensure_schema, schema_version};

        let store = Store::open_memory().unwrap();
        rollback_to_v1_schema(&store);
        insert_v1_event(
            &store,
            "ssh.login_failed",
            serde_json::json!({"details": {"src_ip": "203.0.113.55"}}),
        );
        insert_v1_event(
            &store,
            "http",
            serde_json::json!({"details": {"path": "/etc"}}),
        );

        let conn = store.conn().unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 1);

        ensure_schema(&conn).unwrap();
        assert_eq!(
            schema_version(&conn).unwrap(),
            2,
            "v2 migration must record its version even though backfill is deferred"
        );

        // Both rows still have NULL src_ip — backfill has not run.
        let null_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE src_ip IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            null_count, 2,
            "ensure_schema must NOT backfill rows inline — that work belongs to the slow_loop"
        );
    }

    #[test]
    fn backfill_events_src_ip_populates_legacy_rows_and_marks_no_ip_rows() {
        let store = Store::open_memory().unwrap();
        rollback_to_v1_schema(&store);
        insert_v1_event(
            &store,
            "ssh.login_failed",
            serde_json::json!({"details": {"src_ip": "203.0.113.55"}}),
        );
        insert_v1_event(
            &store,
            "http",
            serde_json::json!({"details": {"path": "/etc"}}),
        );
        // Use the `ip` fallback path too.
        insert_v1_event(
            &store,
            "outbound",
            serde_json::json!({"details": {"ip": "198.51.100.7"}}),
        );

        let conn = store.conn().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();
        drop(conn);

        assert_eq!(store.events_pending_src_ip_backfill().unwrap(), 3);
        let updated = store.backfill_events_src_ip(100).unwrap();
        assert_eq!(updated, 3);
        // Row with no extractable IP is now sentinel-marked, so the
        // pending count drops to zero — the loop is guaranteed to
        // terminate.
        assert_eq!(store.events_pending_src_ip_backfill().unwrap(), 0);

        // events_for_training normalizes the empty-string sentinel to
        // None so callers see uniform NULL-or-IP semantics.
        let rows = store
            .events_for_training("1970-01-01T00:00:00Z", 100)
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[0],
            (
                "ssh.login_failed".to_string(),
                Some("203.0.113.55".to_string())
            )
        );
        assert_eq!(rows[1], ("http".to_string(), None));
        assert_eq!(
            rows[2],
            ("outbound".to_string(), Some("198.51.100.7".to_string()))
        );
    }

    #[test]
    fn backfill_events_src_ip_resumes_across_batches() {
        // Five legacy rows, batch size 2 → must finish in 3 calls
        // (2 + 2 + 1) and remain idempotent on a fourth call.
        let store = Store::open_memory().unwrap();
        rollback_to_v1_schema(&store);
        for i in 0..5 {
            insert_v1_event(
                &store,
                "ssh.login_failed",
                serde_json::json!({"details": {"src_ip": format!("10.0.0.{i}")}}),
            );
        }
        let conn = store.conn().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();
        drop(conn);

        assert_eq!(store.backfill_events_src_ip(2).unwrap(), 2);
        assert_eq!(store.events_pending_src_ip_backfill().unwrap(), 3);
        assert_eq!(store.backfill_events_src_ip(2).unwrap(), 2);
        assert_eq!(store.events_pending_src_ip_backfill().unwrap(), 1);
        assert_eq!(store.backfill_events_src_ip(2).unwrap(), 1);
        assert_eq!(store.events_pending_src_ip_backfill().unwrap(), 0);
        // Fourth call returns 0 — no work left.
        assert_eq!(store.backfill_events_src_ip(2).unwrap(), 0);
    }

    #[test]
    fn backfill_events_src_ip_is_noop_on_post_v2_inserts() {
        // Rows inserted via the public Store::insert_event path already
        // have src_ip populated at write time. The backfill must see
        // zero pending rows on a fresh store.
        let store = Store::open_memory().unwrap();
        let mut ev = sample_event("ssh.login_failed");
        ev.details = serde_json::json!({"src_ip": "203.0.113.99"});
        store.insert_event(&ev).unwrap();
        assert_eq!(store.events_pending_src_ip_backfill().unwrap(), 0);
        assert_eq!(store.backfill_events_src_ip(1000).unwrap(), 0);
    }
}
