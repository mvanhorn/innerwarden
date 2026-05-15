//! Spec 049 PR22 — canonical dashboard counters.
//!
//! **The whack-a-mole ends here.** Before PR22 the dashboard had at
//! least six independent count-producing functions, each with subtly
//! different filters, scopes, and units. Operator-reported on
//! 2026-05-13 after 18 prior PRs: "nunca fica bom" — same field name
//! across surfaces, different math, no canonical.
//!
//! Concrete examples from the prod inspection that drove this PR:
//!
//! * `/api/overview.events_count` returned **129,853** (KG edge count).
//! * `/api/sensors.total_events` returned **3,774** (KG ingested
//!   counter). Same label, 34× gap, both internally consistent for
//!   their original purpose but nonsense to the operator.
//! * `/api/overview.incidents_count` returned **508** (SQLite count).
//! * `/api/sensors.total_incidents` returned **508** (KG nodes_of_type).
//!   These happen to agree TODAY but the SQL/KG sources can drift any
//!   time the cap evicts.
//! * `/api/status.graph.incident_nodes` returned **736** — the KG
//!   carries incidents from prior days, so it overcounts "today"
//!   when read by the Sensors HUD.
//!
//! ## Contract
//!
//! Every dashboard endpoint that needs a count for the current date
//! reads from [`CanonicalCounts`] via [`compute`]. No exceptions.
//! A cross-endpoint anchor (`every_dashboard_endpoint_reads_canonical_counts`)
//! source-greps the handlers to prove the rule.
//!
//! Endpoint migrations are tracked in `IMPACT.md` under "Dashboard
//! count surfaces"; each handler that calls anything other than
//! `canonical_counts::compute` for a today-count is a regression.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Snapshot of every numeric counter a dashboard page might want to
/// render, computed in one pass over the canonical SQLite source.
///
/// Field naming is honest about scope and unit:
/// * `_today` suffix = today's UTC calendar day (matches the date
///   picker default and the `incidents.ts LIKE 'YYYY-MM-DD%'` query).
/// * `attackers` = unique external IPs (dedup).
/// * `incidents` = SQLite row count.
/// * `events` = sensor-emitted event count for the date, from
///   `Store::events_count_for_date(date)`. PR22 originally documented
///   `graph.total_events_ingested` here, but that is a process-lifetime
///   counter — it resets to zero on restart and aggregates every day
///   the binary has been running. PR28 moved `/api/overview` to the
///   SQLite per-date count; PR30 makes the canonical module agree.
#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct CanonicalCounts {
    pub(super) date: String,

    /// Sensor pipeline event volume for the date. Source:
    /// `Store::events_count_for_date(date)` — the SQLite `events` table
    /// filtered by `ts LIKE 'YYYY-MM-DD%'`. Pre-PR22 `/api/overview` used
    /// `metrics.edge_count` (a 30×–40× inflation). PR22 originally
    /// pinned `graph.total_events_ingested` here, but that's a
    /// process-lifetime counter (resets on restart, aggregates every
    /// uptime day) and caused Home and Sensors HUD to disagree
    /// (130k vs 3.7k on 2026-05-13). PR30 switched to SQLite per-date.
    pub(super) events_today: u64,

    /// SQLite `incidents` table row count for the date, post-filter
    /// (research_only + self-traffic excluded). Authoritative answer
    /// to "how many incidents did we surface to the operator today?".
    pub(super) incidents_today: usize,

    /// SQLite `decisions` table row count for the date. Includes every
    /// decision the agent wrote — block_ip, monitor, dismiss, etc.
    pub(super) decisions_today: usize,

    /// Distinct external IPs that appeared on any non-research_only
    /// incident today. Mirrors `/api/entities` total post-filter.
    pub(super) unique_attackers_today: usize,

    /// Spec 049 §5: "flagged by system" = the operator's audit slice.
    /// `contained + observing + filtered_out + needs_review`. Equals
    /// `unique_attackers_today` for a fully classified day.
    pub(super) flagged_by_system: usize,

    /// Spec 049 §5: "warden decisions" = contained + observing +
    /// filtered_out. Excludes `needs_review` (operator action pending).
    pub(super) warden_decisions: usize,

    /// Unique IPs with at least one block_ip / honeypot outcome today.
    pub(super) blocked_attackers: usize,

    /// Unique IPs with at least one monitor outcome today.
    pub(super) observing_attackers: usize,

    /// Unique IPs whose every outcome was dismiss / ignore today.
    pub(super) filtered_out_attackers: usize,

    /// Unique IPs with at least one open / awaiting-decision incident.
    pub(super) needs_review_attackers: usize,

    /// Unique IPs whose every incident landed in the allowlist bucket
    /// (operator trust rule silenced them pre-AI).
    pub(super) allowlisted_attackers: usize,

    /// Detector frequency on today's surfaced incidents.
    pub(super) by_detector: BTreeMap<String, usize>,

    /// Severity frequency on today's surfaced incidents
    /// (`low` / `medium` / `high` / `critical` / `info`).
    pub(super) by_severity: BTreeMap<String, usize>,
}

/// Side-channel inputs for the canonical computation. None of these
/// reach a SQL query — they're operator-facing filters applied to the
/// in-memory pass.
#[derive(Debug, Clone, Default)]
pub(super) struct CountFilters {
    /// Minimum severity rank (0 = no filter, see
    /// `investigation::severity_rank`).
    pub(super) sev_min_rank: u8,

    /// Detector substring (case-insensitive); rows whose detector
    /// does NOT contain this drop out.
    pub(super) detector_substring: Option<String>,

    /// Hour-of-day window (inclusive, UTC). Both `Some` and
    /// `from <= to` to apply; otherwise no-op.
    pub(super) hour_filter: Option<(u32, u32)>,
}

/// Pick the events_today value from the SQLite per-date result, falling
/// back to the KG ingestion counter when SQLite returns Err.
///
/// Pulled out of `compute` so both arms are unit-testable directly. The
/// Err arm is operationally rare (corrupt DB / schema mismatch) and
/// driving a real `Store::events_count_for_date` to return Err takes
/// filesystem mischief that's heavier than the contract being tested.
fn resolve_events_today(
    store_result: innerwarden_store::error::Result<u64>,
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
) -> u64 {
    match store_result {
        Ok(n) => n,
        Err(_) => kg.read().unwrap().total_events_ingested as u64,
    }
}

/// Compute the canonical counter snapshot for `date`. Single SQL pass
/// over SQLite incidents+decisions; reads `events_today` from
/// `Store::events_count_for_date` so the per-date semantics agree
/// across every dashboard surface.
///
/// On store/IO errors returns an empty snapshot with the date set —
/// downstream handlers fall through to a "no data" UI rather than
/// crashing the response.
///
/// The `kg` parameter is retained for the fallback path: when the
/// SQLite store is unavailable (early boot, dev-only mode, store
/// truncation), the live KG counter is the best signal the operator
/// has and is preferred over showing zero.
pub(super) fn compute(
    store: &innerwarden_store::Store,
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    date: &str,
    filters: &CountFilters,
    now: DateTime<Utc>,
) -> CanonicalCounts {
    let mut out = CanonicalCounts {
        date: date.to_string(),
        ..Default::default()
    };

    // ── events_today: SQLite per-date count is the source of truth.
    //    `graph.total_events_ingested` is a process-lifetime counter —
    //    it resets to zero on restart and aggregates every day the
    //    binary has been running. SQLite gives the honest "events
    //    today" the operator expects. Fall back to the KG counter
    //    only when SQLite can't answer (unlikely; mostly dev-only).
    //    Extracted into `resolve_events_today` so both the Ok and the
    //    Err arm are unit-testable directly (the Err arm is hard to
    //    reach through a real store without filesystem trickery).
    out.events_today = resolve_events_today(store.events_count_for_date(date), kg);

    // ── incidents + decisions today, with attacker dedup and bucket
    //    classification. Reuses `compute_overview_counts_from_sqlite`
    //    as the single source of bucket math; PR22 wraps its output
    //    into the canonical struct so every consumer reads the same
    //    shape. Future PRs may inline the body here once every caller
    //    is migrated; for now wrapping keeps the diff focused.
    let degraded = super::data_api::DegradedSignals::default();
    let data_dir = std::path::Path::new("");
    if let Some(snap) = super::data_api::compute_overview_counts_from_sqlite(
        store,
        date,
        filters.sev_min_rank,
        filters.detector_substring.as_deref(),
        filters.hour_filter,
        now,
        &degraded,
        data_dir,
    ) {
        out.incidents_today = snap.incidents_count;
        out.decisions_today = snap.decisions_count;
        out.unique_attackers_today = snap.handled_ips_today;
        out.flagged_by_system = snap.flagged_by_system_count;
        out.warden_decisions = snap.warden_decisions_count;
        out.blocked_attackers = snap.blocked_count;
        out.observing_attackers = snap.observing_count;
        out.filtered_out_attackers = snap.filtered_out_count;
        out.needs_review_attackers = snap.attention_count;
        out.allowlisted_attackers = snap.allowlisted_count;
        out.by_detector = snap.by_detector;
        // `severity_breakdown` is a HashMap; convert to BTreeMap for
        // stable ordering across surfaces (operator screenshots /
        // diffs are easier when severity buckets sort consistently).
        out.by_severity = snap.severity_breakdown.into_iter().collect();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::KnowledgeGraph;
    use innerwarden_core::entities::{EntityRef, EntityType};
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;
    use std::sync::{Arc, RwLock};

    fn mk_kg() -> Arc<RwLock<KnowledgeGraph>> {
        Arc::new(RwLock::new(KnowledgeGraph::new()))
    }

    fn day() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 5, 13).unwrap()
    }

    fn now() -> DateTime<Utc> {
        day().and_hms_opt(15, 0, 0).unwrap().and_utc()
    }

    fn insert_incident(
        store: &innerwarden_store::Store,
        id: &str,
        ts: DateTime<Utc>,
        sev: Severity,
        ip: &str,
    ) {
        let inc = Incident {
            ts,
            host: "h".into(),
            incident_id: id.into(),
            severity: sev,
            title: "fixture".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef {
                r#type: EntityType::Ip,
                value: ip.into(),
            }],
        };
        store.insert_incident(&inc).unwrap();
    }

    fn insert_decision(
        store: &innerwarden_store::Store,
        incident_id: &str,
        action: &str,
        ts: DateTime<Utc>,
        ip: &str,
    ) {
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts.to_rfc3339(),
            incident_id: incident_id.into(),
            action_type: action.into(),
            target_ip: Some(ip.into()),
            target_user: None,
            confidence: 0.95,
            auto_executed: true,
            reason: Some("test".into()),
            data: serde_json::json!({
                "ts": ts.to_rfc3339(),
                "incident_id": incident_id,
                "action_type": action,
                "target_ip": ip,
                "confidence": 0.95,
                "estimated_threat": "high",
                "reason": "test",
                "execution_result": "ok"
            })
            .to_string(),
        };
        store.insert_decision(&row).unwrap();
    }

    #[test]
    fn canonical_counts_returns_zero_for_clean_store() {
        // The boot path on a clean install must not crash and must
        // return well-formed zeros. The operator's first hour
        // should not be polluted with "Unknown" / "—" placeholders.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let counts = compute(
            &store,
            &mk_kg(),
            "2026-05-13",
            &CountFilters::default(),
            now(),
        );
        assert_eq!(counts.date, "2026-05-13");
        assert_eq!(counts.events_today, 0);
        assert_eq!(counts.incidents_today, 0);
        assert_eq!(counts.blocked_attackers, 0);
    }

    #[test]
    fn canonical_counts_aggregates_one_blocked_incident() {
        // Hot path: one incident with one block_ip decision must
        // land in incidents_today=1, blocked_attackers=1,
        // unique_attackers_today=1, flagged_by_system=1,
        // warden_decisions=1.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let ts = now() - chrono::Duration::hours(2);
        insert_incident(&store, "ssh_bf:1", ts, Severity::High, "203.0.113.10");
        insert_decision(&store, "ssh_bf:1", "block_ip", ts, "203.0.113.10");

        let counts = compute(
            &store,
            &mk_kg(),
            "2026-05-13",
            &CountFilters::default(),
            now(),
        );
        assert_eq!(counts.incidents_today, 1);
        assert_eq!(counts.blocked_attackers, 1);
        assert_eq!(counts.unique_attackers_today, 1);
        assert_eq!(counts.flagged_by_system, 1);
        assert_eq!(counts.warden_decisions, 1);
        assert_eq!(counts.filtered_out_attackers, 0);
    }

    #[test]
    fn canonical_counts_excludes_self_traffic_ips() {
        // PR20+PR21 contract end-to-end: Cloudflare-edge IPs and
        // RFC1918 must not inflate any counter. An incident whose
        // only entity is 172.70.80.132 (Cloudflare) must surface as
        // zero across every bucket.
        //
        // `cloud_safelist::init()` populates the static CLOUD_RANGES
        // table; production calls it at agent boot, but tests have to
        // call it explicitly. Idempotent — multiple init()s are a
        // no-op after the first.
        crate::cloud_safelist::init();
        let store = innerwarden_store::Store::open_memory().unwrap();
        let ts = now() - chrono::Duration::hours(2);
        // Cloudflare edge — should be filtered.
        insert_incident(&store, "self:cf", ts, Severity::High, "172.70.80.132");
        insert_decision(&store, "self:cf", "block_ip", ts, "172.70.80.132");
        // Real attacker — should count.
        insert_incident(&store, "ssh_bf:1", ts, Severity::High, "203.0.113.10");
        insert_decision(&store, "ssh_bf:1", "block_ip", ts, "203.0.113.10");

        let counts = compute(
            &store,
            &mk_kg(),
            "2026-05-13",
            &CountFilters::default(),
            now(),
        );
        assert_eq!(
            counts.unique_attackers_today, 1,
            "Cloudflare edge IP must not count as an attacker"
        );
        assert_eq!(counts.blocked_attackers, 1);
    }

    #[test]
    fn canonical_counts_reads_events_today_from_sqlite_per_date_not_kg_counter() {
        // PR30: the events_today source moved from
        // `graph.total_events_ingested` (process-lifetime) to
        // `Store::events_count_for_date(date)` (per-date). The KG
        // counter is wrong because:
        //   * it resets to zero on every restart, so right after a
        //     restart at 14:00 UTC the operator sees 0 events even if
        //     the morning had thousands;
        //   * it aggregates EVERY day the process has been alive, so
        //     after a week of uptime today's tile reports 7 days of
        //     events. PR28 already fixed /api/overview to use SQLite;
        //     this test pins the canonical module to the same source.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let date = "2026-05-13";

        // KG counter is set to a wildly wrong value to prove canonical
        // ignores it when SQLite can answer.
        let kg = mk_kg();
        {
            let mut g = kg.write().unwrap();
            g.total_events_ingested = 999_999;
        }

        // Insert 3 events for the target date and 1 for yesterday into
        // SQLite. Canonical must report 3, not 999_999 (KG), not 4 (cross-date).
        let day_dt = day().and_hms_opt(12, 0, 0).unwrap().and_utc();
        let yesterday_dt = day_dt - chrono::Duration::days(1);
        let mk_event = |ts: DateTime<Utc>| innerwarden_core::event::Event {
            ts,
            host: "h".into(),
            source: "auth_log".into(),
            kind: "ssh.login".into(),
            severity: innerwarden_core::event::Severity::Info,
            summary: String::new(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        for i in 0..3 {
            store
                .insert_event(&mk_event(day_dt + chrono::Duration::seconds(i)))
                .unwrap();
        }
        store.insert_event(&mk_event(yesterday_dt)).unwrap();

        let counts = compute(&store, &kg, date, &CountFilters::default(), now());
        assert_eq!(
            counts.events_today, 3,
            "events_today must come from Store::events_count_for_date \
             for the requested date — not the process-lifetime KG counter"
        );
    }

    #[test]
    fn resolve_events_today_returns_sqlite_value_on_ok_arm() {
        // Ok arm contract: when SQLite gives a per-date count, that's
        // what we report — even when the KG counter is non-zero (the
        // common case: process has been running, ingestion counter
        // has accumulated, but the operator is asking for "today").
        let kg = mk_kg();
        {
            let mut g = kg.write().unwrap();
            g.total_events_ingested = 1_000_000;
        }
        let v = resolve_events_today(Ok(42), &kg);
        assert_eq!(
            v, 42,
            "Ok(n) arm must return n verbatim; the KG counter (1M) is \
             a process-lifetime number and must not leak through the \
             happy path. Got {v}"
        );
    }

    #[test]
    fn resolve_events_today_falls_back_to_kg_counter_on_err_arm() {
        // Err arm contract: this is the actual test of the fallback
        // behavior the docstring promises. Pre-refactor this contract
        // was un-exercised because driving `events_count_for_date` to
        // return Err takes filesystem mischief; extracting the
        // decision into `resolve_events_today` makes the Err arm
        // directly testable by passing a synthetic Err.
        let kg = mk_kg();
        {
            let mut g = kg.write().unwrap();
            g.total_events_ingested = 7_777;
        }
        // Synthesize a real `innerwarden_store::error::Error` to drive
        // the Err arm — any variant works since the canonical module
        // only inspects ok-vs-err, not the error payload.
        let err = innerwarden_store::error::StoreError::Migration("synthetic-for-test".into());
        let v = resolve_events_today(Err(err), &kg);
        assert_eq!(
            v, 7_777,
            "Err(_) arm must surface graph.total_events_ingested so the \
             operator sees SOME signal during degraded operation. Got {v}"
        );
    }

    #[test]
    fn canonical_counts_happy_path_with_empty_sqlite_reports_zero_not_kg_counter() {
        // End-to-end happy path on the full `compute()` function with
        // an empty SQLite store. Replaces the misnamed
        // `canonical_counts_falls_back_to_kg_counter_when_sqlite_call_errors`
        // which pre-refactor never actually drove the Err arm. The Err
        // arm is now exercised by `resolve_events_today_falls_back_to_kg_counter_on_err_arm`;
        // this test pins the complement: with SQLite reachable AND
        // empty, the canonical compute() must return 0, NOT the KG
        // counter, regardless of how high the KG counter is. A future
        // refactor that re-introduces "graph.total_events_ingested as a
        // fallback when SQLite returns 0" would fail here.
        let store = innerwarden_store::Store::open_memory().unwrap();
        let kg = mk_kg();
        {
            let mut g = kg.write().unwrap();
            g.total_events_ingested = 42;
        }
        let counts = compute(&store, &kg, "2026-05-13", &CountFilters::default(), now());
        assert_eq!(
            counts.events_today, 0,
            "with SQLite reachable and empty, canonical must report 0 \
             (per-date), not the KG counter (42)"
        );
    }
}
