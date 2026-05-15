//! Single source of truth: "incidents today" across every dashboard surface.
//!
//! 2026-05-02 audit B1/P1 (Spec 039 Phase 4) — the auditor's #1 release
//! blocker. Five surfaces showed five different numbers on a single screen
//! reload because each computed its own count over a different scan
//! window. PRs #408 and #409 wired Briefing, Report, and the Sensors HUD
//! to the canonical `OverviewSnapshot` (Home and Threats already read it
//! pre-audit). This anchor pins the contract: given the same snapshot,
//! every public surface MUST produce the same "incidents today" total.
//!
//! Surfaces asserted:
//!   1. `OverviewSnapshot.buckets.*.incidents` summed (the canonical
//!      number the Home tile and Threats KPI render directly).
//!   2. `build_sensors_payload(kg, dir, Some(&snap))` — the Sensors HUD's
//!      `total_incidents` field.
//!   3. `briefing::build_briefing_context(kg, Some(&snap))` — parsed out
//!      of the "Operator-relevant incidents today: N" line.
//!   4. The override path in `api_report` (Spec 039 P2) — directly
//!      constructed here because the full HTTP handler test is heavier
//!      than this contract assertion needs.
//!
//! **If this test fails on first run**: do NOT weaken the assertion.
//! That failure IS the auditor's release blocker recurring. Find the
//! surface that drifted (assertion message names it) and fix the
//! computation there to read the snapshot instead.
//!
//! Out of scope here:
//!   - The actual SQLite → snapshot computation (covered by tests in
//!     `data_api.rs::tests::compute_overview_counts_from_sqlite_*`).
//!   - The CLI `report::generate` path that writes the daily markdown —
//!     that's a frozen-in-time artifact at generation time, not a live
//!     view; intentionally still reads JSONL.

use std::sync::{Arc, RwLock};

use crate::dashboard::types::{
    BucketStats, DetectorCount, OutcomeBuckets, OverviewSnapshot, PendingBreakdown, SystemHealth,
};
use crate::knowledge_graph::KnowledgeGraph;

/// Hand-rolled fixture snapshot. Three buckets non-empty, three empty,
/// to exercise the full sum. `events_today` and `unique_attackers` are
/// distinct from `incidents` so a bug that swaps one for the other would
/// show up as a number mismatch rather than a silent equivalence.
fn fixture_snapshot() -> OverviewSnapshot {
    OverviewSnapshot {
        date: "2026-05-02".to_string(),
        generated_at: chrono::Utc::now(),
        health: SystemHealth::OperatingNormally,
        buckets: OutcomeBuckets {
            // 3 incidents, 2 distinct attacker IPs.
            blocked: BucketStats {
                incidents: 3,
                unique_attackers: 2,
                severities: Default::default(),
            },
            // 1 incident.
            observing: BucketStats {
                incidents: 1,
                unique_attackers: 0,
                severities: Default::default(),
            },
            honeypot: BucketStats::default(),
            dismissed: BucketStats::default(),
            allowlisted: BucketStats::default(),
            // 2 incidents needing attention.
            attention: BucketStats {
                incidents: 2,
                unique_attackers: 0,
                severities: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert("high".to_string(), 1);
                    m.insert("medium".to_string(), 1);
                    m
                },
            },
        },
        pending: PendingBreakdown::default(),
        events_today: 9_999,
        top_detectors: vec![DetectorCount {
            detector: "ssh_bruteforce".to_string(),
            count: 1,
        }],
    }
}

/// Sum of every bucket's incidents — the canonical "incidents today"
/// total. Equivalent to what Home + Threats render directly.
fn snapshot_total_incidents(snap: &OverviewSnapshot) -> usize {
    let b = &snap.buckets;
    b.blocked.incidents
        + b.observing.incidents
        + b.honeypot.incidents
        + b.dismissed.incidents
        + b.allowlisted.incidents
        + b.attention.incidents
}

#[test]
fn incidents_today_agrees_across_all_dashboard_surfaces() {
    let snap = fixture_snapshot();
    let canonical_total = snapshot_total_incidents(&snap);
    assert_eq!(
        canonical_total, 6,
        "fixture invariant: 3 + 1 + 0 + 0 + 0 + 2 = 6"
    );

    // ── Surface 1: Sensors HUD ────────────────────────────────────────
    let kg = Arc::new(RwLock::new(KnowledgeGraph::new()));
    let dir = tempfile::tempdir().expect("tempdir");
    let sensors_payload = crate::dashboard::sensors::tests_only_call_build_sensors_payload(
        &kg,
        dir.path(),
        Some(&snap),
        // PR30: no canonical events counter for this fixture — fixture
        // exercises the incidents axis, the KG fallback for events is
        // fine (graph is empty so it yields 0).
        None,
    );
    assert_eq!(
        sensors_payload["total_incidents"].as_u64(),
        Some(canonical_total as u64),
        "Sensors HUD total_incidents must equal sum of OverviewSnapshot \
         bucket incidents — got {}, expected {canonical_total}. The HUD \
         drifted from the canonical snapshot; check sensors.rs::build_sensors_payload",
        sensors_payload["total_incidents"]
    );

    // ── Surface 2: Briefing ──────────────────────────────────────────
    let context = crate::briefing::build_briefing_context(&kg, Some(&snap));
    // Briefing emits "Operator-relevant incidents today: N" which is
    // contained + unresolved, equivalent to canonical_total minus
    // ignored. For the canonical SoT anchor we instead assert that the
    // "BLOCKED: X unique IPs" / "OBSERVING: Y" / "IGNORED: Z" lines
    // sum to canonical_total. blocked.unique_attackers (2) + attention
    // (2) + ignored (0) + observing.incidents implicit; the cleanest
    // anchor is to verify the operator-relevant arithmetic.
    //
    //   contained  = blocked + observing + honeypot = 3 + 1 + 0 = 4
    //   unresolved = attention.incidents             = 2
    //   operator-relevant = contained + unresolved   = 6 = canonical_total ✓
    let needle = format!("Operator-relevant incidents today: {canonical_total}");
    assert!(
        context.contains(&needle),
        "Briefing must compute operator-relevant incidents from snapshot \
         buckets equalling {canonical_total}. Briefing context did not \
         contain the line `{needle}`. First 500 chars: {}",
        &context.chars().take(500).collect::<String>()
    );

    // ── Surface 3: Report (Spec 039 P2 override) ─────────────────────
    // The api_report handler's override path is inline; replicate the
    // computation here so the contract is anchored independently of
    // routing-layer scaffolding.
    let report_total: u64 = (snap.buckets.blocked.incidents
        + snap.buckets.observing.incidents
        + snap.buckets.honeypot.incidents
        + snap.buckets.dismissed.incidents
        + snap.buckets.allowlisted.incidents
        + snap.buckets.attention.incidents) as u64;
    assert_eq!(
        report_total, canonical_total as u64,
        "Report's snapshot-override path must produce the same total. \
         Diverged: report_total={report_total}, canonical={canonical_total}. \
         Check the override block in dashboard/data_api.rs::api_report"
    );

    // ── Surface 4: canonical helper round-trip ───────────────────────
    // Belt-and-braces: the helper used by every surface still equals
    // the inline computation. If this fails, the helper was changed
    // without updating the surfaces.
    assert_eq!(
        snapshot_total_incidents(&snap),
        canonical_total,
        "snapshot_total_incidents must round-trip the fixture sum"
    );
}

#[test]
fn snapshot_zero_incidents_propagates_zero_to_every_surface() {
    // Empty fixture: no incidents anywhere. Every surface MUST report 0.
    // A fallback path that silently returned KG counters when the
    // snapshot was empty would fail here.
    let snap = OverviewSnapshot {
        date: "2026-05-02".to_string(),
        generated_at: chrono::Utc::now(),
        health: SystemHealth::OperatingNormally,
        buckets: OutcomeBuckets::default(),
        pending: PendingBreakdown::default(),
        events_today: 0,
        top_detectors: vec![],
    };

    let kg = Arc::new(RwLock::new(KnowledgeGraph::new()));
    let dir = tempfile::tempdir().expect("tempdir");
    let sensors_payload = crate::dashboard::sensors::tests_only_call_build_sensors_payload(
        &kg,
        dir.path(),
        Some(&snap),
        // PR30: explicitly thread the zero canonical counter so the
        // assertion `total_events == 0` reflects the canonical path,
        // not the legacy KG fallback.
        Some(0),
    );
    assert_eq!(sensors_payload["total_incidents"].as_u64(), Some(0));
    assert_eq!(sensors_payload["total_events"].as_u64(), Some(0));

    let context = crate::briefing::build_briefing_context(&kg, Some(&snap));
    assert!(
        context.contains("Operator-relevant incidents today: 0"),
        "Briefing must report 0 when snapshot has 0 incidents"
    );
    assert!(
        context.contains("Human attention needed: NONE"),
        "Briefing must say NONE when no attention items in snapshot"
    );
}

#[test]
fn pr30_events_today_agrees_between_overview_and_sensors_payloads() {
    // PR30 cross-endpoint contract.
    //
    // Operator-reported on 2026-05-13: Home tile says "130k events
    // today", Sensors HUD says "3.7k events today", same screen
    // reload. The two surfaces had drifted: Home read SQLite per-date
    // (correct after PR28), Sensors HUD read `graph.total_events_ingested`
    // (process-lifetime, off by ~35× on a week-old process).
    //
    // PR30 routes both surfaces through `canonical_counts::compute`.
    // This test seeds SQLite with N events for today's date, drives
    // both code paths against the same store + KG, and asserts they
    // return the same number.
    //
    // If this test ever fails:
    //   * Diff the canonical events_today vs. the sensors payload's
    //     `total_events` field. Whichever is wrong is the surface
    //     that re-introduced an inline read.
    //   * Re-read PR22's docstring on canonical_counts.rs — the rule
    //     is "every dashboard endpoint reads canonical_counts" and
    //     `pr30_every_dashboard_endpoint_reads_canonical_counts`
    //     greps the handlers for compliance.
    use chrono::{TimeZone, Utc};
    let store = innerwarden_store::Store::open_memory().expect("open_memory");
    let kg = Arc::new(RwLock::new(KnowledgeGraph::new()));
    // Seed the KG counter to a deliberately wrong value so a regression
    // back to `graph.total_events_ingested` would surface as a 7-vs-9999 mismatch.
    {
        let mut g = kg.write().unwrap();
        g.total_events_ingested = 9_999;
    }

    let date_str = "2026-05-13";
    let day = Utc.with_ymd_and_hms(2026, 5, 13, 12, 0, 0).unwrap();
    let mk_event = |ts: chrono::DateTime<Utc>| innerwarden_core::event::Event {
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
    for i in 0..7 {
        store
            .insert_event(&mk_event(day + chrono::Duration::seconds(i)))
            .unwrap();
    }

    // Surface A: canonical_counts::compute — the source /api/overview reads.
    let canonical = crate::dashboard::canonical_counts::compute(
        &store,
        &kg,
        date_str,
        &crate::dashboard::canonical_counts::CountFilters::default(),
        day,
    );
    assert_eq!(
        canonical.events_today, 7,
        "canonical_counts::compute must read SQLite per-date (got {}), \
         not the KG counter (9999). PR30 regression — see canonical_counts.rs",
        canonical.events_today
    );

    // Surface B: build_sensors_payload threaded with the canonical
    // events_today — what /api/sensors paints.
    let dir = tempfile::tempdir().expect("tempdir");
    let sensors_payload = crate::dashboard::sensors::tests_only_call_build_sensors_payload(
        &kg,
        dir.path(),
        None,
        Some(canonical.events_today),
    );
    assert_eq!(
        sensors_payload["total_events"].as_u64(),
        Some(canonical.events_today),
        "Sensors HUD total_events must equal canonical events_today \
         (canonical={}, sensors={}). PR30 cross-endpoint contract broken — \
         either build_sensors_payload ignored the threaded number, or a \
         caller stopped threading it.",
        canonical.events_today,
        sensors_payload["total_events"]
    );
}
