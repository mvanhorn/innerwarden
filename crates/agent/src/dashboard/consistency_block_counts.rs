//! Consistency anchor: "blocks today" must read the same on every
//! operator-visible surface when computed over the same knowledge graph.
//!
//! Anchors the recurring bug documented in `.claude-local/RECURRING_BUGS.md`
//! ("Dashboard count != Site count"), which has been fixed twice (2026-04-11
//! and 2026-04-22) and came back both times because no standing assertion
//! pinned the surfaces together. Spec 035 PR-A1.
//!
//! Surfaces asserted (all graph-derived):
//!   1. `agent_api::count_unique_ips_blocked_in_graph` — backs
//!      `/api/agent/security-context` (dashboard Home "Blocked Today" KPI)
//!      and is the helper the site live-feed indirectly consumes through
//!      `is_internal_incident_fields`.
//!   2. `live_feed::build_live_feed_response(...).total_blocked()` — powers
//!      `/api/dashboard/live-feed`. The dashboard widget AND the public
//!      innerwarden.com live feed consume the same endpoint, so asserting
//!      the builder covers both surfaces.
//!   3. Direct re-call of helper #1 on the shared graph — belt-and-braces
//!      against a future refactor that duplicates the helper.
//!
//! **Out of scope** for this anchor:
//!   - Prometheus `metrics::blocks_total` is a historical incremental
//!     counter, not a graph-derived snapshot. Mixing it into this
//!     assertion would conflate two different concepts. A parallel
//!     `blocks_active` gauge would be a separate PR.
//!   - `dashboard/threats.rs::list_blocks_by_window` referenced in
//!     NUMBER_CONSISTENCY.md does not exist in the codebase (stale doc
//!     reference). See the note in that file.
//!
//! **If this test fails on first run**: do NOT weaken the assertion.
//! That failure IS the recurring bug recurring. Per spec 035 A1, extract
//! a canonical `count_blocks_in_window` helper and make both graph-derived
//! surfaces call it, in the same PR.

use std::sync::{Arc, RwLock};

use chrono::Utc;

use crate::knowledge_graph::types::{Edge, Node, Relation};
use crate::knowledge_graph::KnowledgeGraph;

fn seed_incident(
    graph: &mut KnowledgeGraph,
    incident_id: &str,
    detector: &str,
    ip_addr: &str,
    decision: Option<&str>,
    auto_executed: bool,
    research_only: bool,
    title: &str,
) {
    let now = Utc::now();
    let ip_id = graph.upsert_node(Node::Ip {
        addr: ip_addr.into(),
        is_internal: false,
        datasets: vec![],
        risk_score: 10,
        is_tor: false,
        first_seen: now,
        last_seen: now,
        attempted_usernames: vec![],
    });
    let inc_id = graph.upsert_node(Node::Incident {
        incident_id: incident_id.into(),
        detector: detector.into(),
        severity: "high".into(),
        title: title.into(),
        summary: "S".into(),
        ts: now,
        mitre_ids: vec![],
        decision: decision.map(str::to_string),
        confidence: Some(0.9),
        decision_reason: None,
        decision_target: Some(ip_addr.into()),
        auto_executed,
        is_allowlisted: false,
        false_positive: false,
        fp_reporter: None,
        fp_reported_at: None,
        research_only,
    });
    graph.add_edge(Edge::new(inc_id, ip_id, Relation::TriggeredBy, now));
}

/// Mixed fixture per spec 035 A1:
///   - 2 distinct external block_ip + auto_executed incidents (real attackers)
///   - 1 duplicate external IP (same addr as real #1, different incident id) — dedup
///   - 1 advisory-only detector (`host_drift`) — filtered by `is_internal_incident_fields`
///   - 1 `research_only = true` incident — hidden from operator surfaces
///   - 1 non-block decision (`monitor`) — not a block
///
/// Expected canonical "blocks today" across every graph-derived surface: **2**.
fn seed_mixed_fixture(graph: &mut KnowledgeGraph) {
    seed_incident(
        graph,
        "ssh_bruteforce:real1:1",
        "ssh_bruteforce",
        "203.0.113.5",
        Some("block_ip"),
        true,
        false,
        "ssh bruteforce burst",
    );
    seed_incident(
        graph,
        "ssh_bruteforce:real2:1",
        "ssh_bruteforce",
        "198.51.100.7",
        Some("block_ip"),
        true,
        false,
        "ssh bruteforce burst",
    );
    // Same IP as real1 under a different incident id — dedup target.
    seed_incident(
        graph,
        "ssh_bruteforce:dup:1",
        "ssh_bruteforce",
        "203.0.113.5",
        Some("block_ip"),
        true,
        false,
        "ssh bruteforce burst",
    );
    // Advisory-only detector: `host_drift` is in the advisory list
    // (`is_internal_incident_fields`), so this must not count.
    seed_incident(
        graph,
        "host_drift:adv:1",
        "host_drift",
        "203.0.113.99",
        Some("block_ip"),
        true,
        false,
        "host drift detected",
    );
    // research_only: dropped by the live-feed builder before decisions
    // are collected, and skipped by the graph-side helper.
    seed_incident(
        graph,
        "ssh_bruteforce:research:1",
        "ssh_bruteforce",
        "203.0.113.100",
        Some("block_ip"),
        true,
        true,
        "ssh bruteforce burst",
    );
    // Non-block decision: monitor-only, not a contained attacker.
    seed_incident(
        graph,
        "ssh_bruteforce:nb:1",
        "ssh_bruteforce",
        "203.0.113.101",
        Some("monitor"),
        true,
        false,
        "ssh bruteforce burst",
    );
}

const EXPECTED_BLOCKED_IPS: usize = 2;

#[test]
fn blocks_today_agrees_across_all_graph_derived_surfaces() {
    let mut graph = KnowledgeGraph::new();
    seed_mixed_fixture(&mut graph);

    // Surface 1: helper behind `/api/agent/security-context`
    // (`recent_blocks_today` in the Home KPI payload).
    let home_count = super::agent_api::count_unique_ips_blocked_in_graph(&graph);

    // Surface 2: `/api/dashboard/live-feed` via the pure builder. Covers
    // both the dashboard live-feed widget and the public innerwarden.com
    // live feed, which consume the same endpoint.
    let tmp = tempfile::tempdir().expect("tempdir for empty data_dir");
    let kg = Arc::new(RwLock::new(graph));
    let live_feed = super::live_feed::build_live_feed_response(&kg, tmp.path());
    let live_feed_count = live_feed.total_blocked();

    // Surface 3: re-call helper #1 on the shared graph. Guards against a
    // future refactor that forks a parallel counter.
    let graph_ref = kg.read().expect("kg read lock");
    let shared_helper_count = super::agent_api::count_unique_ips_blocked_in_graph(&graph_ref);

    assert_eq!(
        home_count, EXPECTED_BLOCKED_IPS,
        "Home/security-context counter diverged from fixture (expected {EXPECTED_BLOCKED_IPS}, got {home_count})",
    );
    assert_eq!(
        live_feed_count, EXPECTED_BLOCKED_IPS,
        "/api/dashboard/live-feed total_blocked diverged from fixture (expected {EXPECTED_BLOCKED_IPS}, got {live_feed_count})",
    );
    assert_eq!(
        shared_helper_count, home_count,
        "shared graph-side helper diverged from Home count ({shared_helper_count} != {home_count})",
    );
    assert_eq!(
        home_count, live_feed_count,
        "RECURRING BUG: Home count {home_count} != Site live-feed count {live_feed_count}. \
         Per spec 035 A1, do NOT weaken this assertion — extract a shared \
         count_blocks_in_window helper and route both surfaces through it.",
    );
}
