# Anchor Tests Manifest

This file is the **public** ledger of regression-anchor tests. Each entry pins one bug class so it cannot come back silently. Anchor tests differ from regular regression tests in two ways:

1. **They are named for the bug, not the function.** A test named `blocks_today_agrees_across_all_graph_derived_surfaces` is an anchor; a test named `test_count_unique_ips` is not.
2. **They are referenced from this file.** A CI gate (`scripts/verify-anchor-tests.sh`) asserts every entry below still exists in the source tree. Deleting or renaming an anchor without updating this file fails CI.

The operator's private `.claude-local/RECURRING_BUGS.md` cross-references entries here for the bugs that needed anchors.

## Format

`<test_module_path>::<test_name>` — one-line description of what the test pins.

## Anchors

### Operator-visible number consistency

- `crates/agent/src/dashboard/consistency_block_counts.rs::blocks_today_agrees_across_all_graph_derived_surfaces` — "Blocks today" agrees across dashboard live feed, top bar, site live feed, and the shared graph helper. Pinned the 2026-04-11 / 2026-04-22 dashboard-vs-site count drift.

- `crates/agent/src/response_lifecycle.rs::tests::current_orphan_count_returns_zero_on_clean_system` — `current_orphan_count()` returns the number of real orphan entries on disk, never the lifetime counter. Pinned the 2026-05-03 banner gaslighting bug ("17 orphaned" persisting after PR #408 GC pruned the entries).

- `crates/agent/src/response_lifecycle.rs::tests::to_json_exposes_gauges_shape_distinct_from_totals` — JSON output keeps `gauges.*` (current state) separate from `totals.*` (lifetime counters). Anti-regression for collapsing them back into one field.

- `crates/agent/src/dashboard/mod.rs::tests::js_responses_banner_reads_gauges_not_totals` — frontend banner reads `r.gauges?.orphaned`, drift trigger does not key off the lifetime counter, banner copy says "currently pending" so the operator reads it as present-tense gauge.

### Knowledge graph correctness

- `crates/agent/src/knowledge_graph/ingestion.rs::tests::ingest_clears_current_event_metadata_after_run` — `_current_event_*` fields are cleared at the end of every `ingest()` call. Pinned the 2026-05-03 cross-attribution bug (agent self-traffic appearing under attacker IP journey).

- `crates/agent/src/knowledge_graph/ingestion.rs::tests::add_edge_outside_ingest_does_not_inherit_stale_summary` — edges created outside an ingest cycle do not inherit the previous event's summary as a stale property.

### Memory budget

- `crates/agent/src/loops/boot.rs::heap_budget::run_agent_once_allocates_under_budget` — boot path stays under 500MB peak alloc.
- `crates/agent/src/knowledge_graph/persistence.rs::heap_budget::save_to_store_allocates_under_budget` — KG snapshot save stays under 5MB per call.
- `crates/agent/src/loops/slow_loop.rs::heap_budget::process_narrative_tick_allocates_under_budget` — slow-loop tick stays under 10MB.

### Dashboard UX consistency

- `crates/agent/src/dashboard/mod.rs::tests::js_intel_baseline_tab_is_english_not_pt_br` — Baseline tab strings are English. Anti-regression for PT-BR copy reintroduction.

### Baseline UX honesty

- `crates/agent/src/dashboard/mod.rs::tests::js_login_heatmap_hides_service_accounts_by_default` — the "Who logs in, when" heatmap default-hides daemon PAM sessions (snap_daemon, systemd-resolve, messagebus, _apt, ...) and exposes a "Show system accounts" toggle. Pinned the 2026-05-03 visual report where the operator read the heatmap as "all these people have logged in" when only `ubuntu` had real SSH sessions.

- `crates/agent/src/dashboard/intelligence.rs::baseline_enrich_tests::build_user_classes_marks_daemon_sessions_as_service` — the `/api/baseline-status` endpoint enriches the JSON with a `user_classes` map keyed by username. snap_daemon (uid 584788, /usr/bin/false) classifies as `service`, ubuntu (uid 1000, /bin/bash) as `human`, root as `root`, and unknown users fall through to `unknown` so the operator still sees them. Anti-regression for the classification contract that the frontend keys off.

### Baseline learning honesty (Wave 5b)

- `crates/agent/src/baseline.rs::tests::is_valid_unix_username_rejects_brute_force_and_garbage` — `is_valid_unix_username` rejects `Admin`, `AdminGPON`, `1234`, `123456789`, `!`, `(`, `*` and other shapes observed in the operator's polluted prod baseline on 2026-05-03. Anti-regression for any change that loosens the regex to allow uppercase, leading digits, or special chars.

- `crates/agent/src/baseline.rs::tests::observe_event_skips_honeypot_source_logins` — events with `source` starting `honeypot` never write to `user_login_hours`. Pinned because the agent's honeypot accepts every credential to fool attackers; if the session log is wired into the event pipeline (now or later), baseline must not record those usernames.

- `crates/agent/src/baseline.rs::tests::observe_event_skips_invalid_usernames` — even from non-honeypot sources, entity values that fail `is_valid_unix_username` are not written. This is the actual operator-hit case: a third-party sshd or PAM module emitted `ssh.login_success` for `AdminGPON` and baseline recorded it.

- `crates/agent/src/baseline.rs::tests::prune_invalid_users_cleans_pre_wave5b_pollution` — `prune_invalid_users()` removes existing pollution from on-disk baseline.json. The boot path calls it once at load so existing prod hosts get cleaned on the next agent restart.

### XDP availability gate (Wave 5b PR-2)

- `crates/agent/src/xdp_availability.rs::tests::xdp_availability_gate_skips_attempts_and_rate_limits_warns` — `should_attempt_xdp()` skips XDP attempts for `RECHECK_INTERVAL_SECS` (5 min) after a failure, AND `mark_failed()` rate-limits the operator-facing WARN to one per window. Pinned the 2026-05-03 prod log-spam where bpffs was unmounted and the agent emitted two WARN lines per block decision (3+ blocks/hour) plus a wasted bpftool subprocess each time.

## Adding a new anchor

When fixing a bug that fits any of these shapes, add the anchor here in the same PR:

- The bug recurred (operator reported it twice).
- The bug is a class, not an instance (drift between two surfaces, stale state crossing a boundary, counter-as-gauge confusion, etc.).
- The fix is structural (new helper, new invariant, new contract) rather than a pointed code change.

Format the entry consistent with the existing ones. Keep the description to one sentence. Reference the historical bug (date or PR number) in the description so a future reader understands the cost of the test.

## Running the verify script

```bash
./scripts/verify-anchor-tests.sh
```

Greps the source tree for every named test in this file. Exits non-zero if any are missing. CI runs this on every PR via `.github/workflows/anchor-tests.yml`.
