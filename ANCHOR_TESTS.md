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
