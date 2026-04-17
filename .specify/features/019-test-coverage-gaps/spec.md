# Feature Specification: Test Coverage Gaps — Full Plan

**Feature Branch**: `019-test-coverage-gaps`
**Created**: 2026-04-15
**Status**: ✅ Closed. Batch 1 delivered (PR #110, 19 tests). Batches 2-7 subsumed by spec 023 Coverage Closeout (PR #125, 11 batches across ctl/sensor/agent/knowledge-graph/neural/hypervisor/smm/shield) plus spec 026 decomposition phases A/B/C. The modules this spec targeted (incident_enrichment, decision_block_ip, narrative, inline ticks, skills, CTL commands, honeypot, bot commands) all gained coverage under those later specs' crate-level cuts. No remaining work belongs to 019 as such — new test gaps should be filed under the relevant component spec or a fresh coverage spec.
**Priority**: P1 (42.85% coverage → target 55%+)
**Depends on**: nothing
**Superseded by**: spec 023 + spec 026

## Current state (post PR #110)

| Crate | Lines | Tests | Coverage | Notes |
|---|---|---|---|---|
| agent | 75,054 | 596 | ~35% | Biggest gap. 71 files with 0 tests. |
| sensor | 48,460 | 762 | ~55% | Reasonable. Detectors covered. |
| ctl | 24,433 | 221 | ~22% | 31 modules with 0 tests. |
| shield | 5,492 | 93 | ~50% | OK |
| smm | 5,796 | 76 | ~45% | OK |
| dna | 3,801 | 55 | ~45% | OK |
| killchain | 2,184 | 58 | ~60% | Good |
| store | 2,863 | 49 | ~55% | Good |
| agent-guard | 2,558 | 50 | ~55% | Good |
| hypervisor | 2,848 | 25 | ~30% | Small, low priority |
| core | 388 | 3 | ~25% | Small, low priority |
| **Total** | **177,877** | **1,988** | **42.85%** | |

## Principles

1. **Test logic, not I/O.** Extract pure functions. Test inputs → outputs.
2. **No mocking frameworks.** `#[cfg(test)] mod tests` with hand-built structs.
3. **Each batch is a standalone PR on its own branch.** Independent, mergeable alone.
4. **Tests go at the bottom of each source file**, following existing convention.
5. **No test-only refactoring** beyond extracting pure functions from async flows.
6. **Every test must run without network, root, or external services.**

---

## Batch plan

Each batch is designed to be given to ONE AI in ONE session. Branches named `019-batch-N`. All branch from `development`.

---

### Batch 1 — Decision pipeline + auto-rules + setup wizard ✅ DONE

**Branch**: `019-test-coverage-gaps` (PR #110)
**Tests added**: 19
**Status**: Merged/ready to merge

Covered: `decision_block_ip`, `decision_cooldown`, `decision_skill_actions`, `decisions`, `incident_autodismiss`, `incident_decision_eval`, `incident_obvious`, `narrative_autofp`, `trust_rules`, `setup.rs` pure functions.

---

### Batch 2 — Decision pipeline remainder + incident enrichment

**Branch**: `019-batch-2`
**Target**: ~20 tests
**Crate**: agent

| File | Lines | What to test |
|---|---|---|
| `decision_honeypot.rs` | 101 | Honeypot eligibility: port mapping, IP check, protocol match, max concurrent sessions |
| `decision_confirmation.rs` | 67 | Confirmation required vs auto-approve: severity threshold, trust rules match, dry_run bypass |
| `incident_enrichment.rs` | 305 | Enrichment logic: GeoIP lookup result parsing, AbuseIPDB score interpretation, enrichment merge. Extract pure functions from async flow. |
| `incident_notifications.rs` | 214 | Notification routing: severity-to-channel mapping, cooldown check, batch grouping logic |
| `incident_abuseipdb.rs` | 219 | Score threshold parsing, confidence calculation, report count interpretation |
| `honeypot_post_session.rs` | 280 | Session analysis: command classification, credential extraction, attacker fingerprint building |

**Instructions for AI**:
1. Read each file. Identify pure logic entangled with async/IO.
2. Extract testable functions (like Batch 1 did with `check_block_eligibility`, `is_obvious_attack`, etc.).
3. Add `#[cfg(test)] mod tests` at bottom of each file.
4. `cargo clippy --workspace -- -D warnings` must pass.
5. `cargo fmt` must pass.
6. `cargo test -p innerwarden-agent` must pass.

---

### Batch 3 — Config validation + narrative

**Branch**: `019-batch-3`
**Target**: ~25 tests
**Crate**: agent

| File | Lines | What to test |
|---|---|---|
| `config.rs` | 2,654 | Default values for all sections. Invalid value rejection (negative intervals, empty strings, out-of-range ports, invalid URLs). Config merge: file + env + defaults. Feature flag interactions. Sensitivity level mapping. |
| `narrative_daily_summary.rs` | 192 | Summary text generation: empty day, single incident, multiple incidents, severity breakdown, top attackers formatting |
| `narrative_incident_ingest.rs` | 186 | Incident narrative text building: entity formatting, evidence summarization, MITRE technique description |
| `briefing.rs` | 332 | Briefing content assembly: threat level calculation, active threats count, system status aggregation |

**Instructions for AI**:
1. `config.rs` is the highest-value target. It has 2,654 lines but only 9 tests. Focus on validation/defaults.
2. For narrative files, test text generation functions — they're usually pure (input incident → output string).
3. Same quality bar: clippy clean, fmt clean, all tests pass.

---

### Batch 4 — Skills builtin + kill chain response

**Branch**: `019-batch-4`
**Target**: ~25 tests
**Crate**: agent

| File | Lines | What to test |
|---|---|---|
| `skills/builtin/kill_chain_response.rs` | 457 | Response action selection per chain type (reverse_shell, bind_shell, code_inject, etc.). Severity escalation. Multi-step response sequencing. |
| `skills/builtin/block_ip_nftables.rs` | 96 | nftables command string generation. Set name construction. TTL formatting. |
| `skills/builtin/block_ip_iptables.rs` | 96 | iptables command construction. Chain selection. Duration-to-timeout conversion. |
| `skills/builtin/block_ip_ufw.rs` | 87 | ufw command construction. Rule formatting. |
| `skills/builtin/block_ip_xdp.rs` | 216 | XDP map key construction. IP-to-bytes conversion. TTL encoding. |
| `skills/builtin/block_ip_pf.rs` | 154 | pf table command construction (macOS/BSD). |
| `skills/builtin/suspend_user_sudo.rs` | 367 | sudoers line construction. User validation. Duration formatting. Has 1 test — add more edge cases. |
| `skills/builtin/kill_process.rs` | 247 | Signal selection per process type. PID validation. Has 1 test — add more. |
| `skills/builtin/block_container.rs` | 341 | Docker/podman command construction. Container ID validation. Has 1 test — add more. |

**Instructions for AI**:
1. Skills construct shell commands. Test the COMMAND STRINGS, not execution. Extract command-building into pure functions.
2. **Critical**: these commands run as root. Malformed commands = security risk. Test edge cases: empty IPs, IPv6, special characters, very long TTLs.
3. DO NOT test functions that call `Command::new()` — test the argument construction.

---

### Batch 5 — Inline modules + ticks

**Branch**: `019-batch-5`
**Target**: ~20 tests
**Crate**: agent

| File | Lines | What to test |
|---|---|---|
| `dna_inline.rs` | 349 | Atom extraction from incidents. DNA hash computation. Fuzzy match scoring. Feature vector building. |
| `shield_inline.rs` | 335 | Rate calculation. SYN ratio computation. Escalation state transitions. Threshold comparison. |
| `killchain_inline.rs` | 205 | Bitmask operations: set stage, check pattern match, extract matched pattern name. PID tracking. |
| `hypervisor_tick.rs` | 320 | Probe result interpretation: CPUID anomaly detection, timing deviation threshold, DMI string matching. |
| `firmware_tick.rs` | 295 | Check result classification: MSR value validation, SPI flash hash comparison, UEFI variable parsing. |

**Instructions for AI**:
1. These are integration wrappers. They call into library crates (dna, killchain, etc.) but have their own logic.
2. Test the WRAPPER logic, not the library. Example: `dna_inline.rs` builds features from `Incident` — test that mapping.
3. Same quality bar.

---

### Batch 6 — CTL commands (pure logic extraction)

**Branch**: `019-batch-6`
**Target**: ~30 tests
**Crate**: ctl

| File | Lines | What to test |
|---|---|---|
| `commands/ops.rs` | 2,144 | Sensitivity tuning calculation (level → config values). Fail2ban config generation (jail.local template). Doctor diagnostic checks (parse results). Backup path construction. |
| `commands/notify.rs` | 1,152 | Channel config construction. Validation (empty token, invalid URL, missing chat_id). Digest interval parsing. Alert level filtering. |
| `commands/module.rs` | 1,110 | Module path resolution. Manifest merging. Enable/disable toggle logic. Search filtering. |
| `commands/history.rs` | 902 | Query construction. Time range parsing ("24h", "7d", "30d"). Severity filtering. Output formatting. |
| `commands/status.rs` | 573 | Status aggregation. Service state interpretation. Uptime calculation. |
| `commands/ai.rs` | 510 | Provider validation. Model name normalization. API key env var name construction. |
| `commands/agent.rs` | 489 | Agent state parsing. PID file reading. Config path resolution. |
| `calibrate.rs` | 217 | Calibration score computation. Threshold adjustment. Sensitivity mapping. |
| `helpers.rs` | 189 | Path construction. Size formatting. Duration formatting. |

**Instructions for AI**:
1. Most of these are CLI commands with heavy I/O (file reads, systemd calls, dialoguer prompts).
2. **Only test pure logic.** Extract calculation/formatting/validation functions.
3. `helpers.rs` and `calibrate.rs` should be the easiest — likely already pure.
4. For `ops.rs` (2,144 lines), focus on sensitivity tuning and fail2ban config generation — those are the most impactful.

---

### Batch 7 — Honeypot + bot commands (stretch)

**Branch**: `019-batch-7`
**Target**: ~20 tests
**Crate**: agent

| File | Lines | What to test |
|---|---|---|
| `skills/honeypot/mod.rs` | 3,157 | Session state machine: connection → interaction → classification. Port service mapping. Banner generation. Has 13 tests — add state transition edge cases. |
| `skills/honeypot/ssh_interact.rs` | 801 | Command parsing. Response generation for fake shell commands. Credential logging. Has 3 tests — add more commands. |
| `skills/honeypot/custom_responses.rs` | 192 | Custom response matching. Template substitution. Has 2 tests — add edge cases. |
| `bot_commands.rs` | 1,042 | Command parsing: extract command name and args from Telegram message text. Help text generation. Permission check. |
| `bot_helpers.rs` | 938 | HTML escaping. Message truncation. Keyboard construction. Status emoji mapping. Severity-to-color mapping. |
| `bot_actions.rs` | 457 | Action dispatch: callback data parsing, action validation, response formatting. |

**Instructions for AI**:
1. Honeypot files already have some tests. Read existing tests first, then add missing edge cases.
2. Bot files are Telegram-dependent but have pure formatting logic. Test the formatting, not the API calls.
3. `bot_helpers.rs` (938 lines of formatting) should yield easy high-value tests.

---

## Summary table

| Batch | Branch | Crate | Files | Target tests | Estimated coverage lift |
|---|---|---|---|---|---|
| 1 ✅ | `019-test-coverage-gaps` | agent + ctl | 11 | 19 | +0.5% |
| 2 | `019-batch-2` | agent | 6 | ~20 | +0.8% |
| 3 | `019-batch-3` | agent | 4 | ~25 | +1.5% |
| 4 | `019-batch-4` | agent | 9 | ~25 | +1.2% |
| 5 | `019-batch-5` | agent | 5 | ~20 | +0.8% |
| 6 | `019-batch-6` | ctl | 9 | ~30 | +1.5% |
| 7 | `019-batch-7` | agent | 6 | ~20 | +1.0% |
| **Total** | | | **50** | **~160** | **42.85% → ~50%** |

## Execution rules (for any AI working on a batch)

1. **Branch from `development`**, not from another batch branch.
2. **`cargo clippy --workspace -- -D warnings`** must be clean. CI uses `-D warnings`.
3. **`cargo fmt`** must be run before commit. CI checks formatting.
4. **No changes to non-test code** except extracting pure functions (like Batch 1 did).
5. **PR title format**: `test(crate): batch N — description`
6. **PR base**: `development` (NOT `main`).
7. **Each test must have a comment** explaining what code path it exercises.
8. **No `unwrap()` in test setup** — use proper construction or `panic!` with message.
9. **Check existing tests first** — some files already have a few tests. Don't duplicate.
10. **Read the file before writing tests** — understand the function's contract.

## Acceptance criteria

- [ ] All 7 batches merged
- [ ] `make test` passes (~2150+ tests)
- [ ] Codecov shows 48%+ (stretch: 50%+)
- [ ] Zero clippy warnings
- [ ] No test requires network, root, or external services
- [ ] Every previously-untested P0/P1 module has at least one meaningful test

## Out of scope

- **Dashboard** (9,660 lines) — needs HTTP test harness. Separate spec.
- **Telegram API integration tests** — needs mock server. Separate spec.
- **sensor-ebpf** (3,276 lines) — `#![no_std]`, eBPF bytecode. Cannot run standard tests.
- **Sensor detectors** — already at 762 tests, reasonable coverage.
- **Satellite crates with 45%+ coverage** — shield, smm, dna, killchain, store, agent-guard.
