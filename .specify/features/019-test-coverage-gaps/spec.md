# Feature Specification: Test Coverage Gaps

**Feature Branch**: `019-test-coverage-gaps`
**Created**: 2026-04-15
**Status**: Draft
**Priority**: P1 (blocks CI confidence — 42.85% coverage, agent crate is the primary gap)
**Depends on**: nothing (independent work)

## Problem

Codecov reports 42.85% line coverage. The agent crate has 75K lines but only 581 tests — the largest gap. The ctl crate has 24K lines with 217 tests but 78% of its code (18K lines) has zero tests. Many critical code paths (decision pipeline, auto-rules, setup wizard) are completely untested.

## Audit summary

### Agent crate (75K lines, 581 tests)

| Module group | Lines | Tests | Coverage | Priority |
|---|---|---|---|---|
| **Decision pipeline** (6 files) | 1,175 | 0 | 0% | **P0** |
| **Auto-rules** (3 files) | 326 | 0 | 0% | **P0** |
| **Config** | 2,654 | 9 | minimal | P1 |
| **Dashboard** (16 files) | 9,660 | 24 | 0.25% | P2 (HTTP-heavy) |
| **Skills/builtin** (12 files) | 3,400 | 12 | minimal | P1 |
| **Skills/honeypot** (5 files) | 5,308 | 44 | 0.8% | P2 |
| **Telegram** | 3,360 | 45 | 1.3% | P2 |
| **Bot commands/helpers/actions** | 2,437 | 0 | 0% | P2 |
| **Inline modules** (dna, shield, killchain, hypervisor, firmware) | 1,504 | 0 | 0% | P1 |
| **Incident pipeline** (enrichment, notifications, decision_eval, autodismiss, obvious) | 1,109 | 0 | 0% | P0 |
| **Narrative** (daily_summary, incident_ingest, autofp) | 487 | 0 | 0% | P1 |
| **Briefing** | 332 | 0 | 0% | P2 |

#### Top 20 largest untested agent modules

| File | Lines | What it does |
|---|---|---|
| `bot_commands.rs` | 1,042 | Telegram bot command handlers |
| `bot_helpers.rs` | 938 | Telegram formatting/helpers |
| `bot_actions.rs` | 457 | Telegram action execution |
| `dna_inline.rs` | 349 | Threat DNA inline integration |
| `shield_inline.rs` | 335 | Shield inline integration |
| `incident_decision_eval.rs` | 335 | Incident decision evaluation |
| `briefing.rs` | 332 | Briefing generation |
| `hypervisor_tick.rs` | 320 | Hypervisor periodic check |
| `incident_enrichment.rs` | 305 | Incident enrichment pipeline |
| `decisions.rs` | 301 | Decision orchestrator |
| `firmware_tick.rs` | 295 | Firmware periodic check |
| `decision_cooldown.rs` | 293 | Decision cooldown logic |
| `honeypot_post_session.rs` | 280 | Honeypot session post-processing |
| `decision_block_ip.rs` | 247 | IP blocking decision |
| `incident_abuseipdb.rs` | 219 | AbuseIPDB enrichment |
| `incident_notifications.rs` | 214 | Notification dispatch |
| `killchain_inline.rs` | 205 | Kill chain inline integration |
| `narrative_daily_summary.rs` | 192 | Daily narrative summary |
| `narrative_incident_ingest.rs` | 186 | Narrative incident ingestion |
| `incident_obvious.rs` | 168 | Obvious incident classification |

### CTL crate (24K lines, 217 tests)

| Module group | Lines | Tests | Priority |
|---|---|---|---|
| **Setup wizard** (`setup.rs`) | 1,352 | 0 | **P0** |
| **Ops** (`ops.rs`) | 2,144 | 0 | P1 |
| **Notify** (`notify.rs`) | 1,152 | 0 | P1 |
| **Module lifecycle** (`module.rs`) | 1,110 | 0 | P1 |
| **History** (`history.rs`) | 902 | 0 | P2 |
| **Status** (`status.rs`) | 573 | 0 | P2 |
| **AI setup** (`ai.rs`) | 510 | 0 | P2 |
| **Agent control** (`agent.rs`) | 489 | 0 | P2 |
| **Response** (`response.rs`) | 443 | 0 | P2 |
| **Integrations** (`integrations.rs`) | 378 | 0 | P2 |
| **Firmware** (`firmware.rs`) | 328 | 0 | P2 |
| **Update** (`update.rs`) | 313 | 0 | P2 |
| **Watchdog** (`watchdog.rs`) | 303 | 0 | P2 |
| **Calibrate** (`calibrate.rs`) | 217 | 0 | P2 |
| **Helpers** (`helpers.rs`) | 189 | 0 | P2 |
| **Welcome** (`welcome.rs`) | 152 | 0 | P2 |

#### Already tested (good coverage)

| Module | Lines | Tests |
|---|---|---|
| `module_validator.rs` | 882 | 23 |
| `module_manifest.rs` | 806 | 22 |
| `upgrade.rs` | 753 | 27 |
| `config_editor.rs` | 490 | 19 |
| `scan.rs` | 2,021 | 15 |
| `main.rs` | 2,930 | 30 |
| All 5 capabilities | 2,045 | 45 |

## Scope

### In scope — Phase 1 (P0, testable without mocks of external systems)

**Agent — Decision pipeline** (1,175 lines, 0 tests):
- `decisions.rs` — orchestration logic, decision routing
- `decision_cooldown.rs` — cooldown window tracking, expiry, duplicate prevention
- `decision_block_ip.rs` — IP block decision with allowlist checks
- `decision_honeypot.rs` — honeypot routing decisions
- `decision_confirmation.rs` — confirmation flow logic
- `decision_skill_actions.rs` — skill action dispatch

**Agent — Auto-rules** (326 lines, 0 tests):
- `narrative_autofp.rs` — auto false-positive detection
- `incident_autodismiss.rs` — auto-dismiss logic
- `trust_rules.rs` — trust rule evaluation

**Agent — Incident pipeline** (1,109 lines, 0 tests):
- `incident_decision_eval.rs` — decision evaluation for incidents
- `incident_obvious.rs` — obvious incident classification
- `incident_enrichment.rs` — enrichment pipeline (mockable parts)

**CTL — Setup wizard** (1,352 lines, 0 tests):
- `setup.rs` — pure functions: `ai_provider_defaults`, `count_failed_setup_checks`, `setup_verdict`, `setup_remediation_command`, struct construction

### In scope — Phase 2 (P1, needs some test infrastructure)

**Agent — Config** (2,654 lines, 9 tests):
- Config parsing, validation, defaults, merge logic

**Agent — Skills/builtin** (3,400 lines, 12 tests):
- `kill_chain_response.rs` — 457 lines, 0 tests
- `block_ip_nftables.rs`, `block_ip_iptables.rs`, `block_ip_ufw.rs`, `block_ip_xdp.rs` — firewall command construction (testable without root)

**Agent — Inline modules** (1,504 lines, 0 tests):
- `dna_inline.rs`, `shield_inline.rs`, `killchain_inline.rs` — integration wrappers
- `hypervisor_tick.rs`, `firmware_tick.rs` — periodic check logic

**Agent — Narrative** (487 lines, 0 tests):
- `narrative_daily_summary.rs`, `narrative_incident_ingest.rs`, `narrative_autofp.rs`

**CTL — Ops** (2,144 lines, 0 tests):
- Pure logic: sensitivity tuning calculation, config validation, diagnostic checks

**CTL — Notify** (1,152 lines, 0 tests):
- Config construction, validation, channel routing logic

### Out of scope (P2 — hard to test unitarily, deferred)

- **Dashboard** (9,660 lines) — HTTP handlers, HTML/JS responses. Needs integration test harness.
- **Telegram** (3,360 lines) — API integration, already at 45 tests.
- **Bot commands/helpers/actions** (2,437 lines) — Telegram API dependent.
- **Briefing** (332 lines) — text generation, low risk.
- **CTL interactive commands** — `dialoguer` dependent (stdin prompts).
- **CTL commands that call systemd/sudo** — need real system.

## Principles

1. **Test logic, not I/O.** Extract pure functions from modules that mix logic with HTTP/filesystem/network calls. Test the extracted logic.
2. **No mocking frameworks.** Use Rust's built-in `#[cfg(test)]` modules with hand-built test structs where needed.
3. **Test the contract, not the implementation.** Decision pipeline tests verify "given these inputs, this decision is produced" — not internal state transitions.
4. **Each test file self-contained.** Tests go in `#[cfg(test)] mod tests` at the bottom of each source file, following existing project convention.
5. **No test-only refactoring.** If a function is untestable because it's entangled with I/O, add tests for the parts that ARE testable. Refactoring to make things testable is a separate spec.

## Proposed changes

### Change 1 — Decision pipeline tests (~30 tests)

**Where**: `crates/agent/src/decision_*.rs` (6 files)

Tests for:
- `decision_cooldown.rs`: cooldown window creation, expiry check, duplicate detection, window overlap
- `decision_block_ip.rs`: allowlist bypass, private IP skip, duplicate block prevention, severity threshold
- `decision_honeypot.rs`: honeypot eligibility check, port mapping
- `decision_confirmation.rs`: confirmation required vs auto-approve logic
- `decision_skill_actions.rs`: skill dispatch routing, parameter validation
- `decisions.rs`: end-to-end decision routing (incident → correct decision type)

### Change 2 — Auto-rules and incident pipeline tests (~20 tests)

**Where**: `crates/agent/src/narrative_autofp.rs`, `incident_autodismiss.rs`, `trust_rules.rs`, `incident_decision_eval.rs`, `incident_obvious.rs`

Tests for:
- Auto-FP: pattern matching, confidence threshold, repeated-source detection
- Auto-dismiss: severity filter, age check, source reputation
- Trust rules: trust score computation, rule evaluation
- Decision eval: severity-to-action mapping, override logic
- Obvious classification: known-benign patterns, known-attack patterns

### Change 3 — Setup wizard pure function tests (~15 tests)

**Where**: `crates/ctl/src/commands/setup.rs`

Tests for:
- `ai_provider_defaults`: all 10+ providers return valid defaults
- `count_failed_setup_checks`: edge cases (0, all pass, all fail, mixed)
- `setup_verdict`: threshold logic (0 failures = pass, 1+ = fail, critical vs warning)
- `setup_remediation_command`: correct command generation per check type and OS

### Change 4 — Config validation tests (~15 tests)

**Where**: `crates/agent/src/config.rs`

Tests for:
- Default values for all config sections
- Invalid value rejection (negative intervals, empty strings, out-of-range ports)
- Config merge logic (file + env + defaults)
- Feature flag interactions

### Change 5 — Skills builtin command construction tests (~15 tests)

**Where**: `crates/agent/src/skills/builtin/`

Tests for:
- `kill_chain_response.rs`: response action selection per chain type
- `block_ip_*.rs`: correct iptables/nftables/ufw/pf command string generation
- Parameter validation (valid IP, valid port range)

### Change 6 — Inline module integration tests (~10 tests)

**Where**: `crates/agent/src/*_inline.rs`, `*_tick.rs`

Tests for:
- `dna_inline.rs`: atom extraction, DNA hash computation
- `killchain_inline.rs`: bitmask operations, pattern matching
- `hypervisor_tick.rs`: probe result interpretation
- `firmware_tick.rs`: check result classification

## Execution plan

Multi-session work. Each phase is independently deployable.

### Session 1 — Phase 1 (P0)
1. Decision pipeline tests (Change 1) — ~30 tests
2. Auto-rules + incident pipeline tests (Change 2) — ~20 tests
3. Setup wizard tests (Change 3) — ~15 tests
4. `make test` — all pass
5. Commit on branch `019-test-coverage-gaps`

### Session 2 — Phase 2 (P1)
1. Config tests (Change 4) — ~15 tests
2. Skills tests (Change 5) — ~15 tests
3. Inline module tests (Change 6) — ~10 tests
4. CTL ops/notify pure logic tests — ~10 tests
5. `make test` — all pass

### Target
- Phase 1: +65 tests → ~2540 total
- Phase 2: +50 tests → ~2590 total
- Estimated coverage lift: 42.85% → ~48-50%

## Acceptance criteria

### Phase 1
- [ ] All 6 decision pipeline files have `#[cfg(test)] mod tests` with meaningful tests
- [ ] All 3 auto-rule files have tests
- [ ] `incident_decision_eval.rs` and `incident_obvious.rs` have tests
- [ ] `setup.rs` pure functions have tests
- [ ] `make test` passes with 0 failures
- [ ] No test requires network, root, or external services

### Phase 2
- [ ] `config.rs` has validation and default tests
- [ ] Skills builtin command construction tested
- [ ] Inline module logic tested
- [ ] CTL ops/notify pure logic tested
- [ ] `make test` passes with 0 failures
- [ ] Coverage reaches ~48%+

## Risks

### Risk — Tests couple to internal implementation
**Mitigation**: test public contract (inputs → outputs), not internal state. If a refactor breaks tests, the tests were too tight.

### Risk — Some modules are untestable without refactoring
**Mitigation**: Phase 1 targets only modules with extractable pure logic. Entangled modules are Phase 2 or out of scope. No test-driven refactoring in this spec.

### Risk — Test count inflation without real coverage
**Mitigation**: each test must exercise a distinct code path or edge case. No trivial "assert true" tests. Codecov delta must show line coverage improvement.

## Related work

- **Spec 018** — Autonomy Gap (agent detects but never acts). Test coverage for decision pipeline directly validates the fix path.
- **Spec 015** — Graph Signal Quality. Detector tests already exist (29 tests). This spec does not add more detector tests.
- **Spec 016** — SQLite Store. Store crate already at 49 tests (good coverage). Not in scope.
