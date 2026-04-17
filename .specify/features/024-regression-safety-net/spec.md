# Feature Specification: Regression Safety Net

**Feature Branch**: `024-regression-safety-net`
**Created**: 2026-04-17
**Status**: DRAFT
**Priority**: P0 (production trust is broken — fixing one thing keeps breaking another)
**Depends on**: spec 005 (Intelligent Notifications) for Phase 3 only
**Related**: all future behavior-change PRs

## Origin

Operator feedback (2026-04-17): "não confio na nossa estrutura de regras — arrumamos uma coisa e quebramos outra. Ex: resolve tracker, Telegram recebe 300 mensagens/dia. Resolve Telegram, tracker para."

This is a **classic whack-a-mole symptom** of three absent safety nets:

1. No end-to-end scenario tests asserting **expected volumes** per subsystem (tracker → incidents → telegram → blocks).
2. No behavioral contract between subsystems — changing a threshold in one silently perturbs the downstream subsystem.
3. No production drift detection — the 300 msgs/day was discovered by the operator reading their phone, not by metrics.

Spec 005 (Intelligent Notifications) was drafted 2026-04-04 for the noise problem and never shipped. Spec 019 and 023 add unit-test coverage but do nothing for cross-subsystem regressions.

## Problem

The agent is 11 subsystems (tracker, gate, blocker, shield, killchain, DNA, knowledge graph, honeypot, notification, decision lifecycle, correlation) that communicate through files, sqlite, mpsc channels, and in-memory state. Every one of those is tested in isolation, yet production behavior is a function of their **composition**. We have no test for composition.

Current production smells the operator has reported over the last 30 days:

| Symptom | Root cause (inferred) |
|---|---|
| 300 Telegram msgs/day after a tracker fix | gate thresholds derived from tracker volume; changing tracker sensitivity detuned the gate |
| Tracker stopped after a Telegram fix | shared `should_notify` path mutated to skip gate-only branches, inadvertently skipping tracker emits |
| 8 zombie ufw rules after deploy | `response_lifecycle.register()` called for invalid targets (fixed in PR #124, but the same class of bug can recur elsewhere) |
| 40+ DATA_EXFIL/day against agent's own threads | `killchain_inline` had no notion of "platform self" — fixed in PR #124, recurs if sensor adds a new event kind |
| Alerts with 28 re-blocked IPs over 24h | dedup cooldown expired faster than block TTL — no test asserts the relationship |

Every one of these could have been caught by a composition test run on every PR.

## Goals

- **Any PR** that changes the volume of Telegram/Slack messages, blocks, or incidents for a canonical scenario **fails CI** — whether intentional or not.
- **Production drift** (sudden jump or collapse in any of those volumes) is detected automatically within 1 hour via exported metrics + alert rule.
- **Subsystem boundaries** have explicit contracts (input/output shape + volume envelope), tested independently from the compositional tests.
- **Zero new behavior** in production unless a contract test for it exists.

## Non-goals

- Replacing unit tests (019, 022, 023 still needed).
- Rewriting the notification pipeline (that is spec 005).
- Real attack simulation against prod (replay-qa already covers this).
- Fuzz testing individual components.

## Approach — three layers, built in sequence

### Layer 1: Scenario volume tests (Phase A — P0)

Extend the existing `make replay-qa` harness with **canonical scenarios** and **volume envelope assertions**. Each scenario is a fixed input trace (events-*.jsonl + decisions + honeypot sessions), a fixed config, and an assertion block: "this scenario produces N±tolerance incidents, M±tolerance telegram messages, K±tolerance blocks".

Initial canonical scenarios (6 total, ordered by blast radius):

| # | Scenario | Input trace | Expected output envelope |
|---|---|---|---|
| 1 | SSH brute-force single IP | 20 `ssh.login_failed` events over 5 min from one IP | 1 incident, ≤1 telegram, 1 block |
| 2 | SSH brute-force coordinated (10 IPs) | 5 attempts each from 10 distinct IPs in 5 min | 10 incidents, 1 telegram (grouped), 10 blocks |
| 3 | Honeypot hit from known-bad IP | 1 tcp connect to :2222 from IP in AbuseIPDB feed | 1 incident, 1 telegram, 1 block |
| 4 | Honeypot hit from unknown IP | 1 tcp connect to :2222 from clean IP | 1 incident, ≤1 telegram, 0 blocks (honeypot lets it in) |
| 5 | Port scan single IP | 50 connections to different ports in 30s | 1 incident, ≤1 telegram, 1 block |
| 6 | DDoS SYN flood | 10k syn packets/s for 60s from 100 IPs | 1 incident, 1 telegram, ≥1 mitigation (cloudflare push or xdp block) |

Each scenario is a directory under `testdata/scenarios/<N>-<name>/` containing:

```
input/
  events-2026-01-01.jsonl     # fixed input trace
  config.overrides.toml       # any per-scenario config deltas
expected.json                 # envelope assertions
```

`expected.json` shape:

```json
{
  "incidents":      { "min": 1, "max": 1 },
  "telegram_msgs":  { "min": 0, "max": 1 },
  "blocks":         { "min": 1, "max": 1 },
  "honeypot_sessions": { "min": 0, "max": 0 },
  "decisions_auto_executed": { "min": 1, "max": 1 }
}
```

The harness runs the agent against the input, reads the resulting sqlite DB + decisions JSONL + (a mocked) telegram outbox, and asserts each count is in range. Any PR that drifts outside the envelope fails CI.

`make scenario-qa` (new target) runs all scenarios. Added to CI alongside `make test` and `make replay-qa`.

**Deliverables for Phase A**:
- `testdata/scenarios/` directory with 6 scenarios (input + expected.json each).
- `scripts/scenario_qa.sh` runner.
- `Makefile` target `scenario-qa`.
- CI workflow step invoking `make scenario-qa`.
- A `MockTelegramClient` (or equivalent) the agent uses when env `INNERWARDEN_MOCK_TELEGRAM=1` is set — writes to `<data_dir>/telegram-outbox.jsonl` instead of the real API.

**Acceptance**: scenarios 1–6 all pass on `main`; any PR that changes a threshold, cooldown, or gate condition without updating the matching scenario's expected.json fails CI.

### Layer 2: Production drift metrics (Phase B — P1)

Export counters already tracked internally as Prometheus-style metrics on `/metrics`, and define alert rules on each. This catches whatever the scenario tests miss (config drift, upstream data changes, memory leaks changing behavior).

Metrics to expose (most already counted internally — just need exposure):

| Metric | Source | Drift alert |
|---|---|---|
| `innerwarden_incidents_per_hour{severity}` | sqlite `incidents` table rate | ±3σ from 7-day rolling mean |
| `innerwarden_telegram_msgs_per_hour` | notification_gate counter | >50/h for 2h → high; >200/h for 1h → critical |
| `innerwarden_blocks_per_hour{backend}` | response_lifecycle counter | ±3σ from 7-day rolling mean |
| `innerwarden_honeypot_sessions_per_hour` | always-on listener counter | 0 for 24h → warn (honeypot likely broken) |
| `innerwarden_tracker_detections_per_hour{pattern}` | killchain tracker stats | 0 for 24h when incidents > 10 → warn (tracker silent while world burns) |
| `innerwarden_orphaned_responses_total` | response_lifecycle totals | any increment → critical alert (was the whole PR #124 class of bug) |
| `innerwarden_revert_failures_per_hour` | response_lifecycle counter | >10/h → warn |
| `innerwarden_ai_provider_errors_per_hour{provider}` | ai module counter | >5/h → warn |
| `innerwarden_gate_suppressed_total` | notification_gate counter | divergence from incidents count = gate effectiveness signal |
| `innerwarden_event_rate_per_hour{source}` | baseline learner | existing anomaly detector, just export the value |

**Deliverables for Phase B**:
- `/metrics` endpoint on the agent's dashboard (Prometheus text format).
- `crates/agent/src/telemetry.rs` extended with a counter registry.
- Alert rules as a separate file (`docs/prometheus-alerts.yaml`) that any Prometheus install can consume.
- Dashboard tab "Health → Metrics drift" showing the raw numbers with 7-day trend.

**Acceptance**: all metrics exposed; alert rules documented; dashboard surfaces drift without needing external Prometheus.

### Layer 3: Intelligent Notifications (spec 005 implementation — P1)

Spec 005 exists and blocks Phase 3 of this spec. Phases A and B don't depend on it.

When 005 lands:
- Phase A scenarios that currently assert "≤1 telegram" tighten to "exactly 1 telegram (grouped)".
- Phase B telegram-msgs-per-hour threshold drops from "50/h warn" to "10/h warn".
- A new scenario (#7) asserts: 100 incidents from same IP in 1h → 1 grouped telegram.

**Deliverable**: spec 005 implemented per its own acceptance criteria + scenario #7 added.

## Contract tests (supporting infrastructure — part of Phase A)

Every subsystem boundary gets a unit test asserting its **output envelope per input**, independent of other subsystems. These catch the "I changed tracker and gate drifted" pattern earlier than scenario-qa.

Subsystems and their contracts:

| Subsystem | Input | Output contract |
|---|---|---|
| `notification_gate` | Incident | exactly one of: `SendNow`, `DailyBriefingOnly`, `Drop`. No I/O, no side effects. |
| `response_lifecycle::register` | (type, backend, target, id, ttl) | returns id; caller asserts is_tracked(target) == true. Invalid targets rejected. |
| `killchain::PidTracker::process_event` | Event JSON | returns Vec<Incident>; state mutation visible via get_state. Excluded comms skip state creation. |
| `decision_cooldown` | (incident, now) | allows or denies; never mutates on deny. |
| `correlation_response::check_repeat_offenders` | state.ip_reputations | returns Vec<IP to escalate>; invalid IPs filtered pre-escalation. |

These tests live next to the unit — they are the formal spec of each subsystem's contract. Breaking the contract without updating the test is not allowed.

## Sequencing

| Phase | Deliverable | Est. effort | Blocks |
|---|---|---|---|
| A.1 | MockTelegramClient + expected.json schema + scenario 1 runner | 1 session | A.2 |
| A.2 | Scenarios 2–6 input traces + expected files | 1 session | A.3 |
| A.3 | scenario-qa Makefile target + CI wiring | 0.5 session | Phase B |
| A.4 | Contract tests for 5 boundary subsystems | 2 sessions | — |
| B.1 | `/metrics` endpoint skeleton + 3 initial metrics | 1 session | B.2 |
| B.2 | Remaining 7 metrics wired | 1 session | B.3 |
| B.3 | Dashboard "drift" tab + alert rules doc | 1 session | — |
| C | Spec 005 implementation (separate track) | see 005 | full value |

Total before spec 005: **~7 AI sessions**. Worth it even if spec 005 never ships — Phase A alone stops the whack-a-mole.

## Acceptance criteria

- [ ] `make scenario-qa` runs all 6 canonical scenarios and passes on `main`.
- [ ] A deliberate threshold regression (e.g. dropping `notification_gate` suppression) flips CI red on a test PR.
- [ ] `/metrics` returns Prometheus text with all 10 metrics listed above.
- [ ] Dashboard "Health → Metrics drift" renders the 7-day trend.
- [ ] Every subsystem in the "contract tests" table has a `#[cfg(test)]` module asserting its input/output envelope.
- [ ] `docs/prometheus-alerts.yaml` has alert rules for each metric with documented rationale.
- [ ] Any new gate/threshold/cooldown PR after this lands requires the author to update `expected.json` for affected scenarios (enforced by CODEOWNERS / PR template).

## Out of scope

- Real external Prometheus server (operator decides if they run one; we just expose `/metrics`).
- Grafana dashboards (docs-only, out of repo).
- Scenario generation from production data (could be stretch — for now scenarios are handwritten fixtures).
- End-to-end honeypot interaction (the always-on listener is tested in isolation; a full attacker session replay is separate).

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Scenarios become stale as attack patterns evolve | Each scenario has a `last_reviewed` field; CI warns if > 6 months old. |
| MockTelegramClient diverges from real client contract | Contract test on the real `TelegramClient` trait implementation — same interface, same outputs for same input. |
| Metrics cause cardinality explosion (e.g. per-IP labels) | Only bounded labels (severity, backend, pattern); never per-IP or per-incident. |
| Alert thresholds are wrong initially | Start with warn-level only for 7 days; promote to critical after calibration. |
| Spec 005 blocks forever, operator keeps seeing noise | Phase B exposes the noise as a metric — operator has a knob (alert threshold) even without 005. |

## References

- Spec 005: `.specify/features/005-intelligent-notifications/spec.md` — blocks Phase 3.
- `crates/agent/src/notification_gate.rs` (717 lines) — current gate logic.
- `crates/agent/src/telemetry.rs` (327 lines) — existing telemetry scaffolding.
- `scripts/replay_qa.sh` — existing replay harness to extend.
- PR #124 — recent whack-a-mole: killchain / kill_chain sqlite / honeypot mode / cloudflare dup / invalid IP cascade — 4 bugs that composition tests would have prevented.
