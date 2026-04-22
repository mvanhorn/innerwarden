# Feature Specification: Defender Brain Feature Alignment

**Feature Branch**: `031-defender-brain-feature-alignment`
**Created**: 2026-04-22
**Status**: Draft
**Input**: Production investigation 2026-04-22 of the Dashboard `Brain` tab. 5,713 suggestions logged, 12.4% AI agreement, 0 confirmed TP, 5 marked FP. Every recent `brain_top3` is identical (`capture_forensics 21%, enable_outbound_monitor 13%, enable_ssh_rate_limit 6%`) regardless of incident. `brain_value` sits at ~0.35 across the dataset.

## Origin

The defender brain is an AlphaZero-trained dual-head network (19,615 params, 72 inputs → 30 actions) embedded at build time as `crates/agent/src/defender-brain.bin`. Trained in `innerwarden-gym` via adversarial self-play (V4, 6 rounds, 200K+ games). Shipped with the agent; in-process supervised retrain runs daily at 03:30 UTC using `brain-log.json` entries.

Inspection of `crates/agent/src/incident_decision_eval.rs::build_brain_features` shows the function allocates `[f32; 72]` and fills positions **0..=29 only**. Positions 30..=71 stay at zero. The gym's own `innerwarden-gym/src/production_features.rs` acknowledges this explicitly:

```
//!   [30-71] reserved (gym fills with enriched simulation state)
```

So 42 out of 72 inputs (58% of the model's observation) are constant zero in production while the gym trains against rich simulation state. Classic training-serving skew, documented and left open.

## Problem statement

1. **Bias collapse**. With 42 features constant at zero, the policy head receives mostly degenerate input. The network converges to a near-constant posterior that matches the prior distribution of training actions. Every production incident gets the same top-3.

2. **Low agreement, not because AI is right**. The 12.4% agreement is not evidence the AI is better than the brain; it is evidence the brain answers the same thing for everything. Retraining on brain-log in this state only reinforces the degenerate distribution.

3. **Missing detector flags**. Even inside 0..=29, several high-volume production detectors have no dedicated one-hot slot (`host_drift`, `sigma`, `network_sniffing`, `discovery_burst`, `proto_anomaly`). They land on "no detector flag set". That compounds the degeneracy.

4. **Operator confusion**. The Brain tab shows 5,713 rows without filter or pagination. Every row has the same brain suggestion. The operator sees noise and cannot give useful feedback, so the feedback loop that could fix the brain never runs.

5. **Coverage gap on the builder**. `incident_decision_eval.rs::build_brain_features` has 3 tests total and no coverage on the feature wiring. Any change that adds positions needs to land tested.

## Proposal

Close the skew in three tracks. **Only Track 1 ships in this PR; Tracks 2 and 3 are follow-ups** (Track 2 lives in a separate repo, Track 3 is a training run plus a binary swap).

### Track 1 — Agent feature alignment (this PR)

Populate features 30..=71 in `build_brain_features` from state that already exists in the running agent. Keep position semantics identical to the gym so `production_features.rs` stays the source of truth.

Concrete wiring:

| Position | Gym source | Agent source | Notes |
|----------|-----------|--------------|-------|
| 30..=35 | `self.events` filtered by `Layer` | `AgentState::recent_event_kinds` classified by prefix/substring into 6 buckets | Layer classifier is a small pure helper, covered by unit tests |
| 36..=39 | `hist` pattern match | Same, on `recent_event_kinds` | recon / access / exec / persist stage presence |
| 40 | sum(36..=39)/4 | derived | kill chain depth proxy |
| 41 | unique kinds in `hist` | derived | event diversity |
| 42 | `hist.len()/20` | derived | burst density |
| 43..=47 | keyword filters on `hist` | same | technique category counts |
| 48..=59 | bigram windows on `hist` | same | same 12 bigram patterns |
| 60..=63 | `env.kernel` / `env.firmware` | recent rootkit + firmware integrity kinds from history | collapsed from simulated kernel struct to "was a rootkit/firmware kind seen in window" |
| 64..=67 | connection + DNS counters | count matching kinds in `recent_event_kinds` (`.DnsQuery`, `.HttpReq`, etc.) | approximation; full per-session counters are out of scope |
| 68..=71 | zero | grouped new-detector flags | host_drift+sigma / recon / net-anomaly / correlation |

New state field on `AgentState`:

```rust
/// Rolling history of the last N event kinds seen by the agent,
/// used to compute brain features 36..=59 (kill chain stage presence,
/// diversity, burst density, technique categories, attack bigrams).
///
/// Mirrors the `hist` vector in `innerwarden-gym::environment` so
/// defender brain training and serving see the same shape of signal.
recent_event_kinds: std::collections::VecDeque<String>,
```

Capacity: 20 (matches gym comment on line 31 of `environment.rs`). Pushed in the slow-loop event drain alongside `telemetry.observe_events`. Bounded ring, no growth.

Also add flags for production detectors that currently have no slot. To avoid silently breaking the V5 contract on positions 12..=23 (which the embedded `defender-brain.bin` was trained against), reuse the reserved positions 68..=71 for grouped new-detector flags:

| Position | Detectors covered |
|----------|-------------------|
| 68 | `host_drift`, `sigma` (suspicious activity family) |
| 69 | `network_sniffing`, `discovery_burst` (recon family) |
| 70 | `proto_anomaly`, `packet_flood` (network anomaly family) |
| 71 | `correlation` (cross-layer chain detection) |

Pairs are used because 4 reserved slots cover 7 detectors. The pairing follows semantic family to keep the signal useful even before Track 3 retrain — the V5 model will see coherent activation on these positions as related detectors fire together.

**Alternative considered**: Remap positions 12..=23 to the new detectors. Smaller gym divergence, but silently changes the meaning of inputs the V5 model learned against. Rejected: the alternative here (new flags in 68..=71) keeps V5's existing contract and the gym update in Track 2 is a pure addition, not a semantic remap.

### Track 2 — Gym offline replay (follow-up, separate repo)

Move the gym's defender training from simulated `event_sim` streams to offline replay of real production JSONL/SQLite. The gym keeps the same 72-dim feature builder, but the "environment" becomes a sampled sequence of real events with real kill chain progression and real attacker IP distributions. Avoids the sim-vs-prod distribution gap that the current V4 training suffers from.

Deliverables (not in this PR):
- Add `replay_env.rs` in `innerwarden-gym/src/` that loads events from a prod JSONL snapshot and yields `DefenderObs` frames via the existing `production_features::build_production_features`.
- New `selfplay_az` mode: replay-driven (not adversarial). Defender learns to imitate the action the AI actually took on each incident — then fine-tunes via a small adversarial tail.
- Acceptance gate: holdout accuracy > 60% on a dev month of prod data.

### Track 3 — V6 retrain + binary swap (follow-up, training run)

After Track 2 lands:
- Run V6 training (expected cost: a few GPU-hours on a consumer card; gym already runs on CPU but slowly).
- Validate on holdout: agreement >= 50% vs AI decisions, `brain_value` standard deviation > 0.1 (i.e. the value head actually varies), top-1 confidence distribution roughly uniform across actions rather than stuck on one.
- Replace `crates/agent/src/defender-brain.bin` via a dedicated PR.
- Update `BrainStats::last_retrain_accuracy` expectations.

Tracks 2 and 3 are not gated behind Track 1 code-wise, but they are gated value-wise: retraining on broken features will not fix the broken features.

## Functional requirements

### FR-1 Feature coverage

After this PR, `build_brain_features` populates all 72 positions with values derived from `AgentState` or the current `Incident`. Position semantics match `innerwarden-gym/src/production_features.rs` (Track 2 keeps them in sync).

### FR-2 Rolling event kind history

`AgentState::recent_event_kinds` is a bounded `VecDeque<String>` (capacity 20) that accumulates `event.kind` values in the order they arrive. It survives for the lifetime of the process; on restart it starts empty (not persisted). The feature builder reads it as a slice.

### FR-3 Detector one-hot coverage

Positions 12..=23 preserve their V5-contract mapping (unchanged). Positions 68..=71 add grouped flags for the production detectors that were previously uncovered: `host_drift`/`sigma`, `network_sniffing`/`discovery_burst`, `proto_anomaly`/`packet_flood`, `correlation`. The full mapping is documented in a module-level constant so both the agent and the gym can import it.

### FR-4 Coverage floor

Every file touched by this PR ends at >= 80% line coverage, measured by tarpaulin / Codecov. Existing helpers in `incident_decision_eval.rs` that were previously untested are either covered now or removed.

### FR-5 Behavioural test

A test asserts that `build_brain_features` produces **different** feature vectors for three meaningfully different incidents (e.g. `neural_anomaly Critical`, `host_drift Medium`, `ssh_bruteforce High`). If the vector is identical across those, the test fails. Protects against future regressions where someone again forgets to populate a section.

### FR-6 No binary regression

The embedded `defender-brain.bin` stays unchanged in this PR. Its outputs on the new feature distribution will be noisy; this is acceptable because the current output is degenerate regardless. Track 3 closes this gap.

### FR-7 Spec and docs

- Spec file in `.specify/features/031-...` (this document).
- CLAUDE.md at project root adds a short pointer to the spec under "Current State" when V6 binary lands (not now).
- PR body explicitly calls out the Track 2 / Track 3 follow-ups with owners TBD.

## Non-goals

- Retraining the brain in this PR.
- Changing the model architecture (still `[72 -> 256 -> 256]` trunk + policy/value).
- Switching off the defender brain at the agent level. It keeps running with the new features.
- Adding a dashboard pagination/filter for the Brain tab. That is a separate UX ticket; fixing the underlying model makes the UX issue mostly disappear because feedback becomes useful.
- Persisting `recent_event_kinds` across restarts. The window fills within minutes under production load.

## Risks

### R-1 Feature variance without a trained model

Populating features 30..=71 will give the current V5 binary inputs it never saw at training time. Outputs will be noisier than today. **Mitigation**: Today's outputs are degenerate (same three actions, low confidence), not useful. "Noisier but varied" is an input for Track 3; "constant" is a dead end. Acknowledge the transient in the PR.

### R-2 History window overhead

A `VecDeque<String>` of capacity 20 holding short strings is ~1 KB steady state. Bounded writes on the slow-loop path. No measurable overhead.

### R-3 Detector slot reshuffling

Changing what position 12..=23 means inside the 0..=29 block is a silent contract break with the current `.bin`. We explicitly document this in FR-6 and accept the transient accuracy hit; Track 3 retrain absorbs it.

### R-4 Coverage target on big files

`incident_decision_eval.rs` is 550 lines today with 3 tests. Hitting 80% might require test helpers that stand up a minimal `AgentState`. Budget time for that; it is prerequisite work either way.

## Acceptance

- [ ] Spec committed at `.specify/features/031-defender-brain-feature-alignment/spec.md`.
- [ ] `build_brain_features` populates 0..=71 with no zero-only block.
- [ ] `AgentState::recent_event_kinds` field + slow-loop populator shipped.
- [ ] All 12 detector slots cover high-volume production detectors.
- [ ] FR-5 behavioural test passing: three distinct incidents yield three distinct vectors.
- [ ] Touched files (`incident_decision_eval.rs`, `main.rs`, `loops/*.rs` where edited, `tests.rs`) end at >= 80% line coverage on Codecov.
- [ ] `make check` and `make test` green.
- [ ] PR body documents Track 2 and Track 3 deferrals with links to follow-up issues.
