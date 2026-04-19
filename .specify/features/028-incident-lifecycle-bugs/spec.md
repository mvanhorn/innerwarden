# Feature Specification: Incident Lifecycle Bugs - Autonomy Gap 2.0

**Feature Branch**: `028-incident-lifecycle-bugs`
**Created**: 2026-04-19
**Status**: Draft
**Input**: Production audit of the InnerWarden agent on Oracle Cloud London (v0.12.2) surfaced a cluster of bugs where detectors fire, the AI classifies correctly, but no action gets executed. Similar pattern to the autonomy gap fixed in spec 018, but on different code paths.

## Origin

During a 2026-04-19 dashboard review we noticed individual attacker IPs sitting in "Observing" for hours despite high-severity signals and high-confidence AI verdicts. A systematic query against the production sqlite exposed 10 distinct problems that together cause three bad outcomes:

1. **Attacks pass through**: high-severity signals are classified as SUSPICIOUS by the AI but never converted into a block action.
2. **Money leaks**: a single noisy detector (`proto_anomaly:SshVersionAnomaly`) generated 646 incidents in 24h, each one consuming one AI call on the observation-verify path.
3. **Operator blind**: the dashboard's "Observing" bucket mixes truly-open incidents with already-dismissed and already-contained ones, so the operator cannot see what genuinely needs attention.

## Problem statement

The agent's triage pipeline has three stages:

```
Fase 2: detector fires -> incident row
Fase 3: observation_verify scores 0-100
  - low score      -> auto-dismiss
  - high score     -> escalate "to Fase 4"
  - mid score      -> ask AI via chat(); AI says "dismiss" or "escalate"
Fase 4: AI provider.decide() -> pick action -> execute skill
```

The problems below live mostly in the Fase 3 <-> Fase 4 boundary and in the detectors feeding Fase 2.

---

## The 10 bugs

Numbered in order of discovery, classified by severity:

| # | Bug | Severity | Class |
|---|---|---|---|
| 1 | `proto_anomaly:SshVersionAnomaly` fires once per SSH connection with no `(IP, detector, window)` dedup. 646 incidents / 24h, up to 71 from the same IP. | P1 | spam |
| 2 | `VerificationResult::Escalate` in `narrative_observation_verify.rs` only writes an "escalate" label into the knowledge graph and stops. Nothing promotes the incident to the Fase 4 decide() pipeline. | **P0** | leak |
| 3 | Escalated incidents do not surface in the dashboard's "Needs your attention" bucket, so the operator cannot manually block them either. | **P0** | leak |
| 4 | Dashboard classifies IPs that are already blocked (e.g. by `auto-rule:ssh_bruteforce`) into the "Observing" bucket. E.g. 103.41.247.76 was blocked at 17:00:41 by the ufw rule-based path but still lists as `Observing`. | P2 | UI |
| 5 | `proto_anomaly:*` detectors fire on internal/loopback IPs (127.0.0.1, 10.0.0.x, 172.x). 22 SlowConnection incidents and 13 ProtocolMismatch incidents came from 127.x in 24h. Loopback cannot be attacker. | P1 | false positive |
| 6 | `threat_intel:threat_ip`: 75 incidents in 24h, 31 resulted in a `block_ip` decision. The remaining 44 either deduped silently or had a decision but the action was not block_ip. Threat intel match is a max-confidence signal and must be 100% block. | **P0** | leak |
| 7 | `suspicious_execution:unknown` and `suspicious_execution:ubuntu` fired 8 incidents combined, zero decisions recorded. Completely un-triaged high-severity detector. | **P0** | leak |
| 8 | `sudo_abuse:ubuntu` fired 2 incidents, zero decisions. Sudo abuse on a managed server is a max-severity signal. | **P0** | leak |
| 9 | No cross-IP correlation for /24 subnet scans. 5 IPs in the `92.118.39.0/24` block produced 22-32 "Suspicious connection" LOW incidents each in the past few hours. Same ISP/range pattern is a textbook coordinated scan; nothing blocks it. | P1 | missed correlation |
| 10 | Duplicate incident rows: the same `incident_id` appears multiple times in the incidents table. Makes correlation/dedup queries noisy, and confuses the Fase 3 scoring which likely computes the same score for each duplicate. | P1 | data integrity |

P0 = attack gets through or high-severity detector produces no decision.
P1 = cost / noise / reduced signal quality.
P2 = UI only.

---

## Evidence (gathered 2026-04-19, Oracle London, v0.12.2)

### Query: decisions by detector in last 24h

| Detector | Incidents | Blocked | Dismissed | Monitor | Escalated | No decision |
|---|---|---|---|---|---|---|
| proto_anomaly:SshVersionAnomaly | 646 | 0 | 399 | 0 | 0 | 247 |
| proto_anomaly:SlowConnection | 79 | 9 | 19 | 0 | 0 | 51 |
| proto_anomaly:SshNonStandardPort | 77 | 8 | 27 | 0 | 0 | 42 |
| threat_intel:threat_ip | 75 | 31 | 0 | 0 | 0 | 44 |
| proto_anomaly:ProtocolMismatch | 21 | 2 | 0 | 0 | 0 | 19 |
| packet_flood:rate_anomaly | 13 | 9 | 0 | 0 | 0 | 6 |
| ssh_bruteforce:130.250.191.204 | 8 | 2 | 0 | 0 | 0 | 7 |
| ssh_bruteforce:116.99.173.227 | 6 | 2 | 0 | 0 | 0 | 5 |
| ssh_bruteforce:209.14.88.118 | 6 | 1 | 2 | 0 | 0 | 4 |
| suspicious_execution:unknown | 5 | 0 | 0 | 0 | 0 | 5 |
| ssh_bruteforce:34.123.134.194 | 5 | 1 | 5 | 0 | 0 | 0 |
| suspicious_execution:ubuntu | 3 | 0 | 0 | 0 | 0 | 3 |
| sudo_abuse:ubuntu | 2 | 0 | 0 | 0 | 0 | 2 |

(Full set of 25 detectors available in `/var/lib/innerwarden/innerwarden.db` on the prod server. The "no decision" counts can exceed the incident count because of duplicate rows for the same incident_id; bug #10.)

### Representative UI cases

Three IPs that expose bugs #1, #2, #3, #4 in isolation:

- **51.158.205.47 (masscan)**: 32 incidents in 5h, each triggered an AI chat() call that returned "escalate - SUSPICIOUS". Zero blocks. Still Observing.
- **64.89.163.156 (Distributed SSH botnet)**: HIGH severity, AI said "SUSPICIOUS - botnet scan activity" at 85% confidence. Status "Needs review - no automated response taken". 3 hours later still not blocked.
- **103.41.247.76 (rule-blocked but shown Observing)**: ssh_bruteforce rule fired a block at 17:00:41 (recorded in decisions). Dashboard still shows this IP under "Observing" rather than "Blocked".

### Reference files and lines

- `crates/agent/src/narrative_observation_verify.rs:110-126` - escalate branch that only writes to the graph.
- `crates/agent/src/observation_verify.rs` - the Fase 3 scorer; thresholds in `DEFAULT_ESCALATE_THRESHOLD` = 40.
- `crates/sensor/src/detectors/user_agent_scanner.rs` - fires `graph_scanner_ua`, no throttle.
- `crates/sensor/src/detectors/` - most `proto_anomaly:*` detectors; should reject loopback and RFC1918 sources.
- `crates/agent/src/dashboard.rs` - aggregation of threats into Blocked / Observing / Needs attention buckets.

---

## Fixes

Organised as four PRs, sequenced by risk vs impact. All PRs sit behind the shadow-mode mechanism introduced in PR #196 (see `crates/agent/src/ai/shadow.rs`) so comparisons against the current behaviour are first-class.

### 028-a - Detector cooldowns and source filters (P1)
**Fixes**: #1, #5, #9 (partially), #10.

- Add a per-detector `(pivot, window_secs)` throttle in the sensor. `graph_scanner_ua`, `proto_anomaly:SshVersionAnomaly`, `proto_anomaly:SlowConnection`, `proto_anomaly:SshNonStandardPort`, `proto_anomaly:ProtocolMismatch`: one fire per `(source_ip, detector)` per 600s.
- Reject loopback (127.0.0.0/8) and RFC1918 (10/8, 172.16/12, 192.168/16) as the source for any `proto_anomaly:*` detector.
- Dedup the incidents table write path: if an `incident_id` already exists in the last 600s, update the event count on the existing row instead of inserting a new one.

Risk: low. Only reduces emission volume; does not change decisions.
Test plan: unit tests on the throttle, replay harness, one week of shadow-mode observation confirming no previously-blocked IPs go un-blocked because the second detector fire was suppressed.

### 028-b - Escalate -> decide() wiring (P0)
**Fixes**: #2, #6, #7, #8.

- `narrative_observation_verify.rs` escalate branch enqueues the incident into the same queue the main Fase 4 pipeline consumes (whatever the current incident_flow pre-AI queue is).
- Fase 4 calls `ai_provider.decide()` on escalated incidents exactly like it does for incidents that bypass Fase 3.
- For `threat_intel:threat_ip`, `sudo_abuse:*`, `suspicious_execution:*`: make them skip Fase 3 entirely and go direct to Fase 4. These are high-signal detectors that should never be observation-verified away.

Risk: medium. Changes what gets blocked autonomously. MUST shadow-mode validate first: with shadow enabled, the local classifier decides on the escalated stream alongside Azure, and we compare the agreement rate for at least 7 days before flipping.
Test plan: integration test that replays the three UI cases; shadow-mode agreement >= 90% for block_ip on escalated incidents before promoting.

### 028-c - Dashboard bucket fix (P2)
**Fixes**: #3, #4.

- Change the Observing/Blocked/Needs-attention classification to look at the latest *effective* state of the IP, not the most recent incident row.
- Effective state per IP: `Blocked` if any unexpired block decision exists, `Needs attention` if any escalated incident has no resolving decision yet, `Observing` otherwise.
- Drop LOW-severity noise-gate-dismissed incidents from the Observing count entirely; keep them reachable via the full log but do not count them in the header.

Risk: low. UI only, no state mutation.
Test plan: snapshot tests on the classification function with fixtures covering all four transitions.

### 028-d - /24 subnet correlation (P1, optional)
**Fixes**: #9.

- New correlation rule: if >=3 distinct IPs from the same `/24` trigger any `proto_anomaly:*` or `ssh_bruteforce` detector within 30 min, emit a `subnet_scan_correlation` incident severity High with the /24 as the pivot.
- The /24 can then be blocked once via the existing block_ip skill (we already support CIDR blocks per the v11 gym logs).

Risk: medium. A noisy /24 false-positive could accidentally block a whole shared-hosting range. Must be manually-opt-in for the first week.

---

## Sequencing

1. **028-c (dashboard)**: ship first. Immediate visibility win, zero risk.
2. **028-a (cooldowns)**: ship second. Reduces incident volume by an estimated 80% which makes everything else easier to observe.
3. **028-b (escalate to action)**: ship third. Highest value but also highest risk; requires the shadow-mode agreement window.
4. **028-d (/24 correlation)**: optional, ship last once the other three are stable.

## Addendum 2026-04-19 - shadow-mode depends on 028-b

After enabling shadow-mode in production at 19:43 UTC (`[ai.shadow]` in `/etc/innerwarden/agent.toml` with `provider = "local_classifier"`), the log file `/var/lib/innerwarden/shadow-decisions.jsonl` stayed at 0 bytes for over an hour with zero entries.

Root cause: the shadow wrapper in `crates/agent/src/ai/shadow.rs` only intercepts the `AiProvider::decide()` path. It deliberately does not wrap `AiProvider::chat()` because chat returns free-form text that has no `action` label to compare.

In the current production pipeline, the main `decide()` path is almost never invoked. Most traffic goes through `observation-verify` which uses `chat()` to ask "is this suspicious, dismiss or escalate?", and the `escalate` result dead-ends into a graph label (bug #2 in this spec). Concretely: from 19:43 to 20:50 UTC there were 5 `chat()` calls via observation-verify and zero `decide()` calls through the main pipeline.

This exposes a real dependency:

- **Shadow-mode cannot produce useful parity data until 028-b ships.**
- Before 028-b, the shadow log is empty by construction because the code path the shadow observes is rarely exercised.
- Once 028-b is in place, every incident that `observation-verify` escalates will flow into `decide()`, which is what shadow-mode wraps. At that point the shadow log starts populating at the rate that 028-a does not throttle away.

Implication for this spec: the 7-day shadow-agreement window required before promoting the local classifier to primary (referenced in 028-b test plan and in PR #196) cannot start counting down from today. It starts when 028-b lands in production, not when shadow mode is first enabled.

Two workarounds are possible if we want earlier parity data:

- **028-e (optional, not currently scoped)**: wrap `chat()` inside `ShadowProvider` too. The wrapper would send the same message to the shadow provider and log the raw text response. Parity would then be measured as "does the classifier's top action match the action keyword in the chat response text?". Noisier signal but would let us observe earlier. Adds ~50 lines to `shadow.rs`.
- **Force high-severity traffic**: in a staging environment, replay historical high-severity incidents so they hit the main `decide()` path. Good for ad-hoc testing but does not constitute production validation.

Recommendation: accept the dependency, do not add 028-e, and keep the shadow-mode validation gate on 028-b as specified.

## Success criteria

- `proto_anomaly:SshVersionAnomaly` volume drops below 100 incidents / 24h (currently 646).
- Zero incidents in 7 consecutive days where the AI said SUSPICIOUS / escalate and the IP was not actioned by either an autonomous block or an operator review notification.
- Dashboard "Needs your attention" count is non-zero whenever any incident is in the escalated-but-undecided state.
- Dashboard "Observing" count excludes already-blocked IPs.

## Out of scope

- Replacing the Azure AI provider with the local classifier. That is the separate flow tracked in PR #196 and spec-026 (Rust ONNX integration). It benefits from 028-b but does not depend on it.
- Rewriting the Fase 3 scorer. The current scorer is fine; the bug is solely in the escalate branch.
- Changes to the block-ip skills themselves. All existing skills work correctly; the gap is purely getting the decision to fire.
