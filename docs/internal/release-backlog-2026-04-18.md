# Release backlog — snapshot 2026-04-18

Consolidated plan built after the Caldera live-fire exercise on test001.
v0.11.x is paused until the items below are cleared. This doc is the
single source of truth for the day of tech-debt / testing work.

Companion docs:

- `docs/internal/bug-hunt-2026-04-18.md` — the exercise findings (what
  detectors held up, which did not, what to do about it).
- PR #146 — in flight, batches together the 11 bug fixes found during
  the exercise.

## Delegation strategy

Rows marked **Delegable** are self-contained enough to hand to a less
advanced coding agent. The **Needs deep review** rows either require
architectural design or touch orchestration that can silently regress.

All rows are tracked as GitHub issues so each agent gets its own ticket.

## Work queue

Sorted in execution order. Order balances "early wins for momentum"
against "high-risk-first" so any blocker surfaces early.

| Order | # | Title | Diff | Prio | Impact | Delegable |
|-------|---|-------|------|------|--------|-----------|
| 1  | [#152](https://github.com/InnerWarden/innerwarden/issues/152) | fix: `/api/live-feed/geoip` 400 on empty `ips` | S | P3 | 5-min warm-up, hardens API contract | ✅ |
| 2  | [#136](https://github.com/InnerWarden/innerwarden/issues/136) | test: ip_reputation pure helpers | S | P2 | Locks in IP rep math | ✅ |
| 3  | [#137](https://github.com/InnerWarden/innerwarden/issues/137) | test: agent_context pure helpers | S | P2 | Prevents silent ctx corruption | ✅ |
| 4  | [#138](https://github.com/InnerWarden/innerwarden/issues/138) | test: narrative_anomaly text helpers | S | P2 | Alert narrative regressions | ✅ |
| 5  | [#140](https://github.com/InnerWarden/innerwarden/issues/140) | test: ctl calibrate pure config math | S | P2 | Protects config math | ✅ |
| 6  | [#141](https://github.com/InnerWarden/innerwarden/issues/141) | test: ctl commands/capability toggle | S | P2 | Toggle logic reliability | ✅ |
| 7  | [#139](https://github.com/InnerWarden/innerwarden/issues/139) | test: incident_honeypot_router + decision_honeypot | M | P2 | Honeypot decision path | ✅ |
| 8  | [#149](https://github.com/InnerWarden/innerwarden/issues/149) | test: telegram templates + commands + burst | M | **P1** | Operator alert UX regression guard | ✅ |
| 9  | [#150](https://github.com/InnerWarden/innerwarden/issues/150) | test: shield_inline + telemetry_tick | M | **P1** | DDoS + metrics drift visibility | ✅ |
| 10 | [#148](https://github.com/InnerWarden/innerwarden/issues/148) | test: incident enrichment adapters (5 modules) | M-L | **P1** | Parallelisable across agents | ✅ (split) |
| 11 | [#147](https://github.com/InnerWarden/innerwarden/issues/147) | test: **incident_flow orchestrator** | M | **P0** | AI gate + cooldown orchestrator, highest risk module without tests | ⚠️ needs orchestration care |
| 12 | [#151](https://github.com/InnerWarden/innerwarden/issues/151) | test: loops/mod.rs tick dispatch | M | **P1** | Tick scheduling deterministic under test | ⚠️ |
| 13 | [#71](https://github.com/InnerWarden/innerwarden/issues/71)  | feat: dashboard 2FA approval endpoints | M | P2 | Completes spec 002 (Telegram 2FA works, dashboard missing) | ✅ |
| 14 | [#155](https://github.com/InnerWarden/innerwarden/issues/155) | test: sensor integration harness (eBPF + AF_PACKET) | L | **P1** | Closes the "untestable without kernel" gap with pcap fixtures | ⚠️ design first |
| 15 | [#72](https://github.com/InnerWarden/innerwarden/issues/72)  | feat: dynamic allowlist from FP reports | M | P2 | Reduces allowlist toil | ✅ |
| 16 | [#73](https://github.com/InnerWarden/innerwarden/issues/73)  | feat: executable entropy analyzer | M | P3 | Better detection on packed binaries | ✅ |
| 17 | [#68](https://github.com/InnerWarden/innerwarden/issues/68)  | feat: Splunk HEC sink | M | P3 | Enterprise SIEM integration | ✅ |
| 18 | [#67](https://github.com/InnerWarden/innerwarden/issues/67)  | docs: n8n Agent Guard recipe | S | P3 | Integration discoverability | ✅ |
| 19 | [#66](https://github.com/InnerWarden/innerwarden/issues/66)  | docs: module authoring guide | S | P3 | Community contribution onboarding | ✅ |
| 20 | [#153](https://github.com/InnerWarden/innerwarden/issues/153) | spec: AI budget (\$-per-day) with tiered fallback | XL | **P1** | Blocks the "50 Calderas burn budget" failure mode | ⚠️ deep review — Claude |
| 21 | [#154](https://github.com/InnerWarden/innerwarden/issues/154) | spec 027: multi-agent AI + MITRE-tiered policy | XL | **P1** | Active defence architecture | ⚠️ deep review — Claude |

### Difficulty legend

- **S** — under 2h, mostly mechanical
- **M** — 2-6h, needs context
- **L** — 1-3 days
- **XL** — multi-day spec work

### Priority legend

- **P0** — release blocker (shipping without this is a bug)
- **P1** — release-critical (plan v0.11.x around this)
- **P2** — important but can defer to v0.11.1
- **P3** — polish, defer freely

## Not yet tracked as issues

These are queued in `bug-hunt-2026-04-18.md` and will become issues when
test001 SSH is recovered and we can re-run the Caldera exercise to
capture ground-truth fixtures.

### Detection gaps from Caldera exercise (18 technique categories)

For each, open an issue with: (1) the Caldera ability ID, (2) the
`/testdata/` pcap or event fixture to capture, (3) the sensor detector
to add or fix, (4) the regression test. Categories:

T1098.004 (SSH authorized_keys modify), T1110.001 + T1110.004
(sudo + ssh brute force), T1053.002 + T1053.003 (at + cron
persistence), T1048.001 (exfil over SSH), T1003.007 (process memory
dump), T1486 (gpg ransomware), T1485 (dd destroy), T1222.002 (chattr),
T1489 (killall service), T1543.002 (SysV service), T1546.004 (shell
profile), T1140 (base64 obfuscation), T1499 (WiFi disrupt), T1529
(reboot), T1036.005 (process masquerade), T1021.004 (sandcat spawn).

Full table with ability UUIDs + run counts in
`docs/internal/bug-hunt-2026-04-18.md`.

## Ops tasks (not GitHub issues)

1. **Recover SSH to test001**: physical console access, restore
   operator pubkey in `/home/test001/.ssh/authorized_keys`, re-enable
   `PasswordAuthentication no`, remove the
   `/etc/ssh/sshd_config.d/99-recovery.conf` drop-in if anything from
   the exercise created one. Operator pubkey:
   `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNxtQ7rLVM9ut/nYAogIc3rfMeR3t7UoEiVZsAZ4dEM oracle`.
2. **Kill the 141 zombie sandcat processes on test001**:
   `sudo pkill -9 sandcat && rm -f /tmp/sandcat_x86 ~/sandcat.go ~/splunkd`.
3. **Cleanup test001 state**: remove any gpg-encrypted artefacts the
   exercise produced, verify `/etc/ssh/authorized_keys`,
   `/etc/ssh/sshd_config.d/`, `/etc/passwd`, and user crontab are
   untouched.
4. **Re-run Caldera 55 Metal as regression** after detection gaps
   are closed; goal is measurable detection-ratio improvement per
   category, not just "tests pass".

## Criteria for closing v0.11.x

All three must hold, not just the GitHub gate:

1. Every P0/P1 issue above is closed.
2. Re-running Caldera 55 Metal against a cleaned test001 shows a
   detection-ratio > 80% per technique category (up from ~15% today,
   5/28 categories).
3. A fresh operator (no prior test001 context) can run
   `make test` + `make replay-qa` + the Caldera exercise and get a
   green result end-to-end.

## For the next Claude session

When picking this up again, read in this order:
1. `docs/internal/bug-hunt-2026-04-18.md` — exercise findings, already
   committed to PR #146.
2. This file — the delegation table + ops tasks.
3. `CLAUDE.md` under `## Features — Status` — the spec ledger.
4. PR #146 itself — the in-flight fixes and how they were validated.

After v0.11.x ships, archive this doc under
`docs/internal/history/` and reset the backlog against v0.11.1.
