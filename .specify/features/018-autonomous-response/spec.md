# Spec 018: Autonomous Response — From Observer to Defender

## Status: Phases A-D DONE. Phase E (validation) in progress.

### Phase completion

| Phase | Description | Status | PR |
|-------|-------------|--------|-----|
| A | Layer 1 — deterministic auto-response rules (5 rules) | ✅ DONE | #107 |
| B | Layer 2 — correlation-driven escalation (chains + repeat offender + multi-technique) | ✅ DONE | #113 |
| C | Noise-gate reform + confidence threshold 0.80→0.85 | ✅ DONE | #113 |
| D | Model learning — brain trains from all decision layers | ✅ DONE | #113 |
| E | First-hour validation on clean server | 🔄 IN PROGRESS | — |

## Problem

InnerWarden detects threats but does not act on them. Production data from a 3-day window:

- 1812 incidents detected
- 9 decisions made (6 noise-gate dismiss, 3 OpenAI ignore)
- 0 autonomous blocks by AI
- 0 times the internal neural model influenced a decision
- All real blocks came from AbuseIPDB reputation database

The noise-gate discards most incidents before AI sees them. The confidence threshold is 1.01 (above the maximum 1.0), making it impossible for any AI decision to auto-execute. The system is an expensive logger — it consumes RAM and CPU to collect, parse, correlate, and store data that nobody reads and nothing acts upon.

The correlation engine exists. The kill chain detector exists. The baseline learning exists. The autoencoder exists. None of them drive a response. They write to a database that nothing reads for decision-making.

This is not a configuration problem on one server. This is the default behavior for every user who installs InnerWarden.

## Goal

Any user installs InnerWarden on any Linux machine. Without external APIs:

1. **Minutes**: obvious threats blocked automatically (SSH brute-force, port scan)
2. **Hours**: correlated multi-stage attacks detected and escalated (recon → exploit → exfil chain)
3. **Days**: AI triages ambiguous signals the rules can't handle
4. **Weeks**: internal model learns what's normal on THIS machine and reduces AI dependency

## Architecture: 4 Decision Layers

Every incident flows through layers in order. Each layer can act (block, alert, escalate) or pass to the next. No layer is mandatory — the system works from layer 1 alone, and gets smarter as layers are added.

```
Incident
  │
  ▼
Layer 1: Deterministic Rules (free, instant, no deps)
  │ SSH brute-force 20x → block
  │ Port scan 20 ports → block
  │ Packet flood → block
  │ Known? → ACT or pass down
  │
  ▼
Layer 2: Correlation + Repeat Offender (free, uses graph)
  │ Same IP: scan + brute-force + web probe → escalate block
  │ Kill chain pattern matched → block + kill + alert
  │ 3rd visit in 7 days → permanent block
  │ Pattern? → ACT or pass down
  │
  ▼
Layer 3: AI Triage (optional, costs API or local GPU)
  │ Node spawned shell — OpenClaw or attack?
  │ Large outbound data — backup or exfil?
  │ Rootkit signature — false positive or real?
  │ AI explains → ACT or ALERT
  │
  ▼
Layer 4: Internal Model Learns (passive, continuous)
  │ Every decision from layers 1-3 is a training signal
  │ Layer 1 decisions = automatic labels (brute-force = always block)
  │ Layer 3 decisions = AI labels (operator can correct)
  │ Baseline: what's normal on THIS machine
  │ After training: model pre-scores before AI, reduces API cost
  │ Model disagreement with AI → flag for operator review
```

### Why 4 layers, not just AI

- **Layer 1 alone** makes the product useful on day 1 with zero config
- **Layer 2** makes it smarter than a simple firewall — it sees patterns
- **Layer 3** handles the 5% of cases that rules can't — ambiguous, context-dependent
- **Layer 4** makes it adaptive — each machine develops its own definition of normal

A user without AI configured gets layers 1+2. A user with Ollama local gets 1+2+3+4. A user with OpenAI gets all 4 with better AI. The product works at every tier.

## Layer 1: Deterministic Auto-Response Rules

### Design

Built-in rules that execute without AI, external APIs, or operator intervention. Every rule has:

- **Trigger**: which detector fires
- **Condition**: threshold that must be met (prevents false positives)
- **Action**: what to do (block_ip, kill_process, alert)
- **Cooldown**: prevent repeated actions on same target
- **Allowlist**: always checked, always wins

### Rules

| Trigger | Condition | Action | Duration | Cooldown |
|---------|-----------|--------|----------|----------|
| ssh_bruteforce | >= 10 failed auth from same IP in 5 min | block_ip | 24h | per-IP 1h |
| packet_flood | rate anomaly from same IP | block_ip | 24h | per-IP 1h |
| port_scan | >= 20 ports probed from same IP in 60s | block_ip | 12h | per-IP 1h |
| web_scan | >= 50 404s from same IP in 5 min | block_ip | 12h | per-IP 1h |
| credential_stuffing | >= 5 unique usernames from same IP in 5 min | block_ip | 24h | per-IP 1h |

### Config

```toml
[responder]
enabled = true
dry_run = true          # safe default — operator switches to false when ready

[responder.auto_rules]
enabled = true          # layer 1 rules fire regardless of AI
ssh_bruteforce = true
packet_flood = true
port_scan = true
web_scan = true
credential_stuffing = true
```

### Invariants

- **Allowlist always wins.** If an IP is allowlisted, no rule touches it.
- **Dry-run respected.** If dry_run=true, rules log but don't execute.
- **Internal IPs ignored.** RFC 1918 addresses (10.x, 172.16-31.x, 192.168.x) never blocked by default.
- **Cooldown prevents storms.** One block per IP per cooldown window.

## Layer 2: Correlation-Driven Escalation

### Design

The correlation engine and knowledge graph already track multi-stage attacks. Today they write incidents. They should also escalate response.

### Rules

| Pattern | Detection Source | Action | Rationale |
|---------|-----------------|--------|-----------|
| Multi-technique | Same IP triggers 2+ different detectors in 30 min | Escalate block to 48h | Determined attacker, not opportunistic scanner |
| Kill chain complete | Kill chain detector fires (recon→exploit→exfil) | block_ip + kill_process + alert(critical) | Active compromise in progress |
| Repeat offender | Same IP blocked 3+ times in 7 days | Permanent block (until manual unblock) | Persistent attacker |
| Silence after compromise | Baseline detects log rate drop after suspicious activity | alert(critical) | Attacker may be suppressing logs |

### Data Source

These rules read from the knowledge graph, not from raw incidents. The graph already tracks:

- IP → Incident edges (which IP triggered what)
- Temporal relationships (when things happened)
- Process lineages (who spawned whom)
- Block history (how many times, when)

The gap is: nobody queries the graph to make decisions. The graph is read-only for the dashboard.

## Layer 3: AI Triage (Optional)

### Design

For incidents that rules can't handle — ambiguous, context-dependent, requires reasoning. This is where OpenAI/Ollama/Anthropic adds value.

### When AI is called

- Incident severity >= High AND no auto-rule matched
- Correlation pattern is partial (2 of 3 stages seen)
- Detector fires on a process that could be legitimate or malicious

### What AI receives

The existing narrative builder already creates context for AI. The gap is that the noise-gate drops most incidents before they reach AI.

**Fix**: noise-gate controls AI API calls only. Layer 1+2 rules bypass it entirely. High/Critical incidents always reach AI if configured.

### What AI decides

- **block**: auto-execute if confidence >= threshold (default 0.85)
- **alert**: notify operator, no action
- **ignore**: false positive, suppress future similar alerts
- **investigate**: needs human judgment, create dashboard task

### Confidence threshold

Replace the 1.01 impossibility with:

```toml
[responder.ai_triage]
enabled = false         # auto-enabled when AI provider is configured
threshold = 0.85        # decisions above this auto-execute
```

## Layer 4: Internal Model Learning

### Design

Every decision from layers 1-3 becomes a training signal for the autoencoder. The model learns what's normal on THIS specific machine.

### Training signals

| Source | Label | Quality |
|--------|-------|---------|
| Layer 1 auto-block | attack (high confidence) | Excellent — deterministic, correct by definition |
| Layer 1 allowlist pass | benign (high confidence) | Good — operator verified |
| Layer 2 correlation block | attack (high confidence) | Excellent — multi-signal confirmation |
| Layer 3 AI block | attack (moderate confidence) | Good — AI reasoning, but can be wrong |
| Layer 3 AI ignore | benign (moderate confidence) | Good — AI reasoning |
| Operator correction (Telegram undo) | corrected label | Best — human ground truth |

### What the model does after training

- **Pre-scores incidents** before AI is called — if model confidence is high, skip AI call (saves API cost)
- **Disagrees with AI** — flags for operator review (model says attack, AI says ignore, or vice versa)
- **Detects drift** — if model's normal baseline changes significantly, alerts operator

### When it starts being useful

- **Day 1-7**: learning only, no influence on decisions
- **Day 7+**: model starts pre-scoring, reduces AI calls by ~30-50%
- **Day 30+**: model handles most decisions, AI called only for novel threats

## Noise-Gate Reform

The noise-gate currently drops incidents that are "not interesting enough." It was designed to control AI API cost. It should NOT prevent local decision-making.

### Before (current)

```
incident → noise-gate (drops 99.5%) → AI → threshold (blocks 100%) → nothing happens
```

### After

```
incident → Layer 1 rules (always, free)
        → Layer 2 correlation (always, free)
        → noise-gate (controls AI cost only)
            → Layer 3 AI triage (if passes gate)
        → Layer 4 model learning (always, from all decisions)
```

## First-Hour Experience

On fresh install, default config, no API keys, public-facing server:

| Time | What happens |
|------|-------------|
| 0 min | Install complete, sensor + agent start, dry_run=true |
| 0-5 min | Sensor collects events, baseline begins |
| 5-15 min | First SSH brute-force arrives (every public server) |
| 5-15 min | Layer 1 rule fires → logs "WOULD BLOCK 185.x.x.x (SSH brute-force, 47 attempts)" |
| 15 min | Dashboard shows: "3 threats detected, dry-run mode — run `innerwarden config responder --dry-run false` to go live" |
| Post dry-run off | Next brute-force → actually blocked. Operator sees it work. |

No API key. No external database. The agent handled it.

## Implementation Phases

### Phase A: Layer 1 — Auto-Response Rules (2 days)

Wire detectors → rules → skills. The detectors fire. The skills exist (block_ip_ufw, block_ip_iptables, block_ip_nftables, block_ip_pf). The gap is the decision layer.

- Add `auto_rules` evaluation after incident creation in agent loop
- Add `AutoRule` struct with trigger, condition, action, cooldown
- 5 built-in rules (ssh_bruteforce, packet_flood, port_scan, web_scan, credential_stuffing)
- Respect allowlist, dry_run, internal IP exclusion
- Log every rule evaluation (decision audit trail)
- Config in `[responder.auto_rules]`

### Phase B: Layer 2 — Correlation Response (2 days)

Query knowledge graph for patterns that escalate response.

- Multi-technique detection (same IP, multiple detectors, time window)
- Repeat offender tracking (block count per IP from decision history)
- Kill chain completion → escalated response
- Integrate with existing correlation_engine.rs

### Phase C: Noise-Gate Reform + AI Pipeline (1 day)

Split the pipeline: local rules get all incidents, AI gets filtered.

- Noise-gate becomes AI cost controller only
- High/Critical always reach AI if configured
- Change threshold default from 1.01 to 0.85

### Phase D: Layer 4 — Model Learning (2 days)

Feed decisions to autoencoder.

- Every Layer 1 decision = training sample
- Every Layer 3 decision = training sample
- Operator corrections (Telegram undo) = high-quality correction
- Pre-scoring after 7-day warmup
- Disagreement flagging

### Phase E: First-Hour Validation (1 day)

Deploy to clean server, no API keys, observe.

- Measure time-to-first-detection
- Measure time-to-first-block (with dry_run off)
- Verify zero false positives on internal traffic
- Verify dashboard shows clear explanation

## Success Criteria

1. Fresh install blocks first threat within 30 minutes without external APIs
2. Zero false-positive blocks on internal IPs or allowlisted services in 7-day test
3. Layer 1 rules execute in < 100ms from detection
4. Layer 2 correlation queries complete in < 500ms
5. AI API calls reduced by 50%+ after 7-day model warmup
6. Dashboard shows blocked threats with clear explanation per layer
7. Dry-run mode produces identical log output without side effects
8. Every decision (all layers) written to audit trail with full context

## Resource Justification

Every subsystem must earn its RAM by feeding a decision:

| Component | RAM | Feeds Which Layer |
|-----------|-----|-------------------|
| Knowledge graph | ~50MB | Layer 2 (correlation, repeat offender) |
| Correlation engine | ~10MB | Layer 2 (multi-stage attack chains) |
| Baseline learning | ~5MB | Layer 2 (anomaly = escalation trigger) |
| Neural model | ~2MB | Layer 4 (pre-scoring, drift detection) |
| SQLite store | ~20MB | All layers (audit trail, history queries) |

## What This Spec Does NOT Cover

- Honeypot auto-deployment (exists, separate concern)
- Multi-node mesh coordination (separate spec)
- AI provider selection or model tuning (setup wizard, spec 003/004)
- Dashboard UX for response management (spec 017)

## Audit Table: Detector → Response Mapping

| Detector | Layer 1 Rule | Layer 2 Correlation | Layer 3 AI | Notes |
|----------|-------------|--------------------|-----------|----|
| ssh_bruteforce | block_ip 24h | repeat → permanent | — | Highest volume, clearest signal |
| packet_flood | block_ip 24h | repeat → permanent | — | Rate-based, deterministic |
| port_scan | block_ip 12h | + brute-force → 48h | — | Often precedes brute-force |
| web_scan | block_ip 12h | + port_scan → 48h | — | Scanner pattern |
| credential_stuffing | block_ip 24h | repeat → permanent | — | Distributed attack variant |
| process_tree | — | — | AI decides | Could be legitimate (OpenClaw, cron) |
| rootkit | — | — | AI investigates | High impact, needs confirmation |
| data_exfil | — | chain → alert | AI decides | High false positive rate |
| reverse_shell | — | chain → block+kill | AI confirms | Active compromise |
| crypto_miner | — | — | AI decides | kill_process candidate |
| dns_tunneling | — | chain → block | AI decides | C2 channel |
| lateral_movement | — | chain → alert(critical) | AI investigates | Multi-host concern |
