# Spec 020: Zero Trust Autonomous MDR

**Created**: 2026-04-15
**Status**: DRAFT
**Priority**: P0 (product differentiator — nothing else in the market does this)
**Depends on**: Spec 018 (Autonomous Response) must be at least Phase A+C done

## Vision

InnerWarden evolves from **reactive** (detect → respond) to **proactive** (deny by default → permit with proof). Every process, connection, and file access must earn trust continuously. The AI acts as a 24/7 SOC analyst that runs checks, builds reports, and makes decisions — no human in the loop for obvious threats, human approval for ambiguous ones.

**One sentence**: A self-defending Linux host where unknown binaries don't run, unauthorized connections don't leave, and an AI SOC analyst monitors everything 24/7 — all in a single binary, no cloud, no vendor lock-in.

## What exists today vs what this spec adds

```
TODAY (Observer):
  event → detect → log → dashboard → human reads (maybe)

SPEC 018 (Responder):
  event → detect → auto-rule/AI → block/alert → human confirms

SPEC 020 (Zero Trust MDR):
  PREVENTION:  unknown binary → HOLD → verify identity → allow/deny
               unknown connection → HOLD → check policy → allow/deny
               script modified → HOLD → AI evaluates → allow/deny
  DETECTION:   continuous trust scoring on every entity in graph
  RESPONSE:    autonomous, tiered, with escalation SLA
  INTELLIGENCE: daily AI SOC checks → automated report
  RECOVERY:    file quarantine, process containment, automated remediation
```

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    POLICY ENGINE                        │
│         deny-by-default, identity-based, continuous     │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  EXECUTION   │  │   NETWORK    │  │    FILE      │  │
│  │  IDENTITY    │  │   MICRO-SEG  │  │  INTEGRITY   │  │
│  │             │  │              │  │              │  │
│  │ Binary hash │  │ Process→dest │  │ Immutable    │  │
│  │ Lineage     │  │ DNS policy   │  │ paths        │  │
│  │ Script sign │  │ Port allow   │  │ Hash baselin │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                │                  │          │
├─────────┴────────────────┴──────────────────┴──────────┤
│              eBPF ENFORCEMENT PLANE                     │
│                                                         │
│  LSM bprm_check  XDP block      LSM file_open          │
│  LSM bpf         connect probe  fanotify               │
│  execve trace    bind/listen    mprotect               │
├────────────────────────────────────────────────────────┤
│              CONTINUOUS TRUST ENGINE                    │
│                                                         │
│  Entity trust score 0-100 on every Process/IP/User     │
│  Score decays with anomalies, restores with conformity  │
│  Threshold breach → challenge → deny → quarantine      │
├────────────────────────────────────────────────────────┤
│              AI SOC ANALYST                             │
│                                                         │
│  Daily checks (06:00 UTC) → structured output          │
│  AI analysis → delta from yesterday → report           │
│  Threat hunting queries on knowledge graph              │
│  Proactive recommendations                              │
├────────────────────────────────────────────────────────┤
│              RESPONSE & RECOVERY                        │
│                                                         │
│  Tiered: auto → confirm(30s) → escalate(5min)          │
│  File quarantine │ cgroup freeze │ remediation          │
│  Undo window │ Audit trail │ Break-glass               │
└────────────────────────────────────────────────────────┘
```

## Phases

### Phase A — Process Zero Trust: Execution Identity Registry

**What**: No unknown binary executes without verification. Every binary has an identity (SHA-256 hash + lineage).

**What already exists**:
- LSM `bprm_check_security` hook (can allow/deny execve)
- `execution_guard` with tree-sitter-bash AST parsing
- Baseline learning tracks process lineages (parent→child)
- Allowlist system (`allowlist.toml`)

**What to build** (~400 lines, `crates/agent/src/execution_identity.rs`):

1. **Binary Identity Registry** — persistent store of known-good binaries:
   ```rust
   struct BinaryIdentity {
       path: String,
       sha256: String,
       first_seen: DateTime<Utc>,
       last_verified: DateTime<Utc>,
       verified_by: VerifiedBy,   // learning | operator | ai | package_manager
       lineage: Vec<String>,      // expected parent chain: ["systemd", "nginx"]
       trust_score: u8,           // 0-100
   }
   ```

2. **Learning Mode** (days 0-7): observe all executions, build registry automatically. Every binary that runs is recorded with its lineage. No blocking.

3. **Notify Mode** (days 7-30): unknown binaries still run but trigger alert. Operator classifies via Telegram: "known" (add to registry) or "suspicious" (investigate).

4. **Enforce Mode** (day 30+): unknown binaries held at LSM. AI evaluates (or operator approves via Telegram 2FA). Approved = added to registry. Denied = EPERM + alert.

5. **Lineage Policy**: `nginx` can spawn `nginx: worker` but not `sh`. Violations trigger alert even if binary is known.

6. **Script Signing Cache** (from `security-copilot.md`):
   - First execution: AI reads entire script, evaluates, generates SHA-256 signature
   - Subsequent executions: hash match → instant allow (<1ms)
   - Modified script: hash mismatch → re-evaluate
   - Scripts in `/tmp`, `/dev/shm`, `/var/tmp` never cached (attacker-writable)
   - TTL 30 days (dependencies may change)

**Config**:
```toml
[zero_trust.execution]
mode = "learning"    # learning | notify | enforce
learning_period_days = 7
notify_period_days = 30
trusted_parents = ["cron", "systemd", "ansible", "puppet", "chef", "jenkins", "gitlab-runner"]
never_cache_paths = ["/tmp", "/dev/shm", "/var/tmp"]
script_signing = true
script_eval_timeout_secs = 60
```

**Coverage** (from `cobertura-ataques-copilot.md`):
- SSH brute force → shell (25%): blocked — attacker's binaries unknown
- Exploit → download payload (20%): blocked — curl|sh denied, binary unknown
- Web shell (15%): blocked — script in /var/www unknown
- Supply chain (10%): blocked — modified build script has new hash
- Cryptominer (10%): blocked — unknown binary
- Ransomware (5%): blocked — unknown binary + mass write detection
- **Total: ~85% of Linux attacks prevented BEFORE damage**

---

### Phase B — Network Zero Trust: Per-Process Micro-Segmentation

**What**: Every outbound connection must match a per-process network policy. nginx can talk to port 443 but not IRC.

**What already exists**:
- `connect` tracepoint (tracks all outbound connections)
- XDP program (wire-speed IP blocking)
- Baseline learning tracks "destinations per process"
- `ConnectedTo` edges in knowledge graph

**What to build** (~350 lines, `crates/agent/src/network_policy.rs`):

1. **Per-Process Network Policy**:
   ```rust
   struct ProcessNetworkPolicy {
       comm: String,                    // "nginx"
       allowed_ports: Vec<u16>,         // [80, 443]
       allowed_destinations: Vec<String>, // ["*.cloudflare.com"]
       allowed_protocols: Vec<String>,  // ["tcp"]
       deny_internal: bool,            // false (nginx needs loopback)
   }
   ```

2. **Learning Mode**: baseline learning already tracks destinations per process. After 7 days, auto-generate policies from observed behavior.

3. **Enforcement via eBPF**: new BPF map `(comm, dst_port) → allow/deny`. Checked at `connect` tracepoint. Violations blocked + alerted.

4. **DNS Policy**: only authorized resolvers (from baseline). DNS to non-resolver = potential C2. Already have `dns_capture.rs`.

5. **Lateral Movement Prevention**: no process can connect to other hosts on SSH (port 22) unless explicitly allowed. Catches compromised services trying to spread.

**Config**:
```toml
[zero_trust.network]
mode = "learning"    # learning | notify | enforce
learning_period_days = 7
block_lateral_ssh = true
dns_resolvers_only = true

[[zero_trust.network.policies]]
comm = "nginx"
allowed_ports = [80, 443, 8080]

[[zero_trust.network.policies]]
comm = "postgres"
allowed_ports = [5432]
deny_external = true
```

---

### Phase C — Continuous Trust Scoring Engine

**What**: Every entity in the knowledge graph has a trust score 0-100 that decays with anomalies and restores with conformity.

**What already exists**:
- Knowledge graph with 11 node types
- IP reputation scoring (AbuseIPDB, CrowdSec)
- Trust rules (`trust_rules.rs`)
- Baseline learning (process lineages, login hours, event rates)

**What to build** (~300 lines, `crates/agent/src/trust_score.rs`):

1. **Entity Trust Score** on Process, User, IP nodes:
   ```rust
   struct TrustScore {
       score: f32,          // 0.0 - 100.0
       factors: Vec<TrustFactor>,
       last_updated: DateTime<Utc>,
       decay_rate: f32,     // per-hour decay when no activity
   }

   enum TrustFactor {
       KnownBinary { hash_verified: bool },       // +30
       BaselineConformity { deviation: f32 },      // +20 to -20
       LoginHours { within_normal: bool },          // +10 or -10
       NewDestination { count: u32 },               // -5 per new dest
       UnknownLineage { parent: String },           // -20
       ReputationScore { abuseipdb: f32 },          // -0 to -40
       OperatorVerified { when: DateTime<Utc> },    // +30
       IncidentHistory { count_7d: u32 },           // -5 per incident
   }
   ```

2. **Thresholds**:
   - Score > 70: normal operation
   - Score 40-70: enhanced monitoring (extra logging, pcap)
   - Score 20-40: challenge (require 2FA for actions, restrict network)
   - Score < 20: deny (kill process, block IP, suspend user)

3. **Score feeds into Layers 1-4** from spec 018:
   - Layer 1: trust score modifies block duration (low trust = longer block)
   - Layer 2: correlation escalation weighted by trust
   - Layer 3: AI receives trust score as context
   - Layer 4: model learns trust score as feature

---

### Phase D — AI SOC Analyst: Daily Checks + Threat Hunting

**What**: AI runs a daily security checklist, compares with yesterday, builds report, hunts for threats in the graph.

**What already exists**:
- AI provider pipeline (OpenAI/Anthropic/Ollama)
- `agent-guard` for safe command execution (29 patterns, allow/review/deny)
- `threat_report.rs` for monthly reports
- Knowledge graph for queries
- Baseline learning for anomaly context

**What to build** (~400 lines, `crates/agent/src/daily_check.rs`):

1. **Daily Security Checklist** (06:00 UTC, configurable):

   | Check | Command | What it catches |
   |---|---|---|
   | Open ports | `ss -tlnp` | Backdoor listeners, unauthorized services |
   | Recent logins | `last -n 50` | Unauthorized access, unusual hours |
   | System errors | `journalctl --since yesterday --priority err` | Service failures, kernel panics |
   | Disk usage | `df -h` | Exfiltration staging, log bomb |
   | User accounts | `getent passwd \| wc -l` | Persistence via new users |
   | Executables in /tmp | `find /tmp -executable -type f` | Dropped payloads |
   | Failed services | `systemctl --failed` | Tampered services |
   | Firewall rules | `iptables-save \| wc -l` | Rule tampering |
   | InnerWarden scan | `innerwarden scan` | Configuration drift |
   | Shadow changes | `sha256sum /etc/shadow` | Credential modification |
   | Crontab changes | `sha256sum /var/spool/cron/*` | Persistence |
   | SSH authorized_keys | `find /home -name authorized_keys -exec sha256sum {} \;` | Key injection |
   | Kernel modules | `lsmod \| wc -l` | Rootkit modules |
   | SUID binaries | `find / -perm -4000 -type f 2>/dev/null \| sha256sum` | Privilege escalation tools |
   | Package integrity | `debsums -s 2>/dev/null \|\| rpm -Va 2>/dev/null` | Tampered packages |

2. **Execution Safety**:
   - Every command passes through `agent-guard` before execution
   - Read-only commands only (no `rm`, `dd`, `mkfs`)
   - No pipe to shell (`ss | sh` = deny)
   - Timeout 30s per command
   - Audit trail: every command logged to hash chain

3. **AI Analysis**:
   - Collect all outputs → structured JSON
   - Compare with yesterday's baseline (stored in SQLite)
   - Send delta to AI: "What changed? What's suspicious? What should I investigate?"
   - AI produces Daily Security Report

4. **Threat Hunting on Graph**:
   - Query graph for anomalies the checks can't see:
     - Processes with unusual fan-out (>10 children in 1h)
     - IPs that connected to multiple unrelated services
     - Users that ran commands outside their baseline hours
     - Files accessed by processes that never accessed them before
   - Results feed into daily report

5. **Report Delivery**:
   - Dashboard: new "Daily Check" tab
   - Telegram: summary digest
   - Exportable Markdown (for compliance)

**Config**:
```toml
[daily_check]
enabled = true
schedule = "06:00"
timezone = "UTC"
ai_analysis = true
deliver = ["dashboard", "telegram"]

# Custom checks beyond built-in 15
[[daily_check.custom]]
name = "docker_containers"
command = "docker ps --format json"

[[daily_check.custom]]
name = "tls_expiry"
command = "openssl x509 -in /etc/ssl/certs/server.pem -noout -enddate"
```

---

### Phase E — Response & Recovery

**What**: When Zero Trust denies or the MDR detects, respond with containment AND recovery — not just "block IP".

**What already exists**:
- Skills: block_ip (5 backends), kill_process, suspend_user_sudo, block_container
- Playbook engine (20 built-in)
- Pcap capture on incidents
- 2FA approval via Telegram

**What to build** (~500 lines across multiple files):

1. **File Quarantine** (from `edr-xdr-roadmap.md`):
   ```
   malicious file → move to /var/lib/innerwarden/quarantine/
   preserve: original path, permissions, timestamps, SHA-256
   restore: innerwarden quarantine restore <hash>
   ```
   New skill: `quarantine_file`

2. **Process Containment** (from `edr-xdr-roadmap.md`):
   ```
   suspicious process → cgroup freeze (FROZEN state)
   process halted, memory preserved for investigation
   operator can: kill, resume, or inspect via /proc
   ```
   New skill: `contain_process` (cgroup freeze instead of kill)

3. **Automated Remediation**:
   ```
   crontab persistence → remove the injected line
   SSH key injection → remove the injected key
   systemd persistence → disable + remove the unit
   ```
   New skill: `remediate` with per-detector cleanup actions

4. **Escalation Tiers with SLA**:

   | Tier | Trigger | Action | SLA |
   |---|---|---|---|
   | Auto | Trust score < 20 OR Layer 1 rule | Execute immediately | 0s |
   | Confirm | Trust score 20-40 OR Layer 3 AI | Telegram 2FA confirm | 30s, auto-act if no response |
   | Escalate | Novel threat, AI uncertain | Dashboard task + all channels | 5min, alert again |
   | Break-glass | Operator locked out | Pre-generated recovery key | Physical access |

5. **Undo Window**: every automated action has a 5-minute undo window via Telegram. After 5 min, action becomes permanent.

---

### Phase F — Graduated Enforcement Lifecycle

**What**: The entire Zero Trust system follows a maturity model — no host goes from "nothing" to "deny-by-default" overnight.

From `telegram-interactive-triage.md`:

```
Day 0        Day 7           Day 30            Day 60+
LEARNING ──→ NOTIFY ──────→ SOFT ENFORCE ───→ FULL ENFORCE
observe      alert on        block unknown      block + remediate
build        unknown         allow override     auto-quarantine
baseline     operator        via 2FA            minimal human
             classifies
```

**Per-subsystem maturity**:

| Subsystem | Learning (0-7d) | Notify (7-30d) | Enforce (30d+) |
|---|---|---|---|
| Execution identity | Record all binaries | Alert on unknown | Block unknown |
| Network policy | Record all connections | Alert on new dest | Block unauthorized |
| Trust scoring | Calibrate baselines | Show scores in dashboard | Scores drive responses |
| Daily checks | Establish baselines | Report deltas | Auto-investigate anomalies |
| File integrity | Hash all sensitive files | Alert on changes | Quarantine unauthorized changes |

**Key safety**: each subsystem transitions INDEPENDENTLY. Network can be in "enforce" while execution is still in "notify". Operator controls maturity per subsystem.

```toml
[zero_trust]
execution_mode = "notify"      # per-subsystem control
network_mode = "learning"
trust_scoring_mode = "notify"
daily_check_mode = "notify"
file_integrity_mode = "enforce"
```

---

## Implementation plan

| Phase | What | New code | Depends on | Sessions |
|---|---|---|---|---|
| **A** | Execution Identity Registry + Script Signing | ~400 lines | Spec 018 Phase A | 2 |
| **B** | Network Micro-Segmentation | ~350 lines + eBPF map | Phase A | 2 |
| **C** | Continuous Trust Scoring Engine | ~300 lines | Phase A | 1 |
| **D** | AI SOC Daily Checks + Threat Hunting | ~400 lines | Spec 018 Phase C | 2 |
| **E** | File Quarantine + Process Containment + Remediation | ~500 lines | Spec 018 Phase A | 2 |
| **F** | Graduated Enforcement Lifecycle | ~200 lines (config + state machine) | Phases A-E | 1 |
| **Total** | | **~2,150 lines** | | **10 sessions** |

## Competitive analysis

| Feature | CrowdStrike | SentinelOne | Falco | Wazuh | **InnerWarden 020** |
|---|---|---|---|---|---|
| Kernel enforcement | Driver (crashes kernel — July 2024) | Driver | eBPF (observe only) | None | **eBPF + LSM (safe, no crash)** |
| Binary allowlisting | CrowdStrike Prevention | SentinelOne Static AI | No | No | **AI + hash + lineage** |
| Script evaluation | ML on binary | Static + dynamic AI | No | No | **AI reads script content + signs** |
| Network micro-seg | Falcon Firewall | Firewall | No | No | **Per-process eBPF policy** |
| Trust scoring | Risk Score | Confidence | No | No | **Continuous, per-entity, graph-based** |
| AI SOC analyst | Charlotte AI ($$$) | Purple AI ($$$) | No | No | **Built-in, local Ollama or API** |
| Self-hosted | No (cloud-only) | No (cloud-only) | Yes | Yes | **Yes** |
| Price | $25-50/endpoint/month | $20-40/endpoint/month | Free | Free | **Free (Apache-2.0)** |
| File quarantine | Yes | Yes | No | No | **Yes** |
| Process containment | Yes (network isolation) | Yes | No | No | **Yes (cgroup freeze)** |
| Automated remediation | Partial | Partial | No | No | **Yes (per-detector cleanup)** |

**The gap no one fills**: open-source + eBPF enforcement + AI triage + Zero Trust identity — all in one binary, self-hosted, no cloud dependency. CrowdStrike and SentinelOne have the features but cost $300-600/host/year and require cloud. Falco and Wazuh are free but observe-only.

## Success criteria

1. Unknown binary on fresh install (day 31+): blocked within 1ms at LSM
2. Known binary with wrong lineage (nginx→sh): alerted within 2s
3. Process connecting to unauthorized port: blocked at eBPF connect
4. Daily check runs in <2min, report delivered by 06:15 UTC
5. Trust score updates within 30s of relevant event
6. File quarantine preserves evidence (path, perms, hash, timestamps)
7. Process containment via cgroup freeze: process frozen, not killed
8. Graduated enforcement: each subsystem transitions independently
9. Zero false-positive blocks during learning period
10. Works with zero external APIs (Ollama local), better with cloud AI

## Ideas incorporated from /ideias/

| Source file | What was incorporated |
|---|---|
| `edr-xdr-roadmap.md` | File quarantine, process containment, remediation, EDR claim |
| `security-copilot.md` | Script signing, TTY detection, AI command evaluation, trusted parents |
| `cobertura-ataques-copilot.md` | Coverage analysis: 85% prevention rate, attack vector breakdown |
| `active-defence-root-zero-dano.md` | Execution gate, soft/hard lock, recovery automation |
| `telegram-interactive-triage.md` | Graduated enforcement lifecycle (observe→notify→enforce) |
| `URGENT-ai-auto-decision-guard-mode.md` | Guard mode contract, severity recalibration |
| `ux-strategy-three-pillars-2026-04-05.md` | Notification budget, Bayesian scoring, concept drift, federated baseline |
| `data-analysis-features.md` | AI briefing, attack stories, predictive risk, time-of-day patterns |
| `knowledge-graph-implementation-plan.md` | Graph as foundation for trust scoring and threat hunting |

## Out of scope

- **Multi-host central console** — separate spec (needs mesh protocol extension)
- **Cloud telemetry** (AWS/GCP/Azure integration) — future XDR spec
- **IdP integration** (LDAP/OIDC) — future identity spec
- **GNN model** (GraphSAGE/GAT) — requires 100+ labeled scenarios, Phase C trust scoring comes first
- **Network engine deep parsing** (TCP reassembly, HTTP/2, SMB) — separate spec, independent effort
- **Security Copilot terminal response** (write to user's TTY) — nice to have, not MVP
