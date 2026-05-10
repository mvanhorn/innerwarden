# Changelog

All notable changes to Inner Warden are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

- **GHA-released agent now ships with Local Warden Model linked in.** Pre-fix the release workflow built the agent with `cargo zigbuild --release -p innerwarden-agent` without `--features local-classifier`, which meant every binary downloaded from the GitHub release page (including via the `curl | sudo bash` install script and `innerwarden upgrade`) had the on-device ONNX classifier missing — at startup the agent logged `local_warden provider requires building innerwarden-agent with --features local-classifier` and silently fell back to whatever cloud provider was configured. Operators using `scripts/deploy-prod.sh` were unaffected because that script always passed the feature explicitly. The condition has existed at least since v0.13.0 and went undetected because the prior asset manifest checked filenames, not binary content. Fix: pass `--features local-classifier` on both x86_64 and aarch64 build steps in `release.yml`. The binary feature-parity guard from PR #520 verifies the `local_classifier` symbol is present and now hard-fails the release if it is not — so the regression cannot recur.

### Release pipeline

- **Binary feature-parity guard** in `release.yml`. After staging the release assets, the workflow now greps each `innerwarden-agent-linux-{x86_64,aarch64}` binary for the symbol/string markers that prove production features were linked in: `opt_prof` / `prof_init` from jemalloc heap profiling (spec 030, the systemd `MALLOC_CONF=prof:true,...` drop-in), and `local_classifier` from the Local Warden Model provider (spec 029, the `--features local-classifier` build). Local Warden absence is now a hard fail (the build above passes the feature explicitly); jemalloc heap-profile absence is a hard fail too (would segfault every operator with the spec-030 jeprof systemd drop-in). Both regressions reached production in v0.13.0–v0.13.2 undetected because the prior asset manifest only checked filenames, never binary content.

### Known caveat (v0.13.0 – v0.13.2 GHA-released binaries)

- The agent binaries on the GitHub release pages for v0.13.0, v0.13.1, and v0.13.2 were all built without `--features local-classifier`, so the **Local Warden Model is inert** on those binaries — the agent silently falls back to whichever cloud provider is configured (or runs without AI if none is). They also segfault when launched with `MALLOC_CONF=prof:true,...` (the jemalloc heap-profile symbols are missing or unreachable). **Operators on those releases should either re-install once v0.13.3 is published or build locally via `scripts/deploy-prod.sh`** (which always passed the right feature flags). The next release (v0.13.3) is the first to verify both via the binary feature-parity guard above; subsequent releases inherit the gate.

## [0.13.2] - 2026-05-10

Dashboard UX + AI explainer clarity + architecture-diagram honesty bundle. Three small operator-surfaced fixes from the post-v0.13.1 dashboard review, packaged as the next stable release so the v0.13.x line keeps moving.

### Fixed

- **Baseline tab: pagination collapsed the "What I consider normal here" section.** Operator-surfaced 2026-05-10. Repro: Intel → Baseline → expand the learned-baseline `<details>` → click Next on the user-list pagination → section collapses unexpectedly. Root cause: `loadBaseline()` rebuilds `intelContent.innerHTML` from scratch on every pagination click, and the `<details>` element was recreated without the `open` attribute. Fix persists the open state in `localStorage` (mirroring the existing "Show system accounts" toggle pattern) and re-applies the attribute on every render. (`crates/agent/src/dashboard/frontend/js/intel.js`)
- **AI Explainer: "No incidents on record" was confusing on baseline pages.** Operator clicked "Ask AI to explain" for an IP shown on the Baseline tab (50 deviations attributed to the IP) and got "No incidents on record". Technically correct (baseline deviations are not `Node::Incident`), but the operator read this as "the entity is unknown" rather than "the explainer covers a different signal class". Message rewritten to spell out the boundary: the explainer summarises incident-grade events that reached the decision pipeline (block / dismiss / escalate / honeypot), NOT baseline deviations / process-trust drift / threat-intel hits / honeypot probes that did not produce an incident. (`crates/agent/src/dashboard/data_api.rs::build_explain_context`)

### Changed

- **README architecture diagram now shows the Local Warden classifier.** Pre-fix the diagram listed only "AI Triage (opt) — OpenAI / Anthropic / Ollama" as the AI block, which understated reality: Spec 029 (PR #258) made the on-device Local Warden ONNX classifier the canonical Decide path; cloud LLMs are the optional fallback / Explain capability via the AI Capability Router. The diagram now shows Local Warden first (with the model name, on-disk size, and p50 latency) and the cloud LLMs as a second tier behind the router. Reflects what every install with the default `local-classifier` feature actually does at runtime.

### Release pipeline note

- **v0.13.1 macOS binaries are intentionally absent.** Release workflow #113 hit a tag-pointing race (the v0.13.1 tag was force-pushed from the prep-PR commit to the post-merge squash commit while the macOS job was still running, so the macOS runner saw a checkout mismatch and aborted). Linux x86_64 / aarch64 + Docker + GitHub Artifact Attestations all shipped clean for v0.13.1. v0.13.2 is cut from a stable main HEAD so the same race cannot recur; macOS binaries return on the v0.13.2 release.

### Tests

- `cargo test --workspace`: **6632 passed + 5 ignored** across 35 test suites in 94 s.

---

## [0.13.1] - 2026-05-10

Honeypot effectiveness, posture-aware alerting, and infrastructure honesty release. The headline shift is the honeypot turning from a credential mirror with the door always open into a real behavioural trap that captures Mirai-class bots, manual brute-forcers, and human-direct attackers, without giving away what it is. 50 commits since 0.13.0.

### Added — Spec 046 honeypot effectiveness (PRs #508, #509, #510)

- **Tiered SSH authentication** (`crates/agent/src/skills/builtin/honeypot/ssh_interact.rs`). Reject the first `MIN_ATTEMPTS_BEFORE_ACCEPT = 2` password attempts unconditionally, single-shot credential scanners disconnect on the first reject, dropper bots iterate. Then accept ONLY when `(user, password)` matches `KNOWN_WEAK_CREDENTIALS` (38 entries: classic root defaults + Mirai canonical defaults + appliance defaults). Random brute-force NEVER accepted; single-shot scanners NEVER accepted. Credential capture is unconditional and runs BEFORE any branch.
- **Phase A.5 adaptive accept**: after `MIN_UNIQUE_CREDS_FOR_ADAPTIVE_ACCEPT = 3` distinct passwords on a single connection, the next attempt accepts regardless of weakness. Catches human-direct attackers typing org-specific guesses (`Welcome2024!`, `OracleVM!`, `MyHost_admin`) without double-firing on bots (which hit `KNOWN_WEAK` first).
- **OpenSSH banner masquerade**. The russh default `SSH-2.0-russh_*` was a one-token honeypot fingerprint; replaced with `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` via `Config::server_id`. 80 ms `tokio::time::sleep` per rejected attempt simulates real OpenSSH timing.
- **Dashboard pagination + engaged-only default**: `GET /api/honeypot/sessions` accepts `?page=N&size=M&engaged_only=true|false`. Default `engaged_only=true` makes the tab open to the wow-surface (sessions with auth attempts or commands), not the wall of port-scan probes. Page size clamped `[1, 100]`. Three distinct empty states.
- **Per-session transcript expand**: engaged sessions get an "Expand transcript" button revealing full attacker activity inline.
- **Auto-dismiss honeypot probe noise**: `proto_anomaly` (`SshVersionAnomaly`) on the honeypot port writes a `dismiss` decision with reason `honeypot-probe-fp` and removes from "needs attention". KG-hardened: keeps the proto_anomaly visible if the same IP has any non-`proto_anomaly` incident in the last 24h.
- **Feynman-style AI explanations** (`crates/agent/src/dashboard/data_api.rs::explain_system_prompt`): "Ask AI to explain" returned generic 2-sentence summaries that did not help non-technical operators understand "should I worry?". Rewrote the prompt around the Feynman technique (story, why, threat verdict, with explicit honeypot-context awareness). New `build_explain_context` helper extracts as a pure function with KG fallback (walks Incident nodes by `decision_target` / title / summary text when the IP has no `Node::Ip`), retiring the legacy "No data found for IP X" message.

### Added — Spec 044 posture-aware alerting (PRs #502, #503, #504)

- **`HostPosture` snapshot module** (`crates/agent/src/posture/`): every 10 min, the slow loop reads `sshd_config`, `sudoers`, `services`, `firewall`, persists to `data_dir/posture.json`. New CLI subcommand `innerwarden get posture`.
- **Severity downgrade engine** (`effective_severity`): incidents whose severity is dictated by an attack vector the host's posture has already neutralised get demoted (e.g., `ssh_bruteforce method=password` on a host with `PasswordAuthentication=no` becomes Low instead of High). Hard invariant: NEVER demote when `session_established | process_executed | file_written` (you only suppress severity for things the posture provably bounds).
- **Telegram `/posture` command + dashboard panel**: operator can read the live posture from either surface.
- **Daily briefing rewrite**: the dishonest "0/100 server health score" was retired (formula was `100 − critical*20 − high*5` clamped 0..100, dropped to zero on routine activity). Replaced with posture-aware narrative.

### Added — Spec 043 KG justification follow-ups (PRs #472–#481)

- **Decide path reads KG** (`kg_decide_features`): 6 features extracted at decision time (risk_score, prior_incidents_24h, first_seen_age_days, etc.), 4 modifier bands, Critical floor preserved, JSONL shadow log.
- **`/ask` deep context**: Telegram and dashboard `/ask` surfaces now reference KG features and threat-feed datasets directly when the question mentions an IP. 8000-char prompt budget, subgraph triggered by IP regex.
- **KG modifier on direct-block paths**: `apply_kg_decide_modifier` wired into repeat-offender, multi-technique, completed-chain code paths.
- **Four "zona morta" detectors activated**: `yara_match`, `sysctl_drift`, `packed_binary`, `short_lived_process`. Default ON via `[kg]` config.
- **KG-based FP suppression (shadow-first)**: `kg_fp_suppression` module; `fp_likelihood = 0.7×history + 0.3-cap-bonus`; Critical floor hardcoded; `suppress_threshold=0.80`.
- **Akamai/Fastly/CloudFront-specific CIDRs** added to cloud safelist.
- **KG audit hook on AbuseIPDB-gate**: captures the IP's KG snapshot at block time for forensics.

### Added — Kill chain fast-path (PR #507)

- Deterministic strong patterns (`reverse_shell`, `bind_shell`, `code_inject`, `inject_shell` and their sensor-detector aliases `ebpf_reverse_shell`, `ebpf_bind_shell`) bypass the AI router and trigger `decision_block_ip::execute_block_ip_decision` directly. AI verdict was 100% deterministic for these patterns, so the AI call latency (~100 ms local / 1-3 s cloud LLM) was pure overhead. `data_exfil` and `exploit_c2` deliberately stay in the AI path so the codex/openclaw dismiss helpers continue to fire. 10 anchor tests pin every fast-path boundary.

### Fixed

- **Honeypot: russh strips `Password` from method list after reject** (PR #509). Caught during prod smoke. `Auth::Reject { proceed_with_methods: None }` triggers `auth_request.methods.remove(MethodKind::Password)` inside russh-0.60.1. After the first reject, the OpenSSH client saw only `publickey,hostbased,keyboard-interactive` and disconnected, the dropper bot never reached attempt #2 on the same connection. Fix: send `Some(MethodSet::all())` on every reject branch.
- **Honeypot off-by-one in threshold guard** (PR #508 review). First push used `attempt_n < MIN_ATTEMPTS_BEFORE_ACCEPT`, leaking attempt #2 with `admin/admin` through to accept on the second try. Fixed to `<=`. New anchor `weak_credential_on_second_attempt_still_rejects`.
- **Honeypot `max_auth_attempts` floor** (PR #508 review). Caller passing `1` or `2` made the shell unreachable even for perfect Mirai matches (russh closes session before our accept branch runs). New `floor_max_auth_attempts` clamps below-floor values up to `MIN_ATTEMPTS_BEFORE_ACCEPT + 1`.
- **CIDR auto-block** (PRs #496, #497, #498). Three paths (automated decision flow, repeat-offender, safelist gate, AI router execute boundary) still allowed CIDR targets in automated decisions. Closed in layered fashion. ip_reputations zombie cleanup.
- **Decision-cooldown retention** (PR #499). Window was 2h; the longest consumer needed 24h. Raised retention so cooldowns survive the slow path window.
- **AI router suppression when inline path already decided** (PR #500). Avoids double-decisions when kill_chain fast-path or other inline routes already wrote a decision before AI router runs.
- **AbuseIPDB autoblock honesty** (PR #495). Multiple bypass paths fixed; AWS CIDR gap closed; kill_chain `wget` FP eliminated.
- **XDP infrastructure honesty** (PR #494). Three cascading bugs from prod 2026-05-08 audit: cleanup state drift between local set and kernel map, parse failures dropping local entries, adaptive TTL expiry signalling.
- **Profiles dashboard geo** (PRs #492, #493). Cloud-provider IPs now badged + operator can opt-in to exclude; ASN majority drives geo consolidation when WHOIS and ip-api disagree.
- **Threat-DNA hour_distribution drift** (PR #491). Same-actor cross-day clusters were splitting because the hour-of-day distribution changed across midnight. Dropped from the DNA hash.
- **Operator-FP attack chain suppression** (PR #501). Suppress at persistence boundary so the chain UI does not show transient operator-self traffic as "active attack chain".
- **Chains tab honesty bundle** (PR #500). Five lies on the Intelligence > Chains panel fixed: window scope, count cardinality, severity distribution, "active" semantics, attribution.
- **Wave 2-10 audit fixes** (PRs #461-#469): IPv6/IPv4 entity holes, `flock(LOCK_EX)` on hash-chain append, in-batch AbuseIPDB counter prevents burst bypass, agent-guard pipe detector evasion, Cloudflare real-client-behind-edge attribution, blocks counted via non-incident paths.
- **Dashboard label honesty (Wave 8)** (PR #460): every operator-visible counter now declares its window, scope, and cardinality explicitly. Removed implicit "today" / "all" labels that drifted between surfaces.
- **SECURITY.md + THREAT_MODEL.md drift fix (Wave 7)** (PR #461): two of the operator-facing security docs had aged out of sync with the implementation. Synced + added anti-drift anchors that fail CI when prose disagrees with the code.
- **Notification noise + Top-5 leftovers** (PR #470): bundle-fix for the `Top 5 attackers` widget showing duplicate IPs across rows, plus three Telegram digest noise sources (idle-hour kernel-module event spam, stale honeypot session re-emit, briefing redundancy).
- **Briefing "all clear" honesty** (PR #482): suppressed when High+ activity exists.

### Fixed — CTL + harden surface (operator self-audit)

- **Watchdog-aware harden score** (PR #505): `innerwarden harden` was reading `systemctl is-active innerwarden-agent` and reporting "agent not running" because in the new watchdog deploy model the agent is a child process of `innerwarden-watchdog` and `innerwarden-agent.service` is intentionally inactive. New detection logic walks the watchdog process tree. Combined with auditctl rule-syntax fix (the harden-suggested `-w` mixed with `-a -F arch -S` was rejected by auditctl), prod harden score went from 59 → 89 on the operator's box.
- **CTL `nginx error log` discovery + soft-warn** (PR #486, Bug 4 from prod audit): `innerwarden scan` was hard-failing when nginx error.log existed at a non-default path. Now soft-warns + suggests the canonical path; harden continues.
- **CTL `auditd category score` recalibration** (PR #485): auditd rules had a 30-pt bonus that was double-counted across two categories, inflating clean-system scores by ~25 pts.
- **CTL `systemctl bus failure` cascade** (PR #484): a single missing systemd bus connection cascaded the entire harden run into "unknown" status. Split into a tri-state (`active` / `inactive` / `bus-unreachable`) so operator sees the actual problem.

### Performance

- **`Arc<str>` interning** on hot Event-kind/source paths, telemetry counters, baseline HashMap keys (PRs #463, #464, #465). KG telemetry counter keys now share allocations across threads.

### Tests

- **2954 / 2954 pass + 2 ignored**. Net add of ~50 anchor tests across honeypot, posture, KG, CIDR-guard, dismiss helpers.
- **Coverage batches 2 + 3** (PRs #487, #488): 16 files lifted to ≥ 70% with gate-contract anchors. CI fuzz workflow fix.
- **4 new honeypot integration scenarios** (Mirai-class bot, root brute bot, human-direct attacker, retry-loop anti-regression) via real `russh::client` against ephemeral listeners.

### Changed

- Cargo workspace version → `0.13.1`.
- Default honeypot `interaction = "llm_shell"` is now the canonical "trap that captures behaviour" path; `medium` (`RejectAll`) preserved unchanged for credential-only deployments.

### Operator-visible

- Honeypot tab opens to the engaged-only first page by default. Pagination at top + bottom. Engagement banner explains the engaged-vs-unengaged split with Spec 046 context.
- "Ask AI to explain" returns a coherent narrative even when the IP is not yet in the KG node table (operator's 2026-05-10 case for `175.110.112.8`).
- Daily Telegram briefing reflects host posture and dropped the dishonest 0/100 score line.

---

## [0.13.0] - 2026-05-03

Operator-trust release. Closes the recurring "the dashboard says one number, the site says another, JSONL says a third" class of bug. Adds the persistent IP→geo cache that keeps the site map honest at scale (138+ unique attackers/day on the operator's prod host). Removes the half-shipped playbook engine (deferred to Spec 042).

### Added — Wave 6a (PR #434)
- **Persistent GeoIP cache** (`crates/agent/src/geo_cache.rs`) — IP → geo-entry map with 7-day TTL, atomic tmp-rename persistence at `data_dir/geo-cache.json`. Public site `Attack origins` map was making N round-trips to ip-api.com per page load (N = unique attacker IPs); with 138 unique IPs in 24h and ip-api free tier capped at 45 req/min, cold-cache load took ~3 minutes to plot all markers. Cache makes subsequent loads instant.
- **`/api/live-feed` carries pre-attached geo** — new `sources: Vec<{ip, country, lat, lon, incidents}>` field (capped at 200 by activity). Frontend renders the map immediately for cached IPs without per-IP `/geoip` follow-up. Cache misses arrive with `country=""`/`lat=lon=0` so the JS can decide to skip or render at the equator until a backfill round.
- **`/api/live-feed/geoip` is cache-first** — hits return immediately with no network call. Misses fall through to ip-api and write back to the cache so the next call is instant.

### Fixed — Wave 5 / 5b / 5c (PRs #427 #429 #430 #431 #432 #433)

**Number honesty:**
- **Site live-feed and dashboard counts now match prod truth (PR #433)** — public `/api/live-feed` walked ONLY the in-memory KG; KG TTL evicted everything older than ~1 day. Site reported `4 events / 0 IPs blocked / 0 high (24h)` while prod JSONL had 42 incidents and 647 block decisions for the same window. New `merge_incidents_prefer_kg` / `merge_decisions_prefer_kg` helpers concat KG (rich entity context) with JSONL (full daily history), dedup by `incident_id`. Today + yesterday window covers cross-midnight. Anchored by `jsonl_fallback_recovers_count_when_kg_is_empty`.
- **Knowledge graph snapshot no longer carries dangling edges (PR #432)** — `enforce_memory_limit` removed nodes (which tombstones edges via `remove_node`) AFTER the gated `compact_edges` ran in slow_loop. Tombstones leaked into the persisted blob; reload tagged them as dangling and emitted `Knowledge graph has dangling edge references — pruning dangling=30157` every save cycle for days. New `compact_edges_force()` (no 20%-ratio gate) runs LAST in the maintenance order so both passes' tombstones are swept before serialise. Anchored by `snapshot_after_node_eviction_carries_no_dangling_edges`.

**Detection / response correctness:**
- **`graph_discovery_burst` no longer fires HIGH on snap_daemon (PR #432)** — operator's site home rendered `HIGH: Graph Discovery Burst — user uid:584788 (92 actions in 60s)` for routine `snap refresh`. Even with the PR #418 5x Service-class threshold (5×5=25), 92 actions tripped the `>= adjusted * 2 → HIGH` branch. Now caps severity at Medium for Service-class users; signal still recorded (visible in journey + Telegram digest) but no red banner for non-actionable noise. Evidence JSON gains `user_class` field.
- **Baseline learning rejects honeypot + brute-force usernames (PR #429)** — operator's `baseline.json` was full of `Admin`, `AdminGPON`, `Administrator`, `1234`, `123456789`, plus literal special chars. Three filters added: skip events with `source` starting `honeypot` or tag `honeypot`; reject entity values that fail `is_valid_unix_username` (POSIX `[a-z_][a-z0-9_-]{0,31}`); one-shot prune at boot wipes pre-existing pollution. Four anchors pin each layer.
- **Reverse_shell incident summary no longer leaks `uid={uid}` (PR #428, CodeQL #144)** — `uid` already lives in `evidence.uid` as structured data. Removing the redundant interpolation cleared the `rust/cleartext-logging` finding without losing forensic fidelity.

**Runtime resilience:**
- **XDP unavailability stops spamming the journal (PR #430)** — when bpffs is not mounted at `/sys/fs/bpf/innerwarden`, every block decision was emitting two WARN lines (`shield XDP blocklist add failed` + `XDP blocklist map not found`). New `xdp_availability` module gates both call sites: after one observed failure, XDP attempts skip for 5 min and exactly one operator-actionable WARN with the recovery recipe is logged. Auto-recovers when bpffs is mounted. Steady-state log volume drops from ~6 WARN/hour to 1 every 5 min.
- **`events.src_ip` backfill no longer races sensor for SQLite writer lock (PR #431)** — agent and sensor are separate processes sharing the .db file. Agent's 1000-row UPDATE batch held the writer lock long enough that the sensor's INSERTs blocked past `busy_timeout=5000ms`. Three changes: `BACKFILL_BATCH_SIZE` 1000 → 100 (10× shorter lock hold), throttle to 1/min (was every 30s tick), retry-with-backoff up to 3× on `database is locked`. Steady-state log volume drops from ~120 WARN/hour to <5.

**Dashboard UX honesty:**
- **Baseline tab "Who logs in, when" heatmap default-hides daemon PAM sessions (PR #427)** — operator opened the tab and reported many "users logged in" when only `ubuntu` had real SSH sessions. Endpoint enriches the response with `user_classes` map (read from `/etc/passwd` via existing `parse_passwd_for_user_classes` from PR #418). Frontend default-hides Service-class rows behind a "Show system accounts (N)" toggle (state persisted in localStorage). Per-row class badge so the operator sees Human / Root / Service / Unknown. Pagination at 21+ visible rows. Heatmap now uses full card width.

### Changed
- **README + GitHub repo "About" sidebar** (PR #434) — drop "autonomous alternative to MDR / no SOC cost" framing in favour of the site's voice ("The security agent that fights back. ... runs inside your server, decides what's a real threat, and stops it."). Same key points (one binary, one SQLite, no SIEM/IDS/cloud) without renting positioning from a category the project does not occupy.
- **Stale `20 automated playbooks` claim removed from README** — PR #413 (in this release) already removed the playbook engine; the README boast was leftover. Spec 042 active defense will be the future home for declarative orchestration.

### CI / supply chain
- **OpenSSF Scorecard hardening (PR #428)** — `anchor-tests.yml` workflow gained an explicit top-level `permissions: contents: read` block (was implicitly write-all, scoring 0/10 on Token-Permissions) and pinned `actions/checkout@v4` to its commit SHA (Pinned-Dependencies 9 → 10). Recovers ~0.7 of overall Scorecard.

### Anchor-test count
- 8 → 26 (+18 new anchors across Waves 5/5b/5c/6a). Manifest at `ANCHOR_TESTS.md`; CI gate `verify-anchor-tests` runs on every PR.

---

## [0.12.4-pre — entries below were on `Unreleased` from 0.12.4 onward; rolled into 0.13.0]

### Fixed
- **Home tile "X handled today" now matches the Threats tab entry count** — the home tile read `safely_resolved` (incident-count) while the Threats tab grouped by attacker IP. Operators saw "54 handled" then clicked through and counted ~14 entries. New `handled_ips_today` field on `OverviewResponse` is the unique-IP count; `home.js` reads it (with `safely_resolved` fallback for older backends). Validated in prod canary 2026-04-23: home shows 2, threats shows 2 blocked + 12 resolved = 14, site live-feed shows `unique_sources: 14`. (`NUMBER_CONSISTENCY.md` row "handled count")
- **Threats tab now applies the same internal/research filter as the public site** — pre-fix, advisory-only detectors (`neural_anomaly`, `host_drift`, `network_sniffing`, `discovery_burst`) and InnerWarden system processes (`(en-agent)`, `(en-sensor)`, `(systemd)`, etc) showed up in the Threats tab as "attackers" but were filtered out of the site live-feed. Same `is_internal_incident_fields` predicate now applied at both surfaces. Validated in prod: `/api/entities` returns the same 14 unique sources as `/api/live-feed`.
- **Threats tab `?date=`, `?severity_min=`, `?detector=` filters now actually filter** — frontend sent the query string but `api_overview`, `api_entities`, `api_pivots` ignored severity_min/detector. Wired end-to-end through `InvestigationFilters::{severity_min_rank, detector_lower}` helpers; same predicate runs in both the home overview and the threats tab so `/api/overview?severity_min=high` and `/api/entities?severity_min=high` count the same set. Validated: `?severity_min=high` narrows 14→2; `?severity_min=critical` → 0; `?detector=nope` → 0.
- **`sqlite_store` no longer stuck at None after boot-time `database is locked` race** — the boot-only `Store::open` left `state.sqlite_store` as `None` for the entire process lifetime when the file was contended at startup. Discovered during the Finding 5 canary on 2026-04-23: SQLite snapshot saves became silent no-ops for hours after a contended boot. New `try_recover_sqlite_store` runs on every slow_loop tick (60s back-off so a permanent error does not become a tight retry loop) and lazily reopens the store. Underlying long-term lock contention with `innerwarden-sensor` is a separate sensor-coordination bug tracked outside this PR.

### Performance
- **Slow-loop graph-maintenance no longer blocks dashboard for 100-300 ms every 60 s** — the periodic snapshot block held a single write lock across `cleanup_expired + compact_edges + enforce_memory_limit + serialize + gzip + fs::write + SQLite bind + cleanup_old_snapshots`. Restructured into three lock scopes: write (cheap mutations), read (serialize bytes via new `serialize_snapshot_bytes` / `SerializedSnapshot`), no-lock (disk + SQLite I/O). Validated in prod canary: 60/60 dashboard `/api/health` pings completed in 0 ms during a snapshot tick (pre-fix would show 100-300 ms bursts every 60 s).
- **`KnowledgeGraph::metrics()` is now O(N) instead of O(N × E_avg log E_avg)** — `total_degree` was computed by calling `all_edges(id).len()` per node, allocating + sorting a `Vec<&Edge>` per call. Same anti-pattern that PR #261 fixed in `enforce_memory_limit`. Now sums adjacency-list lengths directly: `outgoing.values().map(Vec::len).sum() + incoming.values().map(Vec::len).sum()`. Self-loops contribute +2 here vs +1 in the old `all_edges` (which de-duped); accept the rounding — `avg_degree` is diagnostic only.
- **Dashboard handlers `api_sensors` and `api_honeypot_sessions` no longer block tokio worker threads** — both held `std::sync::RwLock<KG>` and ran sync work inside async scope. Same `tokio::task::spawn_blocking` pattern PR #261 applied to `api_quickwins` / `api_live_feed` / `api_export`. The 30 s cache on `api_sensors` made contention rare but not impossible; now the cache miss path runs on the blocking pool so it cannot stall sibling handlers.

### Performance
- **`/api/quickwins` endpoint always returned empty** — the JSONL reader looked at field `action` but the writer (`decisions.rs`) writes the field as `action_type`, so the blocked-IPs deduplication set was always empty. Severity filter compared against `"High"`/`"Critical"` (PascalCase) but the wire format is lowercase per `Severity` `#[serde(rename_all = "lowercase")]`, so the filter never matched. Both bugs fixed in `dashboard/actions.rs`; 7 fixture-driven regression tests added (`api_quickwins_*`).
- **6h-window report subcounted to zero around midnight** — `compute_recent_window` was string-comparing bucket keys formatted as `"HH:MM"` against `cutoff.format("%H:%M")`. At 02:00 UTC the cutoff was `"20:00"` (yesterday), but today's snapshot only had buckets `"00:00".."02:00"` — all alphabetically less than `"20:00"`, so the loop counted zero events. Fix carries a date dimension on bucket keys (`YYYY-MM-DDTHH:MM`), parses them back to `chrono::DateTime` for comparison, and walks both today's and yesterday's snapshots whenever the cutoff falls into yesterday. Reader is back-compat with legacy bare-`HH:MM` keys via the snapshot's date as fallback.
- **`event_timeline` and `detector_timeline` lost the date dimension under multi-day uptime** — same root cause as the 6h-window bug. Bucket key is now ISO-prefixed; sensors-tab serializer projects keys back to `HH:MM` for chart-display compactness so the UI is unchanged.
- **Dashboard async handlers blocked tokio worker threads** — `api_quickwins`, `api_live_feed`, and `api_export` held the `std::sync::RwLock<KnowledgeGraph>` and ran synchronous JSONL/serde work inside async handler scope. Each now wraps its body in `tokio::task::spawn_blocking`, freeing the runtime for concurrent requests. The full lock migration (71 call sites) is deliberately out of scope; the spawn_blocking pattern addresses the user-impact (worker-starvation under contention) without the migration risk.
- **`KnowledgeGraph::enforce_memory_limit` allocated O(N × E) under memory pressure** — the LRU-eviction path called `all_edges(id)` per node to find each node's last edge timestamp. `all_edges` allocates a `Vec<&Edge>` and sorts it. Worst possible time to allocate is when memory pressure has just triggered the path. New `last_edge_ts: HashMap<NodeId, DateTime<Utc>>` is updated on every `add_edge` and queried in O(1). Index is rebuilt from `edges` on snapshot load (same precedent as `outgoing`/`incoming`), so the wire format is unchanged. 7 invariant tests added (`last_edge_ts_*`).
- **Atomic write for `playbook-log.json` and `attack-chains.json`** — both files used a read-modify-write pattern with `std::fs::write` directly over the target. A crash mid-write would leave dashboard readers with a half-written corrupt JSON array. New shared `crate::capped_log::append_with_cap` helper writes to a sibling temp file (`<path>.<pid>.tmp`) and atomically renames onto the target. POSIX rename is atomic on same-filesystem moves. 6 unit tests including atomic-rename invariants.

### Performance
- **KG snapshot writes shrink ~10× (gzip)** — `save_snapshot` and `save_to_store` now gzip the serialized JSON before write/bind. On the prod baseline (14.5k nodes, 145k edges, ~47 MB JSON) the file/blob shrinks to ~5 MB. Reduces both disk usage AND the per-tick SQLite BLOB-bind transient that pressed RSS. Reader is back-compat: detects gzip via magic bytes (`0x1f 0x8b`), falls through to raw JSON for legacy snapshots.
- **`events_for_training` no longer re-parses each row's full JSON** — schema v2 added an `events.src_ip` column populated at insert time. The training query now reads the column directly. One-time backfill scans existing rows on the first agent boot post-upgrade. (`RECURRING_BUGS.md` "events_for_training reparses full JSON to extract src_ip")

### Schema
- **events table v2** — added `src_ip` column + `idx_events_src_ip` partial index. Migration `apply_v2` ALTERs existing tables and backfills from `details.src_ip` (preferred) or `details.ip` (fallback). `CURRENT_VERSION` bumped to 2.

### Performance
- **Boot heap reduction (~200 MB transient)** — `loops/boot.rs` now constructs the primary AI provider and the spec-029 capability router exactly once and shares the `Arc`-wrapped handles between the dashboard task and the main agent loop. The previous code path built each provider twice (once per consumer), which on production with `[ai.classifier].enabled = true` re-parsed the ONNX classifier model end-to-end (~107 MB allocation pipeline through `tract_onnx::Onnx::parse → into_optimized → codegen`). Validated against jeprof heap dump on 2026-04-22.
- **Knowledge graph snapshot save no longer clones the entire graph** (`knowledge_graph/persistence.rs`) — `save_snapshot` and `save_to_store` now serialise from a borrowing `GraphSnapshotRef<'a>` instead of building an owned `GraphSnapshot` with `nodes.clone() + edges.clone() + …`. Removes ~272 MB of transient allocation per slow-loop tick on the 1354-attacker-profile production baseline. Wire format unchanged; existing roundtrip test (`test_save_and_load_snapshot`) covers the equivalence.
- Removed the unused `ai::router::build_for_dashboard` wrapper (and its three unit tests) — orphaned by the dashboard-router consolidation above.

### Removed
- **AlphaZero defender brain (#258)** — the embedded 19,615-param dual-head MLP (`crates/agent/src/defender_brain.rs`, 1,361 lines, plus `defender-brain.bin`) was a comparison-only second opinion that never influenced production decisions. In production it had 12% AI agreement and collapsed to outputting `capture_forensics` for every incident. The trained SecureBERT V1 classifier (precision 0.975 on 2,481 incidents) is a strict superset and is already wired through the AI router as the `local_classifier` provider. Net diff: -2,841 / +354 lines.
- 🧠 Brain tab from the dashboard intel sub-tabs and the three `/api/defender-brain/*` routes.
- 72-feature builder (`build_brain_features`, `event_kind_layer`, `fill_history_features`, `fill_new_detector_flags`), the rolling-history helper, the AI-agreement helper, the brain-training feeds in `incident_auto_rules` and `correlation_response`, the daily retrain block in `loops/boot.rs`, and the `recent_event_kinds` field on `AgentState`.
- `.specify/features/031-defender-brain-feature-alignment/` spec (made obsolete by this change).

### Added
- **`innerwarden install-classifier` (#258)** — top-level CLI that downloads, SHA-256-verifies and extracts the local SecureBERT classifier into `/var/lib/innerwarden/models/classifier/`. Two variants: `minilm-l6` (87 MB distilled, default, ~60 ms p50 on ARM) and `roberta-v1` (478 MB, validated 0.975 precision on `block_ip`). `--url` and `--sha256` overrides for air-gapped mirrors. The command refuses to install while the artifact SHA is still `TBD-`, forcing the operator to pass an explicit hash until the release is pinned.
- Documented `[ai.classifier]` and `[ai.llm]` slots in `agent-test.toml` so operators see how to wire SecureBERT into the spec 029 capability router after running the installer.

---

## [0.12.4] - 2026-04-19

### Added
- **Circuit breaker for autonomous blocks (#181)** — per-UTC-hour cap (`responder.max_blocks_per_hour`, default 100) that halts the block pipeline when crossed. Three modes via `responder.circuit_breaker_mode`: `pause` refuses further blocks, `log_only` counts but never refuses, `dry_run` audit-writes the decision but skips the skill. Motivated by the CL-008 cascade that queued 1021 blocks in 24h. Auto-rearms on the next UTC hour; operator can reset immediately with the new CLI.
- **`innerwarden system circuit-status` / `circuit-reset` (#182)** — inspect and clear the breaker without editing SQLite by hand. Plaintext and `--json` outputs.
- **`innerwarden system reconcile-blocks` (#188)** — walks ufw DENY rules and releases any target that now falls inside the cloud safelist (Cloudflare, Oracle peers, link-local, agent services, Telegram edge). Dry-run default; `--apply` actually releases via `innerwarden action unblock`. Motivating incident: 60 pre-safelist rules were still blocking Cloudflare after #181 landed.
- **`innerwarden` startup banner (#184)** — running the CLI with no subcommand prints a stylised block-letter banner, version, and a rotating tagline, then falls through to help. Respects `NO_COLOR`.
- **Fuzz harnesses (#190)** — three cargo-fuzz targets for parsers that consume attacker-controlled bytes: `tls_client_hello` (JA3/JA4), `core_event_json`, `core_incident_json`. Excluded from the workspace so stable CI stays on stable; nightly GitHub Actions runs 5 min per target and uploads any crash as an artifact.

### Changed
- **Autonomy gap closed (#183)** — production audit on 2026-04-15 found 1812 incidents produced 0 AI-executed blocks in three days. Two compounding defects:
  - `ai.confidence_threshold` set to `1.01` in prod silently disabled every AI-driven auto-execute. `AiConfig::clamp_confidence_threshold` now warns and resets out-of-range values at load time.
  - The obvious-gate required `ip_seen_before` for every detector. Reasonable for ssh_bruteforce / port_scan, wrong for reverse_shell / web_shell / c2_callback / process_injection / rootkit / crypto_miner. Split the gate into `RepeatOffender` and `FirstHit` policies; those six detectors plus `threat_intel` now auto-block on first observation.
- **`ai.min_severity` default dropped from `"high"` to `"medium"` (#187)** — the Medium layer (port scans, credential stuffing below brute-force threshold, web scans, suspicious_login) was never reaching AI triage; it went straight to the noise-gate. AI now sees Medium/High/Critical. Operators on paid providers with cost sensitivity can set `"high"` explicitly in `agent.toml`.
- **AI voice unified across Telegram, dashboard briefing, threat explain (#185, #186, #188)** — one `cfg.telegram.bot.personality` string is plumbed through `DashboardActionConfig` and injected into every AI-facing prompt. `compose_system_prompt` helper merges persona + runtime snapshot + recent incidents + recent decisions. Persona rewritten from generic "proportional analyst" to a short, confident, dry voice; `briefing_prompt` no longer re-asserts tone that fights the persona. Greeting / small-talk now routes to a friendly one-liner instead of the security catchphrase.
- **Dashboard Home "Handled" KPI single-sourced from `overview.safely_resolved` (#188)** — hero sub, KPI tile, and AI briefing now quote the same number. Prior to this, three code paths reported three different counts for the same time window.
- **Incident decision reasons have a voice (#184)** — the strings written to the decision audit trail and emitted as logs went from stock `Auto-blocked: X from Y` to `Shut the door on {ip}. {detector} caught on first try. Compromise averted.` etc.
- **Telegram daily digest phrasing (#186)** — `Everything is under control.` / `No action needed — everything is under control.` replaced with `All clear. Nothing needs you.`

### Fixed
- **`rand` dependabot alert (#181)** — transitive `rand 0.8.5` via russh's forked ssh-key is unreachable in our build (no `log`-feature custom logger calls `rand::rng()`); dismissed with `tolerable_risk`.
- **Dashboard "Blocked Today" KPI silently swapping data source (#186)** — tile used to fall back from entity-based count to `ai_responded` when the active set was empty. Single source now, label clarified to "Handled".
- **Dashboard `onclick="showContained()"` called a function that never existed (#186)** — replaced with `viewActivity()`.
- **`/api/responses` empty shape missing `state_counts` (#188)** — a clean install returned `{active, active_count, history, totals}` but `responses.js` read `r.state_counts.revert_pending` and threw. `empty_responses_payload` helper now populates every field the renderer consumes; shape-lock test pins the contract.
- **Report tab "events ✗ Absent" (#188)** — spec 016 migrated events to SQLite; the row now reads "SQLite · (in db)".
- **Briefing tone fighting the persona (#188)** — `briefing_prompt` used to demand "Be reassuring" and "Write for a non-technical operator", which overrode the bot personality and produced consultant-speak. Rewritten to carry format structure only.
- **Telegram `/ask` over-applied "bot noise, handled" to greetings (#186)** — persona taught the model a catchphrase without context. Added a "how to read the operator's message first" branch.
- **Threats tab stuck on "Loading..." (#191)** — regression from #188. Removing the hidden `kpi-events` / `kpi-incidents` / `kpi-attackers` spans and the `clusterList` / `topDetectors` divs broke `refreshLeft`, which still wrote to those ids. The first `null.textContent` threw, swallowed by the outer try/catch, and `attackerList.innerHTML` was never reached. Every left-panel write now funnels through `setText` / `setHtml` helpers that no-op on missing nodes.
- **Dashboard "Cannot set properties of null (setting 'textContent')" (#189)** — SSE refresh could reach `threats.js` / `home.js` write paths while the target view was hidden; guarded three sites that wrote without a null check.
- **Dead UI in dashboard (#186, #188)** — removed Recent Activity section from Home (duplicated Threats tab), hidden KPI spans in Threats left panel (never populated), cluster list + top detectors divs (state never assigned).
- **Scenario 04-honeypot-unknown envelope drift (#187)** — with `ai.min_severity = "medium"` the Medium honeypot-from-unknown-IP incident now reaches AI triage and the Monitor action auto-executes a packet capture. `decisions_auto_executed` envelope bumped from `{min:0, max:0}` to `{min:1, max:1}`.

### Tests
- **+93 agent unit tests (#189 #192 #193 #194)** — report.rs 89.1% → 93.4%, playbook engine coverage, defender_brain suggestion engine, monthly threat report pipeline. Total agent tests 1466 → 1559.
- **Circuit breaker CLI commands ~100% patch coverage (#182)** — 19 unit tests covering `read_status`, `reset_hour`, render helpers, and the two end-to-end command entry points.

---

## [0.12.3] - 2026-04-18

### Fixed
- **Autoencoder scores saturated at 1.000 regardless of live event shape** — production emitted `score=1.000 maturity=1.00` on every event even after v0.12.2 repaired the training pipeline. Root cause was in the scoring math: `baseline_std` is tiny by construction when computed on the same windows the autoencoder memorised, so z-score + sigmoid saturates on almost every live window. Replaced the sigmoid path with a 101-anchor percentile table computed over a held-out 20% of training windows. Live MSE is now ranked against that distribution — `p50 → 0.50`, `p95 → 0.95`, `p99 → 0.99` — instead of collapsing to 1.0 anywhere above p95. Falls back to the legacy z-score path when the table is degenerate (v1 model files / tiny datasets), so v0.12.2 installations upgrade without a forced retrain.
- **AbuseIPDB report quota burn-through** — the `/report` endpoint had no daily cap or per-IP dedup (the existing `ABUSEIPDB_DAILY_LIMIT=800` guard lived only on the `/check` path). Production burnt 1,021 reports in 24h during the CL-008 cascade. Added `abuseipdb_report_budget` module with per-IP dedup (24h TTL in sqlite `abuseipdb_reported` KV) + daily hard cap (`abuseipdb.report_daily_cap`, default 800, 0 pauses reporting). Planner + dispatcher are pure helpers so the whole decision matrix is unit-tested without a live HTTP endpoint.

### Added
- **Deterministic train/holdout split** for nightly autoencoder training. `training_holdout_fraction` config (default 0.2, clamped to [0.0, 0.5]) selects every Nth window for baseline computation; the other windows train the network. Setting 0.0 preserves legacy single-set baseline for small datasets.
- **Model file format v2** with embedded percentile anchor table (101 × f32 between the IWAE header and the length-prefixed JSON weights). Loaders auto-detect via the version byte — v1 files still parse and populate a zeroed anchor table.
- **Per-outcome telemetry for AbuseIPDB queue flush**: `SkipCloud`, `Skip(AlreadyReportedToday)`, `Skip(DailyCapReached)`, and `Send` each log their reason + IP, making queue pressure visible in `journalctl` without the `/metrics` endpoint.

### Changed
- **Coverage closeout**: patch tests landed for `shield_inline` rate-limiter + `telemetry_tick` emitter (#150), incident enrichment adapters (#148), and `slow_loop` guard orchestration (#151). Workspace test count grew from 3,712 → 3,763+.

---

## [0.12.2] - 2026-04-18

### Fixed
- **AbuseIPDB daily report quota exhausted** — operator email 2026-04-18: "You've exhausted your daily limit of 1,000 requests for report endpoint." Direct fallout of the CL-008 cascade that v0.12.1 fixed: ~900 false-positive blocks against Cloudflare CIDRs were queued for community reporting, each consuming one `report` call. The block refusal lands at `execute_block_ip_decision`, which prevents NEW reports from being queued, but entries already sitting in `state.abuseipdb_report_queue` before the fix deployed would still fire on the 5-minute grace flush. The slow-loop flush now consults `cloud_safelist::identify_provider` one more time before calling `client.report`, so any pre-fix queue entries targeting cloud ranges are dropped with a log line instead of polluting the community feed and burning our quota.
- **CI `Secrets scan` job flaky on transient 504** — `curl -sSfL` fetching the gitleaks release tarball from github.com sometimes hits a 504 at the CDN edge, failing the whole PR check. Added `--retry 5 --retry-delay 5 --retry-all-errors --retry-connrefused --retry-max-time 180` so the download survives transient upstream hiccups.

---

## [0.12.1] - 2026-04-18

### Fixed
- **Autoencoder trained on zero events since spec 016** — `neural_lifecycle::train_nightly` iterated `events-YYYY-MM-DD.jsonl` files, but spec 016 moved every event into `innerwarden.db`. Every nightly trigger returned `"insufficient data"` and left the stale model in place. `baseline_std` drifted to ~0.0018, saturating sigmoid on every live window (`score=1.000` forever, maturity 1.00 on day 30+). Now reads from SQLite first, falls back to JSONL.
- **Seven high-volume event kinds invisible to the brain** — `http.request` (22K/3d), `tcp_stream.ssh`, `memory.anon_executable`, `network.snapshot`, `memory.deleted_file_mapping`, `file.extracted_from_network`, `kernel.bpf_program_loaded` were not in `kind_index`, so the autoencoder was training on a biased slice. Added at slots 24..30; `NUM_FEATURES` bumped 58 → 65. Models from 0.12.0 auto-invalidate via dimension-mismatch check.
- **Autonomy cascade blocking Cloudflare** — `correlation:CL-008` (file.read_access → network.outbound_connect within 60s) was matching the platform's own outbound traffic and auto-blocking whatever IP the outbound connection targeted. Production 24h snapshot: 1021 auto block_ip decisions, top 9 all Cloudflare CIDRs, 552 triggered by CL-008 alone + 375 `repeat-offender` compounding. New `check_block_eligibility_with_safelist` refuses any block whose target resolves via `cloud_safelist::identify_provider`, and short-circuits `correlation_response::handle_completed_chain` + repeat-offender before they mutate `ip_reputations`.
- **Dashboard decisions table stale since legacy migration** — `DecisionWriter` only wrote JSONL; dashboards, `/metrics`, and scenario-qa all query sqlite `decisions`, which was untouched for a month. `DecisionWriter::with_store` now dual-writes: JSONL remains the audit trail of record, sqlite gets mirrored via `insert_decision`. Failure to persist logs a warning but does not reject the write.
- **`cloud_safelist::identify_provider` mislabelled Cloudflare** — first-octet heuristic classified 104.x as Azure and 172.x as Google Cloud. Now walks `CLOUDFLARE_RANGES` first; heuristic stays as fallback for other providers.

### Added
- **`innerwarden-agent --retrain-anomaly`** one-shot flag (mirrors the spec 015 cleanup pattern). Reads events from `innerwarden.db`, trains `anomaly-model.bin` in place, prints maturity + cycles + model path, exits. Operator no longer has to wait until 03:00 UTC to recalibrate after a feature-layout bump.
- `Store::events_for_training(since_ts, limit)` — streams `(kind, Option<src_ip>)` tuples without deserialising full events. RAM-budget friendly; used by the nightly training path.

### Changed
- Neural feature vector layout encoded in named constants (`KIND_SLOTS`, `BIGRAM_BASE`, `SEQ_BASE`, `GRAPH_BASE`). Future additions bump constants in one place instead of shifting magic slot numbers across the file.

---

## [0.12.0] - 2026-04-18

### Added
- **Regression safety net (spec 024)** — `make scenario-qa` with 7 deterministic canonical scenarios (SSH brute single/coordinated, honeypot known-bad/unknown, port scan, DDoS SYN flood, grouped campaign) gated in CI via envelope assertions; 18 contract tests across the 5 boundary subsystems; `/metrics` now exposes all 10 drift metrics; `docs/prometheus-alerts.yaml` with 10/h warn + 50/h crit thresholds post spec 005 grouping; dashboard "Health → Metrics drift" tab.
- **Intelligent notifications (spec 005)** — incident grouping, channel filter, daily briefing digest, bootstrap environment profile, periodic census, operator feedback loop, AI batch triage (opt-in). Agent now sends ≤ 1 grouped Telegram instead of one-per-incident.
- **Structured subgraph in LLM prompts (spec 025)** — JSON graph context replaces prose narrative (qwen2.5:3b bench: 53% → 73% action accuracy, hallucinated target 47% → 7%).
- **Zero-trust MDR (spec 020)** — continuous trust scoring engine, AI SOC daily checks with 11 system parsers, graduated enforcement state machine (Phase F-partial).
- **Observation verification (spec 021)** — behavioural score engine, AI batch verification for ambiguous observations, dashboard score display.
- **CTL** — new `innerwarden replay` command for E2E validation.
- **Scenario seed mechanism** — `scripts/scenario_seed.py` pre-populates `innerwarden.db` and KV cache so scenarios that require eBPF / root / packet generators still run headless in CI.
- **Auto-response coverage (spec 018 Phases A-D)** — correlation-driven escalation + trusted_processes filter.
- **Graph full connectivity (spec 014)** — 8 → 18 active relations, edges 12K → 33K, Process nodes 411 → 4,470.
- **Graph signal quality audit (spec 015)** — caught 3,954 false-positive `graph_user_creation` incidents from a single presence-scan detector.

### Changed
- **Unified SQLite store (spec 016)** — single `innerwarden.db` replaces 15 storage artifacts; redb removed, JSONL removed, 14 maintenance tasks consolidated.
- **AbuseIPDB per-incident lookup** — now consults SQLite cache before hitting the live API. Removes redundant HTTP on every incident and closes the "no API key → always None" gap.
- **Telegram mock outbox** — new `INNERWARDEN_MOCK_TELEGRAM=1` mode for deterministic scenario testing without touching api.telegram.org.
- **GeoIP** — switched ip-api.com to HTTP (free tier rejects HTTPS).
- **Coverage scaffolding** — 11 coverage batches from spec 023 + 3 decomposition phases from spec 026 (agent crate +10.98pp). 1426 agent tests passing, patch coverage 72% on 7,300 changed lines.

### Fixed
- **Invalid-IP zombie ufw rules** — `response_lifecycle.register()` now rejects invalid targets before hydration; 8 previously-orphaned rules no longer recur.
- **Self-triggered DATA_EXFIL** — killchain now skips the agent's own threads (was producing 40+ self-incidents/day).
- **Kill chain persistence** — incidents now land in sqlite alongside jsonl; honeypot activity accepted as kill chain input.
- **Dashboard threat pivot** — unhidden pivot tabs, detector-pivot drill-down in `/api/journey`, entity population on sigma + crypto_miner incidents, live-feed `/api/live-feed/geoip` returns empty list on missing params instead of 400.
- **Telemetry monotonicity** — `gate_suppressed_total` + `telegram_sent_count` never decrement; `serde(default)` on new counters for backward compat.
- **Replay test expectation** — matches detector dedup reality.
- **Sensor host_drift** — test allowlist synced with detector.
- **Dependency** — `rand` 0.9.2 → 0.9.4 (GHSA unsoundness fix).

---

## [0.11.1] - 2026-04-14

### Added
- **Auto-calibration** — cloud VM detection via DMI (22 signatures), operator UID auto-detection, graph detector CalibrationContext. Eliminates ~1500 FPs/day on fresh installs.
- **Centralized notification gate** — single policy for ALL channels (Telegram, Slack, Webhook, Web Push). Only uncontained active intrusions notify immediately.
- **Burst summary** — 50+ auto-blocked threats/hour sends single "all handled" message instead of 50 alerts.
- **AbuseIPDB cache** — SQLite KV with 24h TTL + 800/day cap. Stops exhausting free tier.
- **GeoIP cache** — SQLite KV with 7-day TTL. Survives restarts.
- **notification_gate.rs** — 27 unit tests for notification policy rules.

### Changed
- **Event retention** — 8 days to 2 days for raw events.
- **Telegram rate limit** — MAX_ALERTS_PER_HOUR 30 → 10.
- **Dashboard toasts** — only uncontained CRITICAL/HIGH. Close button added. Click navigates to Threats tab.
- **Dashboard KPIs** — Home and Threats now use same data source for consistent numbers.

### Fixed
- **SQLite DB growth** — 1.8GB/day → ~80MB/day. High-volume events (tcp_stream.flow, process.exit, etc.) filtered from persistence.
- **AbuseIPDB daily exhaustion** — was using 1440 checks/day on free tier (limit 1000).
- **Honeypot notification spam** — probe-only sessions (0 commands, ≤2s) no longer notify.
- **Kill chain false positives** — allowlist for ruby, node, python, nginx, postgres (legitimate socket+dup).
- **Timing anomaly FPs on cloud** — z-score threshold 20 on VMs (was 4), eliminates I/O jitter noise.
- **Discovery burst FPs for operators** — trusted UIDs get 3x threshold.

---

## [0.11.0] - 2026-04-13

### Added
- **Unified SQLite Store** (Spec 016) — replaces 15 storage artifacts (JSONL files, redb, JSON snapshots) with a single `innerwarden.db` SQLite database. WAL mode for concurrent sensor+agent access.
- **New crate `crates/store/`** — 12 modules, 49 tests. Events, incidents, decisions tables + namespaced KV + graph snapshots + state blobs + cursor tracking.
- **Maintenance scheduler** — automated background tasks: WAL checkpoint (5min), incremental vacuum (hourly), retention cleanup, hash chain verification, integrity check (daily).
- **Legacy migration** — one-shot import on first startup. JSONL/redb/JSON files migrated to SQLite, originals archived to `legacy-archive/`.
- **TOTP QR code in terminal** — `innerwarden config 2fa` renders QR code as ASCII art. Secret never touches disk or logs.
- **SMM + Hypervisor as CTL subcommands** — `innerwarden system smm` and `innerwarden system hypervisor` integrated into the CLI.
- **Centered terminal screens** — install and welcome UX improvements.

### Changed
- **Sensor writes only to SQLite** — JSONL sink removed. No more daily file rotation, 1GB cap, or silent event drops.
- **Agent reads only from SQLite** — JSONL parser and byte-offset cursor removed. Rowid-based cursor tracking.
- **State store migrated from redb to SQLite KV** — 7 redb tables mapped to namespaced KV. Same public API, zero caller changes.
- **Graph snapshots in SQLite** — replaces JSON file rotation with database table. Load/save via `save_to_store()`/`load_from_store()`.
- **6 JSON state files migrated to SQLite blobs** — attacker profiles, campaigns, baseline, playbook log, threat feeds, responses.
- **DB file pre-created with 0664 permissions** — sensor (root) and agent (innerwarden) both write without permission conflicts.

### Removed
- **redb dependency** — replaced entirely by SQLite KV.
- **JsonlWriter** — replaced by SqliteWriter.
- **JSONL reader/parser** — replaced by SQLite rowid-based queries.
- **JSON snapshot rotation** — 3-backup rotation replaced by SQLite table with date-based retention.

### Fixed
- **Silent event drop compliance bug** (ISO 27001 A.12.4) — events at 1GB cap were silently dropped. Now returns explicit backpressure error.
- **6 CodeQL security alerts** resolved — path traversal sanitization, cleartext logging fixes.
- **Firewalld detection** — harden command now detects firewalld alongside UFW.
- **io_uring property test** — bun/deno/node added to allowlist (legitimate io_uring users).

### Security
- **Path traversal prevention** — `Store::open()` canonicalizes data_dir before any file operations.
- **TOTP secret handling** — QR code rendered in terminal only, never written to files or logs.

---

## [0.10.0] - 2026-04-08

### Added
- **Supervised defender brain with agreement tracking** (Feature 006) — brain observes every AI decision and logs agreement/disagreement. Foundation for online learning and AI override.
- **72-dimensional brain-log** — agent records enriched feature vectors to `brain-log.jsonl` for offline model retraining.
- **Autoencoder as decision signal** — converted from standalone detector to integrated decision signal in the agent pipeline.
- **Shield migrated into monorepo** — `innerwarden-shield` now lives as `crates/shield` in the workspace.
- **Dynamic operator IP protection** — active SSH sessions from trusted operators get session-based expiry protection; agent never auto-blocks the operator.
- **CTL restructured** — CLI reorganized from 40 flat commands to 8 intent-based groups (`get`, `stream`, `action`, `trust`, `config`, `system`, `module`, `agent`) for better discoverability. Old commands still work as aliases.

### Changed
- **Autoencoder trains on clean traffic only** — excludes blocked IPs from training data to prevent model poisoning.
- **Live feed uses rolling 24h window** — shows only real external attacks with attacker IP (today + yesterday).
- **Unified XDP blocklist** — shield and agent skill share one source of truth via `XdpManager`. IPv6 support added. XDP now covers 20 detectors (was 5).
- **Defender brain upgraded to V5 50M** — 3.1M training steps, [72→128→64→30] architecture, with daily retrain at 3:30 AM UTC from production decisions.
- **Cross-module correlation** — baseline anomalies, autoencoder scores, and shield escalation now feed the correlation engine. 4 new rules: CL-044 Silence After Compromise, CL-045 Coordinated Volume Attack, CL-046 Neural-Confirmed Attack, CL-047 Attacker IP Rotation.
- **Shield ↔ Attacker Intel bidirectional** — shield blocks enrich attacker profiles (risk score, block count); known high-risk IPs (risk > 60) get 2x tighter rate limits pre-emptively.
- **DNA Cross-IP tracking** — behavioral fingerprint index detects same attacker across different IPs (VPN/Tor rotation). Emits `dna.ip_rotation` correlation event. No other IDS does this.
- **Attacker intel risk scores in decision pipeline** — IPs with risk > 50 get confidence boost in AI triage, reducing latency and API costs for repeat offenders.
- **README fully updated** — all stats aligned (49 detectors, 47 correlation rules, 2361 tests), CLI examples use new command groups, architecture diagram corrected.
- **Website fully updated** — stats, CLI commands, meta tags, and SEO schema version aligned across 25 files.
- **GitHub About & Topics updated** — description includes 46 correlation rules + 65 MITRE techniques; added mitre-attack, behavioral-analysis, kill-chain topics.

### Fixed
- **Notification spam reduced** — 3 critical fixes: gate repeated alerts, suppress non-threat group summaries, rate-limit action reports.
- **Auto-block gates respect operator/trusted IPs** — prevents lockout during active management sessions.
- **Security: XSS in dashboard** — attacker IPs in onclick handlers now escaped via `esc()` function.
- **Security: russh 0.58→0.59** — removes vulnerable `libcrux-sha3` dependency.
- **CI stability** — flaky timing test ignored in CI, dead_code allows for BrainStats, clean deny.toml.

---

## [0.9.4] - 2026-04-06

### Added
- **Consolidated satellite modules into workspace** — killchain, dna, hypervisor, smm migrated from standalone repos to `crates/`. Single build, single CI, unified versioning.
- **Neural model advisory-only mode** — autoencoder observes and scores but never blocks or notifies. Safe ramp-up.
- **Operator IP protection** — never blocks active trusted SSH sessions (publickey detection).
- **AlphaZero defender brain embedded** — IWD1 binary (538KB) integrated as advisory decision signal with dashboard UI + FP audit + API endpoints.

### Changed
- **Dashboard UX overhaul** — defender brain panel, FP audit view, action config improvements.

### Fixed
- **Dashboard JS fixes** — duplicate `esc()` declaration, broken script tag in template literal, HTTP actions with auth.
- **eBPF connect/accept IP byte order** corrected.
- **Security: safe_write_data_file for brain-log** (CodeQL CWE-22 path traversal).
- **Dependencies updated** — fancy-regex 0.17, redb 4.0, redis 1.2, russh yanked version resolved.

---

## [0.9.3] - 2026-04-06

### Added
- **Immediate-threat gate for Telegram** — only real threats (reverse_shell, data_exfil, ransomware, privesc, lateral_movement, container_escape, web_shell, process_injection, fileless, c2_callback, credential_harvest, ssh_key_injection, kernel_module_load, log_tampering, dns_tunneling, persistence detectors) send immediate Telegram notifications. Routine detections (ssh_bruteforce, discovery_burst, port_scan, packet_flood) go to daily digest. Reduces ~70 notifications/day to ~1-3 real threats.
- **Daily notification budget** — configurable `telegram.daily_budget` (default: 10). Critical severity always breaks the budget. Counter resets daily.
- **Daily Security Briefing** — enriched digest with deferred incident breakdown showing what was handled silently overnight. Pre-configured at setup (9 AM, no extra steps).
- **CLI commands** — `innerwarden notify digest <hour|off>` and `innerwarden notify budget <max>` for post-setup tuning.
- **Neural incident pipeline fix** — autoencoder anomaly incidents now route through AgentState buffer instead of writing to sensor's file (was silently failing due to file permissions). 415 detections/day were being lost.
- **Correlated anomaly** (baseline + neural convergence) added to immediate threat list — always pings Telegram.
- **5 new correlation rules** (CL-036 to CL-040) from AlphaZero V4 self-play discoveries.

### Changed
- **Premium Telegram message quality** — all message formats rewritten: structured alerts with severity header + detector label + IP + action status; action reports with shield emoji and confidence line; daily digest as "Security Briefing"; group summaries with human-readable labels.
- **Neural anomaly messaging** — "Neural anomaly: 97% score" → "AI Spider Sense: highly unusual HTTP traffic — 97% anomaly" with training cycle context.
- **Group summaries gated** — non-threat group summaries no longer ping Telegram.
- **All Telegram send paths gated** — action reports (post-AI, obvious gate) and AbuseIPDB autoblock now check immediate-threat before sending.

### Fixed
- **Clippy warnings** — resolved all dead_code, derivable_impl, manual_range_contains, collapsible_if, too_many_arguments warnings.
- **Flaky test** — `execve_event_maps_to_shell_command_exec` used PID 1234 which collided with real CI processes.
- **Correlation rule count** — test assertion updated (35 → 40).

---

## [0.9.2] - 2026-04-03

### Added
- **Main branch catch-up with develop** — synchronized mainline with the latest development baseline (spec-driven artifacts, governance updates, and organization improvements) so stable releases include the full current platform state.

### Changed
- **CI license gate compatibility** — `cargo-deny` policy now explicitly allows `BUSL-1.1` for the `innerwarden-smm` dependency path to keep security checks green while preserving Apache-2.0 licensing for the core project.

### Fixed
- **Telegram triage test stability** — provider assertion updated to match operator identifier semantics, preventing false failures in the release test pipeline.

---

## [0.9.1] - 2026-04-03

### Changed
- **License opened to Apache 2.0** — project moved from BUSL-1.1 to Apache License 2.0 across repository metadata and Cargo package manifests.
- **Documentation and metadata refresh** — updated README license badge/section, governance references, and release collateral to keep licensing and project messaging fully consistent.

---

## [0.9.0] - 2026-04-03

### Changed
- **Large internal modularization (agent + ctl)** — extracted decision flows, narrative pipeline, honeypot runtime, incident processing, and command handlers into focused modules. This keeps behavior stable while making future development and debugging significantly easier.
- **Spec-driven artifacts added to repository workflow** — feature specs/plans/tasks now tracked under `.specify/features/` to keep implementation aligned with product intent.

### Fixed
- **ATR rule compatibility on production hosts** — rule loader now accepts mixed YAML shapes for `tags`/`references` (map, list, string) and supports regex patterns with look-around/backreferences via `fancy-regex` fallback.
- **Doctor accuracy for protected configs** — config checks now distinguish “permission denied” from “file missing” so diagnostics are correct on hardened servers.
- **Doctor sudo-protection check** — corrected expected sudoers drop-in name (`innerwarden-suspend-user`), eliminating false warning when capability is properly enabled.

---

## [0.8.5] - 2026-04-02

### Added
- **`innerwarden daily`** — simplified command group for day-to-day operations (aliases: `quick`, `day`). Subcommands: `status`, `threats`, `actions`, `report`, `doctor`, `test`, `agent`.
- **`innerwarden configure 2fa`** — TOTP wizard (Google Authenticator, Authy, 1Password). Protects allowlist changes, mode switches, and detector disable. Brute force protection: lockout after 3 failures/hour.
- **Telegram triage v2** — allowlist and false positive reporting directly from phone. `/undo` shows last 10 allowlist additions with Remove buttons. Auto-learn: after 3+ same-pattern FP reports, suggests permanent allowlist via Telegram.

### Changed
- **`agent connect` PID is now optional** — auto-detects running agents, connects automatically when one is found, shows guided selection for multiple. New `--name` flag to match by process name.
- **Setup wizard redesigned** — 4 clean steps (Experience, AI, Alerts, Protection) with pre-configured safe defaults and review screen before applying.
- **Dashboard scroll** — page now scrolls instead of cramming content into fixed height.

### Fixed
- **CWE-312 cleartext logging** — Telegram operator first_name (PII) was persisted in cleartext to `decisions-*.jsonl` and `allowlist-history.jsonl`. Replaced with static channel identifier across all 12 occurrences.
- **Security hardening defaults** — dashboard now binds localhost only, insecure HTTP guard added, sensitive URLs redacted from logs.
- **redb 2 → 3** — attacker profile database upgraded to redb 3.1.1.

---

## [0.8.3] - 2026-04-02

### Added
- **Autoencoder anomaly detection** — neural engine learns "what is normal" for each host. 48-feature sliding window, nightly training at 3 AM UTC, maturity-weighted scoring. Replaces V10 classifier.
- **208 Sigma community rules** — imported from SigmaHQ (120 process_creation, 53 auditd, 22 builtin, 8 file_event, 5 network). Field aliasing for eBPF events.
- **ATT&CK Navigator export** — `innerwarden navigator` generates JSON layer for MITRE Navigator visualization. 65 technique IDs mapped.
- **Steganography detection** — 4 LSB steganalysis detectors (Chi-Square, RS, SPA, Primary Sets) with fusion scoring.
- **Cloud provider IP safelist** — prevents auto-blocking Google, AWS, Azure, Oracle, Cloudflare, DigitalOcean, Hetzner IPs (~80 CIDR ranges).
- **Dynamic allowlist** — `/etc/innerwarden/allowlist.toml` for runtime configuration without rebuild. Supports processes, IPs, CIDRs, ports, DNS domains, per-detector suppressions, sigma rule suppression.
- **Telegram alert batching** — groups repeated same-detector alerts into periodic summaries (60s window). First occurrence immediate, repeats batched. Critical always immediate.
- **Deploy script** — `scripts/deploy-prod.sh [sensor|agent|ctl|all]` for one-command production deploys.
- **Canary release channel** — GitHub Actions workflow builds on every develop push, publishes as pre-release.
- **MITRE hunt detector** — 6 new checks: destructive dd (T1485), private key search (T1552.004), suspicious archive (T1560), logging config change (T1562.006), prctl rename (T1036.004), hidden artifacts.

### Changed
- **Setup wizard redesigned** — 3 clean steps (AI, Telegram, Responder) instead of 6. Modules and sensitivity auto-configured.
- **Full argv capture** — eBPF exec events now read full argv from /proc/PID/cmdline instead of just argv[0].
- **Sigma rule engine rewrite** — supports multiple named selections, filters, `|contains|all` modifier, YAML list values.
- **MITRE coverage expanded** — 42 → 65 unique technique IDs via mitre_hunt + multi-technique mapping.

### Fixed
- **15+ false positive sources eliminated** — build tools (cc, ld, cargo), CrowdSec (cscli DNS, http /etc/passwd), Node.js (node→sh), admin deploys (service_stop, discovery_burst uid=0), cloud metadata (254.169.254.169), CDN domains, InnerWarden PAM reads, .git/ paths, profile.d reads.
- **Sigma rules suppression** — noisy rules (Inline Python Execution, Shell Pipe to Shell) suppressed. Dynamic suppression via allowlist.toml.
- **CodeQL CWE-22** — path traversal in threat_report.rs month parameter.

---

## [0.8.1] - 2026-03-31

### Added
- **20 automated response playbooks** — every detector now has a corresponding response path. 14 new playbooks: timestomp, log tampering, privilege escalation (kill + suspend sudo), kernel module load (isolate + escalate), process injection, SSH key injection, crontab persistence, systemd persistence, container escape (block container + isolate), crypto miner (kill + block pool), DNS tunneling, lateral movement (isolate + escalate), web shell (kill + quarantine), discovery burst (forensics + notify).
- **Centralized allowlists** — runtime-security allowlists module (`allowlists.rs`) with ~200 entries across 8 categories: SYSTEM_DAEMONS, PACKAGE_MANAGERS, LOGIN_BINARIES, DISCOVERY_ALLOWED, SENSITIVE_FILE_READERS, TRUNCATE_ALLOWED, PRIVESC_ALLOWED, C2_OUTBOUND_ALLOWED. All detectors reference centralized lists instead of ad-hoc exceptions.

### Fixed
- **Neural V10 scoring disabled** — classifier generates false positives on Cloudflare, WordPress, and Docker production traffic. Disabled until replaced by per-host autoencoder anomaly detection.
- **Privilege escalation FP** — InnerWarden's own tokio runtime threads (uid 998) no longer trigger privesc detector. Kernel truncates thread names to 16 chars producing unpredictable substrings.
- **Sigma rule self-detection** — SIGMA-004 (shadow/passwd access) no longer fires when the sensor reads /etc/shadow for integrity verification. Global exclusion for innerwarden uid + sensitive file reader allowlist.
- **C2 callback FP** — agent's outbound HTTP requests (AbuseIPDB, GeoIP, CrowdSec) no longer trigger C2 beaconing detector. Allowlist covers innerwarden, cloud agents, monitoring tools, web servers.
- **Discovery burst FP** — bpftool (kernel integrity collector), Ubuntu MOTD scripts (00-header, run-parts), and admin tools (cargo, git, journalctl) added to allowlist. Cooldown increased from 5 min to 30 min.
- **Truncate event noise** — expanded allowlist for system daemons (irqbalance, ufw, fail2ban, landscape, tokio-rt-worker).

### Security
- Red team re-validated with allowlists: **41/42 MITRE techniques detected (98%)** — zero blind spots introduced by allowlists.

---

## [0.8.0] - 2026-03-31

### Added
- **eBPF timestomp detection** — kprobe on `vfs_utimes` detects file timestamp manipulation (MITRE T1070.006). Catches `touch -t`, `touch -r`, `utimensat` syscall.
- **eBPF log truncation detection** — kprobe on `do_truncate` detects log file truncation (MITRE T1070.003). Catches `truncate -s 0`, shell redirects (`> /var/log/syslog`).
- **Defense evasion detectors** — userspace patterns for timestomp (`touch -t`, `touch -d`, `touch -r`), log tampering (truncate/clear), LD_PRELOAD injection, history clearing, process injection via ptrace.
- **Discovery burst detector** — alerts on 5+ reconnaissance commands (ps, id, whoami, ss, cat /etc/passwd, etc.) from same user within 60 seconds. Catches MITRE T1087, T1082, T1016, T1049, T1057.

### Changed
- **Detection rate** — 86% → **95%** (42/42 MITRE ATT&CK techniques detected in red team).
- **eBPF hooks** — 38 active → **40 active** (timestomp + truncate kprobes fixed).
- **Tests** — 1,548 → **1,798** passing.
- **Neural scoring** — V10 classifier **disabled** in production. Generates false positives on WordPress/Docker/Cloudflare traffic. Will be replaced by per-host autoencoder anomaly detection in future release. Rules + kill chain + 48 detectors provide 95% detection without ML.
- **Discovery burst cooldown** — 5 min → 30 min. Expanded allowlist: cargo, git, journalctl, systemctl, landscape, apt-check.

### Fixed
- **eBPF verifier rejection** — utimensat/truncate kprobes were rejected by BPF verifier due to `?` operator after `EVENTS.reserve()` leaking ring buffer reference (Aya's `RingBufEntry` has no `Drop` impl). Fixed by using `if let Ok(comm)` pattern, `#[inline(always)]`, and mutable reference instead of raw pointer dereference.
- **Privilege escalation false positives** — innerwarden's own tokio runtime threads (truncated comm: "en-agent", "rden-dna", "illchain", "n-shield") were detected as privilege escalation. Fixed by filtering service uid 998.
- **Truncate event noise** — system daemons (systemd-journal, logrotate, rsyslogd, irqbalance, ufw, fail2ban, sshd, tokio-rt-worker, landscape) filtered from truncate/timestomp events. Non-root truncate always alerts.
- **Stale loader comments** — eBPF syscall collector comments updated to match current kprobe attribute usage.

---

## [0.7.0] - 2026-03-29

### Added
- **Native DNS capture** — AF_PACKET raw socket on UDP:53. Parses domain + query type. Feeds dns_tunneling detector. No external IDS dependency.
- **Native HTTP capture** — AF_PACKET on TCP:80/8080/8443/8787/3000/5000/9090. Parses method/path/Host/User-Agent. Feeds web_scan + user_agent_scanner.
- **TLS fingerprinting** — captures ClientHello, computes JA3 (MD5) and JA4. 10 known malicious fingerprints (Cobalt Strike, Metasploit, Emotet, etc.).
- **Neural scoring model V10** — trained on 2.1M production events, 94.6% F1 cross-validated. 58KB model, microsecond inference.
- **Monthly threat report** — auto-generated on 1st of each month. Top attackers, MITRE heatmap, campaigns, trends.
- **Pcap capture** — selective packet capture on High/Critical incidents. Spawns tcpdump for 60s per attacker IP.

### Changed
- **Correlation rules** — 23 → 30 (4 gym-discovered + 3 red team gaps).
- **Detectors** — 40 → 48 (dns_tunneling, data_exfil_ebpf, discovery_burst, + others).

---

## [0.6.0] - 2026-03-28

### Added
- **Agent Guard** — new `innerwarden-agent-guard` crate for AI agent protection. Auto-detects agents (OpenClaw, ZeroClaw, Claude Code, Aider, Cursor, +15 more), monitors tool calls, blocks credential exposure and data exfiltration. Three-layer defense: warn → shadow → kill.
- **Agent Guard CLI** — `innerwarden agent add/scan/connect/status/list` commands for managing AI agents on the server. Interactive menu, guided install, auto-detection via `/proc` scan.
- **Agent Guard API** — `POST /api/agent-guard/connect`, `GET /api/agent-guard/agents`, `POST /api/agent-guard/disconnect`. Agents self-register with InnerWarden and receive policy + check-command URL.
- **Sensitive path write protection** — LSM hook on `security_file_open` blocks unauthorized writes to `/etc/shadow`, `sudoers`, `authorized_keys`, `crontab`, `systemd units`, `ld.so.preload`, `PAM`. Observe by default, block in guard mode (`LSM_POLICY` key 1).
- **io_uring monitoring** — eBPF tracepoints on `io_uring_submit_sqe`/`io_uring_submit_req` + `io_uring_create`. Closes the biggest blind spot in eBPF security (io_uring bypasses syscall monitoring). Alerts on CONNECT, ACCEPT, OPENAT, URING_CMD. Handles kernel 6.4+ rename.
- **Container drift detection** — eBPF overlayfs upper-layer check at execve (`__upperdentry` at `inode_ptr + sizeof(struct inode)`). Detects binaries dropped after container start. `INODE_SIZE` map populated from kernel BTF at runtime.
- **Host drift detection** — flags execution from non-standard paths (`/tmp`, `/dev/shm`, `/var/www`). Trusted path allowlist, package manager awareness.
- **Capability-based guard mode** — 10 capability bits (`CAP_WRITE_CREDENTIALS`, `CAP_WRITE_SSH`, `CAP_IO_URING`, etc.) in `CGROUP_CAPABILITIES` and `COMM_CAPABILITIES` BPF maps. Per-cgroup and per-process fine-grained permissions replace hardcoded allowlists.
- **ISO 27001 A.13.2** — Information transfer control added. Dashboard now shows 13 controls (was 12).
- **Telegram dev mode** — `dev_mode = true` adds "Check FP" button to every notification. Logs flagged incidents to `fp-review.jsonl` for detector tuning.
- **Property-based tests** — 12 proptest invariants across all 4 new detectors via `proptest` crate.

### Changed
- **Dashboard UX overhaul** — integration cards grouped into 5 collapsible categories (Core, Kernel Hardening, Alerts, Threat Intel, External). Top Action widget surfaces most urgent incidents. Collectors split into active/available. Compliance progress bar with actionable items. Report hero KPIs. Journey TL;DR narrative. Threats panel widened to 380px with search feedback.
- **Default `allowed_skills`** — now includes all block backends (iptables, nftables, pf), not just ufw.
- **Detector count** — 36 → 40 detectors (sensitive_write, io_uring_anomaly, container_drift, host_drift).
- **eBPF hooks** — 22 → 25 hooks (io_uring_submit, io_uring_create, LSM file_open).

### Fixed
- Rate anomaly empty IP — packet_flood detector tracks per-IP connection counts; top offending IP reported instead of empty string.
- Block skill failures — AI parser rejects empty IPs in fallback path. `execute_decision` logs actual failure reason instead of misleading "no block skill available".
- macOS install — `BASH_SOURCE[0]` removed from curl-piped path, `NEXT_GID` scoping on re-install, exact dscl grep matches, quoted install variables.
- 16 pre-existing clippy warnings fixed (exposed by new `lib.rs` target).
- C2 allowlist — web servers and databases no longer trigger false C2 callback alerts.
- Ollama local detection in `innerwarden setup` + macOS config path fix.

---

## [0.5.3] - 2026-03-28

### Fixed
- **macOS install** - `BASH_SOURCE[0]` is unavailable when piping install.sh from curl; macOS now creates the `innerwarden` group via dscl before the user; binaries installed with group `wheel` instead of `root`. Fix NEXT_GID scoping on re-install, exact dscl grep matches, quoted variables. (PR #35 by @aya + follow-up)
- **Rate anomaly empty IP** - packet_flood detector now tracks per-IP connection counts in each minute bucket. Rate anomaly incidents report the top offending IP instead of empty string, eliminating repeat-offender noise with no actionable IP.
- **Block skill failures** - AI parser fallback path (`block-ip-*` skill IDs) now rejects empty IPs instead of passing them through. `execute_decision` early-rejects empty IPs and logs actual failure reason when firewall skill execution fails (was misleading "no block skill available").
- **Default allowed_skills** - all block backends (iptables, nftables, pf) now included in default whitelist, not just ufw. Users overriding `block_backend` no longer silently fall out of the allowed list.
- **C2 allowlist** - web servers (nginx, apache, caddy, traefik, haproxy, envoy) and databases (postgres, mysql, redis, mongodb) added to C2 callback allowlist to prevent false positives on outbound connections.
- **Ollama local detection** - `innerwarden setup` now detects local Ollama instances correctly; macOS config path uses `~/.config/innerwarden/` instead of `/etc/innerwarden/`.
- **Memory badge** - sensor 55MB + agent 26MB confirmed under 100MB badge threshold.

---

## [0.5.2] - 2026-03-27

### Fixed
- **C2 callback: gomon on port 443** - monitoring processes (gomon, prometheus, telegraf) were skipped only for non-C2 ports. Port 443 (HTTPS) is in the C2 port list, so regular HTTPS health checks from monitors triggered beaconing alerts. Now verified infra processes are skipped from all C2 checks (beaconing, exfil, port). Binary path verification via `/proc/PID/exe` prevents evasion.
- **user_creation: NSS cache hooks** - `usermod` invokes `/usr/sbin/nscd` and `/usr/sbin/sss_cache` as NSS cache invalidation hooks after user modifications. These were detected as suspicious user management commands. Now skipped when the command target is a known system utility path.
- **README** - architecture diagram updated: 19 tracepoints (was 18), 1 kprobe (was 2), kill chain 8 patterns shown in LSM box, mesh network box added, 12 skills listed. Skills table includes kill-chain-response.

---

## [0.5.1] - 2026-03-27

### Added
- **Kill chain pipeline E2E** - sensor now creates Critical incidents from `lsm.exec_blocked` events (was only emitting events, agent never saw them). Full pipeline tested: kill chain trigger to sensor incident to AI triage (Feynman 0.95) to Telegram notification.
- **Agent auto-enable LSM** - `should_auto_enable_lsm()` correctly triggers on kill chain incidents. Fixed `Path::exists()` pre-check that failed without root (agent runs as `innerwarden` user). Added sudoers for `innerwarden` user to run bpftool.
- **`AiAction::KillChainResponse`** - new AI action variant for the kill-chain-response skill. AI parser now recognizes `kill-chain-response` and `block-ip-*` skill IDs (was defaulting to Ignore).
- **Mesh broadcast on block** - when the agent blocks an IP (via AI decision), it broadcasts to mesh peers (Layer 2.5 in the layered block). Previously mesh signals only came from test nodes.
- **Mesh peer discovery** - agent now calls `discover_peers()` on startup and `rediscover_if_needed()` on each mesh tick. Nodes that weren't up during initial discovery are found later.
- **Verified infra allowlist** - `is_verified_infra_process()` helper checks `/proc/PID/exe` binary path. Prevents evasion by renaming a malicious binary to "crowdsec" or "nginx". Only allows processes from `/usr/`, `/opt/`, `/snap/`, `/bin/`, `/sbin/`.
- **Mesh tick logging** - agent logs `mesh tick staged=N new_blocks=N` on each mesh tick for observability.

### Fixed
- **Kill chain: 5 handlers chain_flag ordering** - bind, listen, ptrace, mprotect, and openat set chain flags AFTER noise filters, allowing allowlisted processes to evade detection. Fixed: move chain_flag BEFORE `is_comm_allowed`/`is_cgroup_allowed`.
- **Kill chain: `bpf_probe_read_user_str_bytes` on sockaddr_in** - string-read helper stops at null bytes in binary struct (sockaddr_in family 0x0002 has null second byte). Port/addr always read as 0. Fixed: use `bpf_probe_read_user`.
- **Kill chain: dup2/dup3 fallback on aarch64** - dup2 syscall doesn't exist on aarch64, need dup3 fallback. Server code was missing the fallback.
- **Sensor pin management** - `map.pin()` fails with EEXIST when old pin from previous sensor instance exists. Fixed: `remove_file()` before `pin()` for LSM_POLICY, blocklist, and allowlist maps.
- **AbuseIPDB auto-block: ghost blocks** - the auto-block inserted IP into `state.blocklist` BEFORE `execute_decision()`. If the block failed (XDP map missing, ufw error), the IP was still marked as "blocked", causing the AI gate to skip all future detections. Real attacker 144.31.137.41 exploited this. Fixed: insert AFTER execution, verify result.
- **Mesh peer dedup** - config peers with empty `public_key` matched `""==""`, causing only the first peer to be added. Fixed: dedup by endpoint instead of node_id.
- **False positives eliminated:**
  - `fileless:runc` (15+/2h) - Docker container runtimes (runc, crun, containerd-shim) legitimately execute from memfd.
  - `privesc:(en-agent)` (6/2h) - innerwarden agent/sensor added to LEGITIMATE_ESCALATION with starts_with matching.
  - `outbound_anomaly:nginx` - reverse proxies (nginx, haproxy, envoy, caddy, traefik) and monitors excluded.
  - `dns_tunneling:crowdsec` - CrowdSec, gomon, systemd-resolved excluded from eBPF DNS checks.
  - `c2_callback:gomon` - monitoring processes excluded from beaconing/exfil checks.
  - `c2_callback:169.254.169.254` - cloud metadata service (Oracle/AWS/GCP) excluded.
  - `c2_callback:port 0` - DNS resolution artifacts excluded.
  - `privesc:fwupdmgr` - firmware update manager added to legitimate escalation list.

### Changed
- **Mesh crate updated** to `bed8512` (periodic re-discovery, peer dedup by endpoint, rediscover_if_needed in example).
- **innerwarden-mesh** - 3 bug fix releases: discover_peers, peer dedup, example rediscovery.

---

## [0.5.0] - 2026-03-27

### Added
- **Kill chain integration** — kernel-detected attack patterns now flow into the full agent pipeline. AI receives `KILL CHAIN INTELLIGENCE` section in prompts with pattern name, C2 IP, process details, and syscall timeline. Dramatically increases response confidence.
- **Kill chain response skill** — new `kill-chain-response` atomic skill: kills process tree, blocks C2 IP via XDP, captures forensics (`ss`, `/proc` snapshot) in a single action.
- **DATA_EXFIL pattern (8th kill chain pattern)** — new `CHAIN_SENSITIVE_READ` bit flag (bit 8) set when `openat` accesses `/etc/shadow`, `.ssh/`, `.aws/`, credential files. Combined with `CHAIN_SOCKET`, detects data exfiltration without `execve`.
- **IPv6 XDP wire-speed blocking** — new `BLOCKLIST_V6` and `ALLOWLIST_V6` BPF HashMaps with 16-byte keys. XDP program now parses both EtherType `0x0800` (IPv4) and `0x86DD` (IPv6). `block-ip-xdp` skill auto-detects IP version.
- **EFI Runtime Services kprobe (EXPERIMENTAL)** — observational kprobe on `efi_call_rts` to establish firmware behavioral baseline. Monitors UEFI Runtime Services calls (GetVariable, SetVariable, GetTime). Tagged as experimental in all events.
- **Kill chain metrics in dashboard** — `/api/status` includes `kill_chain` counters (total blocked, pre-chain, per-pattern). Dashboard shows Kill Chain integration card with live stats.
- **Kill chain timeline visualization** — incidents with kill chain evidence render as visual timelines showing the syscall sequence with blocked steps highlighted in red.

### Fixed
- **Telegram 4096-char message limit** — all message types now enforced with 4000-char hard limit before POST. Prevents silent message rejection by Telegram API.
- **Telegram rate limiting** — 50ms minimum gap between sends (~20 msg/sec), prevents 429 errors during incident bursts.
- **Telegram bot token in logs** — all log output now sanitizes the bot token from API URLs (`***REDACTED***`).
- **Telegram callback IP validation** — `quick:block:` callbacks validate IP format before processing. Rejects malformed input.
- **Telegram config validation** — startup now validates `bot_token`, `chat_id` are set when enabled, and `daily_summary_hour` is 0-23. Fails fast on misconfiguration.
- **Daily digest truncation** — lowered from 3800 to 3500 chars to account for HTML escaping expansion.

### Changed
- 8 kill chain patterns (was 7): reverse shell, bind shell, code inject, exploit-to-shell, inject-to-shell, exploit-to-C2, full exploit, **data exfiltration**.
- 9 monitored syscall bit flags (was 8): added `CHAIN_SENSITIVE_READ`.
- `block_backend` default recommendation changed to `"xdp"` for wire-speed blocking.
- Skill registry now has 12 skills (was 11): added `kill-chain-response`.

---

## [0.4.5] - 2026-03-26

### Added
- **Dashboard overhaul** - comprehensive update to the embedded SPA dashboard.
- **15 sensor collectors** - added 5 missing collectors to the Sensors HUD: syslog_firewall (iptables/nftables DROP logs), firmware_integrity (UEFI/EFI monitoring), cloudtrail (AWS CloudTrail), macos_log (macOS unified log), and a legacy runtime-security log source.
- **20 integration cards** - added 5 missing cards: Mesh Network (collaborative defense), Web Push (browser notifications), Fail2ban Sync (jail management), Shield DDoS (packet flood + Cloudflare), Threat DNA (attacker fingerprinting). Integration Advisor now recommends Mesh.
- **ISO 27001 control mapping** - Compliance tab maps 12 ISO 27001 Annex A controls to current config state (A.5.1 through A.18.2), showing which controls are met and what to enable.
- **SHA-256 hash chain verification** - Compliance tab verifies the integrity of the decision audit trail hash chain in real time, showing chain length, last hash, and intact/broken status.
- **Data retention policy display** - Compliance tab shows configured retention periods for events (7d), incidents (30d), decisions (90d), telemetry (14d), and reports (30d) with GDPR export/erase commands.
- **Version badge** - dashboard header shows current version from CARGO_PKG_VERSION. Also exposed in `/api/action/config` and `/api/status` responses.
- **`/api/compliance` endpoint** - returns hash chain verification, retention config, and ISO 27001 control checklist in a single call.
- **eBPF description corrected** - collector HUD now shows "22 kernel hooks (19 tracepoints + kprobe + LSM + XDP)" instead of the outdated "6 kernel programs".
- **Expanded `/api/status`** - includes mesh, web_push, shield, dna integration states, data retention config, and version.

### Changed
- **DashboardActionConfig** - added fields for mesh_enabled, web_push_enabled, shield_enabled, dna_enabled, and retention config (events/incidents/decisions/telemetry/reports days).
- **Compliance tab redesign** - replaced Advisory Cache and Audit Trail KPIs with ISO 27001 score and Hash Chain status. Added 3 new sections (hash chain, retention, ISO controls) above the existing admin actions, advisories, and sessions.
- **Compliance data loading** - all compliance data (admin actions, advisories, sessions, compliance API) loaded in parallel via `Promise.all`.
- **Sensor color palette** - added colors for syslog_firewall, firmware_integrity, macos_log, and legacy runtime-security sources in timeline charts.

---

## [0.4.4] - 2026-03-25

### Added
- **Trusted Advisor model** - new `POST /api/advisor/check-command` endpoint tracks advisory recommendations with `advisory_id`. When an AI agent ignores a deny and executes the command, Inner Warden detects it via eBPF/auditd and notifies the server owner via Telegram.
- **Admin action audit log** - hash-chained `admin-actions-YYYY-MM-DD.jsonl` records every CLI and dashboard admin action (enable, disable, configure, block, allowlist, mesh) with operator identity and parameters.
- **Session-based authentication** - `POST /api/auth/login` returns a Bearer token. Configurable timeout (default 8h) and max concurrent sessions (default 5). Login/logout audited.
- **GDPR data subject commands** - `innerwarden gdpr export --entity <ip-or-user>` and `innerwarden gdpr erase --entity <ip-or-user>` with hash chain recomputation after erasure.
- **Privacy documentation** - `docs/privacy.md` with data categories, third-party flows, retention schedule, and data subject rights.
- **GitHub Wiki** - all documentation moved to Wiki as single source of truth. `docs/` folder now redirects to Wiki.

### Changed
- **Documentation consolidation** - replaced 10 docs/ markdown files with a single redirect to the GitHub Wiki. Images preserved.
- **OpenClaw skill rewritten** - uses `INNERWARDEN_DASHBOARD_TOKEN` env var (not interactive passwords), explicit privilege approval rules, passes ClawHub security scan.
- **All em-dashes removed** - replaced with hyphens, commas, or periods across the entire codebase (181 files), Wiki (8 files), and site (6 files).

### Fixed
- **GitHub Actions pinned** - validate-modules.yml and stale.yml actions pinned to SHA (was using tags).
- **sensor-ebpf version** - bumped from 0.3.0 to 0.4.4 (was out of sync with workspace).
- **.gitignore** - added `crates/sensor-ebpf/target/`, removed duplicate `.claude/` entry.

---

## [0.4.3] - 2026-03-25

### Security

- **eBPF parser hardening** - replaced 69 `.try_into().unwrap()` calls in ring buffer parsing with safe macros that continue on malformed events instead of crashing the sensor.
- **Sudoers TOCTOU fix** - replaced predictable `/tmp/innerwarden-sudoers-<PID>` with `tempfile::Builder` (exclusive create, random suffix).
- **Sudoers wildcard constraints** - narrowed `*` wildcards in sudoers rules to `/tmp/innerwarden-*` and `/etc/sudoers.d/innerwarden-*` paths only.
- **Sudoers filename validation** - `SudoersDropIn::path()` now rejects names containing `/`, `..`, or special characters.
- **Dashboard X-Forwarded-For** - proxy headers only trusted when connecting IP is in `dashboard.trusted_proxies` config (default: empty, trust nothing).
- **AI provider HTTPS enforcement** - `http://` base URLs rejected for remote hosts (allowed only for localhost/127.0.0.1/::1).
- **Config file permission warning** - agent warns on startup if `agent.toml` is readable by group/other users.
- **Honeypot handoff injection fix** - replaced `{target_ip}` placeholder expansion in command args with environment variables (`INNERWARDEN_SESSION_ID`, `INNERWARDEN_TARGET_IP`, etc.).
- **Honeypot allowlist path traversal fix** - `is_command_allowed()` now uses `fs::canonicalize()` to resolve symlinks and `../` before matching.
- **Supply chain: pin innerwarden-mesh** - dependency pinned to commit hash instead of branch master.
- **CTL temp file hardening** - all `/tmp/innerwarden-*` paths in CTL replaced with `tempfile::Builder`.
- **Dashboard security headers** - `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` on all responses.
- **SSE connection limit** - max 50 concurrent SSE streams, returns 429 on overflow.
- **Event size enforcement** - JSONL sink skips events exceeding 16KB with a warning.

### Fixed

- **Live feed filter typo** - `(imesyncd)` → `(timesyncd)` in system daemon privesc filter.
- **cargo fmt** - trailing whitespace in dashboard.rs that broke CI.

### Changed

- **README overhaul** - full ASCII architecture diagram, eBPF/detector count badges, all em-dashes removed, warning moved to disclaimer section.

---

## [0.4.2] - 2026-03-25

### Added
- **Firmware & boot integrity collector** - monitors ESP binaries, UEFI variables (SecureBoot, DBX, PK, KEK), ACPI tables, DMI/SMBIOS, and kernel tainted flag every 5 minutes. Detects BlackLotus, LoJax, MosaicRegressor, ACPI rootkits. Based on Peacock (arxiv:2601.07402) and UEFI Memory Forensics (arxiv:2501.16962).
- **Firmware & boot hardening checks** - `innerwarden harden` now checks Secure Boot status, kernel tainted flags, TPM presence, boot loader permissions, IOMMU, and kernel lockdown mode.
- **redb persistent state store** - agent state (cooldowns, block counts) stored in embedded database instead of unbounded HashMaps. Heap stays stable regardless of attack volume.
- **eBPF bytecode embedded in sensor binary** - `include_bytes!()` bakes the 54KB bytecode into the sensor. Single binary deploy, `innerwarden upgrade` updates everything.
- **Shield → Telegram notifications** - escalation/de-escalation events sent to Telegram with state, drops/sec, attacker count, Cloudflare proxy status.
- **Shield → JSONL incidents** - escalation events written to incidents file for live feed visibility.
- **Live feed shows all incidents** - removed IP-only filter, now displays Shield escalations, privilege escalation, rootkit indicators, and all detector types.
- **CLI improvements** - `innerwarden list` shows full system coverage (22 hooks, 36 detectors), `innerwarden status <IP>` searches incidents, `innerwarden test` shows injected incident details.

### Fixed
- **Shield warmup** - ignores first 10 seconds of backlog to prevent false escalation on boot.
- **Live feed internal filter** - hides Inner Warden's own privilege escalation (agent/shield/sensor doing setuid for skills).
- **Unused imports** in firmware_integrity collector.

### Changed
- **3 HashMaps migrated to redb** - decision_cooldowns, notification_cooldowns, block_counts now persistent and bounded.

---

## [0.4.1] - 2026-03-25

### eBPF v2

- **22 kernel hooks** (was 7) - added ptrace, setuid, bind, mount, memfd_create, init_module, dup2, listen, mprotect, clone, unlinkat, renameat2, kill, prctl, accept4
- **Kill chain detection** - 7 patterns blocked at kernel level (reverse shell, bind shell, code injection, 4 zero-day patterns)
- **Kernel-level noise filters** - COMM_ALLOWLIST (137 processes from production rulesets), CGROUP_ALLOWLIST, PID_RATE_LIMIT, PID_CHAIN
- **Ring buffer epoll wakeup** - microsecond latency (was 100ms polling)
- **CO-RE/BTF portability** - any kernel 5.8+
- **Tail call dispatcher** via ProgramArray
- **Ring buffer increased** 256KB → 1MB

### Infrastructure

- **Redis Streams integration** - optional event transport replacing JSONL for events
- **DNA engine deployed to production** - behavioral fingerprinting + attack chains + anomaly detection
- **Shield deployed to production** - DDoS protection, XDP blocking active
- **Cloudflare auto-failover** - configured and tested
- **Shield adaptive kernel defense** - tightens PID_RATE_LIMIT and XDP BLOCKLIST on escalation

### Fixes

- **Ransomware false positives** - allowlist for compilers and package managers
- **clippy if_same_then_else** in ransomware severity logic
- **CodeQL CWE-22** - path traversal fixes (canonicalize paths)
- **russh 0.57→0.58** - libcrux-sha3 vulnerability
- **gitleaks CI** pinned to v8.24.0
- **Shield ingestor** - parse IP from details/entities (was expecting source_ip field)

### UX

- **Professional personality messages** on live feed
- **Telegram messages cleaned up** - no aggressive language
- **Site disclaimer updated**
- **Auto-scroll removed** from live feed

---

## [0.4.0] - 2026-03-23

### New detectors
- **Fileless malware** - detects execution via memfd_create, /proc/self/fd, deleted binaries
- **Log tampering** - detects unauthorized access to auth.log, syslog, wtmp, btmp
- **DNS tunneling** - Shannon entropy analysis on subdomains + eBPF fallback for port 53 beaconing (works without external IDS)
- **Lateral movement** - detects internal SSH scanning, port scanning, and sensitive service probing on private networks

### Agent improvements
- **Adaptive blocking** - repeat offenders get escalating TTL (1h → 4h → 24h → 7d)
- **Local IP reputation** - per-IP scoring persisted to disk, exposed in live-feed API
- **Automated forensics** - captures /proc/{pid}/ data (cmdline, exe, fds, network, memory maps) on High/Critical incidents with PID
- **Configurable AI gate** - `ai.min_severity` setting: "high" (default, conservative) or "medium" (aggressive, more API calls)
- **Honeypot always-on mode** - SSH honeypot with AI-powered fake shell, accepts password auth to lure attackers
- **Live feed API** - real daily totals (total_today, total_blocked, total_high), honeypot sessions endpoint, server-side GeoIP proxy

### Hardening advisor
- **TLS/SSL check** - audits nginx, apache, and OpenSSL configs for deprecated protocols, weak ciphers, missing HSTS
- **Crontab audit** - scans for suspicious entries (download+execute, reverse shells, base64)
- **Kernel modules** - detects known rootkits (diamorphine, reptile, etc)
- **Accepted risks** - `/etc/innerwarden/harden-ignore.toml` for environment-specific exceptions
- **Accuracy fixes** - excludes Inner Warden/Docker services from findings, uses `sudo ufw status verbose`

### Security fixes
- Path validation for ip-reputation and sensors API (CodeQL CWE-22 #37, #38)

---

## [0.3.1] - 2026-03-22

### Hardening advisor + live threat feed

- **`innerwarden harden`** - security hardening advisor that scans SSH, firewall, kernel params, file permissions, pending updates, Docker config, and exposed services. Prints actionable fix commands with severity scoring (0-100). Advisory only - never applies changes.
- **Live threat feed API** - public `/api/live-feed` and `/api/live-feed/stream` (SSE) endpoints with CORS for real-time incident display on external sites. Includes `/api/live-feed/geoip` proxy for server-side GeoIP batch lookups.
- **Dashboard bind fix** - `tower-http` CORS layer added to agent for cross-origin live feed access.

---

## [0.3.0] - 2026-03-21

### Deep kernel security + intelligent response

- **XDP wire-speed firewall** - blocks IPs at the network driver level (10M+ pps drop rate). Pinned BPF map at `/sys/fs/bpf/innerwarden/blocklist` managed by agent via bpftool.
- **kprobe privilege escalation** - hooks kernel `commit_creds` function to detect real-time uid transitions from non-root to root through unexpected paths.
- **LSM execution blocking** - BPF LSM hook on `bprm_check_security` blocks binary execution from /tmp, /dev/shm, /var/tmp. Policy-gated, off by default, auto-enables on high-severity threats.
- **XDP allowlist** - operator IPs never dropped, checked before blocklist in kernel.
- **Layered blocking** - single block decision triggers XDP + firewall + Cloudflare + AbuseIPDB in one action.
- **Cross-detector correlation** - same IP in multiple detectors boosts AI confidence (1.15x for 2, 1.30x for 3, 1.50x for 4+).
- **LSM auto-enable** - agent automatically activates kernel execution blocking when it detects download+execute or reverse shell incidents.
- **Smart honeypot routing** - suspicious_login attackers (brute-force followed by success) redirected to honeypot; 20% of new attackers sampled; rest blocked via XDP.
- **AbuseIPDB delayed reporting** - reports queued 5 minutes before sending to allow false-positive correction.
- **Block rate limiter** - max 20 blocks per minute to prevent false-positive cascades.
- **XDP TTL** - blocked IPs auto-expire after 24 hours.
- **LSM process allowlist** - package managers (dpkg, apt, dnf), compilers (gcc, cargo), and system processes always allowed to execute from /tmp.
- **Sensor HUD dashboard** - new default home page with Chart.js area timeline, threat gauge, polar area detector chart. Design matches innerwarden.com (surface-card, cyber-gradient-text, JetBrains Mono).
- **Removed legacy runtime-security integration** - superseded by native eBPF (kprobe + LSM deeper than tracepoint-based approaches).
- **Deprecated Fail2ban** - native detectors + XDP firewall are faster and smarter.

19 detectors, 11 skills, 6 eBPF kernel programs, 692 tests.

---

## [0.2.0] - 2026-03-21

### Phase 2 - eBPF Deep Visibility

- **eBPF kernel tracing** - 3 tracepoints running in production (execve, connect, openat) via Aya framework on kernel 6.8
- **Container awareness** - `cgroup_id` captured in kernel space via `bpf_get_current_cgroup_id()`, container IDs resolved from `/proc/<pid>/cgroup` (Docker, Podman, k8s)
- **Process tree tracking** - ppid resolved via `/proc/<pid>/status`, full parent-child chain in event details
- **C2 callback detector** - beaconing analysis (coefficient of variation), C2 port monitoring, data exfiltration detection (10+ unique IPs from one process)
- **Process tree detector** - 26 suspicious lineage patterns: web server → shell, database → shell, Java/Node.js RCE, container runtime escape
- **Container escape detector** - nsenter, chroot, mount, modprobe from containers; Docker socket access, /proc/kcore reads, host sensitive file access
- **File access monitoring** - real-time sensitive path monitoring via openat tracepoint with kernel-space filtering (/etc/, /root/.ssh/, /home/*/.ssh/)
- **18 detectors** total (up from 14), 699 tests passing, sensor at 29MB RAM with all tracepoints active

---

## [0.1.6] - 2026-03-20

### Telegram personality overhaul

- **Hacker-partner voice** - all Telegram messages now speak with the personality of a skilled security operator, not a robotic monitoring system
- **Guard mode quips** - incident alerts in GUARD and DRY-RUN modes now include context-aware one-liners per threat type
- **Action reports** - post-kill messages use confidence-scaled quips: "Clean kill. Zero doubt." / "Textbook containment."
- **Mode descriptions** - GUARD: "Threats get neutralized on sight. You get the report." / WATCH: "I flag everything, you make the call."
- **/threats** - visual severity icons, relative time (3h ago), cleaner spacing
- **/decisions** - action-specific icons (block/suspend/honeypot/monitor/kill), confidence + mode display
- **/blocked** - "Kill list" header with count
- **AbuseIPDB auto-block** - "Instant kill - AbuseIPDB reputation gate" / "Dropped on sight - known threat, no AI needed."
- **Honeypot** - "Live target acquired" / "trap them or drop them?" / session debrief with "Their playbook:" heading

### Fixed

- **CrowdSec rate-limit** - cap new blocks per sync to 50 (configurable via `max_per_sync`), preventing OOM when CAPI returns 10k+ IPs. Trim `known_ips` at 10k to prevent unbounded memory growth.
- **Last Portuguese strings removed** - honeypot buttons (Bloquear/Monitorar/Ignorar), toast messages, and monitoring callback all translated to English

---

## [0.1.5] - 2026-03-20

### Security hardening (red team response)

- **Config self-monitoring** - integrity detector always monitors `/etc/innerwarden/*`, detects config tampering
- **Protected IP ranges** - AI can never block RFC1918/loopback IPs, decisions downgraded to ignore
- **Hash-chained audit trail** - each decision includes SHA-256 of the previous, tampering breaks the chain
- **Minimal sudoers** - ufw/iptables/nftables rules restricted to deny/delete/status only (no disable, flush, or reset)
- **Dashboard blocks actions over insecure HTTP** - operator actions disabled when auth is configured on non-localhost without TLS
- **Telegram destructive command warnings** - `/enable` and `/disable` show warning before execution
- **Prompt sanitization on all AI providers** - Anthropic provider now sanitizes attacker-controlled fields (was OpenAI/Ollama only)
- **Disk exhaustion protection** - events file capped at 200MB/day
- **Constant-time auth** - dashboard username comparison prevents timing attacks
- **Ed25519 binary signatures** - `innerwarden upgrade` verifies release signatures when `.sig` sidecars are present
- **Minimal sudoers** - ufw/iptables/nftables restricted to deny/delete/status only (no disable, flush, or reset)
- **Dashboard blocks actions over insecure HTTP** - operator actions disabled when auth configured on non-localhost without TLS

---

## [0.1.4] - 2026-03-19

### New commands
- **`innerwarden backup`** - archive configs to tar.gz for safe upgrades
- **`innerwarden metrics`** - events per collector, incidents per detector, AI latency, uptime

### Security hardening
- **Disk exhaustion protection** - events file capped at 200MB/day, auto-pauses writes
- **Constant-time auth** - dashboard username comparison prevents timing attacks
- **Prompt sanitization on all providers** - Anthropic provider now sanitizes attacker-controlled strings (was OpenAI/Ollama only)

### Performance
- **Dashboard 15x faster** - overview loads in 0.2s instead of 3s by counting lines instead of parsing 165MB of events JSON

### New detector
- **External config-drift anomaly** - promotes High/Critical events around sudoers, SUID, authorized_keys, and crontab changes to incidents

### Fixes
- **install.sh preserves configs** - detects existing installation and skips config overwrite on upgrade
- **Dashboard protection-first UX** - hero shows "Server Protected" with containment rate, resolved incidents faded

---

## [0.1.3] - 2026-03-19

### Security hardening

- **Dashboard login rate limiting** - after 5 failed login attempts within 15 minutes, the IP is blocked from trying again. Returns HTTP 429. Prevents brute-force on the dashboard itself.
- **Ban escalation for repeat offenders** - when an IP is blocked more than once, the decision reason is annotated with "repeat offender (blocked N times)". Flows through to Telegram, audit trail, and AbuseIPDB reports.
- **Dashboard HTTPS warning** - warns when the dashboard runs with auth on a non-localhost address over HTTP. Credentials would be sent in plaintext.
- **AI prompt injection sanitization** - attacker-controlled strings (usernames, paths, summaries) are sanitized before injection into the AI prompt. Control characters stripped, whitespace normalized.

### CrowdSec integration

- CrowdSec installed and enrolled on production server. Community blocklist flowing - known bad IPs are blocked preventively before they attack.

### Other

- Data retention enabled (7-day auto-cleanup of JSONL files)
- Watchdog cron (10-min health check, auto-restart + Telegram alert)
- OpenClaw skill published on ClawHub (innerwarden-security v1.0.3, "Benign" verdict)

---

## [0.1.2] - 2026-03-19

### NPM log support
- **Nginx Proxy Manager format** - the nginx_access collector now auto-detects and parses NPM log format (`[Client IP]` style). Sites behind Docker NPM are now protected by search_abuse, user_agent_scanner, and web_scan detectors.

### Bot detection
- **Known good bot whitelist** - 25+ legitimate crawlers (Google, Bing, DuckDuckGo, etc.) excluded from abuse detection.
- **rDNS verification** - for major search engine bots, the sensor verifies the IP via reverse DNS. Fake Googlebots (spoofed user-agent) are tagged `bot:spoofed` and treated as attackers.

### OpenClaw integration
- **innerwarden-security skill** - OpenClaw skill that installs Inner Warden, validates commands, monitors health, and fixes issues. Auto-detects AI provider. Prompt injection defense built in.

### Fixes
- **All strings in English** - removed all Portuguese from dashboard, Telegram, and agent messages.
- **max_completion_tokens** - auto-detects newer OpenAI models (gpt-5.x, o1, o3) that require the new parameter.
- **systemd dependency** - agent no longer dies when sensor restarts (Requires → Wants).

---

## [0.1.1] - 2026-03-18

### New detectors

- **Network IDS detector** - repeated alerts from same source IP → incident → block-ip
- **Docker anomaly detector** - rapid container restarts / OOM kills → incident → block-container
- **File integrity detector** - any change to monitored files (passwd, shadow, sudoers) → Critical incident

### Telegram follow-up

- **Fail2ban block notifications** - when fail2ban blocks an IP, Telegram now sends a follow-up message confirming the block or reporting failures. Previously only the initial "Live threat" alert was sent.

### Dashboard

- **Incident outcome field** - API now returns `outcome` (blocked/suspended/open) and `action_taken` for each incident by cross-referencing decisions.

### Fixes

- **install.sh: remove NoNewPrivileges from agent service** - the flag prevented sudo from working, breaking all response skills (ufw, iptables, sudoers). Sensor keeps the restriction.
- **Legacy external-tool docs** - honest "Current Limitations" sections explaining they provide context but don't trigger automated actions yet.

---

## [0.1.0] - 2026-03-18

First public release.

### Detection (8 detectors)

- SSH brute-force, credential stuffing, port scan, sudo abuse, search abuse
- `execution_guard` - shell command AST analysis via tree-sitter-bash
- `web_scan` - HTTP error floods per IP
- `user_agent_scanner` - 20+ known scanner signatures (Nikto, sqlmap, Nuclei, etc.)

### Collection (15 collectors)

- auth_log, journald, Docker, file integrity, nginx access/error, exec audit
- macOS unified log, syslog/kern.log firewall
- Legacy runtime, IDS, config-audit, and HIDS alerts
- AWS CloudTrail (IAM changes, root usage, audit tampering)

### Response skills (8 skills)

- Block IP (ufw / iptables / nftables / pf)
- Suspend user sudo (TTL-based, auto-cleanup)
- Rate limit nginx (HTTP 403 deny with TTL)
- Monitor IP (bounded tcpdump capture)
- Kill process (pkill by user, TTL metadata)
- Block container (docker pause with auto-unpause)
- Honeypot - SSH/HTTP decoy with LLM-powered shell, always-on mode, IOC extraction

### AI decision engine

- 12 providers: OpenAI, Anthropic, Groq, DeepSeek, Mistral, xAI/Grok, Google Gemini, Ollama, Together, MiniMax, Fireworks, OpenRouter - plus any OpenAI-compatible API
- Dynamic model discovery - wizard fetches available models from the provider API
- `innerwarden configure ai` - interactive wizard or direct CLI
- Algorithm gate, decision cooldown, confidence threshold, blocklist
- DDoS protection: auto-block threshold, max AI calls per tick, circuit breaker

### Collective defense

- AbuseIPDB enrichment + report-back - blocked IPs reported to global database
- Cloudflare WAF - blocks pushed to edge automatically
- GeoIP enrichment
- Fail2ban sync
- CrowdSec community threat intel

### Operator tools

- Telegram bot: alerts + approve/deny + conversational AI (/status, /incidents, /blocked, /ask)
- Slack notifications, webhook, browser push (VAPID/RFC 8291)
- Dashboard: investigation UI, SSE live push, operator actions, entity search, honeypot tab, attacker path viewer
- `innerwarden test` - pipeline test (synthetic incident → decision verification)

### Agent API for AI agents

- `GET /api/agent/security-context` - threat level and recommendation
- `GET /api/agent/check-ip?ip=X` - IP reputation check
- `POST /api/agent/check-command` - command safety analysis (reverse shells, download+execute, obfuscation, persistence, destructive ops)

### Control plane CLI

- enable/disable, setup wizard, doctor diagnostics, self-upgrade (SHA-256)
- scan advisor, incidents, decisions, entity timeline, block/unblock, export, tail, report, tune, watchdog
- Structured allowlists (IP/CIDR + users)
- `innerwarden configure ai` / `innerwarden configure responder`

### Module system

- 20 built-in modules with manifest, validate, install/uninstall, publish
- `openclaw-protection` module for AI agent environments

### Security CI

- cargo-deny: dependency advisories + license compliance
- gitleaks: secrets scanning
- Dependabot: weekly dependency updates

### Platform

- Linux (x86_64 + arm64) + macOS (x86_64 + arm64)
- 577 tests across four crates
