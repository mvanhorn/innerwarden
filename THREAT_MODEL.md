# Inner Warden Product Threat Model

**Scope.** This document is the canonical product threat model for Inner Warden (sensor + agent + ctl + the response skill set). It supersedes the previous dashboard-only document by absorbing it under §6 below; that subsystem content is preserved verbatim and is still the authoritative dashboard-layer reference.

**Audience.** Maintainers, reviewers, contributor sign-off, enterprise and government procurement readers, OpenSSF Scorecard auditors.

**Status.** Last updated 2026-05-19. Tracks `security-audit/11-product-threat-model/` (full STRIDE + attack trees + abuse cases + invariants). Findings addressed: **11-TM-001**, **11-TM-002**, **11-TM-003**, **11-TM-004**, **11-TM-005**.

**Confidence markers.** Statements are tagged where helpful:
- **(confirmed)** — verifiable in source at this commit.
- **(assumed)** — operational expectation; not enforced by code.
- **(evidence missing)** — gap; tracked as a finding.

---

## 1. Assets

| # | Asset | Why it matters | Where it lives |
|---|---|---|---|
| A1 | Operator's host | The thing Inner Warden defends. | The customer's box. |
| A2 | Operator's data | Incidents, audit chain, attacker profiles, baseline, KV state, knowledge-graph snapshots. | `/var/lib/innerwarden/` (mode `0770` — confirmed). |
| A3 | Operator credentials | SSH keys, dashboard password, TOTP secret, AI provider API keys. | Operator's environment + `/etc/innerwarden/agent.toml`. |
| A4 | Agent binaries | What attackers want to subvert. | `/usr/local/bin/innerwarden-{sensor,agent}`. |
| A5 | Release signing key | The single point of trust for the supply chain. | GitHub Actions Secrets (`RELEASE_SIGNING_KEY`); hardware-backed signing is a roadmap item (evidence missing, finding 08-SC-002). |
| A6 | Release artefacts | What customers download. | GitHub Releases — Ed25519-signed + Sigstore SLSA v1 build attestation (confirmed). |
| A7 | Project reputation | What enables future adoption. | Public OSS posture, marketing, customer references. |

## 2. Actors

- **Operator** — authorised admin of the host. Trusted but fallible.
- **Internal user** — has shell on the host without admin rights.
- **External attacker** — internet-borne; cannot land on the host without exploit.
- **Compromised AI provider** — vendor with API access returning malicious output.
- **Compromised upstream dep** — cargo crate or GitHub Action poisoned.
- **Malicious contributor** — submits a PR with a backdoor or exfil.
- **Investigative researcher** — adversarial but ultimately well-intentioned.
- **Insider** — operator's colleague with partial access (relevant once MSP / multi-tenant ships).

## 3. Out of scope

- Nation-state APT with a fresh kernel zero-day — assume host compromise can occur; Inner Warden's role is detect + minimise, not prevent.
- Physical access to the host.
- Social engineering of the operator.
- Vulnerabilities in dependencies that have not yet been disclosed (we patch on disclosure under §5 of `Vulnerability-Disclosure-Policy`).

## 4. STRIDE per asset (summary)

Full STRIDE table per asset is in `security-audit/11-product-threat-model/THREAT-MODEL.md`. The highlights:

- **Spoofing of operator → dashboard.** Defence: Basic Auth + optional TOTP + session limits + loopback bind default. Gap: rate limit on the auth path (finding 06-ASVS-002).
- **Tampering with audit trail.** Defence: SHA-256 hash chain (`verify_hash_chain` in `crates/agent/src/dashboard/compliance.rs:654`, confirmed). Operator playbook for chain breaks is in §7 below.
- **Information disclosure via AI provider.** Defence: Local Warden Model option avoids externality entirely; otherwise outbound HTTPS. Gap: documented redaction policy (finding 09-AI-003).
- **DoS via panic.** ~5,340 `unwrap()/expect()` across agent/sensor/ctl/agent-guard — confirmed surface; phased audit tracked under finding 07-SSDF-003.
- **Privilege escalation through response skills.** Skill execution runs as the sensor/agent user; no privilege drop today (architectural — assumed).

## 5. Trust boundaries

```
+-----------------------------------------------------------------------+
|                         OPERATOR'S HOST                               |
|                                                                       |
|   [ kernel / eBPF ]   [ journald / auth.log ]   [ docker ]            |
|             \                  |                    /                 |
|              \---- in-process mpsc(1024) ---->                        |
|              ┌────────────────────────────┐                           |
|              │  innerwarden-sensor        │                           |
|              │  (53 collectors → events)  │                           |
|              └─────────────┬──────────────┘                           |
|                            │  TB-1 (sensor → agent, in-process)      |
|                            ▼                                          |
|              ┌────────────────────────────┐                           |
|              │  innerwarden-agent         │                           |
|              │  AI triage, correlation,   │                           |
|              │  response skills, dash     │                           |
|              └──┬───────┬─────────┬───────┘                           |
|                 │       │         │                                   |
|                 ▼       ▼         ▼                                   |
|              SQLite +  HTTPS    /run/innerwarden/                     |
|              JSONL    8787      agent-discovery.json                 |
|              (0770)   (loop-    (0644 — by design,                    |
|                       back      no creds)                             |
|                       default)                                        |
|                          │                                            |
|                          │  TB-2 (operator/peer agent ↔ dashboard)    |
+──────────────────────────┼────────────────────────────────────────────+
                           │                  TB-3 (agent → external)
                           ▼
            ┌──────────────────────────────────────────────┐
            │  AI providers · Telegram · Slack · Webhooks  │
            │  AbuseIPDB · Cloudflare · Sigstore · Mesh    │
            └──────────────────────────────────────────────┘
```

Each boundary, the threats at it, and the controls in place are catalogued in `security-audit/11-product-threat-model/TRUST-BOUNDARIES.md`.

## 6. Dashboard threat model (subsystem detail, preserved verbatim)

> The block below is the original `THREAT_MODEL.md` content from 2026-05-03 (last touched by PR #422 / Wave 4a). Kept verbatim because every assertion in it is verifiable in source. Treat this as the dashboard-layer authoritative reference.

### Surfaces

| Router | Auth | CSRF | Body limit | Bind |
|--------|------|------|------------|------|
| `dashboard` (operator UI + state-changing endpoints) | required (Basic + Bearer) | yes | 1 MiB | configurable, defaults to 127.0.0.1 |
| `agent_api` (`/api/agent/*` for autonomous AI agents) | configurable per `should_require_api_auth` | n/a | 1 MiB | same |
| `auth_login` (`POST /api/auth/login`) | none (this *is* the auth endpoint) | n/a | 1 MiB | same |
| `live_api` (`/api/live-feed/*` public read-only) | none | n/a | 1 MiB | same |

Layers are stacked at `serve()` in `mod.rs`. Order at construction time: `auth_layer` → `csrf_protection` → router merge → `build_body_limit_layer` → `security_headers` → `activity_layer` → `rate_limit_layer`.

### Adversaries we defend against

#### 1. Network attacker (no credentials)

- Reaches the bind address but has no Basic Auth secret and no session token.
- Read attempts on the dashboard router → `require_auth` → `unauthorized_response()` (401).
- Any rate of attempts → `rate_limit_layer` (300 req/min/IP, see `GLOBAL_RATE_LIMIT_PER_MIN`) → 429.
- Failed-login storm → `is_rate_limited` (per-IP failed-login window) → 429 even before argon2 runs.

**Not defended:** the public `live_api` is intentionally open. Sanitisation in `live_feed.rs` strips `host`, `evidence`, `recommended_checks`, and filters `is_internal` / `research_only` incidents. If the operator ever adds a field that leaks internal state, this assumption breaks.

#### 2. Authenticated browser victim (CSRF)

- Operator logged in to dashboard. Visits a malicious site that submits a hidden `<form action="https://dashboard/api/action/...">`.
- Browser auto-attaches Basic Auth credentials → request would otherwise succeed.
- **Defence:** `csrf_protection` middleware on the dashboard router rejects POST/PUT/PATCH/DELETE without `X-Requested-With: XMLHttpRequest`. Cross-origin forms cannot set this header without a CORS preflight, and the dashboard rejects preflights (no `Access-Control-Allow-Origin` configured for state-changing routes).
- **Test anchor:** `csrf_protection_rejects_post_without_header` in `dashboard/mod.rs`.

**Not defended:** GET endpoints are exempt from CSRF (read-only, idempotent). If a future GET endpoint changes state, this assumption breaks — keep new state-mutation routes on POST.

#### 3. Hijacked PR / malicious commit (last-push approval)

- Reviewer approves the PR. Attacker (or compromised contributor) pushes a follow-up commit just before merge.
- Without `require_last_push_approval`, the PR still shows green and merges with the new commit.
- **Defence:** Repository ruleset `Branch protection for protected branches` (after `scripts/update-branch-protection.sh` runs) sets `require_last_push_approval = true` and `dismiss_stale_reviews_on_push = true`.
- **Defence (CODEOWNERS):** `require_code_owner_review = true` on critical paths (`crates/agent/src/dashboard/`, `crates/agent/src/skills/`, `crates/sensor/src/detectors/`, `.github/workflows/`, `scripts/deploy-prod.sh`).

#### 4. Privileged operator action without 2FA (account compromise replay)

- Attacker replays a leaked Basic Auth credential to clear orphan responses or block IPs.
- **Defence:** when `[security].method = "totp"` and `totp_secret` is set, the orphan-resolution endpoints call `verify_dashboard_totp` which gates on a fresh 6-digit TOTP. The other action endpoints (`block-ip`, `suspend-user`, etc.) currently rely only on auth + dry-run config — extending 2FA to those is a follow-up.
- **Test anchor:** `verify_dashboard_totp_*` tests in `dashboard/agent_api.rs`.

**Not defended:** if the attacker also captures a fresh TOTP code (e.g. operator phished into typing it on a fake login page), the protection lapses. We do not bind TOTP to the session origin — this is a classic limitation of plain TOTP without WebAuthn.

#### 5. Exhaustion via large request bodies (DoS)

- `DefaultBodyLimit::max(MAX_BODY_BYTES)` = 1 MiB on every route.
- Test anchor: `body_limit_layer_rejects_oversized_post` in `dashboard/mod.rs`.

#### 6. Path injection / canonical-path escape (CWE-22)

- Every disk-touching dashboard helper canonicalises the data dir and asserts the joined path stays inside before reading or writing. Applied in:
  - `append_orphan_resolution` / `read_orphan_resolutions` (PR #420 Wave 3 + PR #420 follow-up).
  - `enumerate_orphans_from_responses_json` consumers (PR #419 Wave 2).
  - `append_admin_action` in `crates/core/src/audit.rs`.
- **Defence intent:** even if a future feature accepts a partially user-controlled filename, the canonical-prefix check stops the read.

### Audit + observability

| Surface | Source | Format |
|---------|--------|--------|
| Operator actions | `admin-actions-YYYY-MM-DD.jsonl` | hash-chained, viewable on Compliance tab |
| Orphan resolutions | `orphan_resolutions.jsonl` (sidecar) | append-only, last-wins per id |
| AI / auto decisions | `decisions-YYYY-MM-DD.jsonl` | hash-chained |
| Prometheus metrics | `GET /metrics` | text exposition |

PR #422 added `innerwarden_orphan_resolutions_total{kind}` — a non-zero rate against a flat orphaned counter signals "operator is keeping up with maintenance debt" (good); flat both = "drift accumulating" (bad).

### What is *not* in the dashboard threat model

- **Side-channel attacks on argon2 verify** — we use a 5-minute hot-path cache (`VerifiedCache`) to skip the 64 MiB working buffer; an attacker with sub-second timing access to the bind socket could in theory measure cache hit/miss and learn whether a credential is currently valid. Mitigated by rate limiting per IP.
- **TLS termination** — the dashboard speaks plaintext HTTP if no reverse proxy is in front. Operators on non-loopback binds are warned at boot. `--insecure-no-tls` is required to skip TLS bootstrap.
- **Kernel-level rootkit reading the agent process memory** — the agent's eBPF self-defence detects unauthorised attach-to-self attempts but cannot defend against a kernel that's already been replaced.

### How to extend the dashboard layer

When adding a new state-changing dashboard endpoint:

1. Register the route on the auth-protected `dashboard` router. The CSRF middleware fires automatically.
2. If the action affects production state (block, kill, deny, dismiss), gate it on `verify_dashboard_totp(&state, &body.totp)` and write an `AdminActionEntry` to the audit chain.
3. Extract the operator name via `Option<axum::Extension<AuthenticatedUser>>` rather than hardcoding a string. The newtype is in `dashboard/auth.rs`.
4. Add a Prometheus counter so alerting can see the rate of operator decisions of this kind.
5. Add a source-grep anchor test in `dashboard::tests` that pins the route + middleware so a future refactor that drops the middleware fails CI.

When adding a new GET endpoint that may eventually change state, keep it on POST from the start to avoid retrofitting CSRF.

---

## 7. Audit chain integrity playbook

The audit chain is hash-linked (SHA-256 over each line, with `prev_hash` carried forward). Three operational states:

- **intact** — `verify_hash_chain` returns `(true, len, last_hash)`. Normal state.
- **registered break** — an operator-acknowledged break recorded via `innerwarden chain-break register --start <rowid> --end <rowid> --operator <name> --reason "<why>"`. Verifier still reports intact across the break.
- **unregistered break** — `verify_hash_chain` returns `(false, _, _)`. **This is a signal to investigate.**

**When the verifier reports an unregistered break:**

1. Snapshot `/var/lib/innerwarden/` (read-only copy).
2. Run `innerwarden chain-break list` and confirm no registered break covers the affected rowids.
3. Search journald for the corresponding window: any `WARN` from `compliance::verify_hash_chain` or sudden agent restart.
4. If the break aligns with a known operator action (manual db edit, restore from backup), register it.
5. If unexplained, treat as Critical incident and follow `Incident-Response` (in the wiki).

The verifier is intentionally resilient to malformed JSON lines (`crates/agent/src/dashboard/compliance.rs:664`, anchored by PR #702). Partial corruption does not blank the chain.

## 8. Security invariants (the contract every test should anchor)

The full list is in `security-audit/11-product-threat-model/SECURITY-INVARIANTS.md`. The headlines, each backed by an anchor or by a finding tracking an unfilled anchor:

- **AUTH-1** — every dashboard endpoint requires auth unless on the explicit loopback-bypass allow-list AND the peer IP from `ConnectInfo<SocketAddr>` is loopback. (Anchored in `crates/agent/src/dashboard/auth.rs::tests`, PR #680.)
- **AUTH-2** — the peer IP for loopback-bypass is NEVER read from `X-Forwarded-For`. (Same anchor; add explicit XFF-spoof test per finding 06-ASVS-001 suggested test.)
- **RESP-1** — Inner Warden will NOT block an IP in `cfg.allowlist.trusted_ips`, regardless of AI verdict.
- **RESP-2** — Inner Warden will NOT execute a skill not in `cfg.responder.allowed_skills`.
- **RESP-3** — autonomous blocks per hour are capped by the circuit breaker.
- **RESP-4** — `cfg.responder.dry_run = true` suppresses side effects on every skill.
- **AUDIT-1** — every executed response skill writes an entry to the SQLite `decisions` table AND to the JSONL audit chain.
- **AUDIT-2** — the audit chain SHA-256 chain link verifies. Tampering is detected.
- **UPD-1** — `install.sh` MUST reject a binary whose Ed25519 signature does not verify.
- **UPD-2** — `install.sh` MUST reject a binary whose SHA-256 does not match its sidecar.
- **DATA-2** — `/var/lib/innerwarden` is `0770 innerwarden:innerwarden`. Non-privileged users cannot read incident data.
- **DATA-3** — `/run/innerwarden/agent-discovery.json` is intentionally world-readable (0644) and contains ONLY discovery metadata. No credentials.

The detailed mapping from invariant → test exists in `security-audit/11-product-threat-model/TESTS-REQUIRED.md`. Several anchors exist but are not labelled as such — labelling them (`#[doc = "invariant: AUTH-1"]`) is a P0 follow-up that costs ~1 day.

## 9. Documented out-of-scope categories

Beyond the items in §3, the model intentionally does NOT cover:

- Buyer's host hardening below the kernel-eBPF interface — that's CE+ baseline.
- Buyer's own ISMS — that's their certification path.
- Third-party AI providers' own security posture — only the boundary and what is sent across it.
- Marketing-site / CDN compromise of `innerwarden.com` — install.sh remains protected by the embedded Ed25519 public key, so a compromised host cannot inject backdoored binaries; the assumption is that the operator's first install (TOFU) was honest.

## 10. Related documents

- `SECURITY.md` — top-level security policy + VDP entry point.
- Wiki: `Autonomous-Action-Invariants` — formal invariant catalogue for response actions.
- Wiki: `Incident-Response` — project-level IR runbook (not runtime incident handling).
- Wiki: `Vulnerability-Disclosure-Policy` — expanded VDP with SLA.
- Wiki: `Customer-Security-Pack` — one-page summary + supporting docs index.
- `security-audit/11-product-threat-model/` — the long-form artefacts that this document summarises.
- `docs/supply-chain-security.md` — release flow, fingerprints, manual verification recipe.

## 11. Maintenance

- Review on every minor release (currently per-quarter).
- Update on any change to skill_gate, auth middleware, or autonomous action invariants.
- Each invariant change requires a corresponding test update.
- Removing an invariant requires explicit justification in the PR body.
