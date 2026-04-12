# Spec 00 — Shared Foundation (Helpers, CSS, Glossary, Trust)

**Parent**: `../spec.md`
**Phase**: 1 (first to land)
**Depends on**: nothing
**Blocks**: `01-home.md`, `02-threats.md`, `03-health.md`, `04-intel.md`
**Status**: Draft — awaiting implementation approval

## Scope

Foundational JavaScript helpers, CSS classes, glossary constants, and the unified incident-trust function that every page spec in Phase 1 depends on. Must land **before** any page-specific work.

**In scope**:
- Severity helpers (`helpers.js`)
- Temporal-window helper (`helpers.js`)
- Canonical glossary constant (`helpers.js`)
- Severity-scaled alert classes (`app.css`)
- Shared `.table-wrap` utility class (`app.css`)
- Unified `isIncidentTrusted()` with corrected trust rule (`helpers.js`) — removes the duplicate in `home.js` and the inlined variant in `threats.js`
- Guaranteed boot-time load of `_trustedIps` / `_trustedUsers` (fix Bug A if present)
- Label rename in global header checkbox (`index.html`, located by `#hideAllowlisted`) — single exception to "no HTML in shared" rule because the checkbox is shared UI across all 4 pages

**Out of scope**:
- Any page-specific copy changes (Home, Threats, Health, Intel)
- Any other HTML edit besides the one label rename on the `#hideAllowlisted` checkbox in `index.html`
- Any backend change (`dashboard.rs`, Rust)
- Dashboard mode toggle (P2-8)
- Full tooltip/hover system (P2-9)
- Detector-level false positive fixes (e.g., `reverse_shell:netcat_shell` matching legitimate `rsync --server` or interactive `python3 -c`) — this spec only makes them visible; detector tuning is separate work
- Backend support for custom temporal-window params
- Internationalization — UI copy stays English only

## Current state

### `helpers.js` (212 lines, ES5-style)

Already exists:

- `DETECTOR_LABELS` map — `helpers.js:10-26`
- `humanLabel(slug)` — `helpers.js:28`
- `outcomeBadgeHtml(outcome)` — `helpers.js:54-62` (returns `.badge-contained`, `.badge-noise`, `.badge-unresolved`, `.badge-monitor`)
- `contextLine(outcome, severity)` — `helpers.js:70-85`
- `timeAgo(ts)` — `helpers.js:165-172`
- `getUnresolved()` — `helpers.js:2-8`
- `isPrivateIp(ip)` — `helpers.js:109-113` (also duplicated at `home.js:81-85`)
- `isIncidentTrusted(inc)` — `helpers.js:115-133` (also duplicated at `home.js:87-105`; `threats.js:14-16` has a third inlined variant that only calls `isIpTrusted`/`isPrivateIp` without the `hasExternalIp` catch-all)

Missing (net-new for Phase 1):

- No severity → CSS class helper
- No max-severity helper
- No temporal-window label helper
- No canonical glossary constant
- No single-source-of-truth `isIncidentTrusted()`

### `app.css`

Color vars at `app.css:12-16`:

- `--ok: #4ade80`
- `--warn: #ffc566`
- `--danger: #f43f5e`
- `--accent: #78e5ff`
- `--orange: #ff9a55`

Existing severity precedent:

- `app.css:426-428`: `.dot-event-critical` (danger), `.dot-event-high` (warn), `.dot-event-medium` (warn/transparent)
- `app.css:471-475`: `.bk-event-crit`, `.bk-event-high`, `.bk-event-med` — same color ramp pattern, reused for consistency

Missing:

- No `.alert-*` scaled-tone classes for banner/callout containers
- No `.table-wrap` responsive wrapper utility

### `index.html` header (shared UI)

- Element: `<input type="checkbox" id="hideAllowlisted" checked onchange="toggleAllowlistFilter()" ...> Hide trusted`
- Located by `id="hideAllowlisted"` — line number intentionally not pinned, since line numbers drift with unrelated edits
- Checkbox lives in the global header, visible and active on all 4 pages (Home, Threats, Health, Intel)

### `state.js`

- `state.hideAllowlisted = true` default — `state.js:14`

### `threats.js`

- `_trustedIps = []` global — `threats.js:79`
- `_trustedUsers = []` global — `threats.js:80`
- `isIpTrusted(ip)` — `threats.js:82-...`
- `toggleAllowlistFilter()` — `threats.js:101-105` — **lazy-loads** `_trustedIps`/`_trustedUsers` from `actionCfg` only when the checkbox is clicked AND `_trustedIps.length === 0`

### `actions.js`

- Line 8-9: `_trustedIps = actionCfg.trusted_ips || []; _trustedUsers = actionCfg.trusted_users || [];`
- **Unknown**: whether `actions.js` runs at dashboard boot or only on-demand. Verification required during implementation (see Pre-implementation checks).

## Observed problems (foundation gaps)

- **FG-1**: Severity referenced ad-hoc across pages, no central function. Pages cannot scale tone without duplicating logic.
- **FG-2**: No temporal-window labeling utility. KPIs show raw numbers with no window context.
- **FG-3**: UI terminology not centrally defined. Consistent today but undocumented — copy review risks drift.
- **FG-4**: No reusable responsive `<table>` wrapper.
- **FG-5**: `isIncidentTrusted()` is duplicated in `helpers.js:115-133` and `home.js:87-105` (same code), with a third partial variant inlined in `threats.js:14-16` that omits the `hasExternalIp` catch-all. Three call sites, three subtly different behaviors. Drift risk.
- **FG-6** (**critical**): the `!hasExternalIp → trusted` catch-all at `helpers.js:131` and `home.js:103` silently hides incidents with no IP entity. Measured on prod `incidents-2026-04-11.jsonl` (24,900 incidents for the day):

  | Severity | No-IP count | Filter verdict today | Notes |
  |---|---|---|---|
  | medium | 23,673 | **HIDDEN** | host_drift, medium kill_chain (`forming 2/3 bits`), dns_c2, rootkit, kernel_module, network_sniffing, sandbox_evasion, discovery_burst |
  | high | 404 | **HIDDEN** | rootkit, kernel_module, sandbox_evasion, discovery_burst, high kill_chain |
  | **critical** | **13** | **HIDDEN** | 10 `kill_chain:detected:REVERSE_SHELL:…` completed LSM detections + 3 reverse_shell pattern matches |
  | low | 25 | **HIDDEN** | suspicious_execution with user entity only |

  Total: **96.9%** of today's incidents are filtered by this rule. **13 critical and 404 high severity events per day are invisible to the operator.**

  Sample of a hidden critical (verbatim from prod):

  ```
  incident_id: "kill_chain:detected:REVERSE_SHELL:657329:2026-04-11T09:34Z"
  severity:    "critical"
  title:       "Kill chain detected: REVERSE_SHELL (PID 657329, ruby)"
  summary:     "PID 657329 (ruby) completed REVERSE_SHELL pattern
                (socket + dup_stdin + dup_stdout). Kernel LSM will
                block next execve()."
  entities:    []
  ```

  Counterpoint: sample of 5 medium-hidden incidents (validated — these *should* stay hidden):

  ```
  {"det":"host_drift","title":"Host drift: unknown executed from non-standard path","entities":[{"type":"path","value":"sudo"}]}
  {"det":"kill_chain","title":"Kill chain forming: EXPLOIT_SHELL (2/3 bits, PID 670552)","entities":[]}
  {"det":"kill_chain","title":"Kill chain forming: EXPLOIT_SHELL (2/3 bits, PID 666797)","entities":[]}
  {"det":"kill_chain","title":"Kill chain forming: EXPLOIT_SHELL (2/3 bits, PID 668599)","entities":[]}
  {"det":"kill_chain","title":"Kill chain forming: REVERSE_SHELL (2/3 bits, PID 659723)","entities":[]}
  ```

  These are near-miss patterns (2/3 bits, incomplete) and the agent's own sudo calls — genuine noise. The corrected rule preserves hiding for these.

- **FG-7**: `threats.js:101-105` lazy-loads `_trustedIps`/`_trustedUsers` only when the user clicks the checkbox. If the user never clicks (and the checkbox is checked by default), `_trustedIps` stays empty forever, making `isIpTrusted()` return `false` for everything — so `isIncidentTrusted()` effectively only filters RFC1918 private IPs, not the actual configured allowlist. **Bug existence is conditional on whether `actions.js` also loads the allowlist at boot.** Verification required during implementation.

## Proposed changes

### Change 1 — Severity helpers in `helpers.js`

**Where**: after `DETECTOR_LABELS` block (after line 26), before `humanLabel()`.

| Function | Input | Output | Behavior |
|---|---|---|---|
| `severityClass(sev)` | `'critical' \| 'high' \| 'medium' \| 'low' \| 'info'` or null | CSS class from `alert-*` family | lowercase; unknown → `'alert-info'` |
| `severityLabel(sev)` | same | `'Critical' \| 'High' \| 'Medium' \| 'Low' \| 'Info'` | capitalize; fallback `'Info'` |
| `severityRank(sev)` | same | `4` (critical) → `0` (info), `-1` unknown | for comparison/sort |
| `maxSeverity(incidents)` | array of objects with `.severity` or `.effective_severity` | highest severity string, `'info'` if empty | prefers `effective_severity` per existing convention at `home.js:168` |

Pure additions. **Risk**: low.

### Change 2 — Temporal-window helper in `helpers.js`

**Where**: after `timeAgo()` (after line 172).

| Function | Input | Output |
|---|---|---|
| `formatWindow(kind)` | `'live' \| 'today' \| 'last_24h' \| 'last_6h' \| 'last_hour' \| 'since_start'` | `'Live' \| 'Today' \| 'Last 24h' \| 'Last 6h' \| 'Last hour' \| 'Since startup'`; unknown → `''` |

Pure addition. **Risk**: low.

### Change 3 — Canonical glossary in `helpers.js`

**Where**: `helpers.js`, file-level scope (placement fine-tuned in implementation).

```
GLOSSARY = {
  threat:     'A detected security event that may pose risk.',
  incident:   'A threat recorded by the backend (same concept, internal name).',
  unresolved: 'A threat that has not been handled automatically and awaits your review.',
  contained:  'A threat that has been blocked, killed, monitored, or suspended automatically.',
  open:       'A threat with no containment action taken yet.',
  resolved:   'A threat that has been closed — either contained or dismissed.',
  noise:      'A low-signal detection the system chose not to act on.'
}
```

Pure addition. **Risk**: low.

### Change 4 — Severity-scaled alert classes in `app.css`

**Where**: after `:root` vars block (around line 18), labeled `/* ── Severity-scaled alert classes (spec 017 Phase 1) ── */`.

| Class | Tone | Base color |
|---|---|---|
| `.alert-critical` | strong red | `--danger` |
| `.alert-high` | orange | `--orange` |
| `.alert-medium` | amber | `--warn` |
| `.alert-low` | cyan | `--accent` |
| `.alert-info` | neutral | `--muted`/`--ok` low alpha |

Each class scales border color, background alpha, and left-border accent. Text color inside the alert is **not** set by the class so existing typography keeps working. Reference: `app.css:471-475` `.bk-event-*` pattern. **Risk**: low.

### Change 5 — `.table-wrap` utility class in `app.css`

**Where**: near existing responsive section (placement decided in implementation).

- Desktop: `overflow-x: auto; -webkit-overflow-scrolling: touch; width: 100%`
- Mobile (`@media (max-width: 600px)`): safety-net horizontal scroll; the actual table → cards transformation for Intel lives in `04-intel.md` and will extend this class

Pure addition. **Risk**: low.

### Change 6 — Unified `isIncidentTrusted()` in `helpers.js`

**Where**: `helpers.js`, replacing the existing function at lines 115-133.

**Deletions**:

- Duplicate `isIncidentTrusted` at `home.js:87-105` — removed
- Duplicate `isPrivateIp` at `home.js:81-85` — removed (keep the one at `helpers.js:109-113`)
- Inlined variant at `threats.js:14-16` — replaced with a call to the unified `isIncidentTrusted()`

**New function contract**:

```
function isIncidentTrusted(inc)
  Input: incident object (from /api/incidents or graph snapshot)
  Output: boolean — true means "considered noise, hide from view when
          state.hideAllowlisted is on"; false means "show"

  Rules, in order:

  Rule 1 (severity gate):
    Read effective_severity, falling back to severity. Lowercase.
    If value is 'critical' or 'high', return false unconditionally.
    High and critical must never be filtered by the trust rule,
    regardless of entity shape. This is the core fix for FG-6.

  Rule 2 (entity walk, for medium/low/info only):
    Walk inc.entities. Accept both object form ({type, value}) and
    legacy string form ("Type:value").
    Track:
      - sawExternalIp:    any entity of type 'ip' was seen
      - allIpsTrusted:    every ip seen is in _trustedIps OR isPrivateIp
      - sawUntrustedUser: any entity of type 'user' not in _trustedUsers

    After the walk:
      If sawExternalIp AND NOT allIpsTrusted → return false
         (at least one non-trusted external IP → show)
      If sawUntrustedUser → return false
         (non-trusted user activity → show)
      Otherwise → return true
         (all IPs trusted OR no IP and no non-trusted user → hide)

  The sub-high catch-all "no IP means trusted" is preserved by this
  last branch, which is essential for suppressing 44K+ medium
  process/kernel noise events per day.
```

**Key difference from current behavior**:

- **Deleted**: the unconditional catch-all `if (!hasExternalIp) return true;` at `helpers.js:131` / `home.js:103`
- **Added**: Rule 1 severity gate
- **Result**: critical and high always visible; medium/low with no IP entity stay hidden (by Rule 2's default branch); medium/low with untrusted user or external IP now correctly shown

**Measured impact** on prod data `incidents-2026-04-11.jsonl`:

| Severity | Visible before | Visible after | Δ |
|---|---|---|---|
| critical | 27 | 40 | **+13** |
| high | 97 | 501 | **+404** |
| medium | 664 | 664 | 0 |
| low | 0 | 25 | **+25** |
| **Total** | **788** | **1,230** | **+442 (+56%)** |

The 21,960 medium `kill_chain forming` incidents, 23,673 medium host_drift incidents, and 25 low suspicious_execution-with-trusted-user incidents stay hidden by design (baseline noise). If future data shows any of these classes deserves visibility, that's a separate rule change in a follow-up spec.

**Risk**: medium — this changes observable behavior of every page that filters incidents. Verification: confirm that after deploy, the critical and high severity items visible in the Home feed strictly include everything that `/api/incidents` returns with `severity ∈ {critical, high}`, regardless of entity shape. Confirm the sample `kill_chain:detected:REVERSE_SHELL:...` critical from FG-6 is now visible (or an equivalent kill_chain critical if that specific one aged out). The measured single-day count delta in the table above is illustrative, not a target.

### Change 7 — Guaranteed boot-time load of `_trustedIps` / `_trustedUsers`

**Pre-implementation verification** (must run before editing any file):

Grep for `loadJson('/api/action/config')` and trace when it executes:

- **If** it runs at dashboard boot (via `init()` or module load in `actions.js`/`nav.js`/equivalent) → Bug A does not exist. The lazy-load branch in `threats.js:102-105` is redundant but harmless. Delete it for cleanliness, do not add new boot code.
- **If** it runs only on-demand (when the user opens Threats, triggers an action, or clicks the checkbox) → Bug A is real. Add an explicit boot-time call in the dashboard init path. Candidate location: wherever `loadJson('/api/status')` runs at boot today (most likely in `nav.js` init or `home.js loadHome()`).

The spec commits to **the outcome**: after this change lands, `_trustedIps` and `_trustedUsers` MUST be populated before the first `isIncidentTrusted()` call in the rendering pipeline, regardless of whether the user has interacted with the checkbox.

**Verification**: open a fresh dashboard, devtools console immediately after load, confirm that `_allowlistLoaded === true` AND that `JSON.stringify(_trustedIps)` / `JSON.stringify(_trustedUsers)` deep-equal the `trusted_ips` / `trusted_users` fields of a fresh `loadJson('/api/action/config')` response, including when the backend returns empty arrays.

**Risk**: low if redundant (no change needed); medium if fix required (boot sequencing affects all filter call sites).

### Change 8 — Label rename on the `#hideAllowlisted` checkbox in `index.html`

**Where**: `index.html`, the single line that contains `id="hideAllowlisted"`. Located by id, not by line number.

**Before**:

```
... onchange="toggleAllowlistFilter()" ...> Hide trusted
```

**After**:

```
... onchange="toggleAllowlistFilter()" ...> Hide known-safe sources
```

Only the visible label text changes. `id="hideAllowlisted"`, the `onchange` handler, and all JS references stay identical.

**Reason**: "Trusted" is jargon for a non-technical operator. "Known-safe sources" tells her what the toggle actually does without requiring context about the allowlist concept.

**Scope exception**: this is the only HTML edit in `00-shared.md`. Kept here rather than moved to `01-home.md` because the checkbox lives in the global header and is visible on all 4 pages — the label belongs with the foundation layer.

**Risk**: low. Single-line text edit.

## Pre-implementation checks (must pass before any file edit)

1. **Check `actions.js` boot behavior** for Change 7. Grep for `loadJson('/api/action/config')`. Determine whether it runs at boot or on-demand. Decide whether Change 7 needs a new boot call or is a pure cleanup.
2. **Grep for any other call site** of `isIncidentTrusted` or `isPrivateIp` not already listed in FG-5 (`home.js`, `helpers.js`, `threats.js`, `sse.js`). Confirm removing the duplicates in `home.js` doesn't break a hidden caller.
3. **Confirm `incident.effective_severity`** field exists and is populated in the JSON shape returned by `/api/incidents`. Already observed at `home.js:168` and `incidents-2026-04-11.jsonl` samples, but re-verify on the active build during implementation.
4. **Pull one more sample** of the 5 medium-hidden examples from FG-6 during the implementation session — confirm they're still shape-compatible with the new rule (i.e., still correctly hidden by Rule 2's default branch).

If any check fails, stop and update the spec before editing files.

## Acceptance criteria

### Helpers + CSS + glossary (Changes 1-5)

- [ ] `helpers.js` has global symbols: `severityClass`, `severityLabel`, `severityRank`, `maxSeverity`, `formatWindow`, `GLOSSARY`
- [ ] `severityClass('critical')` → `'alert-critical'`
- [ ] `severityClass(null)` → `'alert-info'`
- [ ] `severityClass('HIGH')` → `'alert-high'` (case-insensitive)
- [ ] `maxSeverity([{severity:'low'},{severity:'critical'},{severity:'medium'}])` → `'critical'`
- [ ] `maxSeverity([])` → `'info'`
- [ ] `maxSeverity([{effective_severity:'high',severity:'low'}])` → `'high'` (prefers `effective_severity`)
- [ ] `formatWindow('last_24h')` → `'Last 24h'`
- [ ] `formatWindow('nope')` → `''`
- [ ] `GLOSSARY.contained` is a non-empty English string
- [ ] `app.css` has 5 `.alert-*` classes visible in browser devtools
- [ ] `.alert-critical` applied to a test `<div>` shows red tint; `.alert-info` shows neutral
- [ ] `app.css` has `.table-wrap` with `overflow-x: auto`

### Unified trust (Changes 6-7)

- [ ] `helpers.js` has a single `isIncidentTrusted()` with the new rule
- [ ] `home.js:81-105` no longer contains `isIncidentTrusted` or `isPrivateIp`
- [ ] `threats.js:14-16` inlined variant replaced with a call to the unified function
- [ ] Critical incident with `entities: []` → `isIncidentTrusted()` returns **false** (show)
- [ ] High incident with `entities: []` → returns **false** (show)
- [ ] Medium incident with `entities: []` → returns **true** (hide)
- [ ] Medium incident with `entities: [{type:'path', value:'sudo'}]` → returns **true** (hide)
- [ ] Medium incident with `entities: [{type:'ip', value:'8.8.8.8'}]` (external, not in allowlist) → returns **false** (show)
- [ ] Medium incident with `entities: [{type:'ip', value:'192.168.1.1'}]` → returns **true** (hide)
- [ ] Medium incident with `entities: [{type:'user', value:'root'}]` when `_trustedUsers = ['root']` → returns **true**
- [ ] Medium incident with `entities: [{type:'user', value:'eve'}]` when `_trustedUsers = ['root']` → returns **false**
- [ ] Legacy string entity form `"ip:8.8.8.8"` parses equivalently to object form
- [ ] Dashboard exposes a sentinel (for example `_allowlistLoaded`) that becomes `true` only after the initial `/api/action/config` load completes at boot
- [ ] Immediately after boot (before any user interaction with the checkbox), the sentinel is `true` AND `_trustedIps` / `_trustedUsers` deep-equal the `trusted_ips` / `trusted_users` fields from the most recent `/api/action/config` response — **including the valid empty-array case** when the backend has no entries configured
- [ ] `length >= 0` is explicitly NOT a sufficient criterion (always true) — the check must be equivalence to the fetched config

### Label rename (Change 8)

- [ ] The `#hideAllowlisted` checkbox label in `index.html` shows `Hide known-safe sources`
- [ ] Checkbox still toggles `state.hideAllowlisted` correctly
- [ ] `id="hideAllowlisted"` unchanged
- [ ] `onchange="toggleAllowlistFilter()"` unchanged

### Global

- [ ] `git diff` on this spec's commit shows: additions to `helpers.js` and `app.css`, deletions of the `home.js` trust/private-ip duplicates, replacement of `threats.js` inlined variant with a call, and the single label rename in `index.html`. No unrelated changes.
- [ ] Dashboard loads with zero new console errors on Home / Threats / Health / Intel
- [ ] **Behavior, not count**: after deploy, for any critical or high severity incident observed in the raw `/api/incidents` feed, the same incident is also present in the rendered Home Recent Activity feed when "Hide known-safe sources" is ON. No critical or high incident may be hidden by the trust rule regardless of its entity shape.
- [ ] **Behavior, not count**: for any medium or low incident where the entity walk would classify it as trusted (all IPs private or allowlisted, no non-trusted user, or no entities at all), the incident remains hidden when "Hide known-safe sources" is ON.
- [ ] At least one `kill_chain:detected:*` critical is visible in the Home feed during the post-deploy observation window, provided the sensor emitted one (check prod `incidents-$(date +%Y-%m-%d).jsonl` for `kill_chain:detected:` presence)
- [ ] The specific absolute counts observed during diagnosis (see FG-6 and Change 6 impact table) are illustrative historical measurements of a single day, **not pass/fail thresholds** — day-to-day variation in attack volume can swing the numbers significantly

## Verification

### Local (before deploy)

1. `make build` — ensure compilation is clean
2. Open dashboard locally, browser devtools console:
   - `typeof severityClass === 'function'` → `true`
   - `typeof formatWindow === 'function'` → `true`
   - `typeof isIncidentTrusted === 'function'` → `true`
   - `GLOSSARY.threat` → expected string
   - `_allowlistLoaded === true` immediately at boot (before any user action)
   - Manually fetch `loadJson('/api/action/config')` and confirm `JSON.stringify(_trustedIps)` equals `JSON.stringify(response.trusted_ips)`, and the same for `_trustedUsers` — including the case when both returned arrays are empty
3. Devtools elements panel: apply `.alert-critical` then `.alert-info` to a test `<div>`, confirm tints match the table in Change 4
4. Apply `.table-wrap` to a test `<div>` with wide children, confirm horizontal scroll
5. Devtools console: manually invoke `isIncidentTrusted({severity:'critical', entities:[]})` → `false`; `isIncidentTrusted({severity:'medium', entities:[]})` → `true`; `isIncidentTrusted({severity:'medium', entities:[{type:'ip', value:'192.168.1.1'}]})` → `true`; `isIncidentTrusted({severity:'medium', entities:[{type:'ip', value:'8.8.8.8'}]})` → `false`
6. Navigate Home / Threats / Health / Intel — confirm zero console errors
7. Confirm Home Recent Activity feed shows more items than before (specifically: at least one kill_chain critical or high, and at least one rootkit/kernel_module high)

### Post-deploy (prod at `130.162.171.105`)

1. SSH in, run `sudo wc -l /var/lib/innerwarden/incidents-$(date +%Y-%m-%d).jsonl` — baseline of total for the day
2. Open dashboard at the prod URL (authenticated), Home tab
3. Compare the Recent Activity feed before/after the deploy on the same host. Expected behavior: strictly more critical and high severity items become visible (exact delta varies by daily attack volume and is not a pass/fail threshold)
4. Confirm at least one `kill_chain:detected:` critical is visible in the feed (the Home spec adds feed truncation rules, so this is specifically a "does it appear anywhere before truncation" check)
5. Check label: "Hide known-safe sources" shown in the global header checkbox on all 4 pages
6. Toggle the checkbox off → feed shows strictly more items; toggle back on → filter reapplies. Confirm no stale state
7. Zero new console errors across Home / Threats / Health / Intel
8. Navigate to Threats — confirm the same trust rule applies consistently there (no duplicate/divergent filtering)

### Rollback

Single-commit revert. No runtime state touched, no DB changes, no migration. File-level revert is sufficient.

## Post-rollout noise monitoring

Rule 1 (high/critical never hidden by the trust rule) is load-bearing. It assumes the sensor's severity classifier is stable. If a detector starts emitting large volumes of false-positive high/critical incidents — a concrete example already seen during the diagnostic: `reverse_shell:netcat_shell` matching legitimate `rsync --server` and my own interactive `python3 -c` during SSH work — the operator will be flooded.

**Commitment for the 24 hours following deploy**:

- Observe the rate of critical + high items appearing in the Home Recent Activity feed. The diagnostic baseline (single day, illustrative) was ~124 shown per day (27 critical + 97 high); after the fix the expected order of magnitude is several hundred shown per day.
- If the post-deploy rate of critical/high shown clearly exceeds the illustrative expectation by an order of magnitude (roughly: more than ~5,000 critical+high per day, equivalent to ~200/hour), treat it as a **detector quality regression**, not a UX regression.
- **The correct remediation in that case is to quiet the noisy detector** (allowlist tuning, signature adjust, severity downgrade in the rule config) — NOT to revert the trust rule. The trust rule is doing its job: surfacing what the sensor said was serious.
- **Rollback triggers for spec 017 Phase 1 (00-shared) specifically**: only one of these should trigger a revert of this commit:
  1. `isIncidentTrusted()` returns a wrong verdict on any of the Acceptance Criteria test cases in production
  2. A new JavaScript console error on any of Home / Threats / Health / Intel attributable to the change
  3. The `_allowlistLoaded` sentinel never becomes `true` (meaning `/api/action/config` is not being loaded at boot and the rule can't be evaluated against a known allowlist)
- **Detector noise alone (item above) does NOT trigger revert of this commit.**

This note exists to prevent conflating two different problems after rollout:
- **(a)** operator sees more alerts because events were previously hidden incorrectly — intended outcome of this spec, keep it
- **(b)** operator sees more alerts because a detector became unstable — out of scope of this spec, fix the detector

---

## Implementation commit message (draft)

```
feat(dashboard): unified severity + trust foundation (spec 017 Phase 1, 00-shared)

- Add severityClass/Label/Rank/maxSeverity helpers in helpers.js
- Add formatWindow helper for temporal KPI labels
- Add GLOSSARY constant with canonical English definitions
- Add .alert-critical/high/medium/low/info CSS classes
- Add .table-wrap utility for responsive tables
- Unify isIncidentTrusted in helpers.js (single source of truth)
- Remove duplicate isIncidentTrusted + isPrivateIp from home.js
- Replace inlined trust variant in threats.js with call to unified fn
- Fix FG-6: add severity gate so critical/high always visible
  regardless of entity shape; preserve sub-high catch-all for noise
- Fix FG-7 (Bug A): guarantee _trustedIps/_trustedUsers load at boot
- Rename "Hide trusted" to "Hide known-safe sources" in header

Illustrative single-day sample (prod incidents-2026-04-11.jsonl, 24,900
incidents). These numbers describe one day's observation, NOT a target —
daily variation in attack volume can swing them significantly:
  Visible incidents: ~788 → ~1,230 on that day
  Critical shown: +13 (includes previously hidden kill_chain LSM detections)
  High shown: +404
  Medium kill_chain forming + medium host_drift noise stay hidden by design

The behavioral guarantee is that critical and high incidents are never
hidden by the trust rule — not a specific count delta.

Ref: .specify/features/017-dashboard-operator-ux/pages/00-shared.md
```
