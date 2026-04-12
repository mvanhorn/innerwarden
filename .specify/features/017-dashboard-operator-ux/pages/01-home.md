# Spec 01 — Home Tab

**Parent**: `../spec.md`
**Phase**: 1
**Depends on**: `00-shared.md` must land and be implemented first (provides severity helpers, `formatWindow`, `GLOSSARY`, `.alert-*` classes, unified `isIncidentTrusted`, `_allowlistLoaded` sentinel)
**Blocks**: nothing directly. Change 8 defines a contract consumed by `02-threats.md`. Change 10 surfaces signals also displayed by `03-health.md`.
**Status**: Draft — awaiting implementation approval

## Product philosophy

**Home never demands. Home only informs and observes.**

InnerWarden is an AI-first security agent that decides and acts. The operator is an observer, not a triager. The canonical user experience is:

- 99%+ of the time: the dashboard reassures that the AI is handling things
- Ideally 0 times per year: the operator must make a decision
- 3–5 times per year at most: something unusual happens that the operator might want to look at, but even then the UI describes the unusual state — it never orders the operator to act

Every line of copy, every color, every CTA on Home is written under this philosophy. **The AI is the subject of every sentence. The operator is the reader.**

## Scope

**In scope**:
- Rename `openHighCritical` → `activeHighCritical` in `home.js`; fix its computation (use `effective_severity`, apply the same trust-filtered base as Recent Activity)
- Three hero states via a new `computeHomeState()` function: **AI Protection Active** / **AI Responding to Active Threats** / **System Health Alert**
- "Now" section with 2 lines only (What happened / What the system did) — no third line, ever
- Fixed temporal sub-labels on 3 Home KPIs (Today / Today / Live (today))
- Recent Activity hierarchy combining severity AND outcome; `OPEN` badge text → `ACTIVE`; `.alert-critical` banned from feed rows (reserved for hero state 3)
- Data Collection simplification with human-labeled collectors
- AI Briefing empty state copy replaced with approved reassuring text
- Observational `View activity →` link (secondary, always present); `View system health →` link visible only in state 3
- Home call sites use unified `isIncidentTrusted` / `isPrivateIp` from helpers.js
- New `/api/responses` fetch in `loadHome()` for System Health Alert detection
- 4 state-3 triggers: sensor stall, orphaned responses, revert_failed, revert_failures within the last 24 hours
- Explicit state priority ordering to prevent flicker when multiple signals fire

**Out of scope**:
- All other pages (Threats / Health / Intel)
- Dashboard mode toggle (P2-8)
- Full tooltip/hover system (P2-9)
- Any backend change (unless noted under T4 in Change 10)
- Detector-level false-positive tuning
- Internationalization — copy stays English

## Current state

### `home.js` (~205 lines)

- `loadHome()` — fetches `/api/status`, `/api/overview`, `/api/incidents?limit=100`, `/api/sensors`. Computes `openHighCritical` using `severity` (not `effective_severity`), no trust filter applied.
- `updateHomeBanner()` — binary `status-hero danger` / `status-hero safe`; inline red `Review Threats →` button; sub-text `"X contained · Y noise filtered"`; meta strip with `MODE` and `❤ Ns ago`.
- `updateHomeKpis()` — renders 3 cards as raw numbers, no temporal labels.
- `loadBriefing()` — empty-state fallback: `"Click Generate to create your first briefing."`
- `buildHomeFeed()` — filters via `isIncidentTrusted` when `state.hideAllowlisted`; renders chronologically; all OPEN items tagged with red `badge-unresolved`.
- After 00-shared lands: `home.js` no longer contains local `isIncidentTrusted` / `isPrivateIp` duplicates.

### `index.html` Home view

- `#homeHero`, `#homeHeroIcon`, `#homeHeroTitle`, `#homeHeroSub`, `#homeStatusMeta`
- `#homeKpiThreats`, `#homeKpiResponded`, `#homeKpiEvents`
- `#briefingSection`, `#briefingContent`, `#briefingBtn`
- `#homeFeed`
- Collector strip section

### Screenshot evidence (2026-04-11)

See parent spec discussion. Key baseline problems:
1. Header `🛡 PROTECTED · OPEN · AI 0` (green) contradicts banner `9 Unresolved Threats` (dark red)
2. KPIs `112 / 2 / 85,503` without temporal windows create mental-math confusion
3. Banner is always dark red for any open item regardless of severity
4. Recent Activity items uniformly red, no hierarchy
5. Data Collection lists raw collector slugs (`tcp_stream`, `auditd`, `http_capture`)
6. AI Briefing empty state is clinical

## Observed problems

- **HP-1**: The word `unresolved` appears in the banner title. Incompatible with AI-first philosophy — it implies human pending work.
- **HP-2**: Hero tone is binary (danger / safe). Cannot express "AI is responding to non-trivial activity" without shouting red.
- **HP-3**: `openHighCritical` computation uses `severity` (not `effective_severity`) and skips the allowlist filter, causing banner-vs-feed mismatch.
- **HP-4**: Review Threats button is a primary red CTA, projecting operator urgency. Wrong signal for an AI-first tool.
- **HP-5**: Recent Activity rows are visually uniform. Operator cannot distinguish "AI processing a kill chain" from "trivial port scan logged".
- **HP-6**: AI Briefing empty state reads like a chore.
- **HP-7**: Data Collection exposes raw slugs. No meaning for the primary operator.
- **HP-8**: No UI signal for the 3–5x/year exception states (sensor stall, response drift, execution failure).
- **HP-9**: Hero state is derived only from incident counts. System health (sensor responsiveness, response drift) never reaches Home.
- **HP-10**: Vocabulary across the tab includes `Unresolved`, `needs`, `pending`, `awaiting`, `review`, all imperative-voice terms the AI-first model rejects.

## Proposed changes

### Change 1 — Rename `openHighCritical` → `activeHighCritical`, fix computation

**Where**: `home.js loadHome()`.

**Fix**:

1. Rename the variable from `openHighCritical` to `activeHighCritical`. Reflects AI-first framing.
2. Compute from the same filtered base as Recent Activity:
   ```
   var base = state.hideAllowlisted
     ? items.filter(function(i) { return !isIncidentTrusted(i); })
     : items;
   ```
3. Filter using `effective_severity` with fallback:
   ```
   var activeHighCriticalList = base.filter(function(i) {
     var sev = (i.effective_severity || i.severity || '').toLowerCase();
     return i.outcome === 'open' && (sev === 'critical' || sev === 'high');
   });
   var activeHighCritical = activeHighCriticalList.length;
   ```
4. Pass the filtered **list** (not just count) to `updateHomeBanner` so Change 2 can call `maxSeverity()`.

**Internal naming note**: `outcome === 'open'` stays in the data-model field name — it is the backend's field. The rename applies only to JS variable names within `home.js`.

**Risk**: low.

### Change 2 — Three hero states via `computeHomeState()`

**Where**: `home.js`; new `computeHomeState()` function; rewrite of `updateHomeBanner()` to consume its output.

**New function contract**:

```
function computeHomeState(payload)
  Input: {
    status,                  // /api/status response
    overview,                // /api/overview response
    responsesData,           // /api/responses response (new fetch, Change 10)
    activeHighCriticalList   // from Change 1
  }

  Output: {
    state: 'protection_active' | 'ai_responding' | 'health_alert',
    maxSeverity: 'info'|'low'|'medium'|'high'|'critical',
    heroClass: string,       // 'status-hero alert-{class}'
    heroIcon: string,
    heroTitle: string,
    heroSub: string,
    healthAlertReasons: array of strings  // empty unless state === 'health_alert'
  }
```

**State priority (critical — prevents flicker)**:

The function MUST evaluate triggers in this fixed order. First match wins. Later triggers cannot override earlier ones in the same evaluation.

```
Priority 1 (highest): state 3 = 'health_alert'
    Fired by Change 10 triggers T1, T2, T3, T4.
    Sub-priority within health_alert for the displayed reason:
      T1 (sensor stall)           — highest, always wins
      T2 (orphaned responses)     — second
      T3 (revert_failed)          — third
      T4 (revert_failures 24h)    — fourth
    All matching triggers still populate healthAlertReasons[],
    but heroSub uses the first matching trigger's text.

Priority 2: state 2 = 'ai_responding'
    Fired when activeHighCriticalList.length > 0 AND no state-3
    trigger is active.

Priority 3 (lowest): state 1 = 'protection_active'
    Default state when neither priority 1 nor 2 matches.
```

**Rationale**: without a fixed priority, a rapid refresh cycle where `/api/responses` and `/api/status` land at slightly different times could bounce the hero between state 2 and state 3 (flicker). The fixed priority guarantees that once a state-3 signal appears, it wins until all triggers clear, regardless of how many critical incidents are open. This mirrors the operator's mental model: "system health" outranks "AI activity level" — if the system is sick, that's the headline.

**State 1 — AI Protection Active** (baseline)

| Field | Value |
|---|---|
| `state` | `'protection_active'` |
| `heroClass` | `'status-hero alert-info'` |
| `heroIcon` | `'🛡'` |
| `heroTitle` | `'AI Protection Active'` |
| `heroSub` | `'All systems monitoring. AI is watching.'` |

**State 2 — AI Responding to Active Threats**

Tone is informational, scaled by `maxSeverity(activeHighCriticalList)` but never red.

| `maxSeverity` | `heroClass` | `heroIcon` | `heroTitle` |
|---|---|---|---|
| critical | `'status-hero alert-high'` (orange) | `'⚡'` | `'AI Responding to Critical Activity'` |
| high | `'status-hero alert-medium'` (amber) | `'⚡'` | `'AI Responding to High-Severity Activity'` |
| medium | `'status-hero alert-low'` (cyan) | `'⚡'` | `'AI Responding'` |

`heroSub` format: `'Processing {N} active threat{s}. No action from you.'`

Where `{N}` is `activeHighCriticalList.length`. The phrase `"No action from you"` is a deliberate, repeated reassurance.

**State 3 — System Health Alert**

Informational red. Describes what is unusual and what the AI is doing about it. Never imperative.

| Field | Value |
|---|---|
| `state` | `'health_alert'` |
| `heroClass` | `'status-hero alert-critical'` |
| `heroIcon` | `'⚠'` |
| `heroTitle` | `'System Health Alert'` |
| `heroSub` | `healthAlertReasons[0]` (per Change 10 trigger sub-priority) |

**Risk**: medium. Centralizes state decision. Needs visual validation across transitions.

### Change 3 — "Now" section (2 lines, always observational)

**Where**: new section in `index.html` between `#homeHero` and the KPI row.

**HTML**:

```
<section id="homeNow" class="home-section">
  <h3>Now</h3>
  <ul class="home-now-list">
    <li id="homeNowWhat"></li>
    <li id="homeNowDid"></li>
  </ul>
</section>
```

Exactly 2 `<li>` elements. No third. No `#homeNowTodo`. The structural absence of a third line encodes the AI-first principle: the canonical answer to "what do you need to do?" is nothing, so the question is not asked.

**New JS** in `home.js`: `updateHomeNow(overview, activeHighCritical, stale)`.

**Line 1 — What happened** (observational):

```
"{eventsCount} events detected in the last 24 hours."
```

Or when `eventsCount === 0`:

```
"No events detected in the last 24 hours."
```

`eventsCount` comes from `overview.events_count`.

When `status.last_telemetry_secs > 120 && <= 600` (soft stale, not state 3 yet), prefix line 1 with:

```
"Telemetry is a few minutes behind. "
```

**Line 2 — What the system did** (observational + reassuring):

```
"AI contained {contained} automatically. Filtered {noise} as noise. Currently processing {active}."
```

Where:
- `contained` = `overview.ai_responded || 0`
- `noise` = `overview.ai_ignored || 0`
- `active` = `activeHighCritical` (from Change 1)

When all three are zero:

```
"AI is monitoring. No actions taken yet."
```

**CSS**: `.home-section`, `.home-now-list` — minimal layout. No severity tint on the Now section itself.

**Risk**: low.

### Change 4 — Temporal-window sub-labels on KPIs

**Where**: `home.js updateHomeKpis()` and matching `index.html`.

| KPI id | Sub-label | Source |
|---|---|---|
| `homeKpiThreats` (Threats Detected) | `Today` | `formatWindow('today')` |
| `homeKpiResponded` (Contained) | `Today` | `formatWindow('today')` |
| `homeKpiEvents` (Events) | `Live (today)` | literal string |

**HTML**: add `<span class="kpi-window">` to each KPI card.

**CSS**: `.kpi-window` — 0.65rem, `color: var(--muted)`, `white-space: nowrap`.

**Risk**: low.

### Change 5 — Recent Activity hierarchy (severity × outcome)

**Where**: `home.js buildHomeFeed()` and `helpers.js outcomeBadgeHtml()`.

**Badge rename**: in `outcomeBadgeHtml()` at `helpers.js:54-62`, change the rendered text `'OPEN'` → `'ACTIVE'`. The CSS class `badge-unresolved` stays (internal name only), but visible text and any visible label uses `ACTIVE`.

**Row container class** — combination of severity AND outcome:

| Severity | Outcome | Container class | Visual weight |
|---|---|---|---|
| critical | open | `feed-row alert-high` | prominent orange — NOT red |
| high | open | `feed-row alert-medium` | amber |
| medium | open | `feed-row alert-low` | cyan |
| low / info | open | `feed-row feed-muted` | very subtle gray |
| any | blocked / killed / contained / suspended | `feed-row feed-handled` | muted, subtle green left border |
| any | ignored (noise) | `feed-row feed-noise` | very muted gray |
| any | monitored | `feed-row feed-monitor` | subtle info tint |
| any | honeypot | `feed-row feed-honeypot` | orange informational |

**Critical constraint**: no row in the feed uses `.alert-critical`. Red is reserved exclusively for the hero in state 3.

**Sort order** (was chronological):
- Primary: `outcome === 'open' ? 0 : 1` — active items above handled
- Secondary: `severityRank(effective_severity || severity)` desc
- Tertiary: `ts` desc

**Empty-state copy** when filtered list is empty:

```
"No events in view. AI is monitoring."
```

**New CSS classes**: `.feed-row`, `.feed-muted`, `.feed-handled`, `.feed-noise`, `.feed-monitor`, `.feed-honeypot`. Exact styling in implementation.

**Risk**: medium. Visual weight of every feed row changes.

### Change 6 — Data Collection simplification

**Where**: `home.js updateCollectorStrip()` and matching `index.html`.

**Fix**:

1. Top line: `"{active}/{total} data sources active"`.
2. Color by ratio:
   - `active === total` → `.alert-info`
   - `active / total >= 0.8` → `.alert-low`
   - `active / total < 0.8` → `.alert-medium`
3. `[Show details]` / `[Hide details]` toggle. Details **collapsed by default**.
4. Expanded: render human-readable labels via new `COLLECTOR_LABELS` map in `helpers.js` (colocated with `DETECTOR_LABELS`).

Proposed `COLLECTOR_LABELS`:

| Slug | Label |
|---|---|
| `tcp_stream` | Network traffic |
| `http_capture` | Web requests |
| `dns_capture` | DNS lookups |
| `tls_fingerprint` | TLS fingerprints |
| `auth_log` | Login attempts |
| `auditd` | System audit log |
| `journald` | System journal |
| `docker` | Docker events |
| `proc_maps` | Process memory |
| `fanotify_watch` | File changes |
| `kernel_integrity` | Kernel integrity |
| `cgroup_abuse` | Resource usage |
| `ebpf_syscall` | Kernel system calls |
| `firmware_integrity` | Firmware integrity |
| (fallback) | `humanLabel(slug)` title-case |

**Risk**: low-medium.

### Change 7 — AI Briefing empty state copy

**Where**: `home.js loadBriefing()` — the `else` branch when `!data.available`.

**Fix**: replace the current fallback with the approved English copy:

> `"No briefing yet. You're protected, and we are still monitoring. Generate a briefing now for a quick summary."`

Override `data.message` on the empty case. Backend error paths (rate-limit, etc.) are unaffected.

**Risk**: low.

### Change 8 — `View activity` as secondary observational link

**Where**: removal of the existing red inline button from `updateHomeBanner()`; addition of new subordinate links.

**Fix**:

1. **Remove** the inline red `Review Threats →` button at `home.js:42-46`. The hero no longer contains an action.
2. **Add** a discreet `View activity →` link in a subordinate location (hero footer or Now section corner). Visible in all 3 states. Secondary visual weight. Consistent appearance.
3. **Add** a second discreet `View system health →` link. Hidden in states 1 and 2. Visible only in state 3, next to `View activity`.
4. Handler functions:
   ```
   function viewActivity() {
     state.autoSelectOnThreatsOpen = 'first_critical_or_high';
     showView('investigate');
   }
   function viewSystemHealth() {
     showView('health');
   }
   ```
5. The string `'first_critical_or_high'` is the **contract** with `02-threats.md`. Consume-once semantics (read-and-clear) are 02-threats.md's responsibility.
6. Copy and visual weight: both links are small, muted underline or arrow style, same typography. Neither projects urgency.

**Graceful degradation note**: when this spec lands before `03-health.md`, the `View system health →` link navigates to an unimproved Health tab that may not surface the exception context described in the hero subtitle. This is **acceptable degradation**: the hero subtitle already contains the descriptive information, the link just offers additional context that will improve once `03-health.md` lands. Documented here as a non-blocking cross-spec dependency, not a defect.

**Risk**: low.

### Change 9 — Home uses unified trust helpers from 00-shared

**Where**: `home.js` call sites.

**Fix**: verify that after 00-shared removes the `isIncidentTrusted` and `isPrivateIp` duplicates from `home.js`, all Home call sites resolve correctly to the unified `helpers.js` versions. `helpers.js` loads before `home.js` in the HTML, so resolution should be automatic. Listed as an explicit verification gate.

**Risk**: low.

### Change 10 — System Health Alert detection

**Where**: `home.js loadHome()` adds a 5th fetch `/api/responses`. New function `detectHealthAlerts()` evaluates 4 triggers.

**New fetch**:

```
loadHome() fetches now:
  /api/status
  /api/overview
  /api/incidents?limit=100
  /api/sensors
  /api/responses         <-- new
```

**Four exception triggers** — any one fires state 3:

| # | Condition | Sub-priority | Descriptive text (`healthAlertReasons` entry) |
|---|---|---|---|
| T1 | `status.last_telemetry_secs > 600` | 1 (highest) | `"Sensor has not reported for {X} minutes. AI is operating on cached signals."` |
| T2 | `responsesData.state_counts.orphaned > 0` | 2 | `"{N} response(s) completed with drift. AI is retrying."` |
| T3 | `responsesData.state_counts.revert_failed > 0` | 3 | `"{N} response revert(s) failed. AI has logged the failures."` |
| T4 | revert failures **within the last 24 hours** > 0 | 4 (lowest) | `"Recent revert failures are recorded in the system health log."` |

**T4 implementation note (backend dependency)**:

T4 requires a 24h-windowed count of revert failures, not a cumulative counter. The current `responsesData.totals.revert_failures` field appears to be cumulative since agent boot — using it directly would keep Home in state 3 permanently after any historical failure, which contradicts the 3–5x/year rarity goal.

Two options during implementation:

- **(a)** Backend adds a new field `responsesData.totals.revert_failures_last_24h` or equivalent. T4 uses it. This is the preferred path.
- **(b)** Backend has no 24h-windowed field yet. T4 is **disabled on Home for Phase 1** (still honored by `03-health.md` for the Health tab's cumulative view). A follow-up spec tracks adding the 24h field.

The implementation chooses (a) if feasible, otherwise falls back to (b) — not a blocker for this spec. Document the choice made in the implementation commit.

**State priority summary** (mirrors Change 2):

```
State 3 (health_alert)
  T1: sensor stall   (highest sub-priority)
  T2: orphaned
  T3: revert_failed
  T4: revert_failures_last_24h  (lowest sub-priority, backend-dependent)
State 2 (ai_responding)         — only when no state-3 trigger is active
State 1 (protection_active)     — default
```

No state transition can skip priority levels. If any state-3 trigger is active, state 2 cannot render even with `activeHighCritical > 0`.

**Soft stale cue (not state 3)** for `last_telemetry_secs` in the 120–600s range:

- Meta strip shows `"Data may be delayed · {X}s since last telemetry"` in amber
- Now section line 1 is prefixed with `"Telemetry is a few minutes behind. "`
- Hero state is still determined by the other signals (stays state 1 or 2)

**Out of Phase 1**: other exception triggers (AI engine unreachable, correlation engine error, integration auth failures). Deferred.

**Risk**: medium. Introduces a new state, a new fetch, and state-transition logic requiring visual validation.

## Banned vocabulary in Home UI

The following English terms/phrases are prohibited in any string rendered to the operator from Home (`home.js`, the Home portion of `index.html`, any Home-scoped CSS content, and `COLLECTOR_LABELS` / other shared helper strings consumed by Home):

- `unresolved`
- `open incident` (as a user-facing phrase; `outcome === 'open'` in code is fine)
- `needs review` / `needs attention` / `needs your attention`
- `action required` / `action needed` / `escalation required`
- `pending` (as a noun describing operator work)
- `awaiting` (as in "awaiting your input")
- `manual triage` / `manual check needed`
- `investigate now`
- `you must` / `you need to` / `please`
- `decide` / `take action`
- `review` used as a verb directed at the operator (`review this`, `review the threats`)
- Internal field names like `overview.unresolved_count` may appear in JS code (reading the backend field) — **banned only in strings rendered to the UI**.

**Acceptance criterion**: a grep over `home.js`, the Home HTML block, and Home CSS — scoped to string literals and visible content — returns zero matches on this list.

Approved replacements:

| Banned | Approved |
|---|---|
| `unresolved` | `active` |
| `open incident` | `active event` or omit |
| `needs review` | (omit; or `being processed by AI`) |
| `needs your attention` | (omit) |
| `action required` / `escalation required` | (omit; operators take no action) |
| `pending` | `active` or `processing` |
| `manual triage` / `manual check needed` | (omit) |
| `investigate now` | `view activity` (as a discreet link) |
| `review threats` | `view activity` |
| `take action` | (omit) |

## Pre-implementation checks

1. Confirm 00-shared is implemented and green on the working branch.
2. Confirm `effective_severity` field is populated on `/api/incidents` responses.
3. Confirm `status.last_telemetry_secs` is reliably bounded after sensor restart.
4. Confirm `/api/responses` returns `state_counts.orphaned`, `state_counts.revert_failed`, `totals.revert_failures` fields.
5. Check whether a 24h-windowed revert-failures field exists on `/api/responses`. If yes, T4 uses it (option a). If no, T4 is disabled on Home for Phase 1 (option b). Record the choice in the commit.
6. Grep for external callers of `updateHomeBanner`, `updateHomeKpis`, `loadHome` outside `home.js`.
7. Confirm `state.autoSelectOnThreatsOpen` is unused elsewhere in `state.js`.
8. Confirm `outcomeBadgeHtml()` is the only place generating the `OPEN` badge text. If any page inlines the string `'OPEN'` bypassing the helper, flag for parallel update.
9. Visual sanity check at ~390px mobile width for the proposed Now section layout.

If any check fails, stop and update the spec.

## Acceptance criteria

### State machine

- [ ] With zero open incidents and no exception triggers → hero state 1 (`alert-info`, shield, `AI Protection Active`).
- [ ] With at least one open critical or high incident (filtered base) and no exception triggers → hero state 2 with tone scaled by `maxSeverity`: critical→`alert-high`, high→`alert-medium`, medium→`alert-low`. **Never red.**
- [ ] State-3 triggers always outrank state-2: when T1/T2/T3/T4 and `activeHighCritical > 0` are simultaneously true, hero renders state 3.
- [ ] State-3 sub-priority: T1 > T2 > T3 > T4. The displayed `heroSub` is the text of the highest-priority active trigger.
- [ ] State transitions do not flicker across rapid refresh cycles — a single `loadHome()` result determines the state deterministically based on priority order.
- [ ] `status.last_telemetry_secs > 600` → state 3 with sensor-stall subtitle.
- [ ] `responsesData.state_counts.orphaned > 0` → state 3 with drift subtitle (when T1 is not active).
- [ ] `responsesData.state_counts.revert_failed > 0` → state 3 with revert-failed subtitle (when T1/T2 are not active).
- [ ] If T4 is enabled (option a), `revert_failures_last_24h > 0` → state 3 with the recent-failures subtitle (when T1/T2/T3 are not active).
- [ ] If T4 is disabled (option b), past cumulative failures never fire a state 3 on Home.

### Banner/feed consistency

- [ ] `activeHighCritical` count used by the hero and Now section line 2 equals exactly the number of `active` items in the Recent Activity feed with severity critical or high.
- [ ] Toggling `hideAllowlisted` on/off keeps `activeHighCritical` and feed count exactly synchronized.
- [ ] No allowlisted incident is counted in `activeHighCritical` or shown in the feed when the toggle is on.

### Copy and tone

- [ ] No string visible to the operator on Home contains any banned term listed in the "Banned vocabulary" section.
- [ ] The word `ACTIVE` appears in the feed badges where `OPEN` used to; the class `badge-unresolved` is still used internally in CSS.
- [ ] The phrase `"No action from you"` or equivalent reassurance appears in state 2's hero subtitle.
- [ ] AI Briefing empty-state copy matches exactly the approved text in Change 7.

### Now section

- [ ] Exactly 2 `<li>` elements (`#homeNowWhat`, `#homeNowDid`). No third line element exists in the DOM.
- [ ] Line 1 uses `overview.events_count`, not incident counts.
- [ ] Line 2 names "AI" as the subject of the sentence.
- [ ] When `last_telemetry_secs > 120 && <= 600`, line 1 is prefixed with `"Telemetry is a few minutes behind. "`.

### KPIs

- [ ] Each KPI card shows a sub-label: `Today`, `Today`, `Live (today)` in that order.
- [ ] No KPI is rendered as a raw number without a window indication.

### Recent Activity

- [ ] Open items sort above contained items regardless of timestamp.
- [ ] Within open items, sort by severity desc, then ts desc.
- [ ] Open critical row uses `.alert-high` (orange), NOT `.alert-critical`.
- [ ] No row in `#homeFeed` uses `.alert-critical`.
- [ ] Contained rows use `.feed-handled` (muted, no severity tint).
- [ ] Noise rows use `.feed-noise` (very muted).
- [ ] Empty-state copy reads `"No events in view. AI is monitoring."`

### Data Collection

- [ ] Top line: `"{active}/{total} data sources active"`.
- [ ] Details collapsed by default; expand shows human-labeled rows from `COLLECTOR_LABELS`.
- [ ] No raw collector slug visible without expansion.

### Observation links

- [ ] No red inline button in the hero in any state.
- [ ] `View activity →` link visible in all 3 states, subordinate visual weight.
- [ ] `View system health →` link hidden in states 1 and 2, visible in state 3.
- [ ] Clicking `View activity` sets `state.autoSelectOnThreatsOpen = 'first_critical_or_high'` and navigates to Threats.
- [ ] After Threats consumes the flag (per `02-threats.md`), `state.autoSelectOnThreatsOpen === null`.

### Global

- [ ] Zero new console errors on Home / Threats / Health / Intel.
- [ ] `git diff` on this spec's commit shows changes only in `home.js`, `index.html`, `helpers.js`, and `app.css`.
- [ ] Your wife, on a fresh Home load, describes the state in her own words as "calm" / "nothing to worry about" / "system is handling things". **Observational validation.**

## Verification

### Local (before deploy)

1. `make build`
2. Open dashboard locally, devtools console:
   - `typeof computeHomeState === 'function'` → `true`
   - `typeof updateHomeNow === 'function'` → `true`
   - `typeof viewActivity === 'function'` → `true`
   - `typeof viewSystemHealth === 'function'` → `true`
   - `typeof COLLECTOR_LABELS === 'object'` → `true`
3. Inject state variations via devtools:
   - Empty incident list + healthy responses → state 1 (`alert-info`, shield, `AI Protection Active`)
   - Single critical open incident → state 2 (`alert-high`, `AI Responding to Critical Activity`, `No action from you`)
   - Single medium open incident → state 2 (`alert-low`, `AI Responding`)
   - `last_telemetry_secs = 700` → state 3 (`alert-critical`, sensor-stall subtitle)
   - `responsesData.state_counts.orphaned = 2` AND no stall → state 3, orphan subtitle
   - Both stall AND orphan active → state 3, **stall subtitle** (priority T1 wins)
4. Verify banned-vocabulary grep on loaded Home source → zero matches.
5. Toggle `hideAllowlisted` — banner count and feed count stay equal.
6. Click `View activity` — confirm `state.autoSelectOnThreatsOpen === 'first_critical_or_high'`.
7. In state 1, confirm `View system health` link is hidden; `View activity` is still present.
8. Navigate all 4 tabs — zero console errors.
9. Visual check at ~390px mobile width.

### Post-deploy (prod at `130.162.171.105`)

1. Fresh Home load. Take a screenshot for side-by-side comparison with the 2026-04-11 baseline.
2. Confirm hero is in state 1 or 2, NOT red, when the incident mix is normal.
3. Confirm Now section has exactly 2 lines, observational, AI-first language.
4. Confirm KPI sub-labels present and match the fixed mapping.
5. Confirm Recent Activity hierarchy visible; no red rows; ACTIVE badge instead of OPEN.
6. Confirm Data Collection summary line; details collapsed by default.
7. Confirm AI Briefing empty copy matches.
8. SSH in, `sudo systemctl stop innerwarden-sensor`. Wait ~12 minutes. Refresh Home — confirm hero transitions to state 3 red `System Health Alert` with sensor-stall subtitle and `View system health` link visible. Restart sensor. Confirm hero returns to state 1/2 within the next load cycle.
9. Zero new console errors across all 4 tabs.

### Rollback

Single-commit revert. No state, DB, or migration touched. File-level revert sufficient.

## Post-rollout notes

- **Primary validation is observational**: ask your wife to describe what she sees on Home. If her words are any form of "something is wrong, I should do X", iterate on copy and visual weight BEFORE declaring done. No automated metric substitutes for this.
- **Philosophical guard**: any future edit to Home that re-introduces imperative-voice copy or a primary red CTA outside state 3 should be rejected at review time. The AI-first tone is the deliverable, not a style preference.
- **Cross-spec contracts**:
  - `state.autoSelectOnThreatsOpen = 'first_critical_or_high'` is a dead write unless `02-threats.md` implements the read-and-clear. If `02-threats.md` is delayed, `View activity` still navigates (graceful degradation).
  - `View system health →` link in state 3 navigates to Health tab. Before `03-health.md` lands, the Health tab may not surface the exception context. Acceptable degradation — hero subtitle already carries the description.
- **Threshold tuning**: the `last_telemetry_secs` thresholds (120s soft, 600s state 3) are empirical starting points. Tune after a week of observation.
- **State 3 frequency target**: with a healthy install, state 3 should fire **fewer than 5 times per year**. If it starts firing multiple times per week, that is itself a signal that something in the backend is unstable — fix the backend, do not raise the thresholds.
- **T4 backend dependency**: if option (b) is chosen (T4 disabled), track as a follow-up spec to add a 24h-windowed revert-failures field on `/api/responses`. Health tab still uses cumulative for its own views.

---

## Implementation commit message (draft)

```
feat(dashboard): Home tab AI-first operator UX (spec 017 Phase 1, 01-home)

Restructure Home around the product principle "the operator ideally
never needs to decide anything". The AI is the subject of every
sentence; the operator reads state, never receives commands. Red
color is reserved for the rare System Health Alert state; everything
else is calm or informationally scaled.

State machine (new computeHomeState() in home.js):
- State 1: AI Protection Active (baseline, .alert-info, shield icon)
- State 2: AI Responding to Active Threats (scaled .alert-low through
  .alert-high by maxSeverity; orange maximum, never red; subtitle
  always includes "No action from you")
- State 3: System Health Alert (.alert-critical, only for sensor
  stall >600s, response drift, revert failure; descriptive subtitle,
  observational not imperative)

Fixed state priority to prevent flicker:
  state 3 (T1 > T2 > T3 > T4) > state 2 > state 1

Home no longer contains any demand/imperative copy. A banned-
vocabulary grep is part of acceptance criteria. Words removed
from UI: unresolved, open incident, needs review, needs attention,
action required, escalation required, pending, awaiting,
manual triage, manual check needed, investigate now, you must,
take action, review (as verb directed at operator).

- Rename openHighCritical -> activeHighCritical in home.js
- Fix computation to use effective_severity and the same
  trust-filtered base as Recent Activity
- New "Now" section with 2 lines only (What happened / What the
  system did); no "what you need to do" line, ever
- Fixed temporal KPI sub-labels: Today / Today / Live (today)
- Recent Activity rows use severity x outcome hierarchy; open+critical
  maps to .alert-high (orange) NOT .alert-critical; no feed row uses
  red; OPEN badge text renamed to ACTIVE in helpers.js
- Data Collection simplified: N/M summary line + collapsed details
  with human-readable COLLECTOR_LABELS from helpers.js
- AI Briefing empty state copy: "No briefing yet. You're protected,
  and we are still monitoring. Generate a briefing now for a quick
  summary."
- Remove red inline Review Threats button; add secondary discreet
  "View activity" link (always present) and "View system health"
  link (only in state 3)
- Add 5th fetch /api/responses in loadHome() for System Health
  Alert detection; 4 triggers with fixed sub-priority
- T4 (recent revert failures) uses 24h window, not cumulative;
  if backend lacks a 24h field, T4 is disabled on Home for Phase 1
  and tracked as follow-up
- Home call sites use unified isIncidentTrusted/isPrivateIp from
  helpers.js (already deleted by 00-shared)

Validation is perceptual (observational with the primary operator),
not metric-based. State 3 is expected to fire fewer than 5 times
per year in a healthy install.

Depends on: .specify/features/017-dashboard-operator-ux/pages/00-shared.md
Ref: .specify/features/017-dashboard-operator-ux/pages/01-home.md
```
