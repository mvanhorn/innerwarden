// ── Home view — spec 017 Phase 1 (01-home) ────────────────────────────
// Philosophy: Home never demands. Home only informs and observes.
// The AI is the subject of every sentence. The operator is a reader.
// Red is reserved for System Health Alert (state 3) only.

// Thresholds (tunable after observation)
var HOME_TELEMETRY_STALE_SOFT_SECS = 120;   // amber soft cue
var HOME_TELEMETRY_STALL_SECS      = 600;   // state 3 trigger
var HOME_ORPHAN_WINDOW_MS          = 24 * 60 * 60 * 1000;   // 24h history walk

async function loadHome() {
  try {
    const [status, overview, incidentList, sensors, responsesData, entityData] = await Promise.all([
      loadJson('/api/status'),
      loadJson('/api/overview'),
      loadJson('/api/incidents?limit=100'),
      loadJson('/api/sensors'),
      loadJson('/api/responses').catch(function() { return {}; }),
      loadJson('/api/entities').then(function(r) {
        return { items: (r.attackers || []).map(function(a) { return Object.assign({}, a, { value: a.ip, group_by: 'ip' }); }) };
      }).catch(function() { return { items: [] }; })
    ]);
    window._lastOverview = overview;
    window._agentMode = status.mode || 'guard';
    window._lastIncidentList = incidentList.items || [];
    window._lastEntityItems = entityData.items || [];

    var items = incidentList.items || [];
    var base = state.hideAllowlisted
      ? items.filter(function(i) { return !isIncidentTrusted(i); })
      : items;

    // Items the AI is currently processing at high/critical priority.
    var activeHighCriticalList = base.filter(function(i) {
      var sev = (i.effective_severity || i.severity || '').toLowerCase();
      return i.outcome === 'open' && (sev === 'critical' || sev === 'high');
    });

    var homeState = computeHomeState({
      status: status,
      overview: overview,
      responsesData: responsesData,
      activeHighCriticalList: activeHighCriticalList,
      allIncidents: items,
      entityItems: entityData.items || []
    });

    updateHomeHero(homeState);
    // Total events scanned from sensors (trust signal: "3.3M scanned → 2 blocked")
    var totalEventsScanned = 0;
    (sensors.sources || []).forEach(function(s) { totalEventsScanned += s.count || 0; });
    window._totalEventsScanned = totalEventsScanned;

    // 2026-05-15 slim-down: home renders hero → review banner →
    // activity strip → onboarding tip → briefing. Critical banner,
    // since-last-visit, health line, details panel and host posture
    // sections were removed.
    renderReviewBanner(overview);
    renderActivityStrip(overview, totalEventsScanned);
    renderOnboardingTip(overview);
    // Spec 051 PR1 — Community banner: no telemetry by design, so this
    // is the polite ask. Gated by localStorage; safe to call every render.
    if (typeof renderCommunityBanner === 'function') {
      renderCommunityBanner();
    }

    // Phase 12 (QA fix #1): keep the persistent header pill in sync
    // with runtime SystemHealth. Without this, the green "PROTECTED"
    // pill stayed up while the hero said "System Health Alert" — a
    // contradictory state on one screen.
    syncModeBadgeFromHealth(overview, actionCfg);
    loadBriefing();
    // 2026-05-15 Sensors fold: the standalone Sensors page was
    // deleted. The per-collector telemetry/alarm/snapshot breakdown
    // and the Event Timeline now live on Home below the AI Briefing.
    // Same payload already fetched in the Promise.all above.
    renderHomeSensorsPanel(sensors);
  } catch(e) { console.warn('loadHome error:', e); }
}

// ── Sensors panel on Home (folded in from the deleted Sensors page) ──
// Renders the per-collector telemetry/alarm/snapshot breakdown and the
// Event Timeline under the AI Briefing. Uses `renderSensorSourceRows`
// and `drawTimelineChart` from sensors.js (kept as a helpers module
// even though the standalone Sensors view is gone). Defensive about
// missing DOM nodes so partial-page mounts don't throw.
function renderHomeSensorsPanel(sensors) {
  if (!sensors) return;
  if (typeof renderSensorSourceRows === 'function') {
    renderSensorSourceRows('homeSensorSources', sensors);
  }
  if (typeof drawTimelineChart === 'function') {
    drawTimelineChart('homeSensorChart', sensors.event_timeline || {}, sensors.sources || []);
  }
}


// ── Review-queue banner ─────────────────────────────────────────────
function renderReviewBanner(overview) {
  var banner = document.getElementById('homeReviewBanner');
  if (!banner) return;
  var snap = overview && overview.snapshot;
  var awaiting = snap
    ? (snap.buckets.attention.unique_attackers || 0)
    : (overview.attention_count || 0);
  if (awaiting <= 0) {
    banner.style.display = 'none';
    return;
  }
  banner.style.display = '';
  var countEl = document.getElementById('homeReviewCount');
  if (countEl) {
    countEl.textContent = awaiting + ' attacker' + (awaiting === 1 ? '' : 's');
  }
}

// ── Activity strip ──────────────────────────────────────────────────
// 4 numbers in one row: events watched / flagged by system / Warden
// decisions / needs review. Plus a sub-breakdown row underneath:
// Contained · Observing · Filtered out.
//
// Spec 049 PR2: all four leaf counters + two derived totals come
// from the BACKEND (`overview.flagged_by_system_count`,
// `overview.warden_decisions_count`, etc.). Pre-spec-049 the
// frontend summed `snap.buckets.X.unique_attackers` itself — which
// drifted from the backend on every refactor and silently dropped
// `dismissed` (KpiBucket::None) entirely. Backend now owns the math
// contract (case_metrics.rs); frontend just renders.
function renderActivityStrip(overview, totalEventsScanned) {
  var snap = overview && overview.snapshot;

  // Watched.
  var watched = snap
    ? (snap.events_today || totalEventsScanned || overview.events_count || 0)
    : (totalEventsScanned || overview.events_count || 0);
  setText('homeActWatched', formatBigNumber(watched));

  // Flagged by system = backend-computed sum of all four outcomes
  // (Contained + Observing + Filtered out + Needs review). Replaces
  // the pre-spec-049 frontend bucket sum that excluded dismissed.
  setText('homeActFlagged', overview.flagged_by_system_count || 0);

  // Warden decisions = backend-computed (Contained + Observing +
  // Filtered out). Includes dismiss because dismiss is a decision,
  // not a no-op (spec 049 Q1+Q7).
  setText('homeActStopped', overview.warden_decisions_count || 0);

  // Needs review = attention bucket. Cell gets a warning tint when
  // > 0 so it stands out without being a separate banner copy.
  var needsReview = overview.attention_count || 0;
  setText('homeActAwaiting', needsReview);
  var awaitingCell = document.querySelector('.activity-cell-attention');
  if (awaitingCell) {
    awaitingCell.classList.toggle('activity-cell-attention-active', needsReview > 0);
  }

  // Sub-breakdown row: Contained · Observing · Filtered out. Sum
  // matches `homeActStopped`. Filtered out was invisible pre-spec-
  // 049 (the silent-drop bug RECURRING_BUGS.md anchored).
  setText('homeActContained', overview.blocked_count || 0);
  setText('homeActObserving', overview.observing_count || 0);
  setText('homeActFilteredOut', overview.filtered_out_count || 0);

  // Window label: "since midnight UTC · last Nh".
  var elapsed = computeElapsedHoursUtc();
  var elapsedText = elapsed >= 1
    ? 'since midnight UTC · last ' + elapsed + 'h'
    : 'since midnight UTC';
  setText('homeActivityWindow', elapsedText);
}


// Audit 5.10: onboarding / clean-day tip. Surfaces a quiet info row
// when today has produced zero attackers and zero review-queue items
// so a fresh-install or quiet-day operator sees the agent IS alive
// and watching, not silently broken.
function renderOnboardingTip(overview) {
  var tip = document.getElementById('homeOnboardingTip');
  if (!tip) return;
  var snap = overview && overview.snapshot;
  var flagged = 0;
  var awaiting = 0;
  if (snap) {
    flagged =
      (snap.buckets.blocked.unique_attackers || 0) +
      (snap.buckets.observing.unique_attackers || 0) +
      (snap.buckets.honeypot.unique_attackers || 0) +
      (snap.buckets.attention.unique_attackers || 0) +
      (snap.buckets.allowlisted.unique_attackers || 0);
    awaiting = snap.buckets.attention.unique_attackers || 0;
  } else {
    flagged = overview && overview.handled_ips_today || 0;
    awaiting = overview && overview.attention_count || 0;
  }
  var quiet = flagged === 0 && awaiting === 0;
  tip.style.display = quiet ? '' : 'none';
}

// ── State machine ────────────────────────────────────────────────────
// Fixed priority to prevent flicker:
//   state 3 (health_alert, T1 > T2 > T3) > state 2 (ai_responding) > state 1
function computeHomeState(payload) {
  var status = payload.status || {};
  var overview = payload.overview || {};
  var rd = payload.responsesData || {};
  var activeList = payload.activeHighCriticalList || [];

  // Priority 1: state 3 — System Health Alert. First trigger wins for heroSub.
  var reasons = [];

  // T1: sensor stall
  var telemetrySecs = (typeof status.last_telemetry_secs === 'number')
    ? status.last_telemetry_secs : null;
  if (telemetrySecs != null && telemetrySecs > HOME_TELEMETRY_STALL_SECS) {
    var mins = Math.floor(telemetrySecs / 60);
    reasons.push('Sensor has not reported for ' + mins + ' minute' + (mins === 1 ? '' : 's') + '. AI is operating on cached signals.');
  }

  // T2: currently failing reverts
  var stateCounts = rd.state_counts || {};
  var revertFailed = +stateCounts.revert_failed || 0;
  if (revertFailed > 0) {
    reasons.push(revertFailed + ' response revert' + (revertFailed === 1 ? '' : 's') + ' currently failing. AI has logged the failures.');
  }

  // T3: recent orphans in history (walk last 24h)
  var history = Array.isArray(rd.history) ? rd.history : [];
  var now = Date.now();
  var recentOrphans = history.filter(function(h) {
    var reason = (h && h.reason) || '';
    if (!reason.indexOf || reason.indexOf('orphaned') !== 0) return false;
    var ts = h.reverted_at ? new Date(h.reverted_at).getTime() : 0;
    return ts > 0 && (now - ts) < HOME_ORPHAN_WINDOW_MS;
  }).length;
  if (recentOrphans > 0) {
    reasons.push(recentOrphans + ' response' + (recentOrphans === 1 ? '' : 's') + ' orphaned in the last 24 hours. AI gave up retrying.');
  }

  // Phase 7 / 7B (audit RC-2): T4 — backend SystemHealth verb. The
  // distinction between AiNotResponding (red: no recent decisions
  // AND stuck>0) and AbandonedBacklog (yellow: stuck>0 BUT recent
  // decisions still flowing) was added in Phase 7B after the live
  // dashboard cried "AI pipeline may be wedged" while the AI was
  // healthily processing the steady stream — earlier-day orphans
  // are an audit signal, not an ongoing-outage signal.
  //
  // AiNotResponding -> health_alert (red, top-priority reason).
  // AbandonedBacklog is handled below outside the health_alert
  // gate as a softer signal (medium-severity hero with a recovery
  // hint, not an ALERT).
  var phase7Health = overview && overview.snapshot && overview.snapshot.health;
  if (phase7Health && phase7Health.kind === 'ai_not_responding') {
    var stuckN = phase7Health.stuck_count || 0;
    var lastSecs = phase7Health.last_decision_secs_ago;
    var lastDecisionPart = (lastSecs == null)
      ? 'No decisions recorded today'
      : 'Last decision ' + Math.floor(lastSecs / 60) + ' min ago';
    reasons.unshift(
      stuckN + ' incident' + (stuckN === 1 ? '' : 's') +
      ' pending >1h with no decision. ' + lastDecisionPart + ' — ' +
      'AI provider/Local Warden is likely down.'
    );
  }

  if (reasons.length > 0) {
    return {
      state: 'health_alert',
      maxSeverity: 'critical',
      heroClass: 'status-hero alert-critical',
      // 2026-04-30: heroIcon now lucide SVG; renderer injects via innerHTML.
      heroIcon: lucideIcon('alert-triangle', { size: 28 }),
      heroTitle: 'System Health Alert',
      heroSub: reasons[0],
      healthAlertReasons: reasons
    };
  }

  // Phase 7 (audit RC-2): the backend ships an explicit SystemHealth
  // verb on `overview.snapshot.health`. When it says AiNotResponding
  // (stuck > 0), the health_alert branch above already surfaced it
  // via `reasons`. Here we handle the medium-severity "backed_up"
  // verb that doesn't qualify as health_alert but isn't steady
  // protection_active either.
  var healthVerb = overview && overview.snapshot && overview.snapshot.health;
  if (healthVerb && healthVerb.kind === 'backed_up') {
    return {
      state: 'backed_up',
      maxSeverity: 'medium',
      heroClass: 'status-hero alert-medium',
      heroIcon: lucideIcon('circle-dashed', { size: 28 }),
      heroTitle: 'Heavy attack volume',
      heroSub: 'System is catching up — give it a few minutes. ' +
        (healthVerb.pending_in_flight || 0) + ' threats being analyzed now.',
      healthAlertReasons: []
    };
  }

  // 2026-05-01 audit fix (1.2): the backend now emits a `degraded`
  // verb when chronic drift exists (historical orphaned responses,
  // accumulated revert failures, playbook engine without an
  // executor). None of those is an immediate emergency, but
  // showing a green PROTECTED banner over them is the silent-
  // failure mode the audit caught. Yellow signal with the backend's
  // reason list as both headline and drill-down.
  if (healthVerb && healthVerb.kind === 'degraded') {
    var degReasons = Array.isArray(healthVerb.reasons) ? healthVerb.reasons : [];
    var degHead = degReasons[0] || 'System has chronic maintenance debt';
    return {
      state: 'degraded',
      maxSeverity: 'medium',
      heroClass: 'status-hero alert-medium',
      heroIcon: lucideIcon('alert-circle', { size: 28 }),
      heroTitle: 'Operational with maintenance debt',
      heroSub: degHead,
      // Backward-compat: home.js already renders this list when present.
      // Reuse it instead of inventing a new field.
      healthAlertReasons: degReasons
    };
  }

  // Phase 9: "Abandoned backlog" — plain-English copy. Operator
  // sees "Cleaning up" verb instead of jargon. Yellow signal stays
  // because something IS happening (sweep) but it's not a real
  // problem — AI is processing normally.
  if (healthVerb && healthVerb.kind === 'abandoned_backlog') {
    var abN = healthVerb.stuck_count || 0;
    return {
      state: 'abandoned_backlog',
      maxSeverity: 'medium',
      heroClass: 'status-hero alert-medium',
      heroIcon: lucideIcon('broom', { size: 28 }),
      heroTitle: 'Cleaning up old backlog',
      heroSub: abN + ' threat' + (abN === 1 ? '' : 's') +
        ' from earlier without a decision. Auto-cleanup runs every 10 minutes. ' +
        'Current protection is unaffected.',
      healthAlertReasons: []
    };
  }

  // Priority 2: state 2 — only triggers when the AI genuinely cannot
  // handle something and needs the operator. With Guard ON, routine
  // scanners and unresolved incidents are NOT "active threats" — the
  // AI is processing them autonomously. State 2 only fires for future
  // AI-escalated items (needs_attention field, not yet implemented).
  //
  // With Guard OFF (watch/read_only), ALL unresolved incidents become
  // the operator's responsibility.
  var isGuard = (status.mode || 'guard') === 'guard';

  if (!isGuard && activeList.length > 0) {
    // Guard OFF: operator must decide. Show alarm.
    var n = activeList.length;
    return {
      state: 'ai_responding',
      maxSeverity: maxSeverity(activeList),
      heroClass: 'status-hero alert-high',
      heroIcon: lucideIcon('eye', { size: 28 }),
      heroTitle: 'Detection Mode',
      heroSub: n + ' threat' + (n === 1 ? '' : 's') + ' detected. AI is watching only \u2014 enable Guard mode for automatic protection.',
      healthAlertReasons: []
    };
  }

  // Guard ON or no active threats: AI Protection Active.
  // The operator sees confidence, not alarm.
  //
  // Single source: overview.safely_resolved = every decision today that was
  // NOT "ignore" (block, monitor, honeypot, kill, suspend). The Home KPI
  // tile and the briefing now quote the same field, so the operator no
  // longer sees "9 blocked" in the hero while the KPI says 50 and the
  // briefing says 48 for the same time window.
  // Use the unique-IP-handled count so the number matches the entry
  // count on the Threats tab (which dedupes by attacker IP). Fallback
  // to safely_resolved (incident-count) for back-compat with older
  // backends that don't yet emit handled_ips_today.
  // Phase 9: plain-English copy answering "are you safe right now?"
  // No jargon. Hero verb adapts to the operator's day.
  var handled = (overview.handled_ips_today != null ? overview.handled_ips_today : (overview.safely_resolved || 0));
  var heroTitle;
  var subText;
  if (handled === 0) {
    heroTitle = 'All clear';
    subText = 'Nothing suspicious today.';
  } else {
    heroTitle = 'You are protected';
    var unit = handled === 1 ? 'break-in attempt' : 'break-in attempts';
    subText = handled + ' ' + unit + ' today, all stopped.';
  }

  return {
    state: 'protection_active',
    maxSeverity: 'info',
    heroClass: 'status-hero alert-info',
    heroIcon: lucideIcon('shield-check', { size: 28 }),
    heroTitle: heroTitle,
    heroSub: subText,
    healthAlertReasons: []
  };
}

// ── Hero ─────────────────────────────────────────────────────────────
// 2026-04-30 redesign: renamed from updateHomeBanner. The hero now
// states ONE thing — the verb that answers "am I safe?" in plain
// English. MODE/heartbeat metadata moved to the collapsed details
// panel (renderDetailsPanel) so the 95% 5-second-visit persona never
// sees it on the first read.
function updateHomeHero(homeState) {
  var hero  = document.getElementById('homeHero');
  var icon  = document.getElementById('homeHeroIcon');
  var title = document.getElementById('homeHeroTitle');
  var sub   = document.getElementById('homeHeroSub');
  if (!hero || !icon || !title || !sub) return;
  hero.className  = homeState.heroClass;
  icon.innerHTML    = homeState.heroIcon;
  title.textContent = homeState.heroTitle;
  sub.textContent   = homeState.heroSub;
}


function computeElapsedHoursUtc() {
  var now = new Date();
  var midnightUtc = new Date(Date.UTC(
    now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0
  ));
  var ms = now.getTime() - midnightUtc.getTime();
  return Math.max(0, Math.floor(ms / (3600 * 1000)));
}

function formatBigNumber(total) {
  if (total >= 1000000) return (total / 1000000).toFixed(1) + 'M';
  if (total >= 1000) return (total / 1000).toFixed(0) + 'K';
  return total.toLocaleString();
}

// 2026-04-30 redesign: pending grid now renders DYNAMICALLY — only
// cells with count > 0 are emitted. The previous version always
// rendered all four cells even when every count was zero ("0 / 0 /
// 0 / 0"), which the operator legitimately read as engineer-debug
// noise. Steady state is now: panel hidden entirely.

function setText(id, value) {
  var el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setKpiWindow(id, text) {
  var el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ── AI Intelligence Briefing ────────────────────────────────────────
// 2026-04-30 redesign: per operator request the briefing card is
// ALWAYS visible — it's the single piece of narrative context worth
// reading on every visit. The previous version hid the section on
// fetch errors which dropped the most-trusted card from the page
// silently. Now every state has a visible message:
//   data.available=true  → render summary + "Regenerate" button
//   data.available=false → "No briefing yet" empty state + "Generate"
//   fetch error          → "Briefing unavailable" with manual retry
async function loadBriefing() {
  var section = document.getElementById('briefingSection');
  if (!section) return;
  section.style.display = '';
  var content = document.getElementById('briefingContent');
  var btn = document.getElementById('briefingBtn');
  try {
    var data = await loadJson('/api/briefing');
    if (data.available) {
      var age = data.generated_at ? new Date(data.generated_at).toLocaleTimeString() : '';
      if (content) {
        content.innerHTML = '<div style="margin-bottom:8px;font-size:0.65rem;color:var(--muted)">Generated ' + age + '</div>' +
          '<div>' + esc(data.summary).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') + '</div>';
      }
      if (btn) btn.textContent = 'Regenerate';
    } else if (content) {
      content.innerHTML = '<div class="briefing-empty">' +
        esc("No briefing yet. You're protected, and we are still monitoring. Generate a briefing now for a quick summary.") +
        '</div>';
    }
  } catch(e) {
    if (content) {
      content.innerHTML = '<div class="briefing-empty" style="color:var(--warn)">' +
        esc("Briefing temporarily unavailable. Click Regenerate to retry.") +
        '</div>';
    }
  }
}


async function generateBriefing() {
  var btn = document.getElementById('briefingBtn');
  var content = document.getElementById('briefingContent');
  if (btn) { btn.textContent = 'Generating...'; btn.disabled = true; }
  if (content) content.innerHTML = '<div style="color:var(--accent)">Analyzing knowledge graph and generating briefing via AI...</div>';
  try {
    var r = await fetch('/api/briefing/generate', {
      method: 'POST',
      // CSRF middleware (audit I-14, mod.rs::csrf_protection) rejects every
      // POST/PUT/PATCH/DELETE without this header with HTTP 403. Operator
      // 2026-05-09 prod report: "tentei gerar briefing... Error: HTTP 403".
      headers: { 'x-requested-with': 'XMLHttpRequest' },
      credentials: 'include',
      cache: 'no-store',
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    var data = await r.json();
    if (data.error) {
      content.innerHTML = '<div style="color:var(--danger)">' + esc(data.error) + '</div>';
    } else {
      content.innerHTML = '<div style="margin-bottom:8px;font-size:0.65rem;color:var(--muted)">Generated just now</div>' +
        '<div>' + esc(data.summary).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') + '</div>';
    }
  } catch(e) {
    content.innerHTML = '<div style="color:var(--danger)">Error: ' + esc(e.message) + '</div>';
  }
  if (btn) { btn.textContent = 'Regenerate'; btn.disabled = false; }
}


// ── Handoff links ────────────────────────────────────────────────────
// Both links are observational. No imperative copy. The consume-once
// semantics of autoSelectOnThreatsOpen are honored by 02-threats.md.
function viewActivity() {
  state.autoSelectOnThreatsOpen = 'first_critical_or_high';
  showView('investigate');
}

// Spec 049 PR14 — scoped handoff from Home strip cards + sub-breakdown
// chips into the Cases tab with the matching outcome filter
// pre-applied. Resolves the operator's "cade os 170" reconciliation
// gap: clicking the big number on Home now opens Cases scoped to the
// exact set that number counts.
//
// Buckets accepted (snake-case wire keys, kept stable for anchor tests):
//   - 'all_flagged'        — every outcome (1:1 reconciliation with Home's "Flagged by system")
//   - 'warden_decisions'   — Contained + Observing + Filtered out (excludes Needs review)
//   - 'needs_review'       — only the Needs your attention group
//   - 'contained'          — blocked + honeypot
//   - 'observing'          — monitoring
//   - 'filtered_out'       — dismissed (legacy backend wire name; UI label says Filtered out)
//
// Sets `state.filterOutcome` rather than `state.filters.status` because
// the dropdown filter UI binds to `status` directly — overriding it
// would surprise the operator with a sticky dropdown selection after
// the click. `filterOutcome` is a per-handoff scope; threats.js
// applies it once then UI controls take over normally.
function viewActivityScoped(bucket) {
  state.autoSelectOnThreatsOpen = null;
  state.filterOutcome = bucket || 'all_flagged';
  showView('investigate');
}
