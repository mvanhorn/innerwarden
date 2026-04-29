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

    // Soft stale: telemetry a few minutes behind but not yet state 3.
    var telemetrySecs = (typeof status.last_telemetry_secs === 'number')
      ? status.last_telemetry_secs : null;
    var softStale = (telemetrySecs != null
      && telemetrySecs > HOME_TELEMETRY_STALE_SOFT_SECS
      && telemetrySecs <= HOME_TELEMETRY_STALL_SECS);

    updateHomeBanner(status, homeState);
    // Total events scanned from sensors (trust signal: "3.3M scanned → 2 blocked")
    var totalEventsScanned = 0;
    (sensors.sources || []).forEach(function(s) { totalEventsScanned += s.count || 0; });
    window._totalEventsScanned = totalEventsScanned;

    updateHomeNow(overview, activeHighCriticalList.length, softStale, totalEventsScanned);
    updateHomeKpis(overview, totalEventsScanned);
    updateCollectorStrip(sensors);
    loadBriefing();
  } catch(e) { console.warn('loadHome error:', e); }
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
      'AI provider/classifier is likely down.'
    );
  }

  if (reasons.length > 0) {
    return {
      state: 'health_alert',
      maxSeverity: 'critical',
      heroClass: 'status-hero alert-critical',
      heroIcon: '\u26A0',
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
      heroIcon: '⏳',
      heroTitle: 'AI catching up',
      heroSub: (healthVerb.pending_in_flight || 0) +
        ' incidents in flight. Decisions arriving with delay.',
      healthAlertReasons: []
    };
  }

  // Phase 7B: "Abandoned backlog" — AI is fine right now, but earlier
  // incidents got abandoned (no decision within 1h, but recent
  // decisions are flowing). Soft yellow signal: orphan-recovery
  // slow_loop pass will sweep them automatically; operator gets a
  // heads-up rather than a false "AI is wedged" alarm.
  if (healthVerb && healthVerb.kind === 'abandoned_backlog') {
    var abN = healthVerb.stuck_count || 0;
    var abLastSecs = healthVerb.last_decision_secs_ago || 0;
    var lastMin = Math.max(1, Math.floor(abLastSecs / 60));
    return {
      state: 'abandoned_backlog',
      maxSeverity: 'medium',
      heroClass: 'status-hero alert-medium',
      heroIcon: '🧹',
      heroTitle: 'AI Protection Active',
      heroSub: abN + ' earlier incident' + (abN === 1 ? '' : 's') +
        ' abandoned without decision. Recovery pass will sweep them shortly. ' +
        'AI is currently processing — last decision ' + lastMin + ' min ago.',
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
      heroIcon: '\uD83D\uDC41',
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
  var handled = (overview.handled_ips_today != null ? overview.handled_ips_today : (overview.safely_resolved || 0));
  var unit = handled === 1 ? 'attacker' : 'attackers';
  var subText = handled > 0
    ? handled + ' ' + unit + ' handled today. AI is on shift.'
    : 'All systems monitoring. Nothing requires your attention.';

  return {
    state: 'protection_active',
    maxSeverity: 'info',
    heroClass: 'status-hero alert-info',
    heroIcon: '\uD83D\uDEE1',
    heroTitle: 'AI Protection Active',
    heroSub: subText,
    healthAlertReasons: []
  };
}

// ── Hero ─────────────────────────────────────────────────────────────
function updateHomeBanner(status, homeState) {
  var hero  = document.getElementById('homeHero');
  var icon  = document.getElementById('homeHeroIcon');
  var title = document.getElementById('homeHeroTitle');
  var sub   = document.getElementById('homeHeroSub');
  var meta  = document.getElementById('homeStatusMeta');
  if (!hero || !icon || !title || !sub) return;

  hero.className  = homeState.heroClass;
  icon.textContent  = homeState.heroIcon;
  title.textContent = homeState.heroTitle;
  sub.textContent   = homeState.heroSub;

  if (meta) {
    var mode = (status.mode || 'read_only').replace('_', '-').toUpperCase();
    var telemetrySecs = status.last_telemetry_secs;
    var telemetryHtml;
    if (typeof telemetrySecs !== 'number') {
      telemetryHtml = '<span class="home-meta-item">\u2764 n/a</span>';
    } else if (telemetrySecs > HOME_TELEMETRY_STALL_SECS) {
      var m = Math.floor(telemetrySecs / 60);
      telemetryHtml = '<span class="home-meta-item home-stale-strong">Data stalled \u00B7 ' + m + 'm since last telemetry</span>';
    } else if (telemetrySecs > HOME_TELEMETRY_STALE_SOFT_SECS) {
      telemetryHtml = '<span class="home-meta-item home-stale-soft">Data may be delayed \u00B7 ' + telemetrySecs + 's since last telemetry</span>';
    } else {
      telemetryHtml = '<span class="home-meta-item">\u2764 ' + telemetrySecs + 's ago</span>';
    }

    var links = '<a href="javascript:void(0)" class="home-link" onclick="viewActivity()">View activity \u2192</a>';
    if (homeState.state === 'health_alert') {
      links += ' <a href="javascript:void(0)" class="home-link" onclick="viewSystemHealth()">View system health \u2192</a>';
    }

    meta.innerHTML =
      '<span class="home-meta-item">MODE: ' + mode + '</span>' +
      telemetryHtml +
      '<span class="home-meta-links">' + links + '</span>';
  }
}

// ── Now section (2 lines, always observational) ─────────────────────
function updateHomeNow(overview, activeCount, softStale, totalEventsScanned) {
  var whatEl = document.getElementById('homeNowWhat');
  var didEl  = document.getElementById('homeNowDid');
  if (!whatEl || !didEl) return;

  // Use unique-IP-handled count so it matches the Threats tab entry
  // count (which dedupes by attacker IP). Falls back to safely_resolved
  // if backend hasn't been upgraded yet.
  var handled = (overview.handled_ips_today != null ? overview.handled_ips_today : (overview.safely_resolved || 0));
  var total = totalEventsScanned || overview.events_count || 0;

  // Line 1 — Trust signal: volume scanned
  var line1;
  if (total === 0) {
    line1 = 'No events detected in the last 24 hours.';
  } else {
    line1 = total.toLocaleString() + ' events monitored today.';
  }
  if (softStale) {
    line1 = 'Telemetry is a few minutes behind. ' + line1;
  }
  whatEl.textContent = line1;

  // Line 2 — Outcome summary
  var line2;
  if (handled === 0) {
    line2 = 'Nothing suspicious found. All systems operating normally.';
  } else {
    var word = handled === 1 ? 'attacker' : 'attackers';
    line2 = 'Handled ' + handled + ' ' + word + ' today. AI is on shift.';
  }
  didEl.textContent = line2;
}

// ── KPIs with fixed temporal sub-labels ──────────────────────────────
//
// Phase 7 (audit RC-2): when `overview.snapshot` is populated (the
// SQLite-backed path is wired), the tiles render the *attacker* count
// as the hero number and the *incident* count as the secondary line.
// The two together tell the operator both "how many distinct threats"
// and "how active the system was" without forcing mental math —
// previously the same tile said "21 Blocked" while the list said
// "Blocked 10", and the unit ambiguity made the dashboard read like
// a bug.
//
// When `snapshot` is missing (legacy KG fallback path or sleep mode)
// we render the old single-number layout from the flat fields, so
// existing tests and pre-Phase-7 deployments don't crash.
function updateHomeKpis(overview, totalEventsScanned) {
  var snap = overview && overview.snapshot;
  var threatsEl = document.getElementById('homeKpiThreats');
  var respondedEl = document.getElementById('homeKpiResponded');
  var eventsEl = document.getElementById('homeKpiEvents');
  var threatsPair = document.getElementById('homeKpiThreatsPair');
  var respondedPair = document.getElementById('homeKpiRespondedPair');
  var eventsPair = document.getElementById('homeKpiEventsPair');

  if (snap) {
    // Handled = blocked + observing + honeypot (operator-action buckets).
    // Render attackers (unique IPs) as the hero number; incidents as
    // the supporting line.
    var handledAttackers =
      (snap.buckets.blocked.unique_attackers || 0) +
      (snap.buckets.observing.unique_attackers || 0) +
      (snap.buckets.honeypot.unique_attackers || 0);
    var handledIncidents =
      (snap.buckets.blocked.incidents || 0) +
      (snap.buckets.observing.incidents || 0) +
      (snap.buckets.honeypot.incidents || 0);
    if (threatsEl) threatsEl.textContent = handledAttackers;
    if (threatsPair) threatsPair.textContent = handledIncidents + (handledIncidents === 1 ? ' action' : ' actions');

    // Detections = total qualifying incidents today (sum across all
    // operator-relevant buckets except dismissed). Hero number is the
    // unique-attacker count to match the Threats list group counts.
    var detectionAttackers =
      handledAttackers +
      (snap.buckets.attention.unique_attackers || 0) +
      (snap.buckets.allowlisted.unique_attackers || 0);
    var detectionIncidents =
      handledIncidents +
      (snap.buckets.attention.incidents || 0) +
      (snap.buckets.allowlisted.incidents || 0);
    if (respondedEl) respondedEl.textContent = detectionAttackers;
    if (respondedPair) respondedPair.textContent =
      detectionIncidents + (detectionIncidents === 1 ? ' incident' : ' incidents');

    // Events Scanned: comes from telemetry (sensor counter), date-
    // filtered. No secondary unit — it's already operator-clear.
    var evTotal = snap.events_today || totalEventsScanned || overview.events_count || 0;
    if (eventsEl) eventsEl.textContent = formatBigNumber(evTotal);
    if (eventsPair) eventsPair.textContent = '';
  } else {
    // Legacy path: single-number tiles, no secondary line.
    if (threatsEl) threatsEl.textContent = overview.safely_resolved || 0;
    if (respondedEl) respondedEl.textContent = overview.incidents_count || 0;
    var fallbackTotal = totalEventsScanned || overview.events_count || 0;
    if (eventsEl) eventsEl.textContent = formatBigNumber(fallbackTotal);
    if (threatsPair) threatsPair.textContent = '';
    if (respondedPair) respondedPair.textContent = '';
    if (eventsPair) eventsPair.textContent = '';
  }

  // Fixed sub-labels: Today / Today / Live (today)
  setKpiWindow('homeKpiThreatsWindow',   formatWindow('today'));
  setKpiWindow('homeKpiRespondedWindow', formatWindow('today'));
  setKpiWindow('homeKpiEventsWindow',    'Live (today)');

  // Phase 7: pending breakdown panel — visible only when there is
  // pending work to look at. Hidden in the steady state so the Home
  // view stays clean.
  updatePendingPanel(snap);
}

function formatBigNumber(total) {
  if (total >= 1000000) return (total / 1000000).toFixed(1) + 'M';
  if (total >= 1000) return (total / 1000).toFixed(0) + 'K';
  return total.toLocaleString();
}

function updatePendingPanel(snap) {
  var panel = document.getElementById('homePendingPanel');
  if (!panel) return;
  var pending = snap && snap.pending;
  if (!pending) {
    panel.style.display = 'none';
    return;
  }
  var total =
    (pending.in_flight || 0) +
    (pending.declined_by_ai || 0) +
    (pending.cooldown_suppressed || 0) +
    (pending.stuck || 0);
  if (total === 0) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = '';
  setText('homePendingInFlight', pending.in_flight || 0);
  setText('homePendingDeclined', pending.declined_by_ai || 0);
  setText('homePendingCooldown', pending.cooldown_suppressed || 0);
  setText('homePendingStuck', pending.stuck || 0);

  // Phase 7B hint line. Branches on the snapshot's health verb so
  // the copy reflects whether the AI is actually wedged or whether
  // it's just earlier-day backlog (which the orphan-recovery pass
  // will clear). Pre-7B this said "AI pipeline may be wedged" any
  // time stuck>0, which gave false alarms whenever the AI was
  // healthily processing the steady stream.
  var hint = '';
  var hintHealth = snap && snap.health;
  if (hintHealth && hintHealth.kind === 'ai_not_responding') {
    var hintLast = hintHealth.last_decision_secs_ago;
    var hintLastPart = (hintLast == null)
      ? 'no decisions today'
      : 'last decision ' + Math.floor(hintLast / 60) + ' min ago';
    hint = pending.stuck + ' incident' + (pending.stuck === 1 ? '' : 's') +
      ' stuck >1h, ' + hintLastPart + ' — AI provider/classifier likely down.';
  } else if (hintHealth && hintHealth.kind === 'abandoned_backlog') {
    hint = pending.stuck + ' incident' + (pending.stuck === 1 ? '' : 's') +
      ' abandoned earlier (deploy-orphan or AI skip). Orphan recovery pass ' +
      'will auto-dismiss them shortly. AI is processing normally.';
  } else if (pending.declined_by_ai > 0) {
    hint = pending.declined_by_ai + ' incident' +
      (pending.declined_by_ai === 1 ? '' : 's') +
      ' need operator triage (AI declined to decide).';
  } else if (pending.in_flight > 50) {
    hint = pending.in_flight + ' incidents in flight — AI is catching up.';
  }
  var hintEl = document.getElementById('homePendingHint');
  if (hintEl) hintEl.textContent = hint;

  // Stuck cell: hide the warn styling when stuck=0 so the operator
  // doesn't see permanent red noise.
  var stuckCell = document.getElementById('homePendingStuckCell');
  if (stuckCell) {
    if (pending.stuck > 0) stuckCell.classList.add('pending-cell-warn');
    else stuckCell.classList.remove('pending-cell-warn');
  }
}

function setText(id, value) {
  var el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setKpiWindow(id, text) {
  var el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ── AI Intelligence Briefing ────────────────────────────────────────
async function loadBriefing() {
  var section = document.getElementById('briefingSection');
  if (!section) return;
  try {
    var data = await loadJson('/api/briefing');
    section.style.display = '';
    var content = document.getElementById('briefingContent');
    var btn = document.getElementById('briefingBtn');
    // SSE can fire refresh while the Home view is hidden; children may
    // briefly be null during markup rerender. Guard each write so the
    // whole loadHome pipeline does not throw on null.textContent /
    // null.innerHTML.
    if (data.available) {
      var age = data.generated_at ? new Date(data.generated_at).toLocaleTimeString() : '';
      if (content) {
        content.innerHTML = '<div style="margin-bottom:8px;font-size:0.65rem;color:var(--muted)">Generated ' + age + '</div>' +
          '<div>' + esc(data.summary).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') + '</div>';
      }
      if (btn) btn.textContent = 'Regenerate';
    } else if (content) {
      // Spec 017 Change 7 exact approved English copy.
      content.innerHTML = '<div class="briefing-empty">' +
        esc("No briefing yet. You're protected, and we are still monitoring. Generate a briefing now for a quick summary.") +
        '</div>';
    }
  } catch(e) {
    section.style.display = 'none';
  }
}

async function generateBriefing() {
  var btn = document.getElementById('briefingBtn');
  var content = document.getElementById('briefingContent');
  if (btn) { btn.textContent = 'Generating...'; btn.disabled = true; }
  if (content) content.innerHTML = '<div style="color:var(--accent)">Analyzing knowledge graph and generating briefing via AI...</div>';
  try {
    var r = await fetch('/api/briefing/generate', { method: 'POST', cache: 'no-store' });
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

// ── Data Collection (summary + collapsed details) ───────────────────
function updateCollectorStrip(sensors) {
  var stripEl = document.getElementById('homeCollectorStrip');
  if (!stripEl) return;
  var sources = sensors.sources || [];
  var active = sources.filter(function(s) { return s.count > 0; });
  var total = sources.length;
  var ratio = total > 0 ? (active.length / total) : 1;

  var summaryClass = 'collector-summary-line';
  if (ratio < 0.8) summaryClass += ' alert-medium';
  else if (ratio < 1) summaryClass += ' alert-low';
  else summaryClass += ' alert-info';

  var html = '<div class="' + summaryClass + '">' +
    active.length + ' of ' + total + ' data sources active' +
    ' <button type="button" class="collector-details-toggle" onclick="toggleCollectorDetails()">Show details</button>' +
    '</div>';

  html += '<div id="homeCollectorDetails" class="collector-details" style="display:none">';
  active.forEach(function(s) {
    var color = sensorColor(s.name);
    var label = typeof collectorLabel === 'function' ? collectorLabel(s.name) : s.name;
    html += '<div class="collector-row">' +
      '<span class="collector-dot" style="background:' + color + ';box-shadow:0 0 6px ' + color + '"></span>' +
      '<span class="collector-name">' + label + '</span>' +
      '<span class="collector-count" style="color:' + color + '">' + s.count.toLocaleString() + '</span>' +
      '</div>';
  });
  if (sources.length > active.length) {
    var idle = sources.length - active.length;
    html += '<div class="collector-idle-note">' + idle + ' idle</div>';
  }
  html += '</div>';
  stripEl.innerHTML = html;
}

function toggleCollectorDetails() {
  var el = document.getElementById('homeCollectorDetails');
  if (!el) return;
  var btn = document.querySelector('.collector-details-toggle');
  if (el.style.display === 'none') {
    el.style.display = '';
    if (btn) btn.textContent = 'Hide details';
  } else {
    el.style.display = 'none';
    if (btn) btn.textContent = 'Show details';
  }
}

// ── Handoff links ────────────────────────────────────────────────────
// Both links are observational. No imperative copy. The consume-once
// semantics of autoSelectOnThreatsOpen are honored by 02-threats.md.
function viewActivity() {
  state.autoSelectOnThreatsOpen = 'first_critical_or_high';
  showView('investigate');
}

function viewSystemHealth() {
  showView('status');
}
