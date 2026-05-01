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

    updateHomeHero(homeState);
    // Total events scanned from sensors (trust signal: "3.3M scanned → 2 blocked")
    var totalEventsScanned = 0;
    (sensors.sources || []).forEach(function(s) { totalEventsScanned += s.count || 0; });
    window._totalEventsScanned = totalEventsScanned;

    // 2026-04-30 redesign: render the new attention-first home.
    // Order matches reading priority: critical alert (if any) →
    // review queue (if any) → activity strip → briefing → health
    // line → details (collapsed).
    var topCritical = findTopOpenCritical(items);
    window._lastTopCritical = topCritical;
    renderCriticalBanner(topCritical);
    renderReviewBanner(overview);
    renderActivityStrip(overview, totalEventsScanned);
    renderHealthLine(status, sensors, overview, softStale);
    renderDetailsPanel(overview, status, sensors);

    // Phase 12 (QA fix #1): keep the persistent header pill in sync
    // with runtime SystemHealth. Without this, the green "PROTECTED"
    // pill stayed up while the hero said "System Health Alert" — a
    // contradictory state on one screen.
    syncModeBadgeFromHealth(overview, actionCfg);
    loadBriefing();
  } catch(e) { console.warn('loadHome error:', e); }
}

// ── Critical incident banner ────────────────────────────────────────
// Returns the top open critical/high incident the operator should act on,
// or null when none. Open = no decision yet (the AI did not autodismiss
// or autodecide). Filters out incidents already trusted/allowlisted.
function findTopOpenCritical(items) {
  var sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  var open = (items || []).filter(function(i) {
    var sev = (i.effective_severity || i.severity || '').toLowerCase();
    if (i.outcome !== 'open') return false;
    if (sevRank[sev] < 3) return false;
    if (typeof isIncidentTrusted === 'function' && isIncidentTrusted(i)) return false;
    return true;
  });
  open.sort(function(a, b) {
    var ra = sevRank[(a.effective_severity || a.severity || '').toLowerCase()] || 0;
    var rb = sevRank[(b.effective_severity || b.severity || '').toLowerCase()] || 0;
    if (rb !== ra) return rb - ra;
    return (b.ts || '') > (a.ts || '') ? 1 : -1;
  });
  return open[0] || null;
}

function renderCriticalBanner(top) {
  var banner = document.getElementById('homeCriticalBanner');
  if (!banner) return;
  if (!top) {
    banner.style.display = 'none';
    return;
  }
  banner.style.display = '';
  var titleEl = document.getElementById('homeCriticalTitle');
  var subEl = document.getElementById('homeCriticalSub');
  var sev = ((top.effective_severity || top.severity || '').toUpperCase()) || 'CRITICAL';
  // Title: severity + short description. The operator should be able
  // to tell what kind of attack this is without clicking through.
  var detector = (top.incident_id || '').split(':')[0] || '';
  var label = (typeof humanLabel === 'function' && detector)
    ? humanLabel(detector) : (detector || 'Active threat');
  if (titleEl) {
    titleEl.textContent = sev + ': ' + label;
  }
  if (subEl) {
    var ipEntity = (top.entities || []).find(function(e) {
      return e && (e.type === 'Ip' || e.type === 'ip');
    });
    var ip = ipEntity ? ipEntity.value : '';
    var ageSec = top.ts ? Math.max(0, Math.floor((Date.now() - new Date(top.ts).getTime()) / 1000)) : null;
    var ageText = fmtAgo(ageSec);
    var parts = [];
    if (ip) parts.push(ip);
    if (ageText) parts.push(ageText);
    if (top.title) parts.push(top.title);
    subEl.textContent = parts.join(' · ');
  }
}

// CTA on the critical banner: deep-link to Threats with the
// banner's subject preselected so the operator lands directly on
// the matching journey.
//
// 2026-05-01 (audit finding 1.4): the previous version pivoted
// only by IP. Some detectors emit incidents whose only entity is a
// User (`graph_discovery_burst` is the canonical example — title
// "Discovery burst: user uid:X" with `entities: [User]`, no IP).
// When the operator clicked Review on a user-only incident, the
// IP lookup returned undefined, `loadJourney` was skipped, and the
// investigate panel kept showing whatever journey was last
// rendered (typically a kill_chain IP from earlier in the
// session). The operator concluded the link was broken.
//
// Fix: extract the most-specific entity available in priority
// order (Ip > Container > User > Process), pivot accordingly. If
// none is available, fall back to clearing the journey so the
// operator sees the empty state instead of a stale subject.
function openTopCritical(event) {
  if (event && event.preventDefault) event.preventDefault();
  var top = window._lastTopCritical;
  showView('investigate');
  if (!top) return false;
  if (typeof loadJourney !== 'function') return false;
  var entities = top.entities || [];
  var matchType = function(types) {
    return entities.find(function(e) {
      if (!e || !e.type) return false;
      var t = String(e.type).toLowerCase();
      return types.indexOf(t) !== -1;
    });
  };
  var pivotEntity =
    matchType(['ip']) ||
    matchType(['container']) ||
    matchType(['user']) ||
    matchType(['process']);
  if (pivotEntity) {
    var pivotKind = String(pivotEntity.type).toLowerCase();
    setTimeout(function() { loadJourney(pivotKind, pivotEntity.value); }, 30);
  } else {
    // No actionable subject on this incident — reset the journey
    // panel to the empty state so a previously-loaded journey for
    // an unrelated subject does not appear "as if Review opened
    // the wrong thing" (the original audit symptom).
    setTimeout(function() {
      var content = document.getElementById('journeyContent');
      var homeSt = document.getElementById('homeState');
      if (content) content.style.display = 'none';
      if (homeSt) homeSt.style.display = '';
      document.querySelectorAll('.attacker-card').forEach(function(c) {
        c.classList.remove('active');
      });
    }, 30);
  }
  return false;
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
// 4 numbers in one row: events watched / flagged / stopped / awaiting.
// Replaces both the 7-row "summary pyramid" and the standalone "Now"
// section — same data, single line, scannable in 2 seconds.
function renderActivityStrip(overview, totalEventsScanned) {
  var snap = overview && overview.snapshot;

  // Watched.
  var watched = snap
    ? (snap.events_today || totalEventsScanned || overview.events_count || 0)
    : (totalEventsScanned || overview.events_count || 0);
  setText('homeActWatched', formatBigNumber(watched));

  // Flagged = total unique attackers across all buckets (matches the
  // unified attacker-count contract from Phase 10).
  var flagged = 0;
  if (snap) {
    flagged =
      (snap.buckets.blocked.unique_attackers || 0) +
      (snap.buckets.observing.unique_attackers || 0) +
      (snap.buckets.honeypot.unique_attackers || 0) +
      (snap.buckets.attention.unique_attackers || 0) +
      (snap.buckets.allowlisted.unique_attackers || 0);
  } else {
    flagged = overview.handled_ips_today || 0;
  }
  setText('homeActFlagged', flagged);

  // Stopped automatically = blocked + observing + honeypot.
  var stopped = 0;
  if (snap) {
    stopped =
      (snap.buckets.blocked.unique_attackers || 0) +
      (snap.buckets.observing.unique_attackers || 0) +
      (snap.buckets.honeypot.unique_attackers || 0);
  } else {
    stopped = overview.handled_ips_today || 0;
  }
  setText('homeActStopped', stopped);

  // Awaiting review = attention bucket. Cell gets a warning tint
  // when > 0 so it stands out without being a separate banner copy.
  var awaiting = snap
    ? (snap.buckets.attention.unique_attackers || 0)
    : (overview.attention_count || 0);
  setText('homeActAwaiting', awaiting);
  var awaitingCell = document.querySelector('.activity-cell-attention');
  if (awaitingCell) {
    awaitingCell.classList.toggle('activity-cell-attention-active', awaiting > 0);
  }

  // Window label: "since midnight UTC · last Nh".
  var elapsed = computeElapsedHoursUtc();
  var elapsedText = elapsed >= 1
    ? 'since midnight UTC · last ' + elapsed + 'h'
    : 'since midnight UTC';
  setText('homeActivityWindow', elapsedText);
}

// ── System health line ──────────────────────────────────────────────
// One row, three states. Green check + summary when everything is OK.
// Amber when telemetry is soft-stale. Red when sensor stalled.
function renderHealthLine(status, sensors, overview, softStale) {
  var line = document.getElementById('homeHealthLine');
  var iconEl = document.getElementById('homeHealthIcon');
  var summaryEl = document.getElementById('homeHealthSummary');
  if (!line || !iconEl || !summaryEl) return;
  var sources = (sensors && sensors.sources) || [];
  var active = sources.filter(function(s) { return s.count > 0; }).length;
  var total = sources.length;
  var telemetrySecs = (typeof status.last_telemetry_secs === 'number')
    ? status.last_telemetry_secs : null;
  var snap = overview && overview.snapshot;
  var unhealthy = (snap && snap.health && snap.health.kind === 'ai_not_responding') ||
    (telemetrySecs != null && telemetrySecs > HOME_TELEMETRY_STALL_SECS);
  // Class + icon by state.
  line.classList.remove('home-health-warn', 'home-health-bad');
  var iconName = 'check';
  if (unhealthy) {
    line.classList.add('home-health-bad');
    iconName = 'alert-triangle';
  } else if (softStale || (total > 0 && active < total)) {
    line.classList.add('home-health-warn');
    iconName = 'alert-circle';
  }
  iconEl.innerHTML = lucideIcon(iconName, { size: 14 });
  // Summary copy.
  var parts = [];
  if (unhealthy) {
    if (snap && snap.health && snap.health.kind === 'ai_not_responding') {
      parts.push('AI not responding');
    } else if (telemetrySecs != null && telemetrySecs > HOME_TELEMETRY_STALL_SECS) {
      parts.push('Sensor stalled (' + Math.floor(telemetrySecs / 60) + 'm since last data)');
    } else {
      parts.push('System health alert');
    }
  } else {
    parts.push('All systems operational');
  }
  if (total > 0) {
    parts.push(active + ' of ' + total + ' data sources active');
  }
  if (telemetrySecs != null && !unhealthy) {
    parts.push('last data ' + fmtAgo(telemetrySecs));
  }
  summaryEl.textContent = parts.join(' · ');
}

// ── Details panel (collapsed by default) ────────────────────────────
function renderDetailsPanel(overview, status, sensors) {
  // Pending breakdown — only renders cells with count > 0 so the
  // operator never sees "0 / 0 / 0 / 0" engineer-debug noise.
  var snap = overview && overview.snapshot;
  updatePendingPanel(snap);
  // Sensor list.
  updateCollectorStrip(sensors);
  // Mode + heartbeat metadata.
  var modeEl = document.getElementById('homeMetaMode');
  if (modeEl) modeEl.textContent = (status.mode || 'read_only').replace('_', '-').toUpperCase();
  var hbEl = document.getElementById('homeMetaHeartbeat');
  var hbItem = document.getElementById('homeMetaHeartbeatItem');
  var telemetrySecs = (typeof status.last_telemetry_secs === 'number')
    ? status.last_telemetry_secs : null;
  if (hbEl) {
    if (telemetrySecs == null) {
      hbEl.textContent = 'unknown';
      if (hbItem) hbItem.classList.add('home-stale-strong');
    } else {
      hbEl.textContent = telemetrySecs < 60
        ? telemetrySecs + 's ago'
        : Math.floor(telemetrySecs / 60) + 'm ago';
      if (hbItem) {
        hbItem.classList.toggle('home-stale-strong', telemetrySecs > HOME_TELEMETRY_STALL_SECS);
        hbItem.classList.toggle('home-stale-soft',
          telemetrySecs > HOME_TELEMETRY_STALE_SOFT_SECS &&
          telemetrySecs <= HOME_TELEMETRY_STALL_SECS);
      }
    }
  }
}

function toggleHomeDetails() {
  var panel = document.getElementById('homeDetailsPanel');
  var btn = document.getElementById('homeDetailsToggle');
  if (!panel || !btn) return;
  var isHidden = panel.hasAttribute('hidden');
  if (isHidden) {
    panel.removeAttribute('hidden');
    btn.textContent = 'Hide details';
    btn.setAttribute('aria-expanded', 'true');
  } else {
    panel.setAttribute('hidden', '');
    btn.textContent = 'Show details';
    btn.setAttribute('aria-expanded', 'false');
  }
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
function updatePendingPanel(snap) {
  var panel = document.getElementById('homePendingPanel');
  var grid = document.getElementById('homePendingGrid');
  if (!panel || !grid) return;
  var pending = snap && snap.pending;
  if (!pending) {
    panel.style.display = 'none';
    grid.innerHTML = '';
    return;
  }
  var cells = [
    {
      id: 'in_flight',
      n: pending.in_flight || 0,
      label: 'Being analyzed now',
      hint: 'Less than 5 minutes old',
      warn: false,
    },
    {
      id: 'declined_by_ai',
      n: pending.declined_by_ai || 0,
      label: 'AI escalated to you',
      hint: 'Needs your judgement',
      warn: false,
    },
    {
      id: 'cooldown_suppressed',
      n: pending.cooldown_suppressed || 0,
      label: 'Same threat already decided',
      hint: 'Silenced for 1 hour',
      warn: false,
    },
    {
      id: 'stuck',
      n: pending.stuck || 0,
      label: 'No decision after 1 hour',
      hint: 'System will auto-clean',
      warn: true,
    },
  ];
  var visible = cells.filter(function(c) { return c.n > 0; });
  if (visible.length === 0) {
    panel.style.display = 'none';
    grid.innerHTML = '';
    return;
  }
  panel.style.display = '';
  grid.innerHTML = visible.map(function(c) {
    var cls = 'pending-cell' + (c.warn ? ' pending-cell-warn' : '');
    return '<div class="' + cls + '">' +
      '<div class="pending-num"' + (c.warn ? ' style="color:var(--danger)"' : '') + '>' + c.n + '</div>' +
      '<div class="pending-label">' + c.label + '</div>' +
      '<div class="pending-hint">' + c.hint + '</div>' +
      '</div>';
  }).join('');

  var hint = '';
  var hintHealth = snap && snap.health;
  if (hintHealth && hintHealth.kind === 'ai_not_responding') {
    var hintLast = hintHealth.last_decision_secs_ago;
    var hintLastPart = (hintLast == null)
      ? 'no decisions yet today'
      : 'last decision ' + Math.floor(hintLast / 60) + ' minutes ago';
    hint = 'AI stopped responding (' + hintLastPart + '). Check the agent logs.';
  } else if (hintHealth && hintHealth.kind === 'abandoned_backlog') {
    hint = pending.stuck + ' threat' + (pending.stuck === 1 ? '' : 's') +
      ' without a decision yet. The system will auto-clean within 10 minutes.';
  } else if (pending.declined_by_ai > 0) {
    hint = pending.declined_by_ai + ' threat' +
      (pending.declined_by_ai === 1 ? '' : 's') +
      ' need your judgement.';
  } else if (pending.in_flight > 50) {
    hint = 'Heavy attack volume. AI is catching up — give it a few minutes.';
  }
  var hintEl = document.getElementById('homePendingHint');
  if (hintEl) hintEl.textContent = hint;
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

  // 2026-04-30 redesign: this lives inside the home details panel
  // which is itself collapsible. The previous inline "Show details"
  // toggle inside the strip is now redundant — the entire strip
  // is already opt-in.
  var html = '<div class="' + summaryClass + '">' +
    active.length + ' of ' + total + ' data sources active' +
    '</div>';
  html += '<div class="collector-details">';
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
