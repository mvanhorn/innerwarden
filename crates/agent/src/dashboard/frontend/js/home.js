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
    const [status, overview, incidentList, sensors, responsesData] = await Promise.all([
      loadJson('/api/status'),
      loadJson('/api/overview'),
      loadJson('/api/incidents?limit=100'),
      loadJson('/api/sensors'),
      loadJson('/api/responses').catch(function() { return {}; })
    ]);
    window._lastOverview = overview;
    window._agentMode = status.mode || 'guard';
    window._lastIncidentList = incidentList.items || [];

    // Filtered base matches what Recent Activity will render.
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
      allIncidents: items
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
    buildHomeFeed(base);
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
  var blockedSet = new Set();
  (payload.allIncidents || []).forEach(function(inc) {
    if (inc.outcome === 'blocked' || inc.outcome === 'contained') {
      (inc.entities || []).forEach(function(e) {
        var s = typeof e === 'string' ? e : (e.value || '');
        if (s.startsWith('ip:')) blockedSet.add(s.slice(3));
      });
    }
  });
  var blocked = blockedSet.size || (overview.ai_responded || 0);
  var observing = activeList.length;
  var subParts = [];
  if (blocked > 0) subParts.push(blocked + ' blocked');
  if (observing > 0) subParts.push(observing + ' observing');
  var subText = subParts.length > 0
    ? subParts.join(' \u00B7 ') + '. Everything handled automatically.'
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

  var blockedIpsNow = new Set();
  (window._lastIncidentList || []).forEach(function(inc) {
    if (inc.outcome === 'blocked' || inc.outcome === 'contained') {
      (inc.entities || []).forEach(function(e) {
        var s = typeof e === 'string' ? e : (e.value || '');
        if (s.startsWith('ip:')) blockedIpsNow.add(s.slice(3));
      });
    }
  });
  var contained = blockedIpsNow.size > 0 ? blockedIpsNow.size : (overview.ai_responded || 0);
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
  if (contained === 0 && activeCount === 0) {
    line2 = 'Nothing suspicious found. All systems operating normally.';
  } else if (contained > 0 && activeCount === 0) {
    line2 = 'Blocked ' + contained + ' threat' + (contained > 1 ? 's' : '') + ' automatically. Nothing requires your attention.';
  } else {
    line2 = 'Blocked ' + contained + ' automatically. Observing ' + activeCount + ' more. No action needed.';
  }
  didEl.textContent = line2;
}

// ── KPIs with fixed temporal sub-labels ──────────────────────────────
function updateHomeKpis(overview, totalEventsScanned) {
  // Count unique IPs with block decisions (matches Threats tab entity count).
  // API entities are strings "ip:1.2.3.4", not {type,value} objects.
  var blockedIps = new Set();
  (window._lastIncidentList || []).forEach(function(inc) {
    if (inc.outcome === 'blocked' || inc.outcome === 'contained') {
      (inc.entities || []).forEach(function(e) {
        var s = typeof e === 'string' ? e : (e.value || '');
        if (s.startsWith('ip:')) blockedIps.add(s.slice(3));
      });
    }
  });
  var el = document.getElementById('homeKpiThreats');
  if (el) el.textContent = blockedIps.size > 0 ? blockedIps.size : (overview.ai_responded || 0);

  el = document.getElementById('homeKpiResponded');
  if (el) el.textContent = overview.incidents_count || 0;

  el = document.getElementById('homeKpiEvents');
  var total = totalEventsScanned || overview.events_count || 0;
  if (el) el.textContent = total >= 1000000
    ? (total / 1000000).toFixed(1) + 'M'
    : total >= 1000
      ? (total / 1000).toFixed(0) + 'K'
      : total.toLocaleString();

  // Fixed sub-labels: Today / Today / Live (today)
  setKpiWindow('homeKpiThreatsWindow',   formatWindow('today'));
  setKpiWindow('homeKpiRespondedWindow', formatWindow('today'));
  setKpiWindow('homeKpiEventsWindow',    'Live (today)');
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
    if (data.available) {
      var age = data.generated_at ? new Date(data.generated_at).toLocaleTimeString() : '';
      content.innerHTML = '<div style="margin-bottom:8px;font-size:0.65rem;color:var(--muted)">Generated ' + age + '</div>' +
        '<div>' + esc(data.summary).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') + '</div>';
      btn.textContent = 'Regenerate';
    } else {
      // Spec 017 Change 7 — exact approved English copy.
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

// ── Recent Activity (severity × outcome hierarchy, never red) ──────
function buildHomeFeed(incidents) {
  var feedEl = document.getElementById('homeFeed');
  if (!feedEl) return;

  incidents = (incidents || []).slice();

  if (incidents.length === 0) {
    feedEl.innerHTML =
      '<div class="home-feed-empty">' +
      '<div class="home-feed-empty-icon">\u2705</div>' +
      '<div class="home-feed-empty-title">No events in view.</div>' +
      '<div class="home-feed-empty-sub">AI is monitoring.</div>' +
      '</div>';
    return;
  }

  // Sort: open first, then severity desc, then ts desc.
  incidents.sort(function(a, b) {
    var ao = (a.outcome || 'open') === 'open' ? 0 : 1;
    var bo = (b.outcome || 'open') === 'open' ? 0 : 1;
    if (ao !== bo) return ao - bo;
    var as = severityRank(a.effective_severity || a.severity);
    var bs = severityRank(b.effective_severity || b.severity);
    if (as !== bs) return bs - as;
    return (new Date(b.ts).getTime() || 0) - (new Date(a.ts).getTime() || 0);
  });

  var html = '<div class="activity-feed">';
  incidents.slice(0, 15).forEach(function(inc) {
    var slug = (inc.incident_id || '').split(':')[0] || '';
    var label = humanLabel(slug);
    var ago = timeAgo(inc.ts);
    var outcome = inc.outcome || 'open';
    var sev = (inc.effective_severity || inc.severity || '').toLowerCase();
    var entities = inc.entities || [];
    var ipEntity = entities.find(function(e) {
      return (e.type || '').toLowerCase() === 'ip' || (typeof e === 'string' && e.startsWith('ip:'));
    });
    var ipVal = ipEntity ? (ipEntity.value || (typeof ipEntity === 'string' ? ipEntity.slice(3) : '')) : '';

    // Row class: severity × outcome. Open + critical/high uses
    // .alert-high / .alert-medium (orange/amber) — never .alert-critical.
    var rowClass = 'feed-row';
    if (outcome === 'blocked' || outcome === 'killed' || outcome === 'contained' || outcome === 'suspended') {
      rowClass += ' feed-handled';
    } else if (outcome === 'ignored') {
      rowClass += ' feed-noise';
    } else if (outcome === 'monitored') {
      rowClass += ' feed-monitor';
    } else if (outcome === 'honeypot') {
      rowClass += ' feed-honeypot';
    } else {
      // open — scale by severity, but never red
      if (sev === 'critical')    rowClass += ' alert-high';
      else if (sev === 'high')   rowClass += ' alert-medium';
      else if (sev === 'medium') rowClass += ' alert-low';
      else                       rowClass += ' feed-muted';
    }

    var icon = '\u26A0';
    if (outcome === 'blocked' || outcome === 'killed' || outcome === 'contained' || outcome === 'suspended') icon = '\uD83D\uDEE1';
    else if (outcome === 'ignored') icon = '\u2796';
    else if (sev === 'critical' || sev === 'high') icon = '\u26A1';

    // Map raw outcome to AI-first model: open/active → OBSERVING with Guard ON
    var mappedOutcome = outcome;
    if ((outcome === 'open' || outcome === 'active') && (window._agentMode || status?.mode || 'guard') === 'guard') {
      mappedOutcome = 'monitoring';
    }
    var badge = outcomeBadgeHtml(mappedOutcome);

    html += '<div class="' + rowClass + '" onclick="viewActivity();handleCardClickByValue(\'ip\',\'' + ipVal + '\')">' +
      '<span class="activity-icon">' + icon + '</span>' +
      '<div style="flex:1;min-width:0">' +
      '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
      '<span style="font-size:0.8rem;font-weight:600;color:var(--text)">' + label + '</span>' +
      badge +
      '</div>' +
      (ipVal ? '<div style="font-size:0.72rem;color:var(--muted);margin-top:2px;font-family:\'JetBrains Mono\',monospace">' + ipVal + '</div>' : '') +
      '</div>' +
      '<span class="activity-time">' + ago + '</span>' +
      '</div>';
  });
  html += '</div>';
  feedEl.innerHTML = html;
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
