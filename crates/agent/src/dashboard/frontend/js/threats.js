var DETECTOR_PRIORITY = {
  reverse_shell: 100, fileless_exec: 95, container_escape: 90,
  rootkit: 85, data_exfil_cmd: 80, sudo_abuse: 75,
  threat_intel: 70, dns_c2: 65, packet_flood: 60,
  credential_stuffing: 55, ssh_bruteforce: 50,
  proto_anomaly: 40, suspicious_execution: 35, discovery_burst: 30,
  web_scan: 25, port_scan: 20, network_sniffing: 15,
  host_drift: 10, kernel_module: 8, timing_anomaly: 5,
  logging_config_change: 3, suspicious_archive: 2
};

// Outcome display order and labels for the AI-first audit trail.
// Threats is NOT a triage queue — the AI decides and acts. The operator
// reads outcomes, not work items. Grouping by outcome answers "what did
// the AI do?" instead of "what detector fired?".
var OUTCOME_ORDER = ['needs_attention', 'blocked', 'honeypot', 'monitoring', 'dismissed'];
var OUTCOME_META = {
  blocked:         { icon: '\uD83D\uDEE1\uFE0F', label: 'Blocked',          cls: 'outcome-blocked' },
  honeypot:        { icon: '\uD83C\uDF6F',       label: 'Honeypot',          cls: 'outcome-honeypot' },
  monitoring:      { icon: '\uD83D\uDC41\uFE0F', label: 'Observing',         cls: 'outcome-observing' },
  needs_attention: { icon: '\u26A0\uFE0F',       label: 'Needs your attention', cls: 'outcome-attention' },
  dismissed:       { icon: '\u2713',              label: 'Dismissed',         cls: 'outcome-dismissed' },
};

function outcomeOf(item) {
  var o = (item.outcome || '').toLowerCase();
  if (o === 'blocked') return 'blocked';
  if (o === 'honeypot') return 'honeypot';
  if (o === 'monitoring') return 'monitoring';
  if (o === 'ignored' || o === 'noise' || o === 'dismissed') return 'dismissed';
  // 'active', 'open', '' → depends on operational mode:
  //   Guard ON:  AI is processing autonomously → 'monitoring' (observing)
  //   Guard OFF: AI detected but CANNOT act    → 'needs_attention' (operator must decide)
  var mode = (window._agentMode || 'guard');
  if (mode === 'guard') return 'monitoring';
  return 'needs_attention';
}

function buildGroupedList(items) {
  // Filter out trusted/private IPs if toggle is on
  if (state.hideAllowlisted) {
    items = items.filter(function(item) { return !isIpTrusted(item.value) && !isPrivateIp(item.value); });
  }
  // Filter by outcome if set (e.g. from Home CTA click)
  var titleEl = document.getElementById('entityTitle');
  if (state.filterOutcome === 'contained') {
    items = items.filter(function(item) {
      var o = (item.outcome || '').toLowerCase();
      return o === 'blocked' || o === 'honeypot';
    });
    if (titleEl) titleEl.innerHTML = 'Blocked threats <span style="font-size:0.6rem;color:var(--muted);cursor:pointer;margin-left:6px" onclick="state.filterOutcome=null;refreshLeft(false)">\u2715 show all</span>';
  } else {
    if (titleEl) titleEl.textContent = 'AI Defense Log';
  }

  // Group by outcome (what the AI did), not by detector (what was found).
  var seen = {};
  var groups = {};
  OUTCOME_ORDER.forEach(function(o) {
    groups[o] = { outcome: o, items: [] };
  });

  items.forEach(function(item) {
    if (seen[item.value]) return;
    seen[item.value] = true;
    var o = outcomeOf(item);
    if (!groups[o]) groups[o] = { outcome: o, items: [] };
    groups[o].items.push(item);
  });

  // Sort items within each group: highest severity first, then most recent
  var sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  Object.values(groups).forEach(function(g) {
    g.items.sort(function(a, b) {
      var sa = sevRank[(a.max_severity || '').toLowerCase()] || 0;
      var sb = sevRank[(b.max_severity || '').toLowerCase()] || 0;
      if (sb !== sa) return sb - sa;
      return (b.last_seen || '') > (a.last_seen || '') ? 1 : -1;
    });
  });

  var html = '';
  OUTCOME_ORDER.forEach(function(o, idx) {
    var g = groups[o];
    if (!g) return;
    var meta = OUTCOME_META[o] || { icon: '', label: o, cls: '' };
    var count = g.items.length;

    // Always show "Needs your attention" group (even at 0 — reassuring).
    // Hide empty groups for other outcomes.
    if (count === 0 && o !== 'needs_attention') return;

    var startOpen = count > 0 && (o === 'needs_attention' || o === 'blocked' || idx === 0);
    var countLabel = o === 'needs_attention' && count === 0
      ? '<span style="color:var(--ok);font-weight:700">0</span>'
      : count + '';

    html += '<div class="threat-group ' + meta.cls + '">' +
      '<div class="threat-group-header" onclick="toggleThreatGroup(this)">' +
      '<span class="threat-group-chevron' + (startOpen ? ' open' : '') + '">\u25B8</span>' +
      '<span class="threat-group-label">' + meta.icon + ' ' + meta.label + '</span>' +
      '<span class="threat-group-meta">' + countLabel + '</span>' +
      '</div>' +
      '<div class="threat-group-body' + (startOpen ? ' open' : '') + '">' +
      (count === 0
        ? '<div class="empty" style="padding:12px 16px;color:var(--ok);font-size:0.75rem">' +
          (o === 'needs_attention'
            ? ((window._agentMode || 'guard') === 'guard'
                ? 'Nothing here. The AI is handling everything.'
                : 'Enable Guard mode for automatic threat response.')
            : 'None today.') +
          '</div>'
        : g.items.map(function(item) { return renderCard(item); }).join('')) +
      '</div></div>';
  });
  return html;
}

var _trustedIps = [];
var _trustedUsers = [];

function isIpTrusted(ip) {
  return _trustedIps.some(function(t) {
    if (t.includes('/')) {
      // CIDR match — simple prefix check for common cases
      var prefix = t.split('/')[0];
      var bits = parseInt(t.split('/')[1], 10);
      if (bits <= 16) return ip.startsWith(prefix.split('.').slice(0, 2).join('.'));
      if (bits <= 24) return ip.startsWith(prefix.split('.').slice(0, 3).join('.'));
      return ip === prefix;
    }
    return ip === t;
  });
}

function showContained() {
  state.filterOutcome = 'contained';
  showView('investigate');
}

function toggleAllowlistFilter() {
  state.hideAllowlisted = document.getElementById('hideAllowlisted')?.checked || false;
  // _trustedIps / _trustedUsers are loaded at boot by loadActionConfig()
  // in actions.js (called from sse.js module load). No lazy-load needed.
  refreshLeft(false);
  // Also refresh Home if visible
  if (document.getElementById('viewHome').style.display !== 'none') loadHome();
}

function toggleThreatGroup(header) {
  var chevron = header.querySelector('.threat-group-chevron');
  var body = header.nextElementSibling;
  if (chevron) chevron.classList.toggle('open');
  if (body) body.classList.toggle('open');
}

function renderCard(item) {
  const value = item.value;
  const active = state.selected.type === state.pivot && state.selected.value === value ? ' active' : '';
  const sev = item.max_severity || 'unknown';
  const sevCss = sevCls(sev);
  const outcome = item.outcome || 'unknown';
  const dets = (item.detectors || []).map(function(d) { return humanLabel(d); }).join(', ') || '-';

  // Build badges — outcome-first, no "OPEN" status exists in the AI-first model.
  let badges = '';
  const mappedOutcome = outcomeOf(item);
  const outBadgeMap = {
    blocked: 'badge-blocked', honeypot: 'badge-honeypot',
    monitoring: 'badge-monitor', dismissed: 'badge-noise',
    needs_attention: 'badge-unresolved'
  };
  const outBadgeCls = outBadgeMap[mappedOutcome] || 'badge-monitor';
  const outBadgeLabel = (OUTCOME_META[mappedOutcome] || {}).label || 'Observing';
  badges += `<span class="card-badge ${outBadgeCls}">${outBadgeLabel}</span>`;

  const ago = (ts) => {
    if (!ts) return '';
    const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
  };

  const isRecent = item.last_seen && (Date.now() - new Date(item.last_seen).getTime()) < 300000;
  const isContained = ['blocked','monitoring','honeypot'].includes(outcome);
  const dotClass = isContained ? 'pulse-dot contained' : 'pulse-dot';
  const recentDot = isRecent ? '<span class="' + dotClass + '" title="Active in last 5 min"></span>' : '';
  const sevDim = isContained ? ';opacity:0.5' : '';

  return `
    <div class="attacker-card${active}"
         data-subject-type="${esc(state.pivot)}"
         data-subject-value="${esc(value)}"
         onclick="loadJourney('${esc(state.pivot)}','${esc(value)}')">
      <div class="card-row">
        <div class="card-ip">${recentDot} ${esc(value)}</div>
        <span class="${sevCss}" style="font-size:0.65rem;font-weight:700${sevDim}">${esc(sev.toUpperCase())}</span>
      </div>
      <div class="card-detectors">${esc(dets)}</div>
      <div class="card-meta">
        <span class="card-counts">${item.incident_count || 0} inc · ${item.event_count || 0} evt</span>
        <span class="card-time">${ago(item.last_seen)}</span>
      </div>
      ${badges ? `<div class="card-badges">${badges}</div>` : ''}
    </div>`;
}

function renderClusterCard(cluster) {
  return `
    <div class="cluster-card" onclick="openCluster('${esc(cluster.pivot)}')">
      <div class="cluster-row">
        <span class="cluster-id">${esc(cluster.cluster_id)}</span>
        <span class="cluster-meta">${cluster.incident_count} incidents</span>
      </div>
      <div class="cluster-pivot">${esc(cluster.pivot)}</div>
      <div class="cluster-dets">${esc((cluster.detector_kinds || []).join(', '))}</div>
      <div class="cluster-meta">${esc(fmtTime(cluster.start_ts))} → ${esc(fmtTime(cluster.end_ts))}</div>
    </div>`;
}

function openCluster(pivotToken) {
  const parsed = parsePivotToken(pivotToken);
  state.pivot = parsed.type;
  updatePivotUi();
  refreshLeft(false).finally(() => {
    loadJourney(parsed.type, parsed.value);
  });
}

function openPivotShortcut(token) {
  const parsed = parsePivotToken(token);
  state.pivot = parsed.type;
  updatePivotUi();
  refreshLeft(false).finally(() => {
    loadJourney(parsed.type, parsed.value);
  });
}

async function downloadSnapshot(format) {
  try {
    syncFiltersFromUi();
    const qs = buildQuery({
      format,
      date: state.filters.date,
      severity_min: state.filters.severity_min,
      detector: state.filters.detector,
      group_by: state.pivot,
      subject_type: state.selected.value ? state.selected.type : '',
      subject: state.selected.value ? state.selected.value : '',
      window_seconds: state.filters.window_seconds,
    });
    const body = await loadText('/api/export?' + qs);
    const ext = format === 'md' ? 'md' : 'json';
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    downloadBlob(
      `innerwarden-snapshot-${stamp}.${ext}`,
      format === 'md' ? 'text/markdown; charset=utf-8' : 'application/json; charset=utf-8',
      body
    );
  } catch (e) {
    document.getElementById('refreshStatus').textContent = 'export err: ' + e.message;
  }
}

// D7 - update a KPI span; flash on change


function updateStatusHero(incidents, decisions) {
  const hero = document.getElementById('statusHero');
  const icon = document.getElementById('heroIcon');
  const title = document.getElementById('heroTitle');
  const sub = document.getElementById('heroSub');
  if (!hero || !icon || !title || !sub) return;

  const ov = window._lastOverview || {};
  const blocked = ov.ai_responded || 0;
  const noise = ov.ai_ignored || 0;

  // Count items by outcome from the current entity list
  var items = (window._lastEntityItems || []);
  var needsAttention = 0, observing = 0, totalBlocked = 0, totalHoneypot = 0;
  items.forEach(function(item) {
    var o = outcomeOf(item);
    if (o === 'needs_attention') needsAttention++;
    else if (o === 'monitoring') observing++;
    else if (o === 'blocked') totalBlocked++;
    else if (o === 'honeypot') totalHoneypot++;
  });

  var isGuard = (window._agentMode || 'guard') === 'guard';

  if (!isGuard) {
    // Detection-only mode (watch / read_only): AI sees threats but cannot act.
    // Everything unresolved is the operator's responsibility.
    var detected = needsAttention + observing;
    hero.className = detected > 0 ? 'status-hero danger' : 'status-hero safe';
    icon.textContent = '\uD83D\uDC41\uFE0F';
    title.textContent = 'Detection Mode';
    sub.textContent = detected > 0
      ? detected + ' threat' + (detected > 1 ? 's' : '') + ' detected. AI is monitoring only \u2014 enable Guard mode for automatic response.'
      : 'No threats detected. AI is monitoring only.';
  } else if (needsAttention > 0) {
    hero.className = 'status-hero danger';
    icon.textContent = '\u26A0\uFE0F';
    title.textContent = needsAttention + ' item' + (needsAttention > 1 ? 's need' : ' needs') + ' your attention';
    sub.textContent = 'The AI could not resolve ' + (needsAttention > 1 ? 'these' : 'this') + ' automatically. Review below.';
  } else if (observing > 0) {
    hero.className = 'status-hero safe';
    icon.textContent = '\uD83D\uDEE1\uFE0F';
    title.textContent = 'AI Protection Active';
    sub.textContent = totalBlocked + ' blocked \u00B7 ' + totalHoneypot + ' honeypot \u00B7 ' + observing + ' observing \u00B7 ' + noise + ' dismissed';
  } else {
    hero.className = 'status-hero safe';
    icon.textContent = '\u2705';
    title.textContent = 'All Handled';
    sub.textContent = totalBlocked + ' blocked \u00B7 ' + totalHoneypot + ' honeypot \u00B7 ' + noise + ' dismissed. Nothing requires attention.';
  }
}

function buildActivityFeed(incidents, decisions) {
  const feedEl = document.getElementById('activityFeed');
  if (!feedEl) return;

  const actionMap = {};
  (decisions || []).forEach(d => {
    const key = d.target_ip || d.incident_id || '';
    if (key) actionMap[key] = d;
  });

  const detectorLabels = {
    ssh_bruteforce: 'SSH password guessing',
    credential_stuffing: 'credential stuffing attack',
    port_scan: 'port scan',
    sudo_abuse: 'suspicious sudo commands',
    search_abuse: 'search abuse',
    web_scan: 'web scanner detected',
    user_agent_scanner: 'automated scanner',
    execution_guard: 'suspicious command execution',
  };

  const rows = (incidents || []).slice(0, 12).map(inc => {
    const sev = (inc.severity || '').toLowerCase();
    const ip = (inc.entities || []).find(e => e.type === 'Ip' || e.type === 'ip')?.value || '';
    const dec = ip ? actionMap[ip] : null;
    const detectorSlug = (inc.incident_id || '').split(':')[0] || '';
    const label = detectorLabels[detectorSlug] || inc.title || detectorSlug;
    const ago = timeAgo(inc.ts);

    const outcome = inc.outcome || 'open';
    const isResolved = outcome !== 'open';
    let icon, actionText, rowStyle;

    if (isResolved && outcome === 'blocked') {
      icon = '🛡️'; actionText = 'Blocked ' + (ip || ''); rowStyle = 'opacity:0.7';
    } else if (isResolved && outcome === 'suspended') {
      icon = '🔒'; actionText = 'Sudo suspended' + (ip ? ' for ' + ip : ''); rowStyle = 'opacity:0.7';
    } else if (isResolved && outcome === 'ignored') {
      icon = '✓'; actionText = 'Reviewed - no action needed'; rowStyle = 'opacity:0.5';
    } else if (isResolved) {
      icon = '✓'; actionText = 'Contained' + (ip ? ' ' + ip : ''); rowStyle = 'opacity:0.7';
    } else if (sev === 'critical' || sev === 'high') {
      icon = '⚠️'; actionText = ip ? 'Investigating ' + ip : 'Active threat';  rowStyle = '';
    } else {
      icon = '•'; actionText = ip ? 'Monitoring ' + ip : 'Monitoring'; rowStyle = 'opacity:0.8';
    }

    return '<div class="activity-row" style="' + rowStyle + '" onclick="handleCardClickByValue(\'ip\',\'' + esc(ip) + '\')">' +
      '<div class="activity-icon">' + icon + '</div>' +
      '<div class="activity-body">' +
        '<div class="activity-title">' + esc(actionText) + '</div>' +
        '<div class="activity-meta">' + esc(label) + (isResolved ? ' · ' + outcome : '') + '</div>' +
      '</div>' +
      '<div class="activity-time">' + esc(ago) + '</div>' +
      '</div>';
  });

  if (rows.length === 0) {
    feedEl.innerHTML = '<div class="empty" style="padding:20px 0;text-align:center;color:var(--ok)">✅ Nothing suspicious today</div>';
  } else {
    feedEl.innerHTML = '<div class="activity-feed">' + rows.join('') + '</div>';
  }
}


function updateKpi(id, newVal) {
  const el = document.getElementById(id);
  if (!el) return;
  const prev = el.textContent;
  el.textContent = newVal;
  if (String(prev) !== String(newVal)) {
    el.classList.remove('kpi-flash');
    void el.offsetWidth; // reflow to restart animation
    el.classList.add('kpi-flash');
    el.addEventListener('animationend', () => el.classList.remove('kpi-flash'), { once: true });
  }
}

// D7 - soft live refresh: only new cards get animated, existing stay in place.
async function refreshLeftLive() {
  try {
    syncFiltersFromUi();
    const overviewQs = buildQuery({ date: state.filters.date });
    const entityQs = buildQuery({
      date: state.filters.date,
      severity_min: state.filters.severity_min,
      detector: state.filters.detector,
      group_by: state.pivot,
    });

    const [ov, entityData] = await Promise.all([
      loadJson('/api/overview' + (overviewQs ? '?' + overviewQs : '')),
      state.pivot === 'ip'
        ? loadJson('/api/entities?' + entityQs).then((r) => ({
            items: (r.attackers || []).map((a) => ({ ...a, value: a.ip, group_by: 'ip' })),
          }))
        : loadJson('/api/pivots?' + entityQs),
    ]);

    const items = entityData.items || [];

    window._lastOverview = ov;
    window._lastEntityItems = items;

    // Outcome-first KPIs (same logic as refreshLeft)
    var kpiBlocked = 0, kpiObserving = 0, kpiAttention = 0;
    items.forEach(function(item) {
      var o = outcomeOf(item);
      if (o === 'blocked' || o === 'honeypot') kpiBlocked++;
      else if (o === 'needs_attention') kpiAttention++;
      else if (o === 'monitoring') kpiObserving++;
    });
    updateKpi('kpi-confirmed', kpiBlocked);
    updateKpi('kpi-responded', kpiObserving);
    updateKpi('kpi-noise',     kpiAttention);
    updateKpi('kpi-events',    ov.events_count);
    updateKpi('kpi-incidents', ov.incidents_count);
    updateKpi('kpi-attackers', items.length);

    const list = document.getElementById('attackerList');
    const newItems = items.filter(it => !state.knownItemValues.has(it.value));
    if (newItems.length > 0) {
      // Rebuild grouped list when new items arrive
      list.innerHTML = buildGroupedList(items);
      state.knownItemValues = new Set(items.map(it => it.value));
    }

    // Update counts on existing cards (incident/event count may change)
    for (const item of items) {
      const existing = list.querySelector(
        `[data-subject-type="${esc(state.pivot)}"][data-subject-value="${esc(item.value)}"]`
      );
      if (existing && !newItems.includes(item)) {
        const countEl = existing.querySelector('.card-counts');
        if (countEl) countEl.textContent = `${item.incident_count} inc · ${item.event_count} ev`;
      }
    }
    if (newItems.length > 0) applyEntitySearch();  // D9: filter newly inserted cards
  } catch (e) {
    // silent - refreshLeft fallback handles error display
  }
}

async function refreshLeft(forceRefreshJourney = false) {
  try {
    syncFiltersFromUi();

    const overviewQs = buildQuery({ date: state.filters.date });
    const entityQs = buildQuery({
      date: state.filters.date,
      severity_min: state.filters.severity_min,
      detector: state.filters.detector,
      group_by: state.pivot,
    });
    const clusterQs = buildQuery({
      date: state.filters.date,
      severity_min: state.filters.severity_min,
      detector: state.filters.detector,
      window_seconds: state.filters.window_seconds,
    });

    const [ov, entityData, clusterData, statusData] = await Promise.all([
      loadJson('/api/overview' + (overviewQs ? '?' + overviewQs : '')),
      state.pivot === 'ip'
        ? loadJson('/api/entities?' + entityQs).then((r) => ({
            items: (r.attackers || []).map((a) => ({
              ...a,
              value: a.ip,
              group_by: 'ip',
            })),
          }))
        : loadJson('/api/pivots?' + entityQs),
      loadJson('/api/clusters?' + clusterQs),
      loadJson('/api/status').catch(() => ({ mode: 'guard' })),
    ]);

    // Store agent mode globally so outcomeOf() can adapt.
    // guard = AI blocks autonomously, watch/read_only = AI detects only.
    window._agentMode = statusData.mode || 'guard';

    const items = entityData.items || [];
    state.clusters = clusterData.items || [];

    window._lastOverview = ov;
    window._lastEntityItems = items;

    // Outcome-first KPIs: Blocked / Observing / Needs attention
    var kpiBlocked = 0, kpiObserving = 0, kpiAttention = 0;
    items.forEach(function(item) {
      var o = outcomeOf(item);
      if (o === 'blocked' || o === 'honeypot') kpiBlocked++;
      else if (o === 'needs_attention') kpiAttention++;
      else if (o === 'monitoring') kpiObserving++;
    });
    document.getElementById('kpi-confirmed').textContent = kpiBlocked;
    document.getElementById('kpi-responded').textContent = kpiObserving;
    document.getElementById('kpi-noise').textContent     = kpiAttention;
    document.getElementById('kpi-events').textContent    = ov.events_count;
    document.getElementById('kpi-incidents').textContent = ov.incidents_count;
    const kpiAtt = document.getElementById('kpi-attackers');
    if (kpiAtt) kpiAtt.textContent = items.length;

    const list = document.getElementById('attackerList');
    if (items.length === 0) {
      list.innerHTML = '<div class="empty">No records for the selected filters.</div>';
      state.knownItemValues.clear();
    } else {
      list.innerHTML = buildGroupedList(items);
      state.knownItemValues = new Set(items.map(it => it.value));
    }

    const clusterList = document.getElementById('clusterList');
    if (!state.clusters.length) {
      clusterList.innerHTML = '<div class="empty">No clusters for current filters.</div>';
    } else {
      clusterList.innerHTML = state.clusters.map(renderClusterCard).join('');
    }

    if (ov.top_detectors && ov.top_detectors.length) {
      document.getElementById('topDetectors').innerHTML = ov.top_detectors.map(d =>
        `<div class="det-row"><span>${esc(d.detector)}</span><span class="det-count">${d.count}</span></div>`
      ).join('');
    } else {
      document.getElementById('topDetectors').innerHTML = '<div class="empty">No detectors fired.</div>';
    }

    if (state.selected.value) {
      const stillExists =
        state.selected.type === state.pivot &&
        items.some((it) => it.value === state.selected.value);
      if (!stillExists) {
        state.selected = { type: state.pivot, value: null };
        showHomeState();
      } else if (forceRefreshJourney) {
        await loadJourney(state.selected.type, state.selected.value);
      }
    }

    applyEntitySearch();  // D9: re-apply filter after full reload
    syncUrl();
    document.getElementById('refreshStatus').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('refreshStatus').textContent = 'err: ' + e.message;
  }
}

// Boot vars (init code in sse.js which loads last)
const today = new Date().toISOString().slice(0, 10);
