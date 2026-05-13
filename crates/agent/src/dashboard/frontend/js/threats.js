// Spec 049 PR5: write the operator timezone into the scope-picker
// label. Defensive against an absent label element (some test
// fixtures inject only part of the HTML) and against a missing
// `overview.timezone` field (older API responses default to UTC).
function renderTzLabel(tz) {
  var el = document.getElementById('flt-tz-label');
  if (!el) return;
  var label = (typeof tz === 'string' && tz.trim()) ? tz.trim() : 'UTC';
  el.textContent = 'TZ: ' + label;
}

// Spec 049 PR6: render the `Current state` band on Cases. ALWAYS
// reads from `overview.current_state.*` — backend-computed against
// today's full-day window regardless of the scope picker. The
// operator can pick `Yesterday 14h-16h` and this band keeps
// reporting what is alive RIGHT NOW.
function renderCurrentStateBand(currentState) {
  var cs = currentState || {};
  var setNum = function(id, val) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = (val == null ? 0 : val);
  };
  setNum('kpi-now-blocked', cs.currently_blocked);
  setNum('kpi-now-observing', cs.currently_observing);
  setNum('kpi-now-needs-review', cs.needs_review_now);
}

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
// Phase 7 (audit RC-2): "allowlisted" is now its own group, between
// Observing and Dismissed. The operator-relevant audit question
// "what did my trust rules silence today?" gets a dedicated answer
// instead of being hidden behind the "Hide allowlisted" toggle.
var OUTCOME_ORDER = ['needs_attention', 'blocked', 'honeypot', 'monitoring', 'allowlisted', 'dismissed'];

// 2026-04-30: replaced emoji icons with inline lucide SVGs to match
// the home pyramid (Phase 11B) and the marketing site. Same icon
// vocabulary across all dashboard surfaces — no more emoji/SVG mix.
//
// Icon source: lucide.dev — Ban (blocked), Bug (honeypot),
// Eye (monitoring/observing), AlertCircle (needs_attention),
// Handshake (allowlisted), Check (dismissed). All inherit
// `currentColor` so CSS controls per-row tint.
//
// Group label: "Blocked attackers" → "Currently blocked attackers"
// (Wave 10, 2026-05-05). The list section is a SNAPSHOT of unique IPs
// currently in the blocked-outcome bucket; the KPI tile above counts
// BLOCK ACTIONS today (decisions, not unique IPs). Pre-Wave-10 the
// labels read "Blocks · Today" and "Blocked attackers" — same page,
// related concepts, different answers, with no copy disclosing the
// "snapshot vs accumulator" axis. Operator looked at Home (26
// attackers handled today), then Threats (12 Blocked attackers) and
// could not reconcile the gap. The "Currently" prefix names the
// snapshot axis explicitly so a future relabel back to "Blocked
// attackers" without disclosing snapshot-vs-aggregate fails CI.
var SVG_ATTRS = 'xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
var ICON_BAN          = '<svg ' + SVG_ATTRS + '><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>';
var ICON_BUG          = '<svg ' + SVG_ATTRS + '><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>';
var ICON_EYE          = '<svg ' + SVG_ATTRS + '><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/></svg>';
var ICON_ALERT_CIRCLE = '<svg ' + SVG_ATTRS + '><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>';
var ICON_HANDSHAKE    = '<svg ' + SVG_ATTRS + '><path d="m11 17 2 2a1 1 0 1 0 3-3"/><path d="m14 14 2.5 2.5a1 1 0 1 0 3-3l-3.88-3.88a3 3 0 0 0-4.24 0l-.88.88a1 1 0 1 1-3-3l2.81-2.81a5.79 5.79 0 0 1 7.06-.87l.47.28a2 2 0 0 0 1.42.25L21 4"/><path d="m21 3 1 11h-2"/><path d="M3 3 2 14l6.5 6.5a1 1 0 1 0 3-3"/><path d="M3 4h8"/></svg>';
var ICON_CHECK        = '<svg ' + SVG_ATTRS + '><path d="M20 6 9 17l-5-5"/></svg>';

var OUTCOME_META = {
  blocked:         { icon: ICON_BAN,          label: 'Currently blocked attackers', cls: 'outcome-blocked' },
  honeypot:        { icon: ICON_BUG,          label: 'Honeypot',               cls: 'outcome-honeypot' },
  monitoring:      { icon: ICON_EYE,          label: 'Observing',              cls: 'outcome-observing' },
  needs_attention: { icon: ICON_ALERT_CIRCLE, label: 'Needs your attention',   cls: 'outcome-attention' },
  allowlisted:     { icon: ICON_HANDSHAKE,    label: 'Allowlisted (silenced)', cls: 'outcome-allowlisted' },
  dismissed:       { icon: ICON_CHECK,        label: 'Dismissed',              cls: 'outcome-dismissed' },
};

function outcomeOf(item) {
  // 2026-04-29 (audit Phase 2): mirror the backend's
  // `threat_contract::classify_decision` so the front-end no longer
  // disagrees with the row's actual classification when only
  // `item.decision` is populated (a freshly-blocked IP arrives with
  // `decision="block_ip", outcome=null` from the SSE stream and the
  // pre-fix code classified it as "monitoring" instead of "blocked").
  // Backend now emits canonical strings; the legacy fallbacks
  // (`monitored`, `ignored`, `noise`, `active`) are kept so a
  // not-yet-deployed agent does not regress.
  var o = (item.outcome || '').toLowerCase();
  if (o === 'blocked') return 'blocked';
  if (o === 'honeypot') return 'honeypot';
  if (o === 'monitoring' || o === 'monitored') return 'monitoring';
  // Phase 7 (audit RC-2): backend emits outcome="allowlisted" for
  // attackers whose incidents were silenced by the operator's trust
  // rule. Treat as a first-class outcome — distinct from dismissed
  // (AI noise gate) and from monitoring (AI explicitly chose to
  // watch). The dedicated group makes the silenced trust auditable.
  if (o === 'allowlisted') return 'allowlisted';
  if (o === 'open') {
    // Phase 13 (QA fix #3, 2026-04-29): explicit `open` outcome from
    // the backend means "no decision yet" — that is, the AI has not
    // committed to an action. Pre-Phase-13 this branch mode-rewrote
    // open→monitoring under guard mode to "reduce alarm fatigue",
    // but the consequence was that the Home tile (which counts
    // `buckets.attention.unique_attackers`) said "Needs attention 3"
    // while the threats list grouped those same 3 IPs under
    // Observing. Two semantic interpretations of the same backend
    // field on the same screen — exactly the RC-2 drift class.
    //
    // Resolution: `open` always maps to `needs_attention`. The
    // Pending breakdown panel in the Home view (Phase 7B) already
    // distinguishes "in flight (<5 min)" from "stuck (>1h)" so the
    // operator gets the right alarm level without re-classifying
    // open as monitoring. If alarm-fatigue regresses, the right fix
    // is to refine the Pending panel copy, not to silently rewrite
    // the outcome.
    return 'needs_attention';
  }
  if (o === 'ignored' || o === 'noise' || o === 'dismissed') return 'dismissed';

  // No outcome string -- fall back to decision-driven classification.
  // Mirrors the backend's contract for the (decision, exec_result=None) path.
  var dec = (item.decision || item.action_taken || '').toLowerCase();
  if (dec === 'block_ip' || dec === 'kill_process' || dec === 'suspend_user_sudo' || dec === 'block_container') {
    return 'blocked';
  }
  if (dec === 'honeypot') return 'honeypot';
  if (dec === 'monitor') return 'monitoring';
  if (dec === 'ignore' || dec === 'dismiss') return 'dismissed';

  // Phase 13 (QA fix #3): 'active', '', escalate, request_confirmation,
  // unknown — these are all "no committed decision". They join the
  // `open` branch above and map to 'needs_attention' regardless of
  // mode. The mode-aware rewrite that used to live here was the same
  // class of semantic drift the explicit `open` branch had.
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
  // Audit 2.6 partial: status dropdown filter. Restricts the
  // grouped list to a single outcome bucket. Country / campaign /
  // playbook-outcome / AI confidence band require backend extension
  // and ship in their own spec.
  var statusFilter = (state.filters && state.filters.status) || '';
  if (statusFilter) {
    items = items.filter(function(item) {
      return outcomeOf(item) === statusFilter;
    });
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

    // Audit 4.2/4.3/4.4: attach glossary tooltip to the group header
    // so the operator sees the canonical definition for the bucket
    // they are reading. `glossaryTitle(o)` falls back to '' when the
    // bucket key is missing — safe to concatenate unconditionally.
    var groupTitle = (typeof glossaryTitle === 'function') ? glossaryTitle(o) : '';
    html += '<div class="threat-group ' + meta.cls + '">' +
      '<div class="threat-group-header" onclick="toggleThreatGroup(this)"' + groupTitle + '>' +
      '<span class="threat-group-chevron' + (startOpen ? ' open' : '') + '">\u25B8</span>' +
      '<span class="threat-group-label">' + meta.icon + '<span>' + meta.label + '</span></span>' +
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
  // Phase 4: kernel-evidence badge appended after the AI-decision
  // badge so the operator sees "Blocked (AI) · Kernel · 45m" when
  // the kernel is still enforcing, and "Blocked (AI) · Expired"
  // when the TTL elapsed but no fresh block has been re-issued.
  badges += blockStateBadgeHtml(item.block_state);

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

  // Phase 12 (QA fix #5, 2026-04-29): cards used to be <div onclick>
  // — not focusable, screen readers couldn't announce them as actions,
  // no Cmd/Ctrl+click affordance. Now <button> with type="button"
  // gives keyboard focus, screen-reader role=button by default, and
  // a visible focus ring. Layout stays the same via class re-use.
  var ariaLabel = 'Open threat details for ' + value + '. Severity ' +
    sev + ', ' + (item.incident_count || 0) + ' incidents.';
  return `
    <button type="button"
            class="attacker-card${active}"
            data-subject-type="${esc(state.pivot)}"
            data-subject-value="${esc(value)}"
            aria-label="${esc(ariaLabel)}"
            onclick="loadJourney('${esc(state.pivot)}','${esc(value)}')">
      <div class="card-row">
        <div class="card-ip">${recentDot} ${esc(value)}</div>
        <span class="${sevCss}" style="font-size:0.65rem;font-weight:700${sevDim}">${esc(sev.toUpperCase())}</span>
      </div>
      <div class="card-detectors">${esc(dets)}</div>
      <div class="card-meta">
        <span class="card-counts">${item.incident_count || 0} inc${(item.event_count || 0) > 0 ? ' · ' + item.event_count + ' evt' : ''}</span>
        <span class="card-time">${ago(item.last_seen)}</span>
      </div>
      ${badges ? `<div class="card-badges">${badges}</div>` : ''}
    </button>`;
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
    var s = document.getElementById('refreshStatus');
    if (s) s.textContent = 'export err: ' + e.message;
  }
}

// D7 - update a KPI span; flash on change


// 2026-04-29 (audit Phase 2): `updateStatusHero` and
// `buildActivityFeed` removed -- both wrote to DOM IDs no
// longer in `index.html` (`statusHero`, `heroIcon`,
// `heroTitle`, `heroSub`, `activityFeed`) and were only
// called from the orphaned `loadHomeState` in helpers.js.
// The Home tab is now driven entirely by `home.js::loadHome`
// writing to `homeHero`/`homeHeroIcon`/`homeHeroTitle`/
// `homeHeroSub`. Removing the dead writes also retired the
// last front-end uses of stale outcome strings
// (`suspended`, `ignored`) that disagreed with the contract.


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
// 2026-04-29: render a diagnostic-aware empty state inside the
// attackers list when /api/entities returns 0 items. Calls
// /api/threats/diagnostic to find out WHY (no incidents in scope,
// scope_mismatch, no entities) and provides clickable date chips
// when historical snapshots exist.
function renderEmptyDiagnostic(targetEl) {
  if (!targetEl) return;
  var qs = '';
  var fd = (state.filters && state.filters.date) || '';
  var fs = (state.filters && state.filters.severity_min) || '';
  var fdet = (state.filters && state.filters.detector) || '';
  if (fd) qs += (qs ? '&' : '?') + 'date=' + encodeURIComponent(fd);
  if (fs) qs += (qs ? '&' : '?') + 'severity_min=' + encodeURIComponent(fs);
  if (fdet) qs += (qs ? '&' : '?') + 'detector=' + encodeURIComponent(fdet);
  loadJson('/api/threats/diagnostic' + qs)
    .then(function(d) {
      var html = '';
      if (d.scope_mismatch) {
        html += '<div class="empty" style="padding:16px">';
        html += '<div style="margin-bottom:6px">' + lucideIcon('clipboard-list',{size:20}) + '</div>';
        html += '<div style="margin-bottom:10px">No incidents on <b>' + esc(fd || d.date) + '</b>.</div>';
        html += '<div style="font-size:0.75rem;color:var(--muted);margin-bottom:8px">Pick a date with data:</div>';
        var chips = (d.available_dates || []).map(function(dd) {
          return '<button type="button" class="journey-btn" style="margin:2px;font-size:0.7rem;padding:3px 8px" onclick="setThreatsDate(\'' + esc(dd) + '\')">' + esc(dd) + '</button>';
        }).join('');
        html += '<div>' + (chips || '<span style="color:var(--muted)">none available</span>') + '</div>';
        html += '<div style="margin-top:10px"><button type="button" class="journey-btn" style="font-size:0.7rem" onclick="setThreatsDate(\'\')">Clear date filter</button></div>';
        html += '</div>';
      } else if (d.has_incidents && !d.has_entities) {
        html += '<div class="empty" style="padding:16px">';
        html += '<div style="margin-bottom:6px">' + lucideIcon('alert-triangle',{size:20}) + '</div>';
        html += '<div style="margin-bottom:8px">' + d.incidents_in_scope + ' incident(s) found, but no IP/User entities linked.</div>';
        if (d.detector_pivot_count > 0) {
          html += '<button type="button" class="journey-btn" style="font-size:0.7rem" onclick="setThreatsPivot(\'detector\')">Switch to Detector pivot</button>';
        }
        html += '</div>';
      } else if (!d.has_incidents) {
        html += '<div class="empty" style="padding:16px">';
        html += '<div style="margin-bottom:6px">' + lucideIcon('flame',{size:20}) + '</div>';
        html += '<div>No threats in scope. Either nothing fired today or the filter is too narrow.</div>';
        if (fs || fdet) {
          html += '<div style="margin-top:10px"><button type="button" class="journey-btn" style="font-size:0.7rem" onclick="clearThreatsFilters()">Clear filters</button></div>';
        }
        html += '</div>';
      } else {
        html += '<div class="empty">No records for the selected filters.</div>';
      }
      targetEl.innerHTML = html;
    })
    .catch(function() {
      targetEl.innerHTML = '<div class="empty">No records for the selected filters.</div>';
    });
}

function setThreatsDate(date) {
  var el = document.getElementById('flt-date');
  if (el) el.value = date;
  refreshLeft(true);
}

// Phase 14 (QA polish, 2026-04-29): KPI tile sub-labels were hardcoded
// to "Today" but the underlying data is scoped by the `flt-date` picker.
// When operator picked 2026-04-22 to investigate yesterday's incident,
// the tiles still read "Today" — misleading. This helper makes the
// sub-label match the active scope: "Today" when the picker is empty
// or set to today's UTC date, otherwise the literal YYYY-MM-DD.
function syncThreatsKpiWindowLabels() {
  var dateInput = document.getElementById('flt-date');
  var picked = dateInput ? (dateInput.value || '') : '';
  var todayStr = new Date().toISOString().slice(0, 10);
  var label = (picked === '' || picked === todayStr) ? 'Today' : picked;
  ['kpi-confirmed', 'kpi-responded', 'kpi-noise'].forEach(function(id) {
    var card = document.getElementById(id);
    if (!card) return;
    var win = card.parentElement && card.parentElement.querySelector('.kpi-window');
    // kpi-responded reads "Now" (live observing) — leave it alone, only
    // the date-scoped tiles ("Blocked Today" / "Needs attention Today")
    // need to track the picker.
    if (!win || win.textContent.trim() === 'Now') return;
    win.textContent = label;
  });
}

function setThreatsPivot(p) {
  // Phase 13 (QA fix #4 follow-up, 2026-04-29): the Phase-12 fix
  // targeted `#journeyPane` (an element that doesn't exist in the
  // current HTML) — the right panel kept showing the stale detail.
  // Real structure: `#rightPanel` is the container; `#homeState` is
  // the placeholder ("Select a threat to investigate"); the
  // `#journeyContent` div carries the actual detail when populated.
  // To clear: hide journeyContent, show homeState.
  if (state.pivot !== p) {
    state.selected = { type: null, value: null };
    state.lastSubjectKey = null;
    var journeyContent = document.getElementById('journeyContent');
    var homeState = document.getElementById('homeState');
    if (journeyContent) {
      journeyContent.style.display = 'none';
      journeyContent.innerHTML = '';
    }
    if (homeState) {
      homeState.style.display = '';
    }
    // Clear selection highlight on cards.
    document.querySelectorAll('.attacker-card.active').forEach(function(c) {
      c.classList.remove('active');
    });
    // Push a clean URL state so a refresh / share doesn't re-open
    // a stale subject from the pre-switch pivot.
    if (typeof history !== 'undefined' && history.replaceState) {
      var qs = '?pivot=' + encodeURIComponent(p);
      history.replaceState(null, '', qs + '#threats');
    }
  }
  state.pivot = p;
  document.querySelectorAll('.pivot-tab').forEach(function(t) {
    t.classList.toggle('active', t.getAttribute('data-pivot') === p);
  });
  refreshLeft(true);
}

function clearThreatsFilters() {
  ['flt-date', 'flt-severity', 'flt-detector'].forEach(function(id) {
    var e = document.getElementById(id);
    if (e) e.value = '';
  });
  refreshLeft(true);
}

async function refreshLeftLive() {
  try {
    syncFiltersFromUi();
    // Spec 049 PR5: scope picker hour range flows through every
    // Cases-tab query so the counters reconcile with the list under
    // the same window.
    const overviewQs = buildQuery({
      date: state.filters.date,
      hour_from: state.filters.hour_from,
      hour_to: state.filters.hour_to,
    });
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

    // Spec 049 PR5: render operator TZ on the scope picker label so
    // the operator never has to guess what timezone "yesterday at
    // 15h" refers to. Backend-emitted (env TZ or /etc/timezone),
    // never browser-derived (which drifts across analysts).
    renderTzLabel(ov && ov.timezone);

    // Spec 049 PR6: render the `Current state` band — live counters
    // that IGNORE the scope picker. Operator never loses situational
    // awareness while auditing a historical window.
    renderCurrentStateBand(ov && ov.current_state);

    // 2026-04-29 (audit Phase 2): KPIs read from `/api/overview`
    // backend-computed fields, identical to `refreshLeft`. The live
    // SSE path used to derive counts locally from `items.outcome`,
    // which gave different totals from the next manual refresh
    // (different filter scope, no research_only normalisation, no
    // execution_result honour). Backend is the single source.
    var kpiBlocked   = ov.blocked_count   != null ? ov.blocked_count   : 0;
    var kpiObserving = ov.observing_count != null ? ov.observing_count : 0;
    var kpiAttention = ov.attention_count != null ? ov.attention_count : 0;
    updateKpi('kpi-confirmed', kpiBlocked);
    updateKpi('kpi-responded', kpiObserving);
    updateKpi('kpi-noise',     kpiAttention);
    syncThreatsKpiWindowLabels();

    const list = document.getElementById('attackerList');
    const newItems = items.filter(it => !state.knownItemValues.has(it.value));
    // SSE refresh can fire while Threats view is hidden; the list node
    // may be absent if the tab was not yet opened. Bail early in that
    // case so the live path never throws on null.innerHTML.
    if (!list) return;
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
        if (countEl) {
          // Phase 14 (QA polish): hide "0 evt" tail when we have no
          // event-count data (mirrors renderCard above so the SSE
          // refresh path doesn't reintroduce the noisy "· 0 evt"
          // suffix the operator complained about).
          const evt = item.event_count || 0;
          countEl.textContent = `${item.incident_count} inc${evt > 0 ? ' · ' + evt + ' evt' : ''}`;
        }
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

    // Spec 049 PR5: same scope-picker plumbing as `refreshLeftLive`.
    // Both paths must pass the same query params or the live + manual
    // refresh paths would show different counts under the same picker
    // — exactly the "Dashboard count != Site count" recurring-bug class.
    const overviewQs = buildQuery({
      date: state.filters.date,
      hour_from: state.filters.hour_from,
      hour_to: state.filters.hour_to,
    });
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

    // Phase 12 (QA fix #1): persistent header pill must reflect
    // runtime SystemHealth, not just the static GUARD/WATCH mode.
    // Without this, the operator sees green "PROTECTED" alongside
    // a red Hero alert — two contradictory states on one screen.
    if (typeof syncModeBadgeFromHealth === 'function') {
      syncModeBadgeFromHealth(ov, typeof actionCfg !== 'undefined' ? actionCfg : null);
    }

    const items = entityData.items || [];
    state.clusters = clusterData.items || [];

    window._lastOverview = ov;
    window._lastEntityItems = items;

    // Spec 049 PR5: render operator TZ on the scope picker label.
    renderTzLabel(ov && ov.timezone);

    // Spec 049 PR6: render the `Current state` band — live counters
    // that IGNORE the scope picker. Operator never loses situational
    // awareness while auditing a historical window.
    renderCurrentStateBand(ov && ov.current_state);

    // Spec 037 Threats UX bundle: read the three KPIs from the
    // backend-computed `/api/overview` fields instead of summing
    // pivot-item outcomes locally. The previous local computation
    // gave inconsistent counts across IP/User/Detector pivots
    // because each pivot's `outcome` semantics differed.
    var kpiBlocked   = ov.blocked_count   != null ? ov.blocked_count   : 0;
    var kpiObserving = ov.observing_count != null ? ov.observing_count : 0;
    var kpiAttention = ov.attention_count != null ? ov.attention_count : 0;
    var setText = function(id, value) {
      var el = document.getElementById(id);
      if (el) el.textContent = value;
    };
    setText('kpi-confirmed', kpiBlocked);
    setText('kpi-responded', kpiObserving);
    setText('kpi-noise', kpiAttention);
    syncThreatsKpiWindowLabels();
    // Spec 037 Threats UX bundle: the kpi-events / kpi-incidents /
    // kpi-attackers / clusterList / topDetectors writes that used to
    // live here targeted DOM nodes that PR #188 already removed. The
    // dead writes are gone; they were silently no-ops with the null
    // guard but kept misleading the reader of this file.

    const list = document.getElementById('attackerList');
    if (list) {
      if (items.length === 0) {
        // 2026-04-29: when the list is empty, ask /api/threats/diagnostic
        // why and surface an actionable hint (clear date / pick a
        // historical date with data) instead of the generic message
        // that left the operator stuck.
        list.innerHTML = '<div class="empty">No records yet. Loading diagnostic...</div>';
        state.knownItemValues.clear();
        renderEmptyDiagnostic(list);
      } else {
        list.innerHTML = buildGroupedList(items);
        state.knownItemValues = new Set(items.map(it => it.value));
      }
    }

    // Spec 037 Threats UX bundle: clusterList + topDetectors writes
    // removed -- those DOM nodes were dropped in PR #188 and the
    // setHtml() calls were silent no-ops. Cluster data is still
    // fetched (state.clusters) for the journey panel that consumes
    // it; only the dead left-panel render is gone.

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
    var s = document.getElementById('refreshStatus');
    if (s) s.textContent = new Date().toLocaleTimeString();
  } catch (e) {
    var s = document.getElementById('refreshStatus');
    if (s) s.textContent = 'err: ' + e.message;
  }
}

// Boot vars (init code in sse.js which loads last)
const today = new Date().toISOString().slice(0, 10);
