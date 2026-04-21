// ── Kind badge ─────────────────────────────────────────────────────────
function kindBadge(entry) {
  const d = entry.data || {};
  switch (entry.kind) {
    case 'event': {
      const s = d.severity || 'info';
      const cls = s === 'critical' ? 'bk-event-crit' : s === 'high' ? 'bk-event-high' : s === 'medium' ? 'bk-event-med' : 'bk-event';
      return `<span class="bk ${cls}">${esc(s)}</span>`;
    }
    case 'incident':     return `<span class="bk bk-incident">INCIDENT</span>`;
    case 'decision': {
      if (!d.auto_executed) return `<span class="bk bk-decision-skip">SKIPPED</span>`;
      if (d.dry_run)        return `<span class="bk bk-decision-dry">DRY RUN</span>`;
      return `<span class="bk bk-decision">EXECUTED</span>`;
    }
    case 'honeypot_ssh':    return `<span class="bk bk-honeypot">🍯 SSH</span>`;
    case 'honeypot_http':   return `<span class="bk bk-honeypot">🍯 HTTP</span>`;
    case 'honeypot_banner': return `<span class="bk bk-honeypot">🍯 BANNER</span>`;
    default: return `<span class="bk bk-event">${esc(entry.kind)}</span>`;
  }
}

// ── Dot class ──────────────────────────────────────────────────────────
function dotCls(entry) {
  const d = entry.data || {};
  switch (entry.kind) {
    case 'event': return 'dot-event-' + (d.severity || 'info');
    case 'incident': return 'dot-incident';
    case 'decision': return (d.dry_run || !d.auto_executed) ? 'dot-decision-dry' : 'dot-decision';
    case 'honeypot_ssh':
    case 'honeypot_http':
    case 'honeypot_banner': return 'dot-honeypot';
    default: return 'dot-default';
  }
}

// ── Summary line ───────────────────────────────────────────────────────
function entrySummary(entry) {
  const d = entry.data || {};
  switch (entry.kind) {
    case 'event':
      return esc((d.event_kind || '') + ' - ' + (d.summary || ''));
    case 'incident':
      return esc('[' + (d.severity || '').toUpperCase() + '] ' + (d.title || '') + ': ' + (d.summary || ''));
    case 'decision': {
      const conf = ((d.confidence || 0) * 100).toFixed(0);
      const reason = (d.reason || '').substring(0, 70);
      return esc(d.action_type + ' (conf: ' + conf + '%) - ' + reason);
    }
    case 'honeypot_ssh': {
      const attempts = d.auth_attempts || [];
      const creds = attempts.filter(a => a.password).slice(0, 3)
        .map(a => esc(a.username) + '/' + esc(a.password)).join(', ');
      return esc(attempts.length + ' auth attempt(s)') + (creds ? ' · ' + creds : '');
    }
    case 'honeypot_http': {
      const reqs = d.http_requests || [];
      const forms = reqs.filter(r => r.form_fields && r.form_fields.length > 0);
      const formCreds = forms.slice(0, 2).map(r => {
        const fields = Object.fromEntries((r.form_fields || []).map(([k,v]) => [k,v]));
        return (fields.username || fields.user || '') + '/' + (fields.password || fields.pass || '');
      }).filter(Boolean).join(', ');
      return esc(reqs.length + ' request(s)') + (formCreds ? ' · ' + formCreds : '');
    }
    case 'honeypot_banner':
      return esc('Banner probe - ' + (d.bytes_captured ?? 0) + ' bytes captured');
    default:
      return esc(entry.kind);
  }
}

// ── D5: Verdict card ───────────────────────────────────────────────────
function verdictValueCls(label, value) {
  const v = (value || '').toLowerCase();
  if (label === 'access') {
    if (v === 'blocked') return 'v-ok';
    if (v === 'successful' || v === 'active') return 'v-danger';
    if (v === 'attempted') return 'v-warn';
    return 'v-muted';
  }
  if (label === 'containment') {
    if (v === 'contained' || v === 'blocked') return 'v-ok';
    if (v === 'active') return 'v-danger';
    return 'v-muted';
  }
  if (label === 'privilege') {
    if (v === 'abused') return 'v-danger';
    if (v === 'suspicious') return 'v-warn';
    return 'v-muted';
  }
  if (label === 'honeypot') {
    return v === 'engaged' ? 'v-accent' : 'v-muted';
  }
  return 'v-muted';
}

function renderVerdictCard(j) {
  if (!j.verdict) return '';
  const v = j.verdict;
  // Simplified verdict: just containment status + confidence
  const isContained = v.containment_status === 'blocked' || v.containment_status === 'honeypot';
  const statusColor = isContained ? 'var(--ok)' : v.containment_status === 'active' ? 'var(--danger)' : 'var(--muted)';
  const statusLabel = isContained ? 'Contained' : v.containment_status === 'active' ? 'Active — needs attention' : 'Under review';
  const confColor = v.confidence === 'high' ? 'var(--ok)' : v.confidence === 'medium' ? 'var(--warn)' : 'var(--muted)';
  return `
    <div class="verdict-card" style="padding:12px 16px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-size:0.72rem;font-weight:700;color:${statusColor}">${statusLabel}</span>
        <span style="font-size:0.62rem;color:var(--dim)">·</span>
        <span style="display:inline-flex;align-items:center;gap:4px;font-size:0.68rem;color:var(--dim)">
          <span class="conf-dot" style="background:${confColor}"></span>${esc(v.confidence || 'low')} confidence
        </span>
        ${v.entry_vector && v.entry_vector !== 'unknown' ? '<span style="font-size:0.62rem;color:var(--dim)">·</span><span style="font-size:0.68rem;color:var(--muted)">' + humanLabel(v.entry_vector) + '</span>' : ''}
      </div>
    </div>`;
}

// ── D5: Chapter rail ────────────────────────────────────────────────────
const STAGE_CLASS = {
  reconnaissance:         'stage-recon',
  initial_access_attempt: 'stage-access',
  access_success:         'stage-success',
  privilege_abuse:        'stage-privilege',
  response:               'stage-response',
  containment:            'stage-containment',
  honeypot_interaction:   'stage-honeypot',
};

function renderChapterRail(j) {
  if (!j.chapters || j.chapters.length === 0) return '';
  const pills = j.chapters.map((ch, i) => {
    const stageCls = STAGE_CLASS[ch.stage] || '';
    return `
      <div class="chapter-pill ${stageCls}" onclick="scrollToChapter(${i})" title="${esc(ch.summary)}">
        <div class="chapter-stage">${esc(ch.stage.replace(/_/g, ' '))}</div>
        <div class="chapter-pill-title">${esc(ch.title)}</div>
        <div class="chapter-count">${ch.entry_count} event${ch.entry_count !== 1 ? 's' : ''}</div>
      </div>`;
  }).join('');
  return `<div class="chapter-rail" id="chapterRail">${pills}</div>`;
}

function scrollToChapter(chapterIdx) {
  if (!window._journeyData || !window._journeyData.chapters) return;
  const ch = window._journeyData.chapters[chapterIdx];
  if (!ch || !ch.entry_indices || ch.entry_indices.length === 0) return;
  const el = document.getElementById('tl-entry-' + ch.entry_indices[0]);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.querySelectorAll('.chapter-pill').forEach((p, i) => {
    p.classList.toggle('active', i === chapterIdx);
  });
}

// ── D5: Evidence card (human-first, raw JSON secondary) ────────────────

// Kill chain timeline renderer - renders when evidence contains kill_chain kind
function renderKillChainTimeline(evidence) {
  if (!evidence || !Array.isArray(evidence)) return null;
  const kc = evidence.find(e => e.kind && e.kind.indexOf('kill_chain') !== -1);
  if (!kc) return null;
  const pattern = kc.pattern || kc.kind || 'KILL_CHAIN';
  const status = kc.blocked ? 'BLOCKED' : 'DETECTED';
  const statusCls = kc.blocked ? 'kc-blocked' : 'kc-detected';
  const proc = kc.process || kc.command || '';
  const pid = kc.pid ? ' (PID ' + kc.pid + (kc.uid != null ? ', UID ' + kc.uid : '') + ')' : '';
  const steps = kc.steps || kc.syscalls || [];
  const c2 = kc.c2 || kc.remote_addr || '';

  let stepsHtml = '';
  steps.forEach(function(s) {
    const ts = s.ts ? esc(fmtTime(s.ts)) + ' → ' : '';
    const desc = esc(s.description || s.call || s.summary || JSON.stringify(s));
    const blocked = s.blocked || s.result === 'BLOCKED';
    stepsHtml += '<div class="kc-step' + (blocked ? ' kc-blocked-step' : '') + '">' +
      ts + desc + (blocked ? ' → BLOCKED' : '') + '</div>';
  });

  return '<div class="kill-chain-timeline">' +
    '<div class="kc-header">' +
      '<span class="kc-pattern">🔗 ' + esc(pattern) + '</span>' +
      '<span class="kc-status ' + statusCls + '">' + esc(status) + '</span>' +
    '</div>' +
    (proc ? '<div class="kc-process">' + esc(proc) + esc(pid) + '</div>' : '') +
    (stepsHtml ? '<div class="kc-steps">' + stepsHtml + '</div>' : '') +
    (c2 ? '<div class="kc-c2">C2: ' + esc(c2) + '</div>' : '') +
  '</div>';
}

function renderEvidenceCard(entry, idx) {
  const d = entry.data || {};

  // Check for kill chain evidence in incident entries
  if (entry.kind === 'incident' && d.evidence) {
    const kcHtml = renderKillChainTimeline(
      Array.isArray(d.evidence) ? d.evidence : [d.evidence]
    );
    if (kcHtml) {
      const kcDetector = d.detector || (d.incident_id || '').split(':')[0] || 'kill_chain';
      const kcIp = d.source_ip || d.ip || '';
      const kcTitle = humanIncidentTitle(kcDetector, d.title || '', kcIp);
      return `
        <div id="tl-entry-${idx}">
          <div class="evidence-header">
            <span class="tl-ts">${esc(fmtTime(entry.ts))}</span>
            <span class="bk bk-incident">KILL CHAIN</span>
          </div>
          <div class="evidence-title">${esc(kcTitle)}</div>
          ${kcHtml}
          <pre class="evidence-raw" id="raw-${idx}" data-json="${esc(JSON.stringify(entry.data))}"></pre>
        </div>`;
    }
  }

  // ── Humanized incident cards ──
  if (entry.kind === 'incident') {
    const detector = d.detector || (d.incident_id || '').split(':')[0] || '';
    const ip = d.source_ip || d.ip || '';
    const sev = (d.severity || 'info').toLowerCase();
    const hTitle = humanIncidentTitle(detector, d.title || '', ip);
    // Determine outcome from journey context (passed via _journeyOutcome global)
    const jOutcome = window._currentJourneyOutcome || 'unknown';
    const ctx = contextLine(jOutcome, sev);

    // Build collapsible forensic detail
    const lines = [];
    if (d.severity)          lines.push('Severity: ' + d.severity);
    if (d.source_ip || d.ip) lines.push('IP: ' + (d.source_ip || d.ip));
    if (d.user)              lines.push('User: ' + d.user);
    if (d.port)              lines.push('Port: ' + d.port);
    if (d.command)           lines.push('Command: ' + d.command);
    if (d.detector)          lines.push('Detector: ' + d.detector);
    if (d.file_path)         lines.push('File: ' + d.file_path);
    const rawTitle = d.title || '';
    const rawSummary = d.summary || '';

    const outcomeClass = jOutcome === 'blocked' ? 'entry-contained' :
      jOutcome === 'active' ? 'entry-open' :
      jOutcome === 'monitoring' ? 'entry-monitored' : '';

    return `
      <div class="evidence-card ${outcomeClass}" id="tl-entry-${idx}">
        <div class="evidence-header">
          <span class="tl-ts">${esc(fmtTime(entry.ts))}</span>
          ${kindBadge(entry)}
          <button type="button" class="detail-toggle" onclick="toggleDetail(this)">Show details</button>
        </div>
        <div class="evidence-title">${esc(hTitle)}</div>
        <div class="human-context ${ctx.cls}">${ctx.text}</div>
        <div class="detail-body">
          <div style="font-size:0.72rem;color:var(--muted);margin-bottom:4px;font-weight:600">Original: ${esc(rawTitle)}</div>
          ${rawSummary ? '<div style="font-size:0.7rem;color:var(--dim);margin-bottom:6px;line-height:1.4">' + esc(rawSummary) + '</div>' : ''}
          ${lines.length ? '<div class="evidence-meta">' + lines.map(l => esc(l)).join('<br>') + '</div>' : ''}
          <button type="button" class="evidence-raw-toggle" onclick="toggleRaw(${idx})" style="margin-top:6px">Raw JSON</button>
          <pre class="evidence-raw" id="raw-${idx}" data-json="${esc(JSON.stringify(entry.data))}"></pre>
        </div>
      </div>`;
  }

  // ── Non-incident entries (decisions, events, honeypot) — keep original rendering ──
  const lines = [];
  if (d.severity)          lines.push('Severity: ' + d.severity);
  if (d.source_ip || d.ip) lines.push('IP: ' + (d.source_ip || d.ip));
  if (d.user)              lines.push('User: ' + d.user);
  if (d.port)              lines.push('Port: ' + d.port);
  if (d.command)           lines.push('Command: ' + d.command);
  if (d.action_type)       lines.push('Action: ' + d.action_type);
  if (d.confidence)        lines.push('Confidence: ' + d.confidence);
  if (d.execution_result)  lines.push('Result: ' + d.execution_result);
  if (d.reason)            lines.push('Reason: ' + d.reason);
  if (d.detector)          lines.push('Detector: ' + d.detector);
  if (d.file_path)         lines.push('File: ' + d.file_path);
  if (d.summary && !lines.length) lines.push(d.summary);
  const metaHtml = lines.length
    ? '<div class="evidence-meta">' + lines.map(l => esc(l)).join('<br>') + '</div>'
    : '';
  const obsVerifyHtml = (d.reason && d.reason.startsWith('obs-verify'))
    ? renderObsVerifyScore(d.reason) : '';
  return `
    <div class="evidence-card" id="tl-entry-${idx}">
      <div class="evidence-header">
        <span class="tl-ts">${esc(fmtTime(entry.ts))}</span>
        ${kindBadge(entry)}
        <button type="button" class="evidence-raw-toggle" onclick="toggleRaw(${idx})">Raw JSON</button>
      </div>
      <div class="evidence-title">${esc(entrySummary(entry))}</div>
      ${metaHtml}
      ${obsVerifyHtml}
      <pre class="evidence-raw" id="raw-${idx}" data-json="${esc(JSON.stringify(entry.data))}"></pre>
    </div>`;
}

function toggleTimeline() {
  var el = document.getElementById('timelineSection');
  if (!el) return;
  var isOpen = el.style.display !== 'none';
  el.style.display = isOpen ? 'none' : 'block';
}

async function askAiExplain(subjectType, subjectValue) {
  var resultEl = document.getElementById('aiExplainResult');
  if (!resultEl) return;
  resultEl.style.display = 'block';
  resultEl.innerHTML = '<div style="font-size:0.75rem;color:var(--muted)">Asking AI to explain...</div>';
  try {
    var resp = await fetch('/api/ai-explain?type=' + encodeURIComponent(subjectType) + '&value=' + encodeURIComponent(subjectValue), { cache: 'no-store' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    resultEl.innerHTML =
      '<div style="font-size:0.68rem;font-weight:700;color:var(--accent);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:6px">\uD83E\uDD16 AI Explanation</div>' +
      '<div style="font-size:0.8rem;color:var(--text);line-height:1.6">' + esc(data.explanation || 'No explanation available.') + '</div>';
  } catch (e) {
    resultEl.innerHTML =
      '<div style="font-size:0.75rem;color:var(--warn)">AI explanation not available yet. This feature requires the AI provider to be configured and reachable.</div>';
  }
}

function toggleRaw(idx) {
  const el = document.getElementById('raw-' + idx);
  if (!el) return;
  if (!el.textContent && el.dataset.json) {
    try { el.textContent = JSON.stringify(JSON.parse(el.dataset.json), null, 2); } catch(e) { el.textContent = el.dataset.json; }
    delete el.dataset.json;
  }
  el.classList.toggle('open');
}

// ── Render single timeline entry ───────────────────────────────────────
function renderEntry(entry, idx) {
  const dot = dotCls(entry);
  return `
    <div class="tl-item">
      <div class="tl-spine">
        <div class="tl-dot ${esc(dot)}"></div>
        <div class="tl-connector"></div>
      </div>
      <div class="tl-body">
        ${renderEvidenceCard(entry, idx)}
      </div>
    </div>`;
}

function toggleEntry(idx) {
  // Legacy: kept for compatibility; D5 uses toggleRaw instead.
  toggleRaw(idx);
}


async function loadJourney(subjectType, subjectValue) {
  state.selected = { type: subjectType, value: subjectValue };
  syncFiltersFromUi();
  syncUrl();
  document.querySelectorAll('.attacker-card').forEach(c => c.classList.remove('active'));
  const card = document.querySelector(
    '.attacker-card[data-subject-type="' + CSS.escape(subjectType) + '"][data-subject-value="' + CSS.escape(subjectValue) + '"]'
  );
  if (card) {
    card.classList.add('active');
    // On mobile: scroll the active card into view and collapse list
    if (window.innerWidth <= 860) {
      card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      setTimeout(collapseLeftOnMobile, 200);
    }
  }

  document.getElementById('homeState').style.display = 'none';
  document.getElementById('journeyContent').style.display = 'block';
  document.getElementById('journeyContent').innerHTML = '<div class="loading" style="padding:40px;text-align:center"><div class="spinner" style="display:inline-block;width:20px;height:20px;border:2px solid var(--line2);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin-bottom:8px"></div><br>Loading timeline\u2026</div>';

  const panel = document.getElementById('rightPanel');

  try {
    const baseQs = buildQuery({
      subject_type: subjectType,
      subject: subjectValue,
      date: state.filters.date,
      severity_min: state.filters.severity_min,
      detector: state.filters.detector,
      window_seconds: state.filters.window_seconds,
    });
    const shouldCompare = state.filters.compare_date && state.filters.compare_date !== state.filters.date;
    const compareQs = shouldCompare
      ? buildQuery({
          subject_type: subjectType,
          subject: subjectValue,
          date: state.filters.compare_date,
          severity_min: state.filters.severity_min,
          detector: state.filters.detector,
          window_seconds: state.filters.window_seconds,
        })
      : '';
    const [j, compare] = await Promise.all([
      loadJson('/api/journey?' + baseQs),
      shouldCompare ? loadJson('/api/journey?' + compareQs) : Promise.resolve(null),
    ]);
    window._currentJourneyOutcome = j.outcome || 'unknown';
    const first = j.first_seen ? fmtDateTime(j.first_seen) : '-';
    const last  = j.last_seen  ? fmtDateTime(j.last_seen)  : '-';
    const summary = j.summary || {};
    const shortcuts = Array.isArray(summary.pivot_shortcuts) ? summary.pivot_shortcuts : [];
    const hints = Array.isArray(summary.hints) ? summary.hints : [];

    const summaryGrid = `
      <div class="summary-grid">
        <div class="summary-cell"><div class="summary-label">Entries</div><div class="summary-value">${summary.total_entries ?? j.entries.length}</div></div>
        <div class="summary-cell"><div class="summary-label">Events</div><div class="summary-value">${summary.events_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Incidents</div><div class="summary-value">${summary.incidents_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Decisions</div><div class="summary-value">${summary.decisions_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Honeypot</div><div class="summary-value">${summary.honeypot_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Window</div><div class="summary-value">${state.filters.window_seconds ? esc(state.filters.window_seconds + 's') : 'full day'}</div></div>
      </div>`;

    const hintsHtml = hints.length
      ? `<ul class="hint-list">${hints.map((h) => `<li class="hint-item">${esc(h)}</li>`).join('')}</ul>`
      : '<div class="empty">No hints available for current scope.</div>';

    const shortcutsHtml = shortcuts.length
      ? `<div class="shortcut-wrap">${shortcuts.map((token) =>
          `<button type="button" class="shortcut-btn" onclick="openPivotShortcut('${esc(token)}')">${esc(token)}</button>`
        ).join('')}</div>`
      : '';

    // Build action buttons if D3 actions are enabled for this subject type.
    let actionBtns = '';
    if (actionCfg && actionCfg.enabled && subjectType === 'ip') {
      if (j.outcome !== 'blocked') {
        actionBtns += `<button type="button" class="journey-btn action-block"
          onclick="showActionModal('block_ip','${esc(subjectValue)}',null)">⊘ Block IP</button>`;
      }
    }
    if (actionCfg && actionCfg.enabled && subjectType === 'user') {
      actionBtns += `<button type="button" class="journey-btn action-suspend"
        onclick="showActionModal('suspend_user',null,'${esc(subjectValue)}')">⏸ Suspend sudo</button>`;
    }

    // D5: store journey data globally for scrollToChapter
    window._journeyData = j;

    let html = `
      <div style="margin-bottom:12px">
        <button type="button" class="journey-btn" onclick="showHomeState()" style="font-size:0.68rem">← Back to Overview</button>
      </div>
      <div class="journey-header">
        <span class="journey-ip">${esc(j.subject || subjectValue)}</span>
        <span class="${outcomeCls(typeof outcomeOf === 'function' ? outcomeOf({outcome: j.outcome}) : j.outcome)}">${outcomeLabel(typeof outcomeOf === 'function' ? outcomeOf({outcome: j.outcome}) : j.outcome)}</span>
        <span class="journey-time">${esc(first)} → ${esc(last)}</span>
      </div>
      <div class="journey-subtitle">${esc((j.subject_type || subjectType).toUpperCase())} journey · ${j.entries.length} timeline entries · click any row to expand</div>
      <div class="journey-actions">
        <button type="button" class="journey-btn" onclick="downloadSnapshot('json')">Export JSON</button>
        <button type="button" class="journey-btn" onclick="downloadSnapshot('md')">Export Markdown</button>
        ${actionBtns}
      </div>
      <!-- verdict card removed: narrative "What happened" + Intelligence section cover this -->
      ${(function() {
        // TL;DR — human-readable narrative, mode-aware.
        const incidents = j.entries.filter(e => e.kind === 'incident');
        const decisions = j.entries.filter(e => e.kind === 'decision');
        // Journey entries serialize decisions as {kind, ts, data:{action_type,...}}.
        // The legacy read of `e.action` returned undefined for every entry so
        // `wasBlocked` was always false and the narrative fell through to
        // "AI decided to monitor" even when a block_ip actually executed.
        const actionOf = e => ((e && e.data && e.data.action_type) || '');
        const blocks = decisions.filter(e => actionOf(e).includes('block'));
        if (incidents.length === 0 && decisions.length === 0) return '';

        const topIncident = incidents.length > 0 ? incidents[0] : null;
        const topData = topIncident ? (topIncident.data || {}) : {};
        const topTitle = topData.title || '';
        const wasBlocked = blocks.length > 0;
        const isGuard = (window._agentMode || 'guard') === 'guard';
        const isResolved = j.outcome === 'blocked' || j.outcome === 'honeypot';

        // Collect all unique detectors across incidents for multi-detector signal
        const allDetectors = new Set();
        incidents.forEach(function(inc) {
          var d = (inc.data || {}).detector || ((inc.data || {}).incident_id || '').split(':')[0] || '';
          if (d) allDetectors.add(d);
        });
        const detLabels = Array.from(allDetectors).map(function(d) { return humanLabel(d); });

        let narrative = '';
        if (topIncident) {
          // Use the incident title for specific context, detector label as category
          if (topTitle && topTitle !== 'unknown') {
            narrative += '<strong>' + esc(topTitle) + '</strong>';
          } else {
            narrative += '<strong>' + esc(detLabels[0] || 'Threat') + '</strong> detected';
          }
          if (incidents.length > 1) narrative += ' (' + incidents.length + ' incidents total)';
          if (detLabels.length > 1) {
            narrative += '. Triggered <strong>' + detLabels.length + ' detectors</strong>: ' + esc(detLabels.join(', '));
          }
          narrative += '. ';
        }
        if (wasBlocked) {
          narrative += 'The AI <strong style="color:var(--ok)">blocked</strong> this threat';
          if (blocks.length > 1) narrative += ' (' + blocks.length + ' actions)';
          narrative += '. ';
        } else if (decisions.length > 0) {
          // Pair with the actionOf() reader above: decisions carry the
          // action label on `data.action_type`, not on the entry itself.
          const action = actionOf(decisions[0]) || 'monitor';
          narrative += 'The AI decided to <strong>' + esc(action.replace(/_/g, ' ')) + '</strong>. ';
        }
        if (isResolved) {
          narrative += 'Threat <strong style="color:var(--ok)">contained</strong>. No action needed.';
        } else if (isGuard) {
          narrative += 'The AI is <strong>still observing</strong> this activity.';
        }

        let html = '<div style="padding:12px 16px;margin-bottom:12px;border-radius:10px;background:rgba(120,229,255,0.04);border:1px solid rgba(120,229,255,0.12)">' +
          '<div style="font-size:0.68rem;font-weight:700;color:var(--accent);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:4px">What happened</div>' +
          '<div style="font-size:0.8rem;color:var(--text);line-height:1.5">' + narrative + '</div></div>';

        // When guard is OFF and the threat is NOT resolved, show a prominent
        // decision block with AI recommendation + action buttons. This is
        // the operator's moment to decide.
        if (!isGuard && !isResolved && subjectType === 'ip') {
          const topSev = topData.severity || '';
          const sevHigh = topSev === 'critical' || topSev === 'high';
          const hasThreatIntel = allDetectors.has('threat_intel') || allDetectors.has('graph_threat_intel');
          const multiDetector = allDetectors.size > 1;

          let recText = '';
          if (hasThreatIntel && sevHigh) {
            recText = 'This IP is in a <strong style="color:var(--danger)">known malicious threat feed</strong> and triggered ' + allDetectors.size + ' detectors. <strong>Blocking is strongly recommended.</strong>';
          } else if (hasThreatIntel) {
            recText = 'This IP is in a <strong>known malicious threat feed</strong>. The AI recommends blocking.';
          } else if (sevHigh && multiDetector) {
            recText = 'This is a <strong style="color:var(--danger)">' + esc(topSev) + ' severity</strong> threat that triggered ' + allDetectors.size + ' detectors. The AI recommends <strong>blocking this IP</strong>.';
          } else if (sevHigh) {
            recText = 'This is a <strong style="color:var(--danger)">' + esc(topSev) + ' severity</strong> threat. The AI recommends <strong>blocking this IP</strong>.';
          } else {
            recText = 'The AI detected suspicious activity from this IP. You can block it or continue observing.';
          }

          html += '<div style="padding:16px;margin-bottom:12px;border-radius:10px;background:rgba(244,63,94,0.06);border:1px solid rgba(244,63,94,0.2)">' +
            '<div style="font-size:0.68rem;font-weight:700;color:var(--danger);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:6px">\u26A0 Your decision needed</div>' +
            '<div style="font-size:0.8rem;color:var(--text);line-height:1.5;margin-bottom:12px">' + recText + '</div>' +
            '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
              '<button type="button" style="padding:8px 20px;font-size:0.8rem;font-weight:700;border-radius:8px;border:1px solid var(--danger);background:var(--danger);color:#fff;cursor:pointer" onclick="showActionModal(\'block_ip\',\'' + esc(subjectValue) + '\',null)">\u26D4 Block this IP</button>' +
              '<button type="button" style="padding:8px 20px;font-size:0.8rem;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--muted);cursor:pointer" onclick="showToast(\'Continuing to observe\',\'ok\')">Keep observing</button>' +
            '</div>' +
          '</div>';
        }

        return html;
      })()}
      <!-- Attack graph available in Graph tab -->
      <div id="journeyGraphContainer" style="display:none"></div>
      <div class="guided-grid">
        <section class="guided-card">
          <div class="guided-title">Investigation Summary</div>
          ${summaryGrid}
          ${shortcutsHtml}
        </section>
        <section class="guided-card">
          <div class="guided-title">Intelligence</div>
          ${hintsHtml}
        </section>
      </div>`;

    if (compare) {
      const baseS = j.summary || {};
      const cmpS = compare.summary || {};
      const metrics = [
        ['Entries', baseS.total_entries ?? j.entries.length, cmpS.total_entries ?? compare.entries.length],
        ['Incidents', baseS.incidents_count ?? 0, cmpS.incidents_count ?? 0],
        ['Decisions', baseS.decisions_count ?? 0, cmpS.decisions_count ?? 0],
        ['Honeypot', baseS.honeypot_count ?? 0, cmpS.honeypot_count ?? 0],
      ];
      const compareRows = metrics.map(([label, current, previous]) => {
        const delta = Number(current) - Number(previous);
        const deltaLabel = delta > 0 ? '+' + delta : String(delta);
        const deltaCls = delta > 0 ? 'delta-pos' : (delta < 0 ? 'delta-neg' : 'delta-neu');
        return `<div class="compare-cell">
          <div class="summary-label">${esc(label)}</div>
          <div class="summary-value">${current} <span class="${deltaCls}">(${deltaLabel})</span></div>
          <div class="summary-label">compare: ${previous}</div>
        </div>`;
      }).join('');
      html += `
        <section class="guided-card" style="margin-bottom:14px">
          <div class="guided-title">Comparison vs ${esc(state.filters.compare_date)}</div>
          <div class="journey-subtitle" style="margin-bottom:10px">
            current outcome: <strong>${esc(outcomeLabel(j.outcome))}</strong> · compare outcome: <strong>${esc(outcomeLabel(compare.outcome))}</strong>
          </div>
          <div class="compare-grid">${compareRows}</div>
        </section>`;
    }

    // ── AI Decision Reasoning (surfaced from decision entries) ─────────
    // Show the AI's own reasoning prominently, before any technical data.
    // This is the "why" that the operator needs to trust the AI's action.
    const aiDecisions = j.entries.filter(e => e.kind === 'decision' && (e.data || {}).reason);
    if (aiDecisions.length > 0) {
      const dec = aiDecisions[0].data;
      const conf = ((dec.confidence || 0) * 100).toFixed(0);
      const wasExecuted = dec.auto_executed && !dec.dry_run;
      const actionLabel = (dec.action_type || '').replace(/_/g, ' ');
      html += '<div style="padding:14px 16px;margin-bottom:12px;border-radius:10px;background:rgba(74,222,128,0.04);border:1px solid rgba(74,222,128,0.15)">' +
        '<div style="font-size:0.68rem;font-weight:700;color:var(--ok);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:6px">' +
        (wasExecuted ? '\uD83E\uDD16 AI Decision — ' + esc(actionLabel) + ' (' + conf + '% confidence)' : '\uD83E\uDD16 AI Analysis') +
        '</div>' +
        '<div style="font-size:0.78rem;color:var(--text);line-height:1.6">' + esc(dec.reason || '') + '</div>' +
      '</div>';
    }

    // ── Ask AI button ─────────────────────────────────────────────────
    html += '<div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">' +
      '<button type="button" class="journey-btn" style="background:rgba(120,229,255,0.08);border-color:var(--accent);color:var(--accent)" ' +
        'onclick="askAiExplain(\'' + esc(subjectType) + '\',\'' + esc(subjectValue) + '\')">' +
        '\uD83E\uDD16 Ask AI to explain</button>' +
      '<button type="button" class="journey-btn" onclick="toggleTimeline()">' +
        '\uD83D\uDCCB Show ' + j.entries.length + ' technical entries</button>' +
    '</div>';
    html += '<div id="aiExplainResult" style="display:none;padding:14px 16px;margin-bottom:12px;border-radius:10px;background:rgba(120,229,255,0.04);border:1px solid rgba(120,229,255,0.12)"></div>';

    // ── Chapter rail (collapsed with timeline) ─────────────────────────
    html += '<div id="timelineSection" style="display:none">';
    html += renderChapterRail(j);

    html += '<div class="timeline">';

    if (j.entries.length === 0) {
      html += '<div class="empty">No entries found for this selection on the chosen filters.</div>';
    } else {
      j.entries.forEach((e, i) => { html += renderEntry(e, i); });
    }

    html += '</div></div>';
    document.getElementById('journeyContent').innerHTML = html;

    // Load mini-graph for this subject
    loadJourneyGraph(subjectType, subjectValue);
  } catch (e) {
    document.getElementById('journeyContent').innerHTML = '<div class="err">Failed to load journey: ' + esc(e.message) + '</div>';
  }
}

async function loadJourneyGraph(subjectType, subjectValue) {
  const container = document.getElementById('journeyGraphContainer');
  if (!container) return;

  // Map journey subject type to graph node type
  const typeMap = { ip: 'ip', user: 'user', container: 'container', path: 'file', file: 'file' };
  const gType = typeMap[subjectType] || subjectType;

  try {
    // Ensure Cytoscape.js is loaded
    if (typeof cytoscape === 'undefined') {
      try {
        await new Promise((resolve, reject) => {
          const s = document.createElement('script');
          s.src = 'https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js';
          s.onload = resolve;
          s.onerror = reject;
          document.head.appendChild(s);
          setTimeout(() => reject(new Error('timeout')), 5000);
        });
      } catch (e) {
        container.innerHTML = '<p style="padding:20px;text-align:center;color:var(--dim);font-size:0.75rem">Graph requires internet (Cytoscape.js)</p>';
        return;
      }
    }

    const data = await loadJson('/api/graph/neighborhood?type=' + encodeURIComponent(gType) + '&value=' + encodeURIComponent(subjectValue) + '&depth=2');

    if (!data.nodes || data.nodes.length === 0) {
      container.innerHTML = '<p style="padding:20px;text-align:center;color:var(--dim);font-size:0.75rem">No graph data for this entity yet</p>';
      return;
    }

    const cy = cytoscape({
      container: container,
      elements: { nodes: data.nodes, edges: data.edges },
      style: [
        { selector: 'node', style: {
          'label': 'data(label)',
          'background-color': function(ele) { return NODE_COLORS[ele.data('type')] || '#6b7280'; },
          'color': '#e8eef5',
          'text-valign': 'bottom',
          'text-margin-y': 3,
          'font-size': '9px',
          'width': function(ele) { return Math.max(12, Math.min(35, 8 + ele.degree() * 2)); },
          'height': function(ele) { return Math.max(12, Math.min(35, 8 + ele.degree() * 2)); },
          'border-width': function(ele) { return ele.data('center') ? 3 : 1; },
          'border-color': function(ele) { return ele.data('center') ? '#00d9ff' : '#333'; },
        }},
        { selector: 'edge', style: {
          'width': 1,
          'line-color': '#444',
          'target-arrow-color': '#555',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(relation)',
          'font-size': '7px',
          'color': '#555',
          'text-rotation': 'autorotate',
          'text-margin-y': -6,
        }},
      ],
      layout: { name: 'cose', animate: false, nodeRepulsion: 6000, idealEdgeLength: 60, padding: 15 },
      minZoom: 0.3, maxZoom: 4,
      userPanningEnabled: true,
      userZoomingEnabled: true,
    });

    // Click on a node: navigate to its journey if it's an IP or user
    cy.on('tap', 'node', function(evt) {
      const d = evt.target.data();
      if (d.type === 'Ip') {
        loadJourney('ip', d.label);
      } else if (d.type === 'User') {
        loadJourney('user', d.label);
      }
    });

  } catch (e) {
    container.innerHTML = '<p style="padding:20px;text-align:center;color:var(--dim);font-size:0.75rem">Graph: ' + esc(e.message) + '</p>';
  }
}

// ── Observation Verification score display (spec 021 Phase D) ──────────

/** Parse obs-verify reason string and render a visual score badge + breakdown.
 *  Format: "obs-verify score X/100: reason1, reason2"
 *  or:     "obs-verify AI: VERDICT — reason"
 */
function renderObsVerifyScore(reason) {
  if (!reason) return '';

  // Parse "obs-verify score X/100: details"
  var scoreMatch = reason.match(/obs-verify score (\d+)\/100:\s*(.*)/);
  if (scoreMatch) {
    var score = parseInt(scoreMatch[1], 10);
    var details = scoreMatch[2] || '';
    var checks = details.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
    var color = score >= 70 ? 'var(--ok)' : score < 40 ? 'var(--critical)' : 'var(--accent)';
    var label = score >= 70 ? 'AUTO-DISMISSED' : score < 40 ? 'ESCALATED' : 'AI VERIFIED';

    var checkIcons = {
      'package managed binary': true, 'trusted directory': true,
      'trusted parent chain': true, 'DNS resolves': true,
      'known binary': true, 'operator context': true,
      'suspicious binary location': false, 'untrusted parent chain': false,
      'suspicious network behaviour': false, 'fresh unknown binary': false,
      'no operator context': false
    };

    var checksHtml = checks.map(function(c) {
      var isGood = checkIcons[c] !== undefined ? checkIcons[c] : !c.startsWith('suspicious') && !c.startsWith('untrusted') && !c.startsWith('fresh') && !c.startsWith('no ');
      var icon = isGood ? '<span style="color:var(--ok)">&#10003;</span>' : '<span style="color:var(--critical)">&#10007;</span>';
      return icon + ' ' + esc(c);
    }).join('<br>');

    return '<div class="obs-verify-card">'
      + '<div class="obs-verify-header">'
      + '<span class="obs-verify-badge" style="background:' + color + '">' + score + '/100</span>'
      + '<span class="obs-verify-label">' + label + '</span>'
      + '</div>'
      + (checksHtml ? '<div class="obs-verify-checks">' + checksHtml + '</div>' : '')
      + '</div>';
  }

  // Parse "obs-verify AI: VERDICT — reason"
  var aiMatch = reason.match(/obs-verify AI:\s*(NORMAL|SUSPICIOUS)\s*[—-]\s*(.*)/i);
  if (aiMatch) {
    var verdict = aiMatch[1].toUpperCase();
    var aiReason = aiMatch[2] || '';
    var aiColor = verdict === 'NORMAL' ? 'var(--ok)' : 'var(--critical)';
    var aiIcon = verdict === 'NORMAL' ? '&#10003;' : '&#10007;';
    return '<div class="obs-verify-card">'
      + '<div class="obs-verify-header">'
      + '<span class="obs-verify-badge" style="background:' + aiColor + '">' + aiIcon + ' AI</span>'
      + '<span class="obs-verify-label">' + esc(verdict) + '</span>'
      + '</div>'
      + '<div class="obs-verify-checks">' + esc(aiReason) + '</div>'
      + '</div>';
  }

  return '';
}

// Detector priority: higher = more important (used to pick primary group)
