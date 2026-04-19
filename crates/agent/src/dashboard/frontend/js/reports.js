// ── D10 - Report tab ────────────────────────────────────────────────────
async function loadReportDates() {
  try {
    const dates = await loadJson('/api/report/dates');
    const sel = document.getElementById('reportDateSelect');
    sel.innerHTML = '<option value="">latest</option>';
    (dates || []).forEach(d => {
      const opt = document.createElement('option');
      opt.value = d; opt.textContent = d;
      sel.appendChild(opt);
    });
  } catch (e) { console.warn('loadReportDates:', e); }
}


async function loadReport() {
  const status = document.getElementById('reportStatus');
  const content = document.getElementById('reportContent');
  const date = document.getElementById('reportDateSelect')?.value || '';
  status.textContent = 'Loading…';
  content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
  try {
    const url = '/api/report' + (date ? '?date=' + encodeURIComponent(date) : '');
    const r = await loadJson(url);
    status.textContent = 'Generated ' + new Date(r.generated_at).toLocaleTimeString();
    content.innerHTML = renderReport(r);
  } catch (e) {
    status.textContent = 'error';
    content.innerHTML = '<div class="empty" style="padding:40px;color:var(--danger)">Failed to load report: ' + esc(e.message) + '</div>';
  }
}

function navigateReport(dir) {
  const sel = document.getElementById('reportDateSelect');
  const opts = Array.from(sel.options).filter(o => o.value);
  if (!opts.length) return;
  const cur = sel.value;
  const idx = opts.findIndex(o => o.value === cur);
  const nextIdx = idx === -1 ? (dir < 0 ? opts.length - 1 : 0) : Math.max(0, Math.min(opts.length - 1, idx - dir));
  sel.value = opts[nextIdx]?.value || '';
  loadReport();
}

async function exportReport() {
  const date = document.getElementById('reportDateSelect')?.value || '';
  try {
    const url = '/api/export?format=markdown' + (date ? '&date=' + encodeURIComponent(date) : '');
    const text = await loadText(url);
    const fname = 'innerwarden-report-' + (date || new Date().toISOString().slice(0,10)) + '.md';
    downloadBlob(fname, 'text/markdown', text);
  } catch(e) {
    showToast('Export failed: ' + e.message, 'err');
  }
}

function renderReport(r) {
  function sparkline(values, color) {
    if (!values || values.length < 2) return '';
    const max = Math.max(...values, 1);
    const w = 80, h = 28, pad = 2;
    const pts = values.map((v, i) => {
      const x = pad + (i / (values.length - 1)) * (w - pad * 2);
      const y = h - pad - ((v / max) * (h - pad * 2));
      return x.toFixed(1) + ',' + y.toFixed(1);
    }).join(' ');
    const lastPt = pts.split(' ').pop().split(',');
    return '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" style="display:block;overflow:visible">' +
      '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" opacity="0.85"/>' +
      '<circle cx="' + lastPt[0] + '" cy="' + lastPt[1] + '" r="2.5" fill="' + color + '"/>' +
      '</svg>';
  }
  const ds = r.detection_summary || {};
  const ai = r.agent_ai_summary || {};
  const rw = r.recent_window || {};
  const tr = r.trend_summary || {};
  const oh = r.operational_health || {};
  const hints = r.anomaly_hints || [];
  const suggestions = r.suggested_improvements || [];

  const pct = (v) => v == null ? '-' : (v > 0 ? '+' : '') + v.toFixed(1) + '%';
  const deltaClass = (d) => d > 0 ? 'up' : (d < 0 ? 'down' : '');
  const deltaSign = (d) => d > 0 ? '+' : '';
  const confColor = (v) => v >= 0.85 ? 'good' : v >= 0.7 ? 'warn' : 'bad';
  const healthVal = (v) => v ? '<span class="health-ok">✓ OK</span>' : '<span class="health-fail">✗ Fail</span>';

  // Hero KPIs — the 3 numbers that matter most
  const hcRecent = rw.high_critical_incidents ?? 0;
  const blocksToday = ai.block_ip_count ?? 0;
  const totalIncidents = ds.total_incidents ?? 0;
  let html = `<div class="report-section">
    <div class="report-section-title">Summary &mdash; ${esc(r.analyzed_date)}</div>
    <div class="report-kpi-row" style="grid-template-columns:repeat(3,1fr)">
      <div class="report-kpi" style="text-align:center">
        <div class="report-kpi-label">Incidents Today</div>
        <div class="report-kpi-value" style="font-size:1.8rem">${totalIncidents}</div>
        <div style="font-size:0.62rem;color:var(--muted)">${ds.total_events ?? 0} events analyzed</div>
      </div>
      <div class="report-kpi" style="text-align:center">
        <div class="report-kpi-label">Auto-Blocked</div>
        <div class="report-kpi-value" style="font-size:1.8rem;color:var(--ok)">${blocksToday}</div>
        <div style="font-size:0.62rem;color:var(--muted)">${((ai.average_confidence ?? 0) * 100).toFixed(0)}% avg AI confidence</div>
      </div>
      <div class="report-kpi" style="text-align:center">
        <div class="report-kpi-label">High-Risk Alerts (6h)</div>
        <div class="report-kpi-value ${hcRecent > 0 ? 'bad' : 'good'}" style="font-size:1.8rem">${hcRecent}</div>
        <div style="font-size:0.62rem;color:var(--muted)">${rw.incidents ?? 0} total last 6 hours</div>
      </div>
    </div>
    <div style="margin-top:8px;cursor:pointer;font-size:0.65rem;color:var(--muted)" onclick="var el=document.getElementById('reportDetailKpis');el.style.display=el.style.display==='none'?'grid':'none'">
      All metrics &#9662;
    </div>
    <div id="reportDetailKpis" class="report-kpi-row" style="display:none;margin-top:8px">
      <div class="report-kpi"><div class="report-kpi-label">Events</div><div class="report-kpi-value">${ds.total_events ?? 0}</div></div>
      <div class="report-kpi"><div class="report-kpi-label">Decisions</div><div class="report-kpi-value">${ai.total_decisions ?? 0}</div></div>
      <div class="report-kpi"><div class="report-kpi-label">Avg Conf</div><div class="report-kpi-value ${confColor(ai.average_confidence ?? 0)}">${((ai.average_confidence ?? 0) * 100).toFixed(0)}%</div></div>
      <div class="report-kpi"><div class="report-kpi-label">Last 6h Incid.</div><div class="report-kpi-value">${rw.incidents ?? 0}</div></div>
    </div>
  </div>`;

  // Trend section
  if (tr.previous_date) {
    html += `<div class="report-section">
      <div class="report-section-title">Trend vs ${esc(tr.previous_date)}</div>
      <div class="report-trend-row">
        ${trendCell('Events', tr.events)}
        ${trendCell('Incidents', tr.incidents)}
        ${trendCell('Decisions', tr.decisions)}
        ${trendCellF('Incid/1k Events', tr.incident_rate_per_1k_events)}
        ${trendCellF('Dec/Incident', tr.decision_rate_per_incident)}
        ${trendCellF('Avg Confidence', tr.average_confidence, true)}
      </div>
    </div>`;
  }

  function trendCell(label, c) {
    if (!c) return '';
    const d = c.delta ?? 0;
    const p = c.pct_change != null ? ` (${pct(c.pct_change)})` : '';
    return `<div class="report-trend-cell">
      <div class="report-trend-label">${esc(label)}</div>
      <div class="report-trend-nums">${c.current} <span style="color:var(--muted)">/ prev ${c.previous}</span></div>
      <div class="report-trend-delta ${deltaClass(d)}">${deltaSign(d)}${d}${p}</div>
    </div>`;
  }
  function trendCellF(label, c, higherGood) {
    if (!c) return '';
    const d = c.delta ?? 0;
    const cls = higherGood ? (d > 0 ? 'down' : d < 0 ? 'up' : '') : deltaClass(d);
    const p = c.pct_change != null ? ` (${pct(c.pct_change)})` : '';
    return `<div class="report-trend-cell">
      <div class="report-trend-label">${esc(label)}</div>
      <div class="report-trend-nums">${c.current.toFixed(2)} <span style="color:var(--muted)">/ prev ${c.previous.toFixed(2)}</span></div>
      <div class="report-trend-delta ${cls}">${deltaSign(d)}${d.toFixed(2)}${p}</div>
    </div>`;
  }

  // Anomaly hints
  if (hints.length > 0) {
    html += `<div class="report-section">
      <div class="report-section-title">Anomaly Hints</div>`;
    hints.forEach(h => {
      const sev = (h.severity || 'info').toLowerCase();
      html += `<div class="report-anomaly ${esc(sev)}">
        <span class="report-anomaly-badge badge-${esc(sev)}">${esc(h.severity)}</span>
        <span class="report-anomaly-msg">${esc(h.message)}</span>
      </div>`;
    });
    html += `</div>`;
  }

  // Top IPs
  if ((ds.top_ips || []).length > 0) {
    html += `<div class="report-section">
      <div class="report-section-title">Top IPs</div>
      <table class="report-table">
        <thead><tr><th>IP</th><th>Events</th></tr></thead><tbody>`;
    ds.top_ips.forEach(e => {
      html += `<tr><td>${esc(e.name)}</td><td>${e.count}</td></tr>`;
    });
    html += `</tbody></table></div>`;
  }

  // Incidents by type
  const ibt = ds.incidents_by_type || {};
  if (Object.keys(ibt).length > 0) {
    html += `<div class="report-section">
      <div class="report-section-title">Incidents by Type</div>
      <table class="report-table">
        <thead><tr><th>Detector</th><th>Count</th></tr></thead><tbody>`;
    Object.entries(ibt).sort((a,b) => b[1]-a[1]).forEach(([k,v]) => {
      html += `<tr><td>${esc(k)}</td><td>${v}</td></tr>`;
    });
    html += `</tbody></table></div>`;
  }

  // Operational health
  html += `<div class="report-section">
    <div class="report-section-title">Operational Health</div>
    <table class="report-table"><thead><tr><th>File</th><th>Exists</th><th>Valid</th><th>Lines</th><th>Size</th></tr></thead><tbody>`;
  (oh.files || []).forEach(f => {
    // Spec 016 migrated events to SQLite. The events.jsonl file no
    // longer exists on disk, so its "Exists: ✗" used to look like a
    // health failure. Show "SQLite" for the events row instead; the
    // rest still use jsonl backing.
    const isSqliteOnly = (f.file === 'events' && !f.exists);
    const existsCell = isSqliteOnly
      ? '<span class="health-ok" title="stored in innerwarden.db (spec 016)">SQLite</span>'
      : (f.exists ? '<span class="health-ok">✓</span>' : '<span class="health-fail">✗</span>');
    const valid = isSqliteOnly
      ? '<span class="health-ok">✓</span>'
      : (f.jsonl_valid == null ? '-' : (f.jsonl_valid ? '<span class="health-ok">✓</span>' : '<span class="health-fail">✗</span>'));
    const linesCell = isSqliteOnly ? '(in db)' : (f.lines ?? '-');
    const sizeCell = isSqliteOnly
      ? '-'
      : (f.size_bytes > 0 ? (f.size_bytes > 1048576 ? (f.size_bytes/1048576).toFixed(1)+'MB' : (f.size_bytes/1024).toFixed(1)+'KB') : '0B');
    html += `<tr>
      <td>${esc(f.file)}</td>
      <td>${existsCell}</td>
      <td>${valid}</td>
      <td>${linesCell}</td>
      <td>${sizeCell}</td>
    </tr>`;
  });
  html += `</tbody></table></div>`;

  // Suggestions
  if (suggestions.length > 0) {
    html += `<div class="report-section">
      <div class="report-section-title">Suggestions</div>`;
    suggestions.forEach(s => {
      html += `<div class="report-suggestion"><span style="color:var(--accent);flex-shrink:0">→</span><span>${esc(s)}</span></div>`;
    });
    html += `</div>`;
  }

  return html;
}
