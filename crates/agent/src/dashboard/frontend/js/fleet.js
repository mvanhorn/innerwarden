// ── Fleet view (spec 038 Phase 3) ─────────────────────────────────
//
// The Fleet tab shows aggregate KPIs across every spoke the manager
// polls plus a per-host card grid. Backend: `/api/fleet/overview`
// returns `{ fleet: FleetSummary, by_host: HostStatus[] }` when
// fleet mode is enabled, 404 otherwise.
//
// Visibility: the Fleet button starts hidden. `probeFleetEnabled`
// runs at boot and unhides the button when the backend reports
// fleet mode active. Operators on a single-host install never see
// a tab they cannot use.

async function probeFleetEnabled() {
  try {
    const r = await fetch('/api/fleet/hosts', { cache: 'no-store' });
    if (!r.ok) return;  // 404 keeps the button hidden
    const btn = document.getElementById('navFleet');
    if (btn) btn.style.display = '';
  } catch (_) {
    // Network error — leave the button hidden.
  }
}

async function loadFleet() {
  const status = document.getElementById('fleetViewStatus');
  const content = document.getElementById('fleetContent');
  if (!status || !content) return;
  status.textContent = 'Loading…';
  try {
    const r = await fetch('/api/fleet/overview', { cache: 'no-store' });
    if (r.status === 404) {
      content.innerHTML = '<div class="empty" style="padding:40px;text-align:center;color:var(--muted)">Fleet mode is not enabled. Set <code>[fleet] enabled = true</code> in <code>agent.toml</code> with at least one host configured.</div>';
      status.textContent = '';
      return;
    }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    content.innerHTML = renderFleet(data);
    status.textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    content.innerHTML = '<div class="empty" style="padding:40px;text-align:center;color:var(--danger)">Failed to load fleet: ' + esc(e.message) + '</div>';
    status.textContent = 'Error';
  }
}

function renderFleet(data) {
  const f = data.fleet || {};
  const hosts = data.by_host || [];
  const anyUnhealthy = !!f.any_unhealthy || (f.degraded_count || 0) > 0;
  const headColor = (f.down_count || 0) > 0
    ? 'var(--danger)'
    : anyUnhealthy
    ? 'var(--warn)'
    : 'var(--ok)';
  const upTotal = f.up_count || 0;
  const headLabel = `${upTotal} of ${f.host_count || 0} hosts up`;

  // ── Aggregate KPI strip ───────────────────────────────────────────
  let html = '<div style="margin-bottom:18px">' +
    '<div style="font-size:0.78rem;font-weight:700;color:' + headColor + ';margin-bottom:8px;letter-spacing:0.04em;text-transform:uppercase">' +
      esc(headLabel) +
    '</div>' +
    '<div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px">' +
      kpiTile('Events', f.events_count || 0) +
      kpiTile('Incidents', f.incidents_count || 0) +
      kpiTile('Decisions', f.decisions_count || 0) +
      kpiTile('Blocked', f.blocked_count || 0, 'var(--ok)') +
      kpiTile('Observing', f.observing_count || 0, 'var(--accent)') +
      kpiTile('Awaiting review', f.attention_count || 0, (f.attention_count || 0) > 0 ? 'var(--warn)' : '') +
    '</div></div>';

  if ((f.degraded_count || 0) > 0 || (f.down_count || 0) > 0) {
    const parts = [];
    if (f.degraded_count) parts.push(f.degraded_count + ' degraded');
    if (f.down_count) parts.push(f.down_count + ' down');
    html += '<div style="padding:10px 14px;margin-bottom:14px;border-left:3px solid var(--warn);background:rgba(255,184,77,0.06);border-radius:3px;font-size:0.8rem">' +
      '<strong style="color:var(--warn)">Fleet has unhealthy hosts:</strong> ' + esc(parts.join(' · ')) +
      '</div>';
  }

  // ── Per-host card grid ────────────────────────────────────────────
  html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">';
  hosts.forEach(function(h) {
    html += renderHostCard(h);
  });
  html += '</div>';

  if (hosts.length === 0) {
    html += '<div class="empty" style="padding:40px;text-align:center;color:var(--muted)">No hosts configured. Add entries under <code>[[fleet.hosts]]</code> in <code>agent.toml</code>.</div>';
  }
  return html;
}

function kpiTile(label, value, valueColor) {
  const colorStyle = valueColor ? ('color:' + valueColor + ';') : '';
  return '<div class="kpi-card">' +
    '<div class="kpi-value" style="' + colorStyle + '">' + esc(formatBigNumber(value)) + '</div>' +
    '<div class="kpi-label">' + esc(label) + '</div>' +
    '</div>';
}

function renderHostCard(h) {
  const stateColors = {
    up: 'var(--ok)',
    down: 'var(--danger)',
    degraded: 'var(--warn)',
    unknown: 'var(--muted)',
  };
  const dotColor = stateColors[h.state] || 'var(--muted)';
  const lastPolled = h.last_polled_at ? fmtAgo(Math.floor((Date.now() - new Date(h.last_polled_at).getTime()) / 1000)) : 'never';
  const ov = h.overview;
  let kpiLine = '';
  if (h.state === 'up' || h.state === 'degraded') {
    if (ov) {
      kpiLine = '<div style="display:flex;gap:14px;font-size:0.7rem;color:var(--muted);margin-top:8px;flex-wrap:wrap">' +
        '<span><strong style="color:var(--text)">' + (ov.events_count || 0) + '</strong> events</span>' +
        '<span><strong style="color:var(--text)">' + (ov.incidents_count || 0) + '</strong> incidents</span>' +
        '<span><strong style="color:var(--ok)">' + (ov.blocked_count || 0) + '</strong> blocked</span>' +
        ((ov.attention_count || 0) > 0
          ? '<span><strong style="color:var(--warn)">' + ov.attention_count + '</strong> awaiting</span>'
          : '') +
        '</div>';
    } else {
      kpiLine = '<div style="font-size:0.7rem;color:var(--muted);margin-top:8px">snapshot pending…</div>';
    }
  } else if (h.last_error) {
    kpiLine = '<div style="font-size:0.7rem;color:var(--danger);margin-top:8px;font-family:\'JetBrains Mono\',monospace">' +
      esc(h.last_error) + '</div>';
  }
  return '<div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:14px">' +
    '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
      '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + dotColor + ';box-shadow:0 0 6px ' + dotColor + '"></span>' +
      '<span style="font-weight:700;color:var(--text);font-size:0.88rem">' + esc(h.id) + '</span>' +
      '<span style="font-size:0.62rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.08em;margin-left:auto">' + esc(h.state) + '</span>' +
    '</div>' +
    '<div style="font-size:0.68rem;color:var(--dim);font-family:\'JetBrains Mono\',monospace;word-break:break-all">' + esc(h.url) + '</div>' +
    '<div style="font-size:0.65rem;color:var(--muted);margin-top:4px">last poll: ' + esc(lastPolled) + '</div>' +
    kpiLine +
    '</div>';
}

// Boot probe: hide the Fleet button on single-host installs.
probeFleetEnabled();
