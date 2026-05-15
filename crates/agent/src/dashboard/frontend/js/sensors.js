// ── Sensors view ─────────────────────────────────────────────────────
// Site palette: chart-1 #7fe7ff, chart-2 #4ade80, chart-3 #fbbf24, chart-4 #fb7185, chart-5 #60a5fa
const SENSOR_COLORS = {
  ebpf: '#7fe7ff', auditd: '#fb7185', auth_log: '#fbbf24', journald: '#4ade80',
  docker: '#60a5fa', nginx: '#f97316', syslog: '#8b9db8', integrity: '#84cc16', cloudtrail: '#3b82f6',
  exec_audit: '#fb7185', syslog_firewall: '#8b9db8', firmware_integrity: '#84cc16',
  macos_log: '#a78bfa',  };
function sensorColor(name) { return SENSOR_COLORS[name] || '#78e5ff'; }

// Mirror of `crates/sensor/src/collector_health.rs::COLLECTOR_MANIFEST`.
// Frontend needs to know which collectors are alarm-style (low count
// = healthy, silence is good) vs telemetry-style (low count = broken).
// Cross-file anchor in `crates/agent/src/dashboard/mod.rs` asserts
// every Rust manifest entry has a JS entry — drift fails CI.
const COLLECTOR_CATEGORY = {
  // Telemetry: always-on, high-volume feeds. Low count → broken.
  auth_log: 'telemetry',
  auditd: 'telemetry',
  cgroup: 'telemetry',
  cloudtrail: 'telemetry',
  dns_capture: 'telemetry',
  ebpf: 'telemetry',
  ebpf_syscall: 'telemetry',
  exec_audit: 'telemetry',
  file_extract: 'telemetry',
  http_capture: 'telemetry',
  journald: 'telemetry',
  kernel_integrity: 'telemetry',
  macos_log: 'telemetry',
  net_snapshot: 'telemetry',
  nginx_access: 'telemetry',
  nginx_error: 'telemetry',
  osquery_log: 'telemetry',
  proc_maps: 'telemetry',
  proto_http: 'telemetry',
  proto_smb: 'telemetry',
  proto_ssh: 'telemetry',
  suricata_eve: 'telemetry',
  syslog_firewall: 'telemetry',
  tcp_stream: 'telemetry',
  // Alarm: event-driven detectors. Silence is healthy.
  docker: 'alarm',
  fanotify_watch: 'alarm',
  firmware_integrity: 'alarm',
  integrity: 'alarm',
  sysctl_drift: 'alarm',
  tls_fingerprint: 'alarm',
  usb_monitor: 'alarm',
  // Snapshot: periodic point-in-time inventory.
  suid_inventory: 'snapshot',
  systemd_inventory: 'snapshot',
};

function collectorCategory(name) {
  // Unknown collectors default to 'telemetry' — same fallback as the
  // Rust `category_for()` function. Better to mis-classify as
  // "broken if low" than to silently hide an unknown collector.
  return COLLECTOR_CATEGORY[name] || 'telemetry';
}

function categoryBadge(cat) {
  // Tiny pill that tells the operator at a glance whether a low
  // count is concerning. Hover tooltip explains.
  if (cat === 'alarm') {
    return '<span class="cat-badge cat-alarm" title="Event-driven detector — silence means the system is healthy. Only emits when something interesting happens (malicious TLS handshake, file drift, etc).">ALARM</span>';
  }
  if (cat === 'snapshot') {
    return '<span class="cat-badge cat-snapshot" title="Periodic snapshot collector — count reflects scheduled cycles, not detected items.">SNAPSHOT</span>';
  }
  return '<span class="cat-badge cat-telemetry" title="Always-on telemetry stream — low count signals the collector or its source is broken.">TELEMETRY</span>';
}

// PR29 — index `data.collector_health.statuses` by name for O(1)
// lookup. Returns `{}` (empty map) when the sensor didn't write a
// health file (old sensor binary or non-default deploy).
function indexHealth(healthBlock) {
  const map = {};
  const statuses = (healthBlock && healthBlock.statuses) || [];
  for (const s of statuses) {
    if (s && s.name) map[s.name] = s;
  }
  return map;
}

function healthBadge(status) {
  // PR29 — health pill rendered next to the category badge. Only
  // emits when the sensor reported a non-Active state for this
  // collector. The pill carries the operator-readable reason as a
  // tooltip so they know what to investigate.
  if (!status || !status.health) return '';
  const h = status.health;
  const state = h.state || 'active';
  if (state === 'active') return '';
  let label = state.toUpperCase();
  let cls = 'cat-badge health-warn';
  let title = '';
  if (state === 'source_unavailable') {
    label = 'SOURCE MISSING';
    title = 'Source file does not exist on this host: ' + (h.path || '?') +
            '. Install the upstream service or remove this collector from config.';
  } else if (state === 'source_empty') {
    label = 'SOURCE STALE';
    title = 'Source file exists but has not been written to since ' +
            (h.last_write_iso || 'unknown') + '. Verify the upstream service.';
  } else if (state === 'permission_denied') {
    label = 'NO PERMISSION';
    title = 'Sensor lacks OS-level capability to read this source. Check AmbientCapabilities.';
  } else if (state === 'unsupported') {
    label = 'UNSUPPORTED';
    title = 'Not supported on this host: ' + (h.reason || 'unknown');
  } else if (state === 'disabled') {
    label = 'DISABLED';
    cls = 'cat-badge cat-snapshot';
    title = 'Disabled in config — operator choice.';
  }
  return '<span class="' + cls + '" title="' + title.replace(/"/g, '&quot;') + '">' + label + '</span>';
}

async function loadSensors() {
  try {
    const data = await loadJson('/api/sensors');
    const cards = document.getElementById('sensorCards');
    if (!cards) return;

    // HUD stat cards
    let html = '';
    html += '<div class="hud-card"><div class="hud-val">' + (data.total_events||0).toLocaleString() + '</div><div class="hud-label">Events Today</div></div>';
    var unresolved = getUnresolved().unresolved;
    var incClass = unresolved > 0 ? 'danger' : 'safe';
    var incSuffix = data.total_incidents > 0 && unresolved === 0 ? '<div style="font-size:0.6rem;opacity:0.6;margin-top:2px">all handled</div>' : '';
    html += '<div class="hud-card"><div class="hud-val ' + incClass + '">' + (data.total_incidents||0) + '</div>' + incSuffix + '<div class="hud-label">Incidents</div></div>';
    html += '<div class="hud-card"><div class="hud-val safe">' + (data.sources||[]).length + '</div><div class="hud-label">Sources Active</div></div>';
    html += '<div class="hud-card"><div class="hud-val">' + (data.detectors||[]).length + '</div><div class="hud-label">Detectors Firing</div></div>';
    cards.innerHTML = html;

    // Per-source rows — split into active vs available
    const srcEl = document.getElementById('sensorSources');
    if (srcEl) {
      // 2026-05-14 refactor: split source list by CATEGORY, not by
      // count. A `tls_fingerprint` collector with count=0 was being
      // rendered under "ready — not collecting" alongside genuinely
      // broken collectors, when it's actually an alarm-style detector
      // whose silence means the system is healthy. The category
      // mapping mirrors `crates/sensor/src/collector_health.rs`.
      const allSources = data.sources || [];
      const totalAll = allSources.length;
      // PR29 — index per-collector health from the sensor's
      // side-channel JSON (data.collector_health written by the
      // sensor at boot). Used by renderSourceRow to add a health
      // pill when source_unavailable / source_empty / etc.
      const healthByName = indexHealth(data.collector_health);

      // Telemetry with count > 0 = active; telemetry with count = 0
      // is the operator-actionable case (broken / source missing).
      const telActive = allSources.filter(
        (s) => collectorCategory(s.name) === 'telemetry' && s.count > 0,
      );
      const telBroken = allSources.filter(
        (s) => collectorCategory(s.name) === 'telemetry' && s.count === 0,
      );
      // Alarm collectors with count = 0 are HEALTHY (no detection
      // events). With count > 0 they're surfacing real findings.
      const alarmWithFindings = allSources.filter(
        (s) => collectorCategory(s.name) === 'alarm' && s.count > 0,
      );
      const alarmQuiet = allSources.filter(
        (s) => collectorCategory(s.name) === 'alarm' && s.count === 0,
      );
      const snapshots = allSources.filter(
        (s) => collectorCategory(s.name) === 'snapshot',
      );

      const renderSourceRow = (s, color) => {
        return (
          '<div class="hud-source">' +
          '<div class="hud-source-dot" style="background:' +
          color +
          ';box-shadow:0 0 6px ' +
          color +
          ';"></div>' +
          '<span class="hud-source-name">' +
          s.name +
          '</span>' +
          categoryBadge(collectorCategory(s.name)) +
          healthBadge(healthByName[s.name]) +
          '<span class="hud-source-count" style="color:' +
          color +
          ';">' +
          s.count.toLocaleString() +
          '</span></div>'
        );
      };

      let shtml = '<div style="font-size:0.72rem;font-weight:700;color:var(--ok);letter-spacing:0.05em;margin-bottom:6px">' +
        'TELEMETRY STREAMS &mdash; ' +
        telActive.length +
        '/' +
        (telActive.length + telBroken.length) +
        ' active</div>';
      shtml += '<div style="display:flex;flex-wrap:wrap;gap:6px">';
      for (const s of telActive) {
        shtml += renderSourceRow(s, sensorColor(s.name));
      }
      shtml += '</div>';
      if (telBroken.length > 0) {
        // Operator-actionable: telemetry with zero count IS broken.
        // Surface prominently so they investigate.
        shtml +=
          '<div style="font-size:0.65rem;color:var(--danger);margin-top:8px;font-weight:700">' +
          '⚠ ' +
          telBroken.length +
          ' telemetry streams report zero today &mdash; investigate</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;opacity:0.7">';
        for (const s of telBroken) {
          shtml += renderSourceRow(s, 'var(--danger)');
        }
        shtml += '</div>';
      }

      if (alarmWithFindings.length > 0) {
        shtml +=
          '<div style="font-size:0.72rem;font-weight:700;color:var(--orange);letter-spacing:0.05em;margin-top:12px;margin-bottom:6px">' +
          'ALARM DETECTORS &mdash; ' +
          alarmWithFindings.length +
          ' with findings</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px">';
        for (const s of alarmWithFindings) {
          shtml += renderSourceRow(s, 'var(--orange)');
        }
        shtml += '</div>';
      }
      if (alarmQuiet.length > 0) {
        shtml +=
          '<div style="font-size:0.65rem;color:var(--muted);margin-top:8px;cursor:pointer" onclick="var el=document.getElementById(\'alarmQuiet\');el.style.display=el.style.display===\'none\'?\'flex\':\'none\'">' +
          alarmQuiet.length +
          ' alarms quiet &mdash; healthy (silence is good) &#9662;</div>' +
          '<div id="alarmQuiet" style="display:none;flex-wrap:wrap;gap:6px;margin-top:4px;opacity:0.5">';
        for (const s of alarmQuiet) {
          shtml += renderSourceRow(s, 'var(--muted)');
        }
        shtml += '</div>';
      }

      if (snapshots.length > 0) {
        shtml +=
          '<div style="font-size:0.65rem;color:var(--muted);margin-top:8px">' +
          'Snapshot collectors (periodic) &mdash; ' +
          snapshots.length +
          '</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;opacity:0.7">';
        for (const s of snapshots) {
          shtml += renderSourceRow(s, 'var(--muted)');
        }
        shtml += '</div>';
      }

      srcEl.innerHTML = shtml;
    }

    // Charts
    drawTimelineChart(data.event_timeline || {}, data.sources || []);
    drawThreatGauge(data.total_incidents || 0, data.total_events || 0);

    // Top kinds list
    const kindsEl = document.getElementById('sensorKinds');
    if (kindsEl) {
      let khtml = '';
      for (const k of (data.top_kinds || []).slice(0, 10)) {
        const pct = data.total_events > 0 ? ((k.count / data.total_events) * 100).toFixed(1) : '0';
        khtml += '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.05);">' +
          '<span style="color:var(--fg);">' + k.name + '</span>' +
          '<span style="color:var(--muted);">' + k.count.toLocaleString() + ' (' + pct + '%)</span></div>';
      }
      kindsEl.innerHTML = khtml || '<span style="color:var(--muted);">No events yet</span>';
    }

    // Detector activity chart
    drawDetectorChart(data.detectors || []);
  } catch(e) { console.error('loadSensors', e); }
}

// ── Top Action Widget: surface the most urgent decision ───────────
async function loadTopAction() {
  try {
    const ctx = await loadJson('/api/agent/security-context');
    const el = document.getElementById('topAction');
    if (!el) return;

    const level = ctx.threat_level || 'low';
    const hc = ctx.high_or_critical_today || 0;
    const threats = ctx.top_threats || [];
    const blocks = ctx.recent_blocks_today || 0;

    if (level === 'low' && hc === 0) {
      // All clear — show subtle green bar
      el.style.display = 'block';
      el.style.borderColor = 'rgba(58,194,126,0.3)';
      el.style.background = 'rgba(58,194,126,0.04)';
      el.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between">' +
        '<div style="display:flex;align-items:center;gap:10px">' +
        '<span style="font-size:1.3rem">&#9989;</span>' +
        '<div><div style="font-size:0.85rem;font-weight:700;color:var(--ok)">All Clear</div>' +
        '<div style="font-size:0.7rem;color:var(--muted)">' + blocks + ' IPs blocked today. No unresolved high-severity incidents.</div></div></div>' +
        '<button onclick="this.closest(\'[id]\').style.display=\'none\'" style="' +
        'padding:4px 8px;border-radius:6px;border:1px solid var(--line);' +
        'background:transparent;color:var(--muted);font-size:0.75rem;' +
        'cursor:pointer;line-height:1" title="Dismiss">\u2715</button></div>';
      return;
    }

    // There are incidents the AI is handling. With Guard ON, present
    // as informational (blue), not alarming (red). The AI is autonomous.
    const topThreat = threats.length > 0 ? threats[0] : null;
    const isGuard = (window._agentMode || 'guard') === 'guard';
    const color = isGuard ? '#78e5ff' : (level === 'critical' ? '#f43f5e' : '#fb923c');

    el.style.display = 'block';
    el.style.borderColor = isGuard ? 'rgba(120,229,255,0.3)' : 'rgba(244,63,94,0.3)';
    el.style.background = isGuard ? 'rgba(120,229,255,0.04)' : 'linear-gradient(135deg, rgba(244,63,94,0.06), transparent)';

    const statusLabel = isGuard
      ? hc + ' incident' + (hc > 1 ? 's' : '') + ' being handled by AI'
      : hc + ' unresolved ' + (level === 'critical' ? 'CRITICAL' : 'high-severity') + ' incident' + (hc > 1 ? 's' : '');

    let actionHtml = '<div style="display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap">' +
      '<div style="display:flex;align-items:center;gap:10px">' +
      '<span style="font-size:1.3rem">' + (isGuard ? '&#128737;' : (level === 'critical' ? '&#128680;' : '&#9888;&#65039;')) + '</span>' +
      '<div>' +
      '<div style="font-size:0.85rem;font-weight:700;color:' + color + '">' + statusLabel + '</div>' +
      '<div style="font-size:0.7rem;color:var(--muted)">';

    if (topThreat) {
      actionHtml += 'Top threat: <strong style="color:var(--text)">' + esc(topThreat) + '</strong>';
      if (threats.length > 1) actionHtml += ' + ' + (threats.length - 1) + ' more';
    }
    actionHtml += '</div></div></div>';

    // Action button + dismiss
    actionHtml += '<div style="display:flex;align-items:center;gap:8px">' +
      '<button onclick="showView(\'investigate\')" style="' +
      'padding:8px 18px;border-radius:10px;border:1px solid ' + color + ';' +
      'background:transparent;color:' + color + ';font-size:0.75rem;font-weight:700;' +
      'cursor:pointer;white-space:nowrap;transition:background 0.2s' +
      '" onmouseover="this.style.background=\'' + color + '20\'" onmouseout="this.style.background=\'transparent\'">' +
      'Investigate &#8594;</button>' +
      '<button onclick="this.closest(\'[id]\').style.display=\'none\'" style="' +
      'padding:4px 8px;border-radius:6px;border:1px solid var(--line);' +
      'background:transparent;color:var(--muted);font-size:0.75rem;' +
      'cursor:pointer;line-height:1" title="Dismiss">\u2715</button></div></div>';

    el.innerHTML = actionHtml;
  } catch(e) { console.warn('loadTopAction:', e); }
}

// Chart.js global config - match site design system
let timelineChart = null;
let detectorChart = null;
let gaugeChart = null;
const CJ = typeof Chart !== 'undefined';
if (CJ) {
  Chart.defaults.color = '#8b9db8';
  Chart.defaults.borderColor = '#1a2943';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;
  Chart.defaults.animation.duration = 1200;
  Chart.defaults.animation.easing = 'easeOutQuart';
}

// Tooltip config reused across charts
const siteTooltip = {
  backgroundColor: 'rgba(9,17,33,0.95)',
  borderColor: 'rgba(127,231,255,0.25)',
  borderWidth: 1,
  titleFont: { family: "'Space Grotesk', sans-serif", weight: '600', size: 12 },
  bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
  padding: 12,
  cornerRadius: 12,
  boxPadding: 4,
};

// Create vertical gradient for area fills
function makeGradient(ctx, canvas, color, alpha1, alpha2) {
  const g = ctx.createLinearGradient(0, 0, 0, canvas.height);
  g.addColorStop(0, color.replace(')', ',' + alpha1 + ')').replace('rgb', 'rgba'));
  g.addColorStop(1, color.replace(')', ',' + alpha2 + ')').replace('rgb', 'rgba'));
  return g;
}

// ── 1. AREA CHART - Event Timeline (smooth curves + gradient fills) ──
function drawTimelineChart(timeline, sources) {
  const canvas = document.getElementById('sensorChart');
  if (!canvas || !CJ) return;

  const buckets = Object.keys(timeline).sort();
  const sourceNames = sources.map(s => s.name);
  const ctx = canvas.getContext('2d');

  const datasets = sourceNames.map((name, i) => {
    const color = sensorColor(name);
    const hex2rgba = (h, a) => {
      const r = parseInt(h.slice(1,3),16), g = parseInt(h.slice(3,5),16), b = parseInt(h.slice(5,7),16);
      return 'rgba('+r+','+g+','+b+','+a+')';
    };
    return {
      label: name,
      data: buckets.map(b => (timeline[b] || {})[name] || 0),
      borderColor: color,
      backgroundColor: (context) => {
        const chart = context.chart;
        const {ctx: c, chartArea} = chart;
        if (!chartArea) return hex2rgba(color, 0.3);
        const g = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        g.addColorStop(0, hex2rgba(color, 0.4));
        g.addColorStop(1, hex2rgba(color, 0.02));
        return g;
      },
      borderWidth: 2,
      fill: true,
      tension: 0.4,
      pointRadius: 0,
      pointHoverRadius: 5,
      pointHoverBackgroundColor: color,
      pointHoverBorderColor: '#edf6ff',
      pointHoverBorderWidth: 2,
    };
  });

  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(canvas, {
    type: 'line',
    data: { labels: buckets, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          stacked: true,
          grid: { color: 'rgba(26,41,67,0.5)', lineWidth: 0.5 },
          ticks: { maxTicksLimit: 12, font: { size: 9 } },
        },
        y: {
          stacked: true,
          grid: { color: 'rgba(26,41,67,0.5)', lineWidth: 0.5 },
          beginAtZero: true,
          ticks: { font: { size: 10 } },
        }
      },
      plugins: {
        legend: {
          position: 'top',
          labels: { boxWidth: 8, boxHeight: 8, padding: 14, font: { size: 10, family: "'Space Grotesk', sans-serif" }, usePointStyle: true, pointStyle: 'circle' }
        },
        tooltip: { ...siteTooltip, mode: 'index' },
      },
      interaction: { mode: 'index', intersect: false },
    }
  });
}

// ── 2. THREAT GAUGE - Doughnut speedometer ──
function drawThreatGauge(incidents, events) {
  const canvas = document.getElementById('threatGauge');
  if (!canvas || !CJ) return;
  const label = document.getElementById('threatLabel');

  // Scale based on UNRESOLVED threats only — blocked threats = success, not danger.
  const ur = getUnresolved().unresolved;
  const ratio = Math.min(ur / 10, 1);
  let level = 'NOMINAL';
  let color = '#4ade80';
  if (ur >= 10) { level = 'CRITICAL'; color = '#f43f5e'; }
  else if (ur >= 5) { level = 'ELEVATED'; color = '#fbbf24'; }
  else if (ur >= 1) { level = 'GUARDED'; color = '#7fe7ff'; }

  if (label) label.textContent = level;
  if (label) label.style.color = color;

  const val = Math.max(ratio * 100, 2); // min 2% for visibility

  if (gaugeChart) gaugeChart.destroy();
  gaugeChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [val, 100 - val],
        backgroundColor: [
          (context) => {
            const chart = context.chart;
            const {ctx, chartArea} = chart;
            if (!chartArea) return color;
            const g = ctx.createRadialGradient(
              (chartArea.left+chartArea.right)/2, chartArea.bottom, 0,
              (chartArea.left+chartArea.right)/2, chartArea.bottom, (chartArea.right-chartArea.left)/2
            );
            g.addColorStop(0, color);
            g.addColorStop(1, color + '44');
            return g;
          },
          'rgba(26,41,67,0.3)'
        ],
        borderWidth: 0,
        borderRadius: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '78%',
      circumference: 240,
      rotation: -120,
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
      },
      animation: { animateRotate: true, duration: 1500, easing: 'easeOutQuart' },
    },
    plugins: [{
      id: 'gaugeCenter',
      afterDraw(chart) {
        // 2026-05-02: section is labelled "UNRESOLVED THREATS" so the
        // big number must match — show the unresolved count, not the
        // total. Pre-fix the gauge rendered "409 NOMINAL" while the
        // tile above said "0 incident being handled by AI": the 409
        // was total_incidents (mostly blocked), but the heading "Unresolved
        // Threats" made it look like 409 needed attention.
        const {ctx, chartArea} = chart;
        const cx = (chartArea.left + chartArea.right) / 2;
        const cy = chartArea.bottom - 10;
        ctx.save();
        ctx.textAlign = 'center';
        ctx.fillStyle = color;
        ctx.font = "bold 22px 'JetBrains Mono', monospace";
        ctx.shadowColor = color;
        ctx.shadowBlur = 12;
        ctx.fillText(ur.toString(), cx, cy - 8);
        ctx.shadowBlur = 0;
        ctx.fillStyle = '#8b9db8';
        ctx.font = "10px 'Space Grotesk', sans-serif";
        ctx.fillText('unresolved', cx, cy + 8);
        ctx.restore();
      }
    }]
  });
}

// ── 3. POLAR AREA - Detector activity (radial, colorful) ──
function drawDetectorChart(detectors) {
  const canvas = document.getElementById('detectorChart');
  if (!canvas || !CJ || detectors.length === 0) return;

  const top = detectors.slice(0, 8);
  const colors = ['#7fe7ff','#4ade80','#fbbf24','#fb7185','#60a5fa','#a78bfa','#f97316','#22d3ee'];

  if (detectorChart) detectorChart.destroy();
  detectorChart = new Chart(canvas, {
    type: 'polarArea',
    data: {
      labels: top.map(d => d.name),
      datasets: [{
        data: top.map(d => d.count),
        backgroundColor: top.map((_, i) => colors[i % colors.length] + '66'),
        borderColor: top.map((_, i) => colors[i % colors.length]),
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          grid: { color: 'rgba(26,41,67,0.5)', lineWidth: 0.5 },
          ticks: { display: false },
          beginAtZero: true,
        }
      },
      plugins: {
        legend: {
          position: 'right',
          labels: { boxWidth: 8, boxHeight: 8, padding: 8, font: { size: 9, family: "'Space Grotesk', sans-serif" }, usePointStyle: true, pointStyle: 'circle' }
        },
        tooltip: { ...siteTooltip, callbacks: { label: (c) => c.label + ': ' + c.raw + ' incidents' } },
      },
      animation: { animateRotate: true, animateScale: true, duration: 1200 },
    }
  });
}

