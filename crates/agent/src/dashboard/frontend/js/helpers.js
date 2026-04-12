// ── Canonical UI glossary (spec 017 shared foundation) ────────────────
// Single source of truth for user-facing UI term definitions. Consumed
// by page specs for title= tooltips and copy review.
var GLOSSARY = {
  threat:     'A detected security event that may pose risk.',
  incident:   'A threat recorded by the backend (same concept, internal name).',
  unresolved: 'A threat that has not been handled automatically and awaits your review.',
  contained:  'A threat that has been blocked, killed, monitored, or suspended automatically.',
  open:       'A threat with no containment action taken yet.',
  resolved:   'A threat that has been closed — either contained or dismissed.',
  noise:      'A low-signal detection the system chose not to act on.'
};

// ── Confidence system helpers ─────────────────────────────────────────
function getUnresolved() {
  var ov = window._lastOverview || {};
  var confirmed = ov.ai_confirmed || 0;
  var responded = ov.ai_responded || 0;
  var unresolved = ov.unresolved_count != null ? ov.unresolved_count : Math.max(confirmed - responded, 0);
  return { total: confirmed, unresolved: unresolved, handled: responded };
}

// Human-readable labels for sensor collectors (spec 017 Change 6).
// Home's Data Collection section renders these instead of raw slugs
// so the primary operator sees "Network traffic" rather than
// "tcp_stream". Unknown slugs fall back to humanLabel().
var COLLECTOR_LABELS = {
  tcp_stream:         'Network traffic',
  http_capture:       'Web requests',
  dns_capture:        'DNS lookups',
  tls_fingerprint:    'TLS fingerprints',
  auth_log:           'Login attempts',
  auditd:             'System audit log',
  journald:           'System journal',
  docker:             'Docker events',
  proc_maps:          'Process memory',
  fanotify_watch:     'File changes',
  kernel_integrity:   'Kernel integrity',
  cgroup_abuse:       'Resource usage',
  ebpf_syscall:       'Kernel system calls',
  firmware_integrity: 'Firmware integrity',
  nginx_access:       'Web server access',
  nginx_error:        'Web server errors',
  syslog_firewall:    'Firewall log',
  falco_log:          'Falco events',
  suricata_eve:       'Suricata alerts',
  wazuh_alerts:       'Wazuh alerts',
  osquery_log:        'osquery events',
  macos_log:          'macOS log',
  cloudtrail:         'AWS CloudTrail',
  integrity:          'File integrity'
};

function collectorLabel(slug) {
  return COLLECTOR_LABELS[slug] || humanLabel(slug);
}

var DETECTOR_LABELS = {
  ssh_bruteforce: 'SSH login attempts', credential_stuffing: 'Credential testing',
  host_drift: 'Unexpected process', execution_guard: 'Command monitoring',
  port_scan: 'Port scan', web_scan: 'Web vulnerability scan',
  user_agent_scanner: 'Automated scanner', network_sniffer: 'Network monitor detected',
  network_sniffing: 'Network monitoring tool', kernel_module: 'Kernel module loaded',
  dns_tunnel: 'DNS tunnel attempt', dns_c2: 'DNS command-and-control',
  reverse_shell: 'Reverse shell attempt', fileless_exec: 'Memory-only execution',
  sudo_abuse: 'Privilege escalation attempt', search_abuse: 'Search abuse',
  service_stop: 'Service stopped', container_escape: 'Container escape attempt',
  rootkit: 'Rootkit detection', log_tampering: 'Log tampering',
  proto_anomaly: 'Suspicious connection', threat_intel: 'Known malicious IP',
  packet_flood: 'Packet flood', discovery_burst: 'Reconnaissance burst',
  data_exfil_cmd: 'Data exfiltration attempt', suspicious_execution: 'Suspicious command',
  suspicious_archive: 'Suspicious archive creation', logging_config_change: 'Logging config changed',
  timing_anomaly: 'Timing anomaly'
};

// ── Severity helpers (spec 017 shared foundation) ─────────────────────
// Map severity strings to CSS classes, human labels, and numeric ranks.
// Used by every page spec that renders severity-scaled tone.
function severityClass(sev) {
  var s = (sev || '').toString().toLowerCase();
  if (s === 'critical') return 'alert-critical';
  if (s === 'high')     return 'alert-high';
  if (s === 'medium')   return 'alert-medium';
  if (s === 'low')      return 'alert-low';
  return 'alert-info';
}

function severityLabel(sev) {
  var s = (sev || '').toString().toLowerCase();
  if (s === 'critical') return 'Critical';
  if (s === 'high')     return 'High';
  if (s === 'medium')   return 'Medium';
  if (s === 'low')      return 'Low';
  return 'Info';
}

function severityRank(sev) {
  var s = (sev || '').toString().toLowerCase();
  if (s === 'critical') return 4;
  if (s === 'high')     return 3;
  if (s === 'medium')   return 2;
  if (s === 'low')      return 1;
  if (s === 'info')     return 0;
  return -1;
}

// Return the highest severity string found in a list of objects
// with .severity or .effective_severity. Prefers effective_severity.
function maxSeverity(list) {
  var best = -1;
  var bestName = 'info';
  (list || []).forEach(function(item) {
    var sev = item && (item.effective_severity || item.severity);
    var rank = severityRank(sev);
    if (rank > best) { best = rank; bestName = (sev || '').toString().toLowerCase() || 'info'; }
  });
  return best >= 0 ? bestName : 'info';
}

function humanLabel(slug) {
  return DETECTOR_LABELS[slug] || slug.replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
}

function aggregateIncidents(incidents) {
  var groups = {};
  (incidents || []).forEach(function(inc) {
    var slug = (inc.incident_id || '').split(':')[0] || 'unknown';
    var outcome = inc.outcome || 'open';
    var key = slug + '|' + outcome;
    if (!groups[key]) {
      groups[key] = { slug: slug, outcome: outcome, count: 0,
        severity: inc.severity, latest: inc, ips: {} };
    }
    groups[key].count++;
    var ip = (inc.entities || []).find(function(e) { return e.type === 'Ip' || e.type === 'ip'; });
    if (ip) groups[key].ips[ip.value] = true;
    if (inc.ts > groups[key].latest.ts) groups[key].latest = inc;
  });
  return Object.values(groups).sort(function(a, b) {
    if (a.outcome === 'open' && b.outcome !== 'open') return -1;
    if (a.outcome !== 'open' && b.outcome === 'open') return 1;
    return b.count - a.count;
  });
}

function outcomeBadgeHtml(outcome) {
  if (outcome === 'blocked' || outcome === 'killed' || outcome === 'contained' || outcome === 'suspended')
    return '<span class="badge-contained">BLOCKED</span>';
  if (outcome === 'ignored' || outcome === 'dismissed') return '<span class="badge-noise">DISMISSED</span>';
  if (outcome === 'monitoring' || outcome === 'monitored' || outcome === 'open' || outcome === 'active')
    return '<span class="badge-monitor" style="font-size:0.62rem;padding:2px 7px;border-radius:4px">OBSERVING</span>';
  if (outcome === 'honeypot') return '<span style="font-size:0.62rem;padding:2px 7px;border-radius:4px;background:rgba(255,140,66,0.12);color:var(--orange);font-weight:600">HONEYPOT</span>';
  if (outcome === 'needs_attention') return '<span class="badge-unresolved">NEEDS ATTENTION</span>';
  return '';
}

function humanIncidentTitle(detector, rawTitle, ip) {
  var label = humanLabel(detector);
  if (ip) label += ' \u2014 ' + ip;
  return label;
}

function contextLine(outcome, severity) {
  switch (outcome) {
    case 'blocked': case 'killed': case 'contained': case 'suspended':
      return { text: 'Handled automatically \u2014 no action needed', cls: '' };
    case 'ignored':
      return { text: 'Classified as noise \u2014 no action needed', cls: '' };
    case 'monitored':
      return { text: 'Being monitored \u2014 system watching for escalation', cls: '' };
    case 'honeypot':
      return { text: 'Redirected to honeypot \u2014 attacker contained safely', cls: '' };
    default:
      if (severity === 'critical' || severity === 'high')
        return { text: 'Needs review \u2014 no automated response taken', cls: 'needs-action' };
      return { text: 'Awaiting analysis', cls: '' };
  }
}

function entryOutcomeClass(entry) {
  var d = entry.data || {};
  // For decisions, use the action to infer outcome
  if (entry.kind === 'decision') {
    var at = d.action_type || '';
    if (['block_ip','kill_process','block_container','suspend_user_sudo'].includes(at)) return 'entry-contained';
    if (at === 'ignore') return 'entry-noise';
    return '';
  }
  // For incidents, check if there's an outcome hint or use severity
  // We don't have outcome directly on the entry, so we check if the journey has it
  return '';
}

function toggleDetail(btn) {
  // Find .detail-body within the same evidence-card, not by sibling
  // position (the header/title/context divs sit between the button
  // and the detail body, breaking nextElementSibling).
  var card = btn.closest('.evidence-card');
  var body = card ? card.querySelector('.detail-body') : null;
  if (!body) return;
  body.classList.toggle('open');
  btn.textContent = body.classList.contains('open') ? 'Hide details' : 'Show details';
}


function isPrivateIp(ip) {
  return ip.startsWith('10.') || ip.startsWith('127.') || ip.startsWith('192.168.') ||
    ip.startsWith('169.254.') || ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

// Unified incident-trust check (spec 017 Change 6).
// Returns true when the incident should be hidden while
// state.hideAllowlisted is on; false when it should be shown.
//
// Rule 1 (severity gate): critical/high are NEVER filtered by trust —
//   they must always reach the operator regardless of entity shape.
//
// Rule 2 (entity walk, for medium/low/info): inspect entities. If any
//   external non-trusted IP is present, show. If any non-trusted user
//   is present, show. Otherwise hide (handles allowlisted-only and
//   no-entity noise like host_drift sudo or kill_chain forming).
function isIncidentTrusted(inc) {
  var sev = ((inc && (inc.effective_severity || inc.severity)) || '').toString().toLowerCase();
  if (sev === 'critical' || sev === 'high') return false;

  var entities = (inc && inc.entities) || [];
  var sawExternalIp = false;
  var allIpsTrusted = true;
  var sawUntrustedUser = false;

  for (var i = 0; i < entities.length; i++) {
    var e = entities[i];
    var eType = (typeof e === 'string') ? (e.split(':')[0] || '') : (e.type || '');
    var eVal  = (typeof e === 'string') ? (e.split(':').slice(1).join(':') || '') : (e.value || '');
    eType = eType.toLowerCase();

    if (eType === 'ip') {
      sawExternalIp = true;
      if (!isIpTrusted(eVal) && !isPrivateIp(eVal)) {
        allIpsTrusted = false;
      }
    }
    if (eType === 'user') {
      if (_trustedUsers.indexOf(eVal) < 0) sawUntrustedUser = true;
    }
  }

  if (sawExternalIp && !allIpsTrusted) return false;
  if (sawUntrustedUser) return false;
  return true;
}


// ── E2 - Home state (Threats right-panel) ────────────────────────────────
async function loadHomeState() {
  try {
    const [overview, decisions, pivots] = await Promise.all([
      loadJson('/api/overview'),
      loadJson('/api/decisions?limit=5'),
      loadJson('/api/pivots?group_by=ip&limit=5')
    ]);

    // Update status hero and activity feed
    const incidentList = await loadJson('/api/incidents?limit=30');
    updateStatusHero(incidentList.items || [], decisions.items || []);
    buildActivityFeed(incidentList.items || [], decisions.items || []);

    // KPI strip in left panel
    setHomeKpi('h-events', overview.events_count ?? 0);
    setHomeKpi('h-incidents', overview.incidents_count ?? 0);
    setHomeKpi('h-decisions', overview.decisions_count ?? 0);
    setHomeKpi('h-blocks', (decisions.items || []).filter(d => d.action_type === 'block_ip' && d.auto_executed).length);
  } catch(e) {
    console.warn('Home state load error:', e);
  }
}

function setHomeKpi(id, val) {
  const el = document.getElementById(id);
  if (el) { el.textContent = val; }
}

function timeAgo(ts) {
  if (!ts) return '';
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}

// Temporal window label helper (spec 017 shared foundation).
// Returns a canonical English label for a KPI time window.
// Unknown kinds return '' so callers can omit the label gracefully.
function formatWindow(kind) {
  switch ((kind || '').toString()) {
    case 'live':        return 'Live';
    case 'today':       return 'Today';
    case 'last_24h':    return 'Last 24h';
    case 'last_6h':     return 'Last 6h';
    case 'last_hour':   return 'Last hour';
    case 'since_start': return 'Since startup';
    default:            return '';
  }
}

function handleCardClickByValue(type, value) {
  // Find the card with this value and click it, or load journey directly
  const cards = document.querySelectorAll('.attacker-card');
  for (const card of cards) {
    if (card.dataset.subjectValue === value && card.dataset.subjectType === type) {
      card.click();
      return;
    }
  }
  // Direct load
  loadJourney(type, value);
}

function showHomeState() {
  document.getElementById('homeState').style.display = '';
  document.getElementById('journeyContent').style.display = 'none';
  document.getElementById('journeyContent').innerHTML = '';
  // Deselect active card
  document.querySelectorAll('.attacker-card.active').forEach(c => c.classList.remove('active'));
  state.currentSubject = null;
}

function investigateTopThreat() {
  // Click the first attacker card if one exists, else no-op
  const first = document.querySelector('.attacker-card');
  if (first) { first.click(); return; }
  // Show investigate tab in case we're in a different view
  showView('investigate');
}

function toggleAdvFilters() {
  const el = document.getElementById('advFilters');
  const btn = document.getElementById('flt-adv-toggle');
  if (!el || !btn) return;
  const open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  btn.textContent = open ? '▸ Advanced filters' : '▾ Advanced filters';
}
