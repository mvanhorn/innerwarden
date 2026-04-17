async function loadStatus() {
  const status = document.getElementById('statusViewStatus');
  const content = document.getElementById('statusContent');
  if (!status || !content) return;
  status.textContent = 'Loading…';
  content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
  try {
    const [s, col] = await Promise.all([
      loadJson('/api/status'),
      loadJson('/api/collectors').catch(() => ({ collectors: [] }))
    ]);
    status.textContent = 'Updated ' + new Date().toLocaleTimeString();
    content.innerHTML = renderStatus(s, col.collectors || []);
    loadDeepSecurity();
    // Spec 024: populate the Metrics Drift section after the table
    // skeleton lands in the DOM.
    loadMetricsDrift();
  } catch(e) {
    status.textContent = 'error';
    content.innerHTML = '<div class="empty" style="padding:40px;color:var(--danger)">Failed: ' + esc(String(e.message)) + '</div>';
  }
}

async function loadDeepSecurity() {
  try {
    const ds = await loadJson('/api/deep-security');
    const fw = document.querySelector('#ds-firmware .deep-value');
    const hv = document.querySelector('#ds-hypervisor .deep-value');
    const kc = document.querySelector('#ds-killchain .deep-value');
    const dn = document.querySelector('#ds-dna .deep-value');
    if (fw) {
      if (ds.firmware_trust_score != null) {
        const pct = (ds.firmware_trust_score*100).toFixed(0);
        fw.innerHTML = '<span style="color:' + (pct >= 85 ? 'var(--ok)' : pct >= 50 ? 'var(--warn)' : 'var(--danger)') + '">' + pct + '% trust</span>';
      } else { fw.innerHTML = '<span style="color:var(--ok)">Active</span>'; }
    }
    if (hv) {
      const env = ds.hypervisor_environment || 'Detecting…';
      const col = env.includes('BareMetal') ? 'var(--ok)' : env.includes('Virtual') ? 'var(--accent)' : 'var(--muted)';
      hv.innerHTML = '<span style="color:' + col + '">' + env.replace(/[{}"]/g,'').replace(/hypervisor:\\s*/,'').trim() + '</span>';
    }
    if (kc) {
      kc.innerHTML = '<span style="color:var(--text)">' + ds.killchain_pids_tracked + ' tracked</span>' +
        (ds.killchain_full_matches > 0 ? ' · <span style="color:var(--danger)">' + ds.killchain_full_matches + ' detected</span>' : '') +
        (ds.killchain_pre_chains > 0 ? ' · <span style="color:var(--warn)">' + ds.killchain_pre_chains + ' pre-chain</span>' : '');
    }
    if (dn) {
      dn.innerHTML = '<span style="color:var(--text)">' + ds.dna_fingerprints + ' fingerprints</span>' +
        (ds.dna_anomaly_alerts > 0 ? ' · <span style="color:var(--warn)">' + ds.dna_anomaly_alerts + ' anomalies</span>' : '') +
        ' · <span style="color:var(--muted)">' + ds.dna_attack_chains + ' chains</span>';
    }
  } catch(e) { console.warn('deep-security:', e); }
}

function renderStatus(s, collectors) {
  const files = s.files || {};
  const resp = s.responder || {};
  const integ = s.integrations || {};
  const fmt = (bytes) => bytes > 1048576 ? (bytes/1048576).toFixed(1)+'MB' : bytes > 1024 ? (bytes/1024).toFixed(1)+'KB' : bytes+'B';

  // Agent liveness
  const tSecs = s.last_telemetry_secs;
  let liveStr = '-';
  if (tSecs != null) {
    if (tSecs < 60)        liveStr = tSecs + 's ago';
    else if (tSecs < 3600) liveStr = Math.floor(tSecs/60) + 'm ago';
    else                   liveStr = Math.floor(tSecs/3600) + 'h ago';
  }
  const isHealthy = tSecs != null && tSecs < 300;

  // ── Section 1: Guard Mode card ─────────────────────────────────────────
  // GUARD = green (good, server protected), WATCH = yellow (caution, not acting), READ-ONLY = gray (passive)
  let guardIcon, guardLabel, guardDesc, guardColor, guardBorderColor, guardBg;
  if (s.mode === 'guard') {
    guardIcon = '🛡';
    guardLabel = 'PROTECTED';
    guardDesc = 'Active protection - AI is blocking threats with live firewall rules';
    guardColor = 'var(--ok)';
    guardBorderColor = 'rgba(58,194,126,0.5)';
    guardBg = 'rgba(58,194,126,0.06)';
  } else if (s.mode === 'watch') {
    guardIcon = '👁';
    guardLabel = 'WATCHING';
    guardDesc = 'Dry-run - AI is analysing threats but actions need manual approval or config change';
    guardColor = 'var(--warn)';
    guardBorderColor = 'rgba(255,184,77,0.4)';
    guardBg = 'rgba(255,184,77,0.04)';
  } else {
    guardIcon = '📖';
    guardLabel = 'MONITOR ONLY';
    guardDesc = 'Responder disabled - events are logged and reported, no automated response';
    guardColor = 'var(--muted)';
    guardBorderColor = 'var(--line)';
    guardBg = 'transparent';
  }
  const aiLabel = s.ai_enabled ? '🤖 ' + esc(s.ai_provider || '') + ' / ' + esc(s.ai_model || '') : '- off';

  let html = '<div class="report-section">' +
    '<div class="report-section-title">Protection Status</div>' +
    '<div style="background:' + guardBg + ';border:1px solid ' + guardBorderColor + ';border-radius:12px;padding:16px 20px;display:flex;align-items:center;gap:16px;margin-bottom:4px">' +
    '<div style="font-size:2rem;flex-shrink:0">' + guardIcon + '</div>' +
    '<div>' +
    '<div style="font-size:1.1rem;font-weight:800;color:' + guardColor + '">' + esc(guardLabel) + '</div>' +
    '<div style="font-size:0.75rem;color:var(--muted);margin-top:3px">' + esc(guardDesc) + '</div>' +
    '<div style="margin-top:8px;font-size:0.72rem;color:var(--muted)">AI: <span style="color:var(--' + (s.ai_enabled ? 'ok' : 'muted') + ')">' + aiLabel + '</span> &nbsp;·&nbsp; Agent: <span style="color:var(--' + (isHealthy ? 'ok' : 'warn') + ')">' + liveStr + '</span></div>' +
    '</div></div></div>';

  // ── Section 1b: Deep Security (integrated modules) ────────────────────
  html += '<div class="report-section" id="deepSecuritySection">' +
    '<div class="report-section-title">Deep Security Modules</div>' +
    '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">' +
    '<div class="deep-card" id="ds-firmware"><div class="deep-icon">🔧</div><div class="deep-label">Firmware Layer</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '<div class="deep-card" id="ds-hypervisor"><div class="deep-icon">🖥️</div><div class="deep-label">Hypervisor Layer</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '<div class="deep-card" id="ds-killchain"><div class="deep-icon">⛓️</div><div class="deep-label">Kill Chain</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '<div class="deep-card" id="ds-dna"><div class="deep-icon">🧬</div><div class="deep-label">Threat DNA</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '</div></div>';

  // ── Section 2: Active Integrations grid ───────────────────────────────
  const card = (icon, name, on, desc, badgeLabel, kind, costNote, enableCmd) => {
    const badge = badgeLabel === 'ON'   ? '<span class="integ-badge on">ON</span>'   :
                  badgeLabel === 'OFF'  ? '<span class="integ-badge off">OFF</span>' :
                  badgeLabel === 'DEMO' ? '<span class="integ-badge demo">DEMO</span>' :
                  badgeLabel === 'LIVE' ? '<span class="integ-badge on">LIVE</span>' :
                                         '<span class="integ-badge off">OFF</span>';
    const kindBadge = kind === 'native'
      ? '<span class="integ-kind-native">NATIVE</span>'
      : '<span class="integ-kind-ext">EXTERNAL</span>';
    const cost = costNote ? '<div class="integ-cost">' + esc(costNote) + '</div>' : '';
    let toggleBtn = '';
    if (enableCmd) {
      const disableCmd = enableCmd.replace('enable', 'disable').replace('integrate ', 'integrate --disable ');
      const cmd = on ? disableCmd : enableCmd;
      const label = on ? '⏹ Disable' : '▶ Enable';
      const cls = on ? 'integ-toggle off' : 'integ-toggle on';
      toggleBtn = '<button class="' + cls + '" onclick="copyCmd(\'' + esc(cmd).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + '\')" title="Copy command">' + label + '</button>';
    }
    return '<div class="integ-card ' + (on ? 'active' : 'inactive') + '">' +
      '<div class="integ-icon">' + icon + '</div>' +
      '<div class="integ-body">' +
      '<div class="integ-name">' + esc(name) + badge + kindBadge + '</div>' +
      '<div class="integ-desc">' + esc(desc) + '</div>' +
      cost +
      toggleBtn +
      '</div></div>';
  };

  const hpMode = (integ.honeypot_mode || 'off').toLowerCase();
  const hpBadge = hpMode === 'always_on' ? 'ON' : hpMode === 'listener' ? 'LIVE' : hpMode === 'demo' ? 'DEMO' : hpMode === 'off' ? 'OFF' : 'ON';

  // ── Section 2: Active Integrations — grouped by category ─────────────
  const groupStyle = '<style>' +
    '.integ-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:12px}' +
    '.integ-card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;align-items:flex-start;gap:12px}' +
    '.integ-card.active{border-color:rgba(58,194,126,0.4)}' +
    '.integ-card.inactive{opacity:0.65}' +
    '.integ-icon{font-size:1.4rem;flex-shrink:0}' +
    '.integ-body{flex:1;min-width:0}' +
    '.integ-name{font-size:0.85rem;font-weight:700;color:var(--text);margin-bottom:2px}' +
    '.integ-desc{font-size:0.68rem;color:var(--muted);line-height:1.4}' +
    '.integ-cost{font-size:0.62rem;color:var(--muted);opacity:0.75;margin-top:3px;line-height:1.4}' +
    '.integ-hint{font-size:0.62rem;color:var(--accent);margin-top:5px}' +
    '.integ-toggle{display:inline-block;margin-top:6px;padding:4px 12px;border:1px solid var(--line);border-radius:8px;font-size:0.65rem;font-weight:600;cursor:pointer;background:transparent;transition:all 0.2s}' +
    '.integ-toggle.on{color:var(--ok);border-color:var(--ok)}' +
    '.integ-toggle.on:hover{background:rgba(74,222,128,0.1)}' +
    '.integ-toggle.off{color:var(--muted);border-color:var(--line)}' +
    '.integ-toggle.off:hover{background:rgba(139,157,184,0.1)}' +
    '.integ-hint code{font-family:\'JetBrains Mono\',monospace}' +
    '.integ-badge{display:inline-block;font-size:0.6rem;font-weight:700;padding:2px 7px;border-radius:20px;margin-left:6px;vertical-align:middle}' +
    '.integ-badge.on{background:rgba(58,194,126,0.2);color:var(--ok)}' +
    '.integ-badge.off{background:rgba(139,157,184,0.1);color:var(--muted)}' +
    '.integ-badge.demo{background:rgba(255,184,77,0.15);color:var(--warn)}' +
    '.integ-kind-native{display:inline-block;font-size:0.52rem;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:5px;vertical-align:middle;background:rgba(120,229,255,0.12);color:var(--accent);letter-spacing:0.04em}' +
    '.integ-kind-ext{display:inline-block;font-size:0.52rem;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:5px;vertical-align:middle;background:rgba(255,184,77,0.12);color:var(--warn);letter-spacing:0.04em}' +
    '.integ-group{margin-bottom:18px}' +
    '.integ-group-header{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding:8px 0;user-select:none}' +
    '.integ-group-title{font-size:0.72rem;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--accent)}' +
    '.integ-group-count{font-size:0.65rem;color:var(--muted)}' +
    '.integ-group-chevron{font-size:0.8rem;color:var(--muted);transition:transform 0.2s}' +
    '.integ-group-chevron.collapsed{transform:rotate(-90deg)}' +
    '.integ-group-body{overflow:hidden;transition:max-height 0.3s ease}' +
    '.integ-group-body.collapsed{max-height:0 !important;margin:0;padding:0}' +
    '@media(max-width:640px){.integ-grid{grid-template-columns:1fr}}' +
    '</style>';

  // Group builder: title, cards array, initially expanded?
  const group = (title, cards, expanded) => {
    const onCount = cards.filter(c => c.includes('integ-card active')).length;
    const total = cards.length;
    const id = 'ig-' + title.replace(/[^a-z]/gi, '').toLowerCase();
    const chevCls = expanded ? '' : ' collapsed';
    const bodyCls = expanded ? '' : ' collapsed';
    return '<div class="integ-group">' +
      '<div class="integ-group-header" onclick="(function(){ var b=document.getElementById(\'' + id + '\'); var c=b.previousElementSibling.querySelector(\'.integ-group-chevron\'); b.classList.toggle(\'collapsed\'); c.classList.toggle(\'collapsed\'); })()">' +
      '<span class="integ-group-title">' + title + '</span>' +
      '<span style="display:flex;align-items:center;gap:8px">' +
      '<span class="integ-group-count">' + onCount + '/' + total + ' active</span>' +
      '<span class="integ-group-chevron' + chevCls + '">&#9662;</span>' +
      '</span></div>' +
      '<div class="integ-group-body' + bodyCls + '" id="' + id + '" style="max-height:2000px">' +
      '<div class="integ-grid">' + cards.join('') + '</div></div></div>';
  };

  // ── Build Kill Chain card (needs runtime data) ──
  const kcCard = (function() {
    const kc = s.kill_chain || {};
    const kcTotal = (kc.total_blocked || 0) + (kc.total_pre_chain || 0);
    const kcOn = (kc.pids_tracked !== undefined) || kcTotal > 0; // ON if tracker is loaded
    const kcDesc = kcTotal > 0
      ? kcTotal + ' chain(s) detected today — ' + (kc.total_blocked||0) + ' blocked, ' + (kc.total_pre_chain||0) + ' pre-chain'
      : 'Multi-step attack correlation — detects reverse shells, privilege escalation chains';
    const kcPatterns = kc.patterns || {};
    const patternList = Object.keys(kcPatterns).map(function(p) { return p + ': ' + kcPatterns[p]; }).join(', ');
    const kcCost = 'Native syscall correlation. Patterns: ' + (patternList || 'none detected yet');
    return card('🔗', 'Kill Chain', kcOn, kcDesc, kcOn ? 'ON' : 'OFF', 'native', kcCost, '');
  })();

  html += '<div class="report-section"><div class="report-section-title">Active Integrations</div>' +
    groupStyle +

    // ── Core Protection (always visible, expanded) ──
    group('Core Protection', [
      card('🤖', 'AI Analysis',   s.ai_enabled,     'Analyzes threats and selects the best response action',       s.ai_enabled ? 'ON' : 'OFF', 'native', 'Built into InnerWarden - no external service needed.', 'innerwarden enable ai'),
      card('🛡️', 'IP Blocker',    resp.enabled,     'Automatically blocks IPs via UFW/iptables when AI decides',   resp.enabled ? 'ON' : 'OFF', 'native', 'Zero cost. Uses your existing firewall.',               'innerwarden enable block-ip'),
      card('🪤', 'Honeypot',      hpMode !== 'off', 'Decoy server that captures and logs attacker behavior',       hpBadge,                     'native', 'listener mode activates on AI demand; always_on keeps it permanently open.', ''),
      card('⚡', 'XDP Firewall',  !!s.ebpf_events,  'Wire-speed IP blocking at network driver - 10M+ pps drop',    s.ebpf_events ? 'ON' : 'OFF', 'native', 'Requires eBPF sensor + BPF filesystem mounted. Layered: XDP + firewall + Cloudflare + AbuseIPDB.', ''),
    ], true) +

    // ── Kernel Hardening (expanded — v0.6.0 features) ──
    group('Kernel Hardening', [
      kcCard,
      card('🔒', 'Sensitive Path Guard', s.sensitive_write||true, 'LSM hook blocks writes to /etc/shadow, sudoers, authorized_keys, crontab', s.sensitive_write !== false ? 'ON' : 'OFF', 'native', 'Capability-based policy: per-cgroup and per-process write permissions via BPF maps.', ''),
      card('⚡', 'io_uring Monitor',     s.io_uring||true,       'Detects io_uring syscall bypass evasion — invisible to most security tools', s.io_uring !== false ? 'ON' : 'OFF', 'native', 'Tracepoints on submit_sqe/submit_req + create. Alerts on CONNECT, ACCEPT, OPENAT, URING_CMD.', ''),
      card('📦', 'Container Drift',      s.container_drift||true,'Detects binaries dropped after container start via overlayfs upper-layer',   s.container_drift !== false ? 'ON' : 'OFF', 'native', 'Overlayfs upper-layer drift check at execve using inode layout from BTF.', ''),
      card('👑', 'Sudo Protection',      s.sudo_protection||false, 'Detects privilege abuse and suspends sudo access',  s.sudo_protection ? 'ON' : 'OFF', 'native', 'Detects 11 threat categories including SUID manipulation, SSH key injection, log tampering.', 'innerwarden enable sudo-protection'),
      card('🔫', 'Execution Guard',      s.execution_guard||false, 'Structural AST analysis of shell commands - catches obfuscation', s.execution_guard ? 'ON' : 'OFF', 'native', 'tree-sitter-bash analysis. Detects reverse shells, curl|bash, hex obfuscation.', 'innerwarden enable execution-guard'),
      card('🛡️', 'Shield (DDoS)',        integ.shield||false,    'Packet flood detection + Cloudflare edge push for volumetric attacks', integ.shield ? 'ON' : 'OFF', 'native', 'Detects SYN/UDP/ICMP floods. Pushes to Cloudflare edge when enabled.', ''),
      card('🧬', 'Threat DNA',           integ.dna||false,       'Attacker fingerprinting and behavioral correlation across sessions',   integ.dna ? 'ON' : 'OFF', 'native', 'Always active. Tracks attack patterns, timing signatures, tool fingerprints.', ''),
    ], true) +

    // ── Alerts & Notifications (collapsed) ──
    group('Alerts & Notifications', [
      card('🔔', 'Telegram',  integ.telegram,     'Real-time alerts + inline approval buttons on your phone', integ.telegram ? 'ON' : 'OFF', 'external', 'Free. Best solo-operator channel - supports bidirectional approve/reject.', 'innerwarden notify telegram'),
      card('💬', 'Slack',     integ.slack,         'Incident notifications to a Slack team channel',          integ.slack ? 'ON' : 'OFF',    'external', 'Free (requires workspace). Alongside Telegram doubles alert volume.',      'innerwarden notify slack'),
      card('🔔', 'Web Push',  integ.web_push||false, 'Browser push notifications - no Telegram/Slack needed', integ.web_push ? 'ON' : 'OFF', 'native', 'VAPID-based. Subscribe from the dashboard bell icon. No external service.', ''),
      card('🚨', 'PagerDuty', (s.webhook_format||'') === 'pagerduty', 'On-call alerts via PagerDuty Events API v2', (s.webhook_format||'') === 'pagerduty' ? 'ON' : 'OFF', 'external', 'Set webhook.format = \"pagerduty\" and webhook.url to PagerDuty endpoint.', 'innerwarden configure webhook'),
      card('📟', 'Opsgenie',  (s.webhook_format||'') === 'opsgenie',  'On-call alerts via Opsgenie Alert API',      (s.webhook_format||'') === 'opsgenie' ? 'ON' : 'OFF',  'external', 'Set webhook.format = \"opsgenie\" and webhook.url to Opsgenie endpoint.', 'innerwarden configure webhook'),
    ], false) +

    // ── Threat Intelligence (collapsed) ──
    group('Threat Intelligence', [
      card('🌍', 'GeoIP',     integ.geoip,          'Adds country/ISP info to every threat - free, no key needed', integ.geoip ? 'ON' : 'OFF', 'native', 'Free. Calls ip-api.com (45 req/min). Best first enrichment to enable.', 'innerwarden integrate geoip'),
      card('🔍', 'AbuseIPDB', integ.abuseipdb,      'IP reputation + delayed community reporting (5min grace)',    integ.abuseipdb ? 'ON' : 'OFF', 'external', 'Free plan: 1,000 req/day. Reports delayed 5 min for false-positive correction.', 'innerwarden integrate abuseipdb'),
      card('🌐', 'CrowdSec',  integ.crowdsec||false, 'Community threat intelligence - known-bad IPs on incident',  integ.crowdsec ? 'ON' : 'OFF', 'external', 'Free. Requires CrowdSec LAPI running locally. Lookup-only.', 'innerwarden integrate crowdsec'),
      card('🕸️', 'Mesh Network', integ.mesh||false,  'Collaborative defense - peers exchange block signals',       integ.mesh ? 'ON' : 'OFF', 'native', 'Decentralized threat intel sharing between InnerWarden instances.', 'innerwarden integrate mesh'),
    ], false) +

    // ── External Services (collapsed) ──
    group('External Services', [
      card('☁️', 'Cloudflare',   integ.cloudflare,      'Pushes blocked IPs to Cloudflare edge after block-ip fires', integ.cloudflare ? 'ON' : 'OFF', 'external', 'Free plan supports IP Access Rules. Effective for DDoS edge-layer defense.', 'innerwarden integrate cloudflare'),
      card('🚧', 'Fail2ban Sync', integ.fail2ban||false, 'Sync blocked IPs with fail2ban jails for unified bans',     integ.fail2ban ? 'ON' : 'OFF', 'external', 'Requires fail2ban installed. InnerWarden reads jails and pushes blocks.', 'innerwarden integrate fail2ban'),
      card('📊', 'Prometheus',    true,                  'Metrics endpoint at /metrics - scrape with Prometheus/Grafana', 'ON', 'native', 'Always available when dashboard is active. No config needed.', ''),
    ], false) +

    '</div>';

  // ── Section 2b: Integration advisor ────────────────────────────────────
  const conflicts = [];
  // (No conflicts to check - fail2ban removed, AbuseIPDB reports delayed)
  if (integ.telegram && integ.slack) {
    conflicts.push({
      a: 'Telegram', b: 'Slack',
      msg: 'Both send the same High/Critical alert. If you are the only operator, this doubles notification volume with no benefit. Use Telegram for real-time response, Slack for team visibility.'
    });
  }

  const recommendations = [];
  if (!integ.geoip)     recommendations.push({ icon:'🌍', text:'Enable GeoIP - free, zero noise, adds country/ISP to every AI decision', cmd:'innerwarden integrate geoip' });
  if (!integ.telegram)  recommendations.push({ icon:'🔔', text:'Enable Telegram - real-time alerts with approve/reject buttons on your phone', cmd:'innerwarden notify telegram' });
  if (!integ.abuseipdb) recommendations.push({ icon:'🔍', text:'Enable AbuseIPDB - free API key, enriches AI context with IP reputation score', cmd:'innerwarden integrate abuseipdb' });
  if (!integ.cloudflare && resp.enabled) recommendations.push({ icon:'☁️', text:'Enable Cloudflare - push blocked IPs to the edge after every block-ip decision', cmd:'innerwarden integrate cloudflare' });
  if (!integ.mesh) recommendations.push({ icon:'🕸️', text:'Enable Mesh - share threat intel with other InnerWarden instances', cmd:'innerwarden integrate mesh' });

  if (conflicts.length > 0 || recommendations.length > 0) {
    html += '<div class="report-section"><div class="report-section-title">Integration Advisor</div>' +
      '<style>' +
      '.advisor-block{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px}' +
      '.advisor-conflict{border-left:3px solid var(--warn)}' +
      '.advisor-rec{border-left:3px solid var(--accent)}' +
      '.advisor-label{font-size:0.65rem;font-weight:700;letter-spacing:0.06em;margin-bottom:6px}' +
      '.advisor-label.warn{color:var(--warn)}' +
      '.advisor-label.ok{color:var(--accent)}' +
      '.advisor-pair{font-size:0.75rem;font-weight:700;color:var(--text);margin-bottom:3px}' +
      '.advisor-msg{font-size:0.68rem;color:var(--muted);line-height:1.5}' +
      '.advisor-cmd{font-size:0.62rem;color:var(--accent);margin-top:5px;font-family:\'JetBrains Mono\',monospace}' +
      '</style>';

    conflicts.forEach(c => {
      html += '<div class="advisor-block advisor-conflict">' +
        '<div class="advisor-label warn">⚠ OVERLAP DETECTED</div>' +
        '<div class="advisor-pair">' + esc(c.a) + ' ↔ ' + esc(c.b) + '</div>' +
        '<div class="advisor-msg">' + esc(c.msg) + '</div>' +
        '</div>';
    });

    if (recommendations.length > 0) {
      const next = recommendations[0];
      html += '<div class="advisor-block advisor-rec">' +
        '<div class="advisor-label ok">💡 RECOMMENDED NEXT STEP</div>' +
        '<div class="advisor-pair">' + next.icon + ' ' + esc(next.text) + '</div>' +
        '<div class="advisor-cmd">$ ' + esc(next.cmd) + '</div>' +
        '</div>';
      if (recommendations.length > 1) {
        html += '<div style="font-size:0.62rem;color:var(--muted);padding:0 4px 12px">After that: ';
        html += recommendations.slice(1).map(r => esc(r.icon + ' ' + r.cmd)).join(' &nbsp;·&nbsp; ');
        html += '</div>';
      }
    }

    html += '</div>';
  }

  // ── Section 3: Sensor Collectors ──────────────────────────────────────
  if (collectors.length > 0) {
    const colIcons = {
      auth_log:'🔑', journald:'📋', docker:'🐳', nginx_access:'🌐', nginx_error:'⚠️',
      exec_audit:'🔎', ebpf:'⚡',
      syslog_firewall:'🧱', firmware_integrity:'🔧', cloudtrail:'☁️', macos_log:'🍎',      };
    const colStyle =
      '.col-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:4px}' +
      '.col-row{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 14px;display:flex;align-items:center;gap:10px}' +
      '.col-row.col-active{border-color:rgba(58,194,126,0.35)}' +
      '.col-row.col-detected{border-color:rgba(255,184,77,0.25)}' +
      '.col-row.col-missing{opacity:0.5}' +
      '.col-ico{font-size:1.2rem;flex-shrink:0}' +
      '.col-body{flex:1;min-width:0}' +
      '.col-name{font-size:0.78rem;font-weight:700;color:var(--text);display:flex;flex-wrap:wrap;align-items:center;gap:4px}' +
      '.col-meta{font-size:0.62rem;color:var(--muted);margin-top:2px}' +
      '.col-evt{display:inline-block;font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;margin-left:6px;vertical-align:middle;background:rgba(120,229,255,0.12);color:var(--accent)}' +
      '.col-status-active{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(58,194,126,0.2);color:var(--ok)}' +
      '.col-status-detected{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(255,184,77,0.15);color:var(--warn)}' +
      '.col-status-missing{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(100,100,100,0.15);color:var(--muted)}' +
      '.col-kind-native{display:inline-block;font-size:0.5rem;font-weight:700;padding:1px 4px;border-radius:3px;margin-left:4px;vertical-align:middle;background:rgba(120,229,255,0.1);color:var(--accent)}' +
      '.col-kind-ext{display:inline-block;font-size:0.5rem;font-weight:700;padding:1px 4px;border-radius:3px;margin-left:4px;vertical-align:middle;background:rgba(255,184,77,0.1);color:var(--warn)}' +
      '@media(max-width:900px){.col-grid{grid-template-columns:repeat(2,1fr)}}' +
      '@media(max-width:640px){.col-grid{grid-template-columns:1fr}}';

    html += '<div class="report-section"><div class="report-section-title">Sensor Collectors</div>' +
      '<style>' + colStyle + '</style>' +
      '<div style="font-size:0.65rem;color:var(--muted);margin-bottom:12px">' +
      '<span class="col-status-active">ACTIVE</span> log file exists + written in last 2h &nbsp; ' +
      '<span class="col-status-detected">DETECTED</span> log file exists but stale or not yet seen today &nbsp; ' +
      '<span class="col-status-missing">NOT FOUND</span> tool not installed / log absent' +
      '</div>' +
      '<div class="col-grid">';

    collectors.forEach(c => {
      const icon = colIcons[c.id] || '📦';
      const kindBadge = c.kind === 'native'
        ? '<span class="col-kind-native">NATIVE</span>'
        : '<span class="col-kind-ext">EXTERNAL</span>';
      let statusBadge, rowCls;
      if (c.active) {
        statusBadge = '<span class="col-status-active">ACTIVE</span>';
        rowCls = 'col-active';
      } else if (c.detected) {
        statusBadge = '<span class="col-status-detected">DETECTED</span>';
        rowCls = 'col-detected';
      } else {
        statusBadge = '<span class="col-status-missing">NOT FOUND</span>';
        rowCls = 'col-missing';
      }
      const evtBadge = c.events_today > 0
        ? '<span class="col-evt">' + c.events_today + ' events today</span>'
        : '';
      html += '<div class="col-row ' + rowCls + '">' +
        '<div class="col-ico">' + icon + '</div>' +
        '<div class="col-body">' +
        '<div class="col-name">' + esc(c.name) + kindBadge + statusBadge + evtBadge + '</div>' +
        '<div class="col-meta">' + esc(c.desc) + '</div>' +
        ((!c.detected && c.kind === 'external') ? '<div style="font-size:0.58rem;color:var(--accent);margin-top:3px">Not installed - optional external tool</div>' : '') +
        '</div></div>';
    });

    html += '</div></div>';
  }

  // ── Section 4: Data files ──────────────────────────────────────────────
  html += '<div class="report-section"><div class="report-section-title">Data Files - ' + esc(s.date || '-') + '</div>' +
    '<table class="report-table"><thead><tr><th>File</th><th>Status</th><th>Size</th></tr></thead><tbody>';
  Object.entries(files).forEach(([k, v]) => {
    const exists = v.exists;
    // events.jsonl no longer used — events go to SQLite (spec 016)
    const isSqlite = (k === 'events' && !exists);
    const statusLabel = isSqlite
      ? '<span class="health-ok">✓ SQLite</span>'
      : exists ? '<span class="health-ok">✓ Present</span>'
      : '<span style="color:var(--muted)">- Absent</span>';
    html += '<tr>' +
      '<td style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem">' + esc(k) + (isSqlite ? ' (db)' : '.jsonl') + '</td>' +
      '<td>' + statusLabel + '</td>' +
      '<td style="color:var(--muted)">' + (exists ? fmt(v.size_bytes) : isSqlite ? 'innerwarden.db' : '-') + '</td>' +
      '</tr>';
  });
  html += '</tbody></table></div>';

  html += '<div class="report-section"><div class="report-section-title">Data Directory</div>' +
    '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;color:var(--muted);padding:4px 0">' + esc(s.data_dir || '-') + '</div></div>';

  // ── Section 5: Knowledge Graph stats ──────────────────────────────────
  const gs = s.graph || {};
  if (gs.node_count) {
    const gmem = gs.memory_bytes ? (gs.memory_bytes / 1024 / 1024).toFixed(1) + ' MB' : '?';
    const byType = gs.nodes_by_type || {};
    html += '<div class="report-section"><div class="report-section-title">Knowledge Graph</div>' +
      '<div style="display:flex;gap:16px;flex-wrap:wrap;padding:4px 0;font-size:0.78rem;">' +
      '<span>Nodes: <b>' + (gs.node_count||0) + '</b></span>' +
      '<span>Edges: <b>' + (gs.edge_count||0) + '</b></span>' +
      '<span>Memory: <b>' + gmem + '</b></span>' +
      '<span>Incidents: <b>' + (gs.incident_nodes||0) + '</b></span>' +
      '<span>Threat Intel: <b>' + (gs.threat_intel_nodes||0) + '</b></span>' +
      '</div>' +
      '<div style="font-size:0.72rem;color:var(--muted);padding:2px 0">' +
      Object.entries(byType).map(function(e) { return e[0] + ':' + e[1]; }).join(' · ') +
      '</div></div>';
  }

  // ── Section 6: Metrics Drift (spec 024) ──────────────────────────────
  // The populated content is injected asynchronously by loadMetricsDrift().
  html += '<div class="report-section" id="metrics-drift-section">' +
    '<div class="report-section-title">' +
      'Metrics Drift <span style="font-size:0.72rem;color:var(--muted);font-weight:normal">' +
        '· spec 024 · scraping /metrics</span>' +
    '</div>' +
    '<div id="metrics-drift-body"><div class="muted">Loading…</div></div>' +
    '</div>';

  return html;
}

// ─── Spec 024 Metrics Drift ────────────────────────────────────────────
//
// Reads the agent's own /metrics endpoint (Prometheus text, served by
// dashboard/agent_api::api_prometheus_metrics) and renders the 10
// spec-024 drift metrics. No external Prometheus server needed.
//
// Invoked by loadStatus() after renderStatus completes. Missing metrics
// render as 0 rather than omitting rows so operators always see the
// expected shape.

const METRICS_DRIFT_KEYS = [
  { key: 'innerwarden_incidents_per_hour',          labelDim: 'severity', heading: 'Incidents / hour',            alert: '±3σ from 7-day mean' },
  { key: 'innerwarden_telegram_msgs_per_hour',      labelDim: null,       heading: 'Telegram msgs / hour',         alert: '>50/h warn · >200/h crit' },
  { key: 'innerwarden_blocks_per_hour',             labelDim: 'backend',  heading: 'Blocks / hour',                alert: '±3σ from 7-day mean' },
  { key: 'innerwarden_honeypot_sessions_per_hour',  labelDim: null,       heading: 'Honeypot sessions / hour',     alert: '0 for 24h · warn' },
  { key: 'innerwarden_tracker_detections_per_hour', labelDim: 'pattern',  heading: 'Tracker detections / hour',    alert: '0 for 24h when incidents>10 · warn' },
  { key: 'innerwarden_orphaned_responses_total',    labelDim: null,       heading: 'Orphaned responses (total)',   alert: 'Any increment · critical' },
  { key: 'innerwarden_revert_failures_total',       labelDim: null,       heading: 'Revert failures (total)',      alert: 'increase over 1h >10 · warn' },
  { key: 'innerwarden_ai_provider_errors_per_hour', labelDim: 'provider', heading: 'AI provider errors / hour',    alert: '>5/h · warn' },
  { key: 'innerwarden_gate_suppressed_total',       labelDim: null,       heading: 'Gate suppressed (total)',      alert: 'low rate + high telegram volume = gate drift' },
  { key: 'innerwarden_event_rate_per_hour',         labelDim: 'source',   heading: 'Event rate / hour',            alert: '0 for 1h = source silent' },
];

async function loadMetricsDrift() {
  const body = document.getElementById('metrics-drift-body');
  if (!body) return;
  try {
    const resp = await fetch('/metrics', { credentials: 'same-origin' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const text = await resp.text();
    const parsed = parsePrometheusText(text);
    body.innerHTML = renderMetricsDrift(parsed);
  } catch (e) {
    body.innerHTML = '<div class="muted">Could not read /metrics: ' + esc(String(e.message)) + '</div>';
  }
}

function parsePrometheusText(text) {
  // Map: metric_name → Array<{labels: {k:v}, value: number}>
  const out = new Map();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw || raw.startsWith('#')) continue;
    // NAME{l1="v1",l2="v2"} VALUE  |  NAME VALUE
    const m = raw.match(/^([a-zA-Z_][a-zA-Z0-9_]*)(?:\{([^}]*)\})?\s+(-?\d+(?:\.\d+)?)/);
    if (!m) continue;
    const name = m[1];
    const labels = {};
    if (m[2]) {
      const parts = m[2].split(',');
      for (let p = 0; p < parts.length; p++) {
        const pm = parts[p].match(/^\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"\s*$/);
        if (pm) labels[pm[1]] = pm[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      }
    }
    const val = Number(m[3]);
    if (!out.has(name)) out.set(name, []);
    out.get(name).push({ labels: labels, value: val });
  }
  return out;
}

function renderMetricsDrift(parsed) {
  let html = '<div style="font-size:0.74rem;color:var(--muted);padding-bottom:6px">' +
    'Live view of the 10 metrics scraped by <code>docs/prometheus-alerts.yaml</code>. ' +
    'Zero across the board on a quiet host is expected; sudden jumps or collapses signal drift.' +
    '</div>';
  html += '<table class="report-table" style="font-size:0.78rem">' +
    '<thead><tr>' +
    '<th style="text-align:left">Metric</th>' +
    '<th style="text-align:left">Dimension</th>' +
    '<th style="text-align:right">Value</th>' +
    '<th style="text-align:left">Alert rule</th>' +
    '</tr></thead><tbody>';
  for (let i = 0; i < METRICS_DRIFT_KEYS.length; i++) {
    const entry = METRICS_DRIFT_KEYS[i];
    const rows = parsed.get(entry.key) || [];
    if (rows.length === 0) {
      html += '<tr>' +
        '<td><code>' + esc(entry.key) + '</code></td>' +
        '<td class="muted">' + (entry.labelDim ? esc(entry.labelDim) + ': —' : '—') + '</td>' +
        '<td style="text-align:right">0</td>' +
        '<td class="muted">' + esc(entry.alert) + '</td>' +
        '</tr>';
      continue;
    }
    for (let r = 0; r < rows.length; r++) {
      const row = rows[r];
      const dim = entry.labelDim
        ? esc(entry.labelDim) + ': <code>' + esc(row.labels[entry.labelDim] || '—') + '</code>'
        : '—';
      html += '<tr>' +
        '<td><code>' + esc(entry.key) + '</code></td>' +
        '<td>' + dim + '</td>' +
        '<td style="text-align:right">' + formatMetricValue(row.value) + '</td>' +
        '<td class="muted">' + esc(entry.alert) + '</td>' +
        '</tr>';
    }
  }
  html += '</tbody></table>';
  return html;
}

function formatMetricValue(v) {
  if (!isFinite(v)) return '-';
  if (Math.abs(v) >= 100) return v.toFixed(0);
  if (Math.abs(v) >= 10)  return v.toFixed(1);
  return v.toFixed(2);
}

// On mobile: auto-collapse the list when a journey is opened, re-open via button
function collapseLeftOnMobile() {
  if (window.innerWidth <= 860 && leftPanelOpen) {
    toggleLeftPanel();
  }
}
