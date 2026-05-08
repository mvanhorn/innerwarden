// ── Intelligence tab ──────────────────────────────────────────────
// 2026-05-03 (PR #413): the Playbooks Intel sub-tab + probe were
// removed alongside the playbook engine. Future declarative
// orchestration belongs to Spec 042 active defense.

async function loadIntel() {
  const status = document.getElementById('intelViewStatus');
  const content = document.getElementById('intelContent');
  if (status) status.textContent = 'Loading…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const sort = document.getElementById('intelSort')?.value || 'risk_score';
    const minRisk = document.getElementById('intelMinRisk')?.value || '0';
    const data = await loadJson(`/api/attacker-profiles?sort=${sort}&min_risk=${minRisk}&limit=100`, { signal });
    if (!data || !data.profiles) { content.innerHTML = '<p style="color:var(--dim)">No attacker profiles yet.</p>'; return; }

    let html = `<div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${data.total || 0}</div><div class="kpi-label">Total Profiles</div></div>
      <div class="kpi-card"><div class="kpi-value">${data.profiles.filter(p=>p.risk_score>=70).length}</div><div class="kpi-label">High Risk (≥70)</div></div>
      <div class="kpi-card"><div class="kpi-value">${new Set(data.profiles.map(p=>p.dna?.pattern_class).filter(Boolean)).size}</div><div class="kpi-label">Pattern Types</div></div>
      <div class="kpi-card"><div class="kpi-value">${new Set(data.profiles.map(p=>p.geo?.country_code).filter(Boolean)).size}</div><div class="kpi-label">Countries</div></div>
    </div>`;

    html += `<table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
      <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
        <th style="padding:6px;">Risk</th><th style="padding:6px;">IP</th><th style="padding:6px;">Country</th>
        <th style="padding:6px;">Incidents</th><th style="padding:6px;">Blocks</th><th style="padding:6px;">Detectors</th>
        <th style="padding:6px;">Pattern</th><th style="padding:6px;">DNA</th><th style="padding:6px;">Last Seen</th>
      </tr></thead><tbody>`;

    for (const p of data.profiles) {
      const riskColor = p.risk_score >= 70 ? '#e74c3c' : p.risk_score >= 40 ? '#f39c12' : '#27ae60';
      const riskBar = `<div style="display:flex;align-items:center;gap:6px;">
        <div style="width:40px;height:8px;background:var(--border);border-radius:4px;overflow:hidden;">
          <div style="width:${p.risk_score}%;height:100%;background:${riskColor};"></div>
        </div><span style="color:${riskColor};font-weight:600;">${p.risk_score}</span></div>`;
      const country = p.geo?.country_code || '??';
      const detectors = (p.detectors_triggered || []).slice(0, 3).join(', ');
      const patternRaw = p.dna?.pattern_class || 'unknown';
      const dnaShort = (p.dna?.hash || '').slice(0, 10);
      const lastSeen = p.last_seen ? new Date(p.last_seen).toLocaleDateString() : '\u2014';
      const patternLabels = { regular_scanner:'Regular Scanner', targeted:'Targeted Attack', opportunistic:'Opportunistic', unknown:'Unknown' };
      const pattern = patternLabels[patternRaw] || patternRaw.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const patternBadge = pattern === 'Regular Scanner' ? lucideIcon('refresh-ccw') : pattern === 'Targeted Attack' ? lucideIcon('target') : pattern === 'Opportunistic' ? lucideIcon('crosshair') : lucideIcon('alert-circle');

      html += `<tr style="border-bottom:1px solid var(--border);cursor:pointer;" onclick="showProfileDetail('${esc(p.ip)}')">
        <td style="padding:6px;">${riskBar}</td>
        <td style="padding:6px;font-family:monospace;">${esc(p.ip)}</td>
        <td style="padding:6px;">${country}</td>
        <td style="padding:6px;">${p.total_incidents}</td>
        <td style="padding:6px;">${p.total_blocks}</td>
        <td style="padding:6px;font-size:0.75rem;">${detectors}</td>
        <td style="padding:6px;">${patternBadge} ${pattern}</td>
        <td style="padding:6px;font-family:monospace;font-size:0.7rem;color:var(--dim);">${dnaShort}</td>
        <td style="padding:6px;font-size:0.75rem;">${lastSeen}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    content.innerHTML = html;
    if (status) status.textContent = `${data.total} profiles`;
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c;">Failed to load: ${e.message}</p>`;
    if (status) status.textContent = 'Error';
  }
}

async function showProfileDetail(ip) {
  const content = document.getElementById('intelContent');
  try {
    const p = await loadJson(`/api/attacker-profiles/${encodeURIComponent(ip)}`);
    if (!p || p.error) { content.innerHTML = `<p style="color:#e74c3c">${p?.error || 'Not found'}</p>`; return; }

    const riskColor = p.risk_score >= 70 ? '#e74c3c' : p.risk_score >= 40 ? '#f39c12' : '#27ae60';
    let html = `<button type="button" onclick="loadIntel()" style="margin-bottom:12px;padding:4px 12px;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text);cursor:pointer;">← Back</button>`;

    html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">`;

    // Left: Identity + Timeline
    html += `<div class="kpi-card" style="padding:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('target',{size:18})} ${p.ip}</h3>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <div style="width:120px;height:12px;background:var(--border);border-radius:6px;overflow:hidden;">
          <div style="width:${p.risk_score}%;height:100%;background:${riskColor};"></div>
        </div>
        <span style="font-size:1.5rem;font-weight:700;color:${riskColor};">${p.risk_score}/100</span>
      </div>
      <table style="font-size:0.8rem;"><tbody>
        <tr><td style="padding:2px 8px;color:var(--dim);">Country</td><td>${p.geo?.country || '—'} (${p.geo?.country_code || '??'})</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">ISP</td><td>${p.geo?.isp || '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">ASN</td><td>${p.geo?.asn || '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">AbuseIPDB</td><td>${p.abuseipdb_score ?? '—'}/100</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">CrowdSec</td><td>${p.crowdsec_listed ? lucideIcon('alert-triangle',{size:12}) + ' Listed' : lucideIcon('check-circle',{size:12}) + ' Clean'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Tor</td><td>${p.is_tor ? lucideIcon('globe',{size:12}) + ' Yes' : 'No'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">First Seen</td><td>${p.first_seen ? new Date(p.first_seen).toLocaleString() : '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Last Seen</td><td>${p.last_seen ? new Date(p.last_seen).toLocaleString() : '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Days Active</td><td>${p.visit_count} days</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Pattern</td><td>${p.dna?.pattern_class || 'unknown'}</td></tr>
      </tbody></table>
    </div>`;

    // Right: Attack Profile
    html += `<div class="kpi-card" style="padding:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('swords',{size:16})} Attack Profile</h3>
      <table style="font-size:0.8rem;"><tbody>
        <tr><td style="padding:2px 8px;color:var(--dim);">Incidents</td><td>${p.total_incidents}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Blocks</td><td>${p.total_blocks}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Shield Blocks</td><td>${p.shield_blocks || 0}${p.shield_last_blocked ? ' (last: ' + new Date(p.shield_last_blocked).toLocaleString() + ')' : ''}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Honeypot</td><td>${p.total_honeypot_diversions} diversions, ${p.honeypot_sessions} sessions</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Max Severity</td><td style="font-weight:600;">${p.max_severity}</td></tr>
      </tbody></table>
      <h4 style="margin:12px 0 4px;font-size:0.8rem;color:var(--dim);">Detectors Triggered</h4>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">${(p.detectors_triggered||[]).map(d=>`<span style="padding:2px 6px;border-radius:4px;background:var(--border);font-size:0.7rem;">${esc(d)}</span>`).join('')}</div>
      <h4 style="margin:12px 0 4px;font-size:0.8rem;color:var(--dim);">MITRE Techniques</h4>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">${(p.mitre_techniques||[]).map(t=>`<span style="padding:2px 6px;border-radius:4px;background:#2c1810;color:#f39c12;font-size:0.7rem;">${esc(t)}</span>`).join('')}</div>
    </div>`;
    html += `</div>`;

    // DNA section
    html += `<div class="kpi-card" style="padding:16px;margin-top:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('dna',{size:16})} Behavioral DNA</h3>
      <div style="font-family:monospace;font-size:0.75rem;color:var(--dim);margin-bottom:8px;">Hash: ${p.dna?.hash || '—'}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;">
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Hour Distribution</h4>
          <div style="display:flex;align-items:flex-end;gap:1px;height:40px;">${(p.dna?.hour_distribution||[]).map((v,i)=>`<div title="${i}:00 — ${v} events" style="flex:1;background:${v>0?'#3498db':'var(--border)'};height:${v?Math.max(4,v/Math.max(...(p.dna?.hour_distribution||[1]))*40):2}px;border-radius:1px;"></div>`).join('')}</div>
          <div style="display:flex;justify-content:space-between;font-size:0.6rem;color:var(--dim);"><span>0h</span><span>12h</span><span>23h</span></div>
        </div>
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Target Users</h4>
          ${(p.dna?.target_users||[]).map(u=>`<div style="font-family:monospace;font-size:0.75rem;">${esc(u)}</div>`).join('')||'<span style="color:var(--dim);font-size:0.75rem;">none</span>'}
        </div>
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Tool Signatures</h4>
          ${(p.dna?.tool_signatures||[]).map(t=>`<span style="padding:2px 6px;border-radius:4px;background:#1a2634;color:#3498db;font-size:0.7rem;margin:2px;">${esc(t)}</span>`).join('')||'<span style="color:var(--dim);font-size:0.75rem;">none</span>'}
        </div>
      </div>
    </div>`;

    // Honeypot Intel
    if (p.honeypot_sessions > 0) {
      html += `<div class="kpi-card" style="padding:16px;margin-top:16px;">
        <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('bug',{size:16})} Honeypot Intel</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
          <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Credentials Attempted</h4>
            <table style="font-size:0.75rem;"><tbody>
              ${(p.credentials_attempted||[]).slice(0,10).map(([u,pw])=>`<tr><td style="padding:1px 6px;font-family:monospace;">${esc(u)}</td><td style="padding:1px 6px;font-family:monospace;color:var(--dim);">${esc(pw)}</td></tr>`).join('')}
            </tbody></table>
          </div>
          <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Commands Executed</h4>
            ${(p.commands_executed||[]).slice(0,10).map(c=>`<div style="font-family:monospace;font-size:0.7rem;padding:2px 0;border-bottom:1px solid var(--border);">${esc(c)}</div>`).join('')}
          </div>
        </div>
        ${(p.iocs?.urls||[]).length > 0 ? `<h4 style="font-size:0.8rem;color:var(--dim);margin:12px 0 4px;">IOCs</h4>
          ${(p.iocs.urls||[]).map(u=>`<div style="font-family:monospace;font-size:0.7rem;display:flex;align-items:center;gap:6px">${lucideIcon('link',{size:12})} ${esc(u)}</div>`).join('')}
          ${(p.iocs.ips||[]).map(i=>`<div style="font-family:monospace;font-size:0.7rem;display:flex;align-items:center;gap:6px">${lucideIcon('globe',{size:12})} ${esc(i)}</div>`).join('')}` : ''}
      </div>`;
    }

    content.innerHTML = html;
  } catch(e) {
    content.innerHTML = `<p style="color:#e74c3c">Failed: ${e.message}</p><button type="button" onclick="loadIntel()">← Back</button>`;
  }
}

let currentIntelTab = 'profiles';
function switchIntelTab(tab) {
  currentIntelTab = tab;
  const tabs = ['Profiles','Campaigns','Chains','Baseline','Mitre'];
  tabs.forEach(t => {
    const btn = document.getElementById('intelTab'+t);
    if (btn) { const active = t.toLowerCase() === tab; btn.style.background = active ? 'var(--accent)' : 'var(--card-bg)'; btn.style.color = active ? '#0a0f1a' : 'var(--text)'; btn.style.fontWeight = active ? '600' : '400'; btn.style.borderColor = active ? 'var(--accent)' : 'var(--border)'; }
  });

  // 2026-05-02 audit fix (P8): the previous tab's content stayed on
  // screen for ~5s while the new sub-tab fetch was in flight. Clear
  // the content area immediately and abort any in-flight intel fetch
  // so a fast tab cycle never paints stale data under the new title.
  if (window._activeFetch_intel && typeof window._activeFetch_intel.abort === 'function') {
    try { window._activeFetch_intel.abort(); } catch (_) {}
  }
  window._activeFetch_intel = new AbortController();
  const content = document.getElementById('intelContent');
  if (content) content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted);font-size:0.8rem">Loading...</div>';
  const status = document.getElementById('intelViewStatus');
  if (status) status.textContent = '';

  if (tab === 'campaigns') loadCampaigns();
  else if (tab === 'chains') loadChains();
  else if (tab === 'baseline') loadBaseline();
  else if (tab === 'mitre') loadMitreCoverage();
  else loadIntel();
}

async function loadCampaigns() {
  const status = document.getElementById('intelViewStatus');
  const content = document.getElementById('intelContent');
  if (status) status.textContent = 'Loading campaigns…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const data = await loadJson('/api/campaigns', { signal });
    if (!data || !data.campaigns || data.campaigns.length === 0) {
      content.innerHTML = `<div style="text-align:center;padding:40px;">
        <div style="margin-bottom:8px;">${lucideIcon('search',{size:32})}</div>
        <p style="color:var(--dim);">No campaigns detected yet.</p>
        <p style="font-size:0.8rem;color:var(--dim);">Campaigns are detected when multiple IPs share the same behavioral DNA, IOCs (C2 servers, malware URLs), or attack patterns.</p>
      </div>`;
      if (status) status.textContent = '0 campaigns';
      return;
    }

    let html = `<div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${data.total}</div><div class="kpi-label">Active Campaigns</div></div>
      <div class="kpi-card"><div class="kpi-value">${data.campaigns.reduce((s,c)=>s+c.member_ips.length,0)}</div><div class="kpi-label">IPs Involved</div></div>
      <div class="kpi-card"><div class="kpi-value">${data.campaigns.filter(c=>c.confidence==='high').length}</div><div class="kpi-label">High Confidence</div></div>
      <div class="kpi-card"><div class="kpi-value">${new Set(data.campaigns.flatMap(c=>c.countries)).size}</div><div class="kpi-label">Countries</div></div>
    </div>`;

    for (const c of data.campaigns) {
      const confColor = c.confidence === 'high' ? '#e74c3c' : c.confidence === 'medium' ? '#f39c12' : '#27ae60';
      const typeIcon = c.correlation_type.includes('dna') && c.correlation_type.includes('ioc') ? lucideIcon('dna') + lucideIcon('link')
        : c.correlation_type.includes('dna') ? lucideIcon('dna')
        : c.correlation_type.includes('ioc') ? lucideIcon('link') : lucideIcon('radio');

      html += `<div class="kpi-card" style="padding:16px;margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-weight:700;font-size:1.1rem;">${c.campaign_id}</span>
            <span style="font-size:1.2rem;">${typeIcon}</span>
            <span style="padding:2px 8px;border-radius:4px;background:${confColor}20;color:${confColor};font-size:0.75rem;font-weight:600;">${c.confidence}</span>
            <span style="padding:2px 8px;border-radius:4px;background:var(--border);font-size:0.7rem;">${c.correlation_type === 'dna' ? 'Behavioral Pattern' : c.correlation_type === 'ioc' ? 'Shared Indicators' : c.correlation_type}</span>
          </div>
          <div style="text-align:right;">
            <span style="font-weight:600;color:${confColor};">Risk: ${c.max_risk_score}</span>
            <span style="margin-left:8px;font-size:0.8rem;color:var(--dim);">${c.total_incidents} incidents</span>
          </div>
        </div>

        <div style="font-size:0.85rem;margin-bottom:8px;">${c.summary}</div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <div>
            <div style="font-size:0.75rem;color:var(--dim);margin-bottom:4px;">Member IPs (${c.member_ips.length})</div>
            <div style="display:flex;flex-wrap:wrap;gap:4px;">
              ${c.member_ips.map(ip=>`<span onclick="switchIntelTab('profiles');setTimeout(()=>showProfileDetail('${esc(ip)}'),100)" style="padding:2px 8px;border-radius:4px;background:var(--border);font-family:monospace;font-size:0.75rem;cursor:pointer;">${esc(ip)}</span>`).join('')}
            </div>
            ${c.countries.length ? `<div style="font-size:0.7rem;color:var(--dim);margin-top:4px;">Countries: ${c.countries.join(', ')}</div>` : ''}
          </div>
          <div>
            ${c.shared_dna_signature ? `<div style="margin-bottom:4px;">
              <span style="font-size:0.75rem;color:var(--dim);">DNA Signature:</span>
              <code style="font-size:0.7rem;margin-left:4px;">${c.shared_dna_signature}</code>
            </div>` : ''}
            ${c.shared_iocs.length ? `<div style="margin-bottom:4px;">
              <div style="font-size:0.75rem;color:var(--dim);margin-bottom:2px;">Shared IOCs:</div>
              ${c.shared_iocs.slice(0,5).map(i=>`<div style="font-family:monospace;font-size:0.7rem;color:#e74c3c;">${i}</div>`).join('')}
            </div>` : ''}
            ${c.shared_detectors.length ? `<div>
              <div style="font-size:0.75rem;color:var(--dim);margin-bottom:2px;">Shared Detectors:</div>
              <div style="display:flex;flex-wrap:wrap;gap:3px;">
                ${c.shared_detectors.map(d=>`<span style="padding:1px 6px;border-radius:3px;background:#1a2634;color:#3498db;font-size:0.65rem;">${d}</span>`).join('')}
              </div>
            </div>` : ''}
          </div>
        </div>
      </div>`;
    }

    content.innerHTML = html;
    if (status) status.textContent = `${data.total} campaigns`;
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c;">Failed to load: ${e.message}</p>`;
    if (status) status.textContent = 'Error';
  }
}

// ── Chains sub-tab ─────────────────────────────────────────────────
async function loadChains() {
  const content = document.getElementById('intelContent');
  const status = document.getElementById('intelViewStatus');
  if (status) status.textContent = 'Loading chains…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const data = await loadJson('/api/correlation-chains', { signal });
    if (!data?.chains?.length) {
      // 2026-04-30: Fix — was a single-quoted string with ${lucideIcon('link',...)}
      // inside it. The single quote in 'link' closed the outer string and
      // syntax-broke the entire intel.js file, leaving loadIntel() undefined
      // (operator saw "Loading attacker profiles..." stuck forever). Backtick
      // template literal evaluates ${} interpolation correctly.
      content.innerHTML = `<div style="text-align:center;padding:40px;"><div>${lucideIcon('link',{size:32})}</div><p style="color:var(--dim);">No attack chains detected yet.</p><p style="font-size:0.8rem;color:var(--dim);">Chains are multi-stage attacks that span multiple security layers (firmware, kernel, network, userspace).</p></div>`;
      if (status) status.textContent = '0 chains';
      return;
    }
    // 2026-05-08 (fix/chains-tab-honesty-bundle): severity comes from
    // the backend lower-cased ("critical"/"high"/...). The previous
    // filter compared `=== 'Critical'` and `sevRank[c.severity]`
    // expected capitalised keys — both never matched, so the
    // "Critical" KPI showed `0` even when the list was full of
    // critical badges. Normalise via toLowerCase() at every comparison
    // point.
    const sevOf = (c) => (c.severity || '').toLowerCase();
    const criticalCount = data.chains.filter(c => sevOf(c) === 'critical').length;
    let html = `<div class="kpi-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${data.total}</div><div class="kpi-label">Attack Chains</div></div>
      <div class="kpi-card"><div class="kpi-value">${criticalCount}</div><div class="kpi-label">Critical</div></div>
      <div class="kpi-card"><div class="kpi-value">${new Set(data.chains.flatMap(c=>c.layers_involved||[])).size}</div><div class="kpi-label">Layers Involved</div></div>
    </div>`;
    // 2026-05-01 (audit finding 3.4): the chains list rendered every
    // hit individually, producing 100 identical rows when the same
    // rule fired repeatedly ("Data Exfiltration eBPF Sequence: 2
    // stages 2 layers 5s, 85% confidence, ×100"). Original dedup
    // keyed on `(rule_id, summary)` but `summary` includes the
    // duration ("...in 1s" vs "...in 17s") so the same rule firing
    // 6 times in 37s rendered as 6 separate groups (operator's prod
    // 2026-05-08 had `Multi-Persistence Installation` chains
    // CHAIN-0137-0142+0001 all in one 37-second window).
    //
    // 2026-05-08 (fix/chains-tab-honesty-bundle): tighten the dedup
    // key to `rule_id` ALONE. Same rule firing repeatedly → one
    // row with `×N` count + the full time range. Operator can still
    // drill into the sample chain_id when needed.
    const groups = new Map();
    for (const c of data.chains) {
      const key = c.rule_id || '';
      let g = groups.get(key);
      if (!g) {
        g = {
          rule_id: c.rule_id, rule_name: c.rule_name, summary: c.summary,
          severity: c.severity, layers_involved: c.layers_involved || [],
          confidence: c.confidence, stages_matched: c.stages_matched,
          count: 0, first_ts: null, last_ts: null,
          first_chain_id: c.chain_id,
        };
        groups.set(key, g);
      }
      g.count += 1;
      // Track most severe colour across the group; Critical > High > Medium > else.
      // Lower-cased keys to match the backend's lower-cased severity.
      const sevRank = { critical: 4, high: 3, medium: 2, low: 1 };
      if ((sevRank[sevOf(c)] || 0) > (sevRank[sevOf(g)] || 0)) g.severity = c.severity;
      // Track time range across the group.
      if (c.start_ts) g.first_ts = (!g.first_ts || c.start_ts < g.first_ts) ? c.start_ts : g.first_ts;
      if (c.last_ts)  g.last_ts  = (!g.last_ts  || c.last_ts  > g.last_ts)  ? c.last_ts  : g.last_ts;
    }
    const grouped = Array.from(groups.values()).sort((a, b) => b.count - a.count);
    for (const g of grouped) {
      const sev = (g.severity || '').toLowerCase();
      const sevColor = sev === 'critical' ? '#e74c3c' : sev === 'high' ? '#f39c12' : '#27ae60';
      const layers = (g.layers_involved||[]).map(l=>`<span style="padding:1px 6px;border-radius:3px;background:#1a2634;color:#3498db;font-size:0.65rem;">${l}</span>`).join(' → ');
      const countLabel = g.count > 1 ? ` ×${g.count}` : '';
      const sampleLabel = g.count > 1 ? ` (sample: ${g.first_chain_id})` : ` ${g.first_chain_id}`;
      html += `<div class="kpi-card" style="padding:12px;margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div><span style="font-weight:700;">${g.rule_name}${countLabel}</span><span style="font-size:0.8rem;color:var(--dim);">${sampleLabel}</span></div>
          <span style="padding:2px 8px;border-radius:4px;background:${sevColor}20;color:${sevColor};font-size:0.75rem;">${g.severity}</span>
        </div>
        <div style="font-size:0.85rem;margin:6px 0;">${g.summary}</div>
        <div style="margin:4px 0;">Layers: ${layers}</div>
        <div style="font-size:0.75rem;color:var(--dim);">Confidence: ${(g.confidence*100).toFixed(0)}% · ${g.stages_matched} stages · Rule: ${g.rule_id}</div>
        <div style="font-size:0.7rem;color:var(--dim);margin-top:4px;">${g.first_ts ? new Date(g.first_ts).toLocaleString() : ''} → ${g.last_ts ? new Date(g.last_ts).toLocaleString() : ''}</div>
      </div>`;
    }
    content.innerHTML = html;
    if (status) status.textContent = `${data.total} chains`;
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c">Failed: ${e.message}</p>`;
  }
}

// ── Baseline sub-tab ──────────────────────────────────────────────
// ── Baseline tab — three-level UX (2026-05-03 redesign) ──────────────
//
// Operator complaint: the previous version dumped every learned
// signal as a long table and used SOC vocabulary ("lineages",
// "observations", "EMA"). Both the security analyst and the lay
// operator bounced off it. The redesign answers three questions in
// order:
//
//   1. Is everything normal right now?  → Hero (1 line, always visible)
//   2. If not, what changed?              → Deviation cards (top 5)
//   3. What does the agent consider normal here? → "Show learned baseline" (collapsed)
//
// The Hero card paints semaphore colours; deviation cards are
// actionable (each links to the relevant journey); the learned
// baseline section is opt-in. Layouts use heatmap + sparkline so
// the operator can read a week's pattern in one glance instead of
// scrolling a 24-row table per user.

// Friendly headlines + emoji + suggested action text per anomaly type.
// Server returns the raw `anomaly_type` enum value; this map turns it
// into a card the operator can read in 2 seconds.
// 2026-05-03 (PR #419 Wave 2): translated PT-BR → EN to align with
// the rest of the dashboard. Original strings were Portuguese-only,
// inconsistent with all other tabs. Operator request.
const BASELINE_ANOMALY_LABELS = {
  event_rate_drop: {
    icon: '📉',
    headline: (a) => `${prettySource(a)} went silent`,
    explainer: (a) => `Expected this hour: about ${a.expected}. Seen: ${a.observed}.`,
    why: 'Could mean nobody used the service or something disabled the logs. Worth checking.',
  },
  event_rate_spike: {
    icon: '📈',
    headline: (a) => `${prettySource(a)} spiked above normal`,
    explainer: (a) => `Expected: about ${a.expected}. Seen: ${a.observed}.`,
    why: 'Sudden activity peak. Could be a deploy, an external scan, or an attack in progress.',
  },
  process_lineage: {
    icon: '🌿',
    headline: (a) => 'Process lineage never seen before',
    explainer: (a) => a.description,
    why: 'The agent has never observed this parent → child on this host. Often indicates a shell spawning out of a web service.',
  },
  user_login_time: {
    icon: '🌙',
    headline: (a) => `${a.subject || 'User'} logged in outside typical hours`,
    explainer: (a) => `Typical hours: ${a.expected}. Login now: ${a.observed}.`,
    why: 'Access outside the historical pattern. Confirm whether it was you or an authorised user.',
  },
  new_destination: {
    icon: '🔀',
    headline: (a) => `${a.subject || 'Process'} connected to a new destination`,
    explainer: (a) => `Typical destinations: ${a.expected}. Now: ${a.observed}.`,
    why: 'A known process talking to an unfamiliar endpoint. Risk profile changes.',
  },
};

function prettySource(a) {
  // Pull a friendly source name from the description if present, or
  // fall back to a generic phrase. Server passes details inline.
  const m = (a.description || '').match(/source ['"]?([a-z_]+)['"]?/i);
  return m ? m[1] : 'Event collection';
}

function baselineCardForAnomaly(a) {
  const meta = BASELINE_ANOMALY_LABELS[a.anomaly_type] || {
    icon: '⚠️',
    headline: () => 'Pattern outside normal',
    explainer: (x) => x.description || '',
    why: '',
  };
  const ageMin = Math.max(0, Math.floor((Date.now() - new Date(a.ts).getTime()) / 60000));
  const ageStr = ageMin < 60
    ? `${ageMin}m ago`
    : ageMin < 1440
      ? `${Math.floor(ageMin / 60)}h ago`
      : `${Math.floor(ageMin / 1440)}d ago`;
  const sevColor = a.severity === 'critical' ? '#e74c3c'
    : a.severity === 'high' ? '#f39c12'
    : a.severity === 'medium' ? '#f59e0b'
    : 'var(--dim)';
  const subjectLink = a.subject
    ? `<button type="button" onclick="homeBannerOpenPivot('${a.anomaly_type === 'user_login_time' ? 'user' : 'ip'}', '${esc(a.subject)}')" style="margin-top:6px;padding:4px 10px;border-radius:4px;border:1px solid var(--accent);background:transparent;color:var(--accent);cursor:pointer;font-size:0.75rem;">Investigate ${esc(a.subject)} →</button>`
    : '';
  return `
    <div class="baseline-deviation-card">
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <div style="font-size:1.5rem;line-height:1;">${meta.icon}</div>
        <div style="flex:1;">
          <div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;">
            <span style="font-weight:600;font-size:0.92rem;">${esc(meta.headline(a))}</span>
            <span style="font-size:0.7rem;color:${sevColor};text-transform:uppercase;letter-spacing:0.05em;">${esc(a.severity)}</span>
            <span style="font-size:0.7rem;color:var(--dim);">${ageStr}</span>
          </div>
          <div style="font-size:0.82rem;color:var(--text);margin-top:4px;line-height:1.5;">${esc(meta.explainer(a))}</div>
          ${meta.why ? `<div style="font-size:0.75rem;color:var(--dim);margin-top:4px;font-style:italic;">${esc(meta.why)}</div>` : ''}
          ${subjectLink}
        </div>
      </div>
    </div>`;
}

function baselineHeroCard(b, deviations24h) {
  if (!b.mature) {
    const days = b.training_days || 0;
    const remaining = Math.max(0, 7 - days);
    return `
      <div class="baseline-hero baseline-hero-learning">
        <div class="baseline-hero-icon">🔵</div>
        <div class="baseline-hero-body">
          <div class="baseline-hero-title">Learning what's normal on this server</div>
          <div class="baseline-hero-sub">${days} of 7 days collected. Anomaly detection starts in ${remaining} ${remaining === 1 ? 'day' : 'days'}.</div>
        </div>
      </div>`;
  }
  if (deviations24h === 0) {
    return `
      <div class="baseline-hero baseline-hero-normal">
        <div class="baseline-hero-icon">🟢</div>
        <div class="baseline-hero-body">
          <div class="baseline-hero-title">Normal</div>
          <div class="baseline-hero-sub">The server is behaving the same as on recent days. No patterns outside normal in the last 24 hours.</div>
        </div>
      </div>`;
  }
  return `
    <div class="baseline-hero baseline-hero-deviation">
      <div class="baseline-hero-icon">🟡</div>
      <div class="baseline-hero-body">
        <div class="baseline-hero-title">Something changed</div>
        <div class="baseline-hero-sub">${deviations24h} ${deviations24h === 1 ? 'pattern' : 'patterns'} outside normal in the last 24 hours. See what changed below.</div>
      </div>
    </div>`;
}

// 2026-05-03 (Wave 5): pagination state for the login heatmap. Stays a
// module-level let so back/forward inside the same Baseline render
// preserves the page; switching tabs resets via `_loginHeatmapPage = 0`
// in `loadBaseline`. Toggle state is persisted in localStorage so the
// operator's choice survives reloads.
let _loginHeatmapPage = 0;
const LOGIN_HEATMAP_PAGE_SIZE = 20;
const LOGIN_HEATMAP_LS_KEY = 'innerwarden.baseline.showServices';

function loginHeatmapShowServices() {
  try {
    return localStorage.getItem(LOGIN_HEATMAP_LS_KEY) === '1';
  } catch (_) {
    return false;
  }
}

function loginHeatmapSetShowServices(v) {
  try {
    localStorage.setItem(LOGIN_HEATMAP_LS_KEY, v ? '1' : '0');
  } catch (_) {}
}

// Exposed onclick handlers for the toggle + pagination. Re-renders by
// calling `loadBaseline()` so the controls go through the same data path
// as the initial load — a single source of truth for what the user sees.
window.toggleLoginHeatmapServices = function () {
  loginHeatmapSetShowServices(!loginHeatmapShowServices());
  _loginHeatmapPage = 0;
  loadBaseline();
};
window.loginHeatmapNextPage = function () {
  _loginHeatmapPage += 1;
  loadBaseline();
};
window.loginHeatmapPrevPage = function () {
  _loginHeatmapPage = Math.max(0, _loginHeatmapPage - 1);
  loadBaseline();
};

function loginHeatmap(logins, userClasses) {
  // Full-width 24×N heatmap. Each user gets a single row of 24 cells.
  // Bright cell = login activity seen in that hour historically.
  //
  // 2026-05-03 (Wave 5 — semantics fix):
  // - PAM emits "session opened" entries for daemon accounts
  //   (snap_daemon, systemd-resolve, messagebus, _apt, ...) that share
  //   plumbing with real SSH logins. Without filtering, the heatmap
  //   reads as "many users have logged in" when in reality only the
  //   `Human` + `Root` rows are real human SSH sessions.
  // - The endpoint enriches the JSON with `user_classes`. When that
  //   field is missing (older agent / classification failed), every
  //   user falls back to `unknown` and is shown — operator visibility
  //   beats false reassurance.
  // - The "Show system accounts" toggle is persisted in localStorage
  //   so the operator's choice survives reloads.
  // - Pagination kicks in only when visible humans exceed
  //   LOGIN_HEATMAP_PAGE_SIZE (20). Below that threshold, no paging
  //   controls render at all — keeps the simple case simple.
  const allUsers = Object.entries(logins);
  if (allUsers.length === 0) return '';
  const classes = userClasses || {};
  const classOf = (u) => classes[u] || 'unknown';

  const showServices = loginHeatmapShowServices();
  const visible = allUsers.filter(([user]) => {
    const c = classOf(user);
    if (c === 'service') return showServices;
    return true; // human, root, unknown — always visible
  });
  const hiddenServices = allUsers.length - visible.length;

  const totalPages = Math.max(1, Math.ceil(visible.length / LOGIN_HEATMAP_PAGE_SIZE));
  if (_loginHeatmapPage >= totalPages) _loginHeatmapPage = totalPages - 1;
  const pageStart = _loginHeatmapPage * LOGIN_HEATMAP_PAGE_SIZE;
  const pageUsers = visible.slice(pageStart, pageStart + LOGIN_HEATMAP_PAGE_SIZE);

  const classBadge = (c) => {
    const labels = { human: 'human', root: 'root', service: 'service', unknown: 'unknown' };
    const label = labels[c] || c;
    return `<span class="login-class-badge login-class-badge-${c}">${label}</span>`;
  };

  const rows = pageUsers.map(([user, hours]) => {
    const c = classOf(user);
    const cells = hours.map((v, i) => {
      const active = v > 0;
      const cls = active ? 'login-cell login-cell-active' : 'login-cell';
      const tip = `${user} (${c}) - ${i}:00 ${active ? '✓ session at this hour' : '(no record)'}`;
      return `<div class="${cls}" title="${esc(tip)}"></div>`;
    }).join('');
    return `
      <div class="login-heatmap-row">
        <div class="login-heatmap-user">
          ${classBadge(c)}
          <span class="login-heatmap-user-name" title="${esc(user)}">${esc(user)}</span>
        </div>
        <div class="login-heatmap-cells">${cells}</div>
      </div>`;
  }).join('');

  // Toggle row + (optional) pagination row + (optional) hint about
  // hidden service entries. Keep them above the grid so the operator
  // sees the controls before the data.
  const showHideLabel = showServices
    ? `Hide system accounts`
    : (hiddenServices > 0
      ? `Show system accounts (${hiddenServices})`
      : `Show system accounts`);
  const toggleRow = `
    <div class="login-heatmap-controls">
      <button type="button" class="login-heatmap-toggle" onclick="toggleLoginHeatmapServices()">
        ${esc(showHideLabel)}
      </button>
      ${hiddenServices > 0 && !showServices ? `
        <span class="login-heatmap-hint">
          ${hiddenServices} ${hiddenServices === 1 ? 'daemon PAM session is' : 'daemon PAM sessions are'} hidden (snap_daemon, systemd-resolve, etc.) — they share SSH plumbing but are not real human logins.
        </span>` : ''}
    </div>`;

  const paginationRow = visible.length > LOGIN_HEATMAP_PAGE_SIZE ? `
    <div class="login-heatmap-pagination">
      <button type="button" onclick="loginHeatmapPrevPage()" ${_loginHeatmapPage === 0 ? 'disabled' : ''}>← Prev</button>
      <span class="login-heatmap-page-meta">Page ${_loginHeatmapPage + 1} of ${totalPages} · showing ${pageUsers.length} of ${visible.length} users</span>
      <button type="button" onclick="loginHeatmapNextPage()" ${_loginHeatmapPage >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
    </div>` : '';

  return `
    ${toggleRow}
    <div class="login-heatmap">
      <div class="login-heatmap-axis"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
      ${rows}
    </div>
    ${paginationRow}`;
}

function eventRateAggregateSparkline(rates) {
  const sourceCount = Object.keys(rates).length;
  if (sourceCount === 0) return '';
  // Aggregate: sum per hour across all sources. Operator wants the
  // overall pulse, not per-source detail at this level.
  const aggregate = new Array(24).fill(0);
  for (const hours of Object.values(rates)) {
    for (let i = 0; i < 24; i++) aggregate[i] += hours[i] || 0;
  }
  const max = Math.max(...aggregate, 1);
  const bars = aggregate.map((v, i) => {
    const h = Math.max(2, (v / max) * 36);
    const tooltip = `${i}:00 - ~${v.toFixed(0)} typical events`;
    return `<div class="sparkline-bar" style="height:${h}px;" title="${tooltip}"></div>`;
  }).join('');
  return `
    <div class="baseline-sparkline">
      <div class="baseline-sparkline-label">Typical activity per hour (all ${sourceCount} sources combined)</div>
      <div class="baseline-sparkline-bars">${bars}</div>
      <div class="baseline-sparkline-axis"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
    </div>`;
}

function topProcessDestinations(dests, limit) {
  const entries = Object.entries(dests)
    .map(([p, ips]) => ({ proc: p, count: Array.isArray(ips) ? ips.length : 0 }))
    .filter((x) => x.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
  if (entries.length === 0) return '<p style="color:var(--dim);font-size:0.8rem;">No destinations observed yet.</p>';
  return `
    <ul class="baseline-dest-list">
      ${entries.map((x) => `
        <li><code>${esc(x.proc)}</code> connects to <strong>${x.count}</strong> ${x.count === 1 ? 'known destination' : 'known destinations'}</li>
      `).join('')}
    </ul>`;
}

function topProcessLineages(lineages, limit) {
  // The wire shape can be either an array of strings ("nginx→sh") or
  // an object map. Normalise.
  let list = [];
  if (Array.isArray(lineages)) list = lineages;
  else if (lineages && typeof lineages === 'object') list = Object.keys(lineages);
  if (list.length === 0) return '';
  return `
    <p style="font-size:0.8rem;margin:6px 0;color:var(--dim);">
      ${list.length} parent→child chains considered normal. Examples:
      ${list.slice(0, limit).map((l) => `<code>${esc(l)}</code>`).join(' · ')}
    </p>`;
}

async function loadBaseline() {
  const content = document.getElementById('intelContent');
  const statusEl = document.getElementById('intelViewStatus');
  if (statusEl) statusEl.textContent = 'Loading…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const b = await loadJson('/api/baseline-status', { signal });

    // Anomalies in the last 24h. Server may or may not surface them;
    // tolerate both shapes.
    const anomalies = Array.isArray(b.recent_anomalies) ? b.recent_anomalies : [];
    const since24h = Date.now() - 24 * 3600 * 1000;
    const recent = anomalies
      .filter((a) => a.ts && new Date(a.ts).getTime() >= since24h)
      .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

    let html = '';

    // ── Level 1: Hero ────────────────────────────────────────
    html += baselineHeroCard(b, recent.length);

    // ── Level 2: deviation cards (top 5) ─────────────────────
    if (recent.length > 0) {
      html += '<h3 class="baseline-section-title">What changed in the last 24 hours</h3>';
      html += '<div class="baseline-deviations">';
      html += recent.slice(0, 5).map(baselineCardForAnomaly).join('');
      html += '</div>';
      if (recent.length > 5) {
        html += `<p style="font-size:0.78rem;color:var(--dim);margin-top:8px;">+${recent.length - 5} other patterns. <a href="#threats" style="color:var(--accent);">See in investigation →</a></p>`;
      }
    } else if (b.mature) {
      html += '<div class="baseline-empty-deviations">No deviations detected in the last 24 hours.</div>';
    }

    // ── Level 3: collapsed "learned baseline" ────────────────
    const lineages = b.process_lineages;
    const lineageCount = Array.isArray(lineages)
      ? lineages.length
      : (lineages && typeof lineages === 'object' ? Object.keys(lineages).length : 0);
    const learnedSummary = `
      ${(b.training_days || 0) >= 7 ? '✓ 7+ days of learning' : `${b.training_days || 0}/7 days of learning`}
      · ${(b.total_observations || 0).toLocaleString('en-US')} events observed
      · ${lineageCount} known process lineages
    `;
    html += `
      <details class="baseline-learned" id="baselineLearnedSection">
        <summary class="baseline-learned-summary">
          <span>What I consider normal here</span>
          <span class="baseline-learned-meta">${learnedSummary.replace(/\s+/g, ' ').trim()}</span>
        </summary>
        <div class="baseline-learned-body">
          ${eventRateAggregateSparkline(b.event_rate_by_hour || {})}
          ${Object.keys(b.user_login_hours || {}).length > 0 ? `
            <h4 class="baseline-subtitle">Who logs in, when</h4>
            <p style="font-size:0.8rem;color:var(--dim);margin:0 0 8px;">Each row is a user; each square is an hour of the day this user was seen with an active session. System accounts (snap_daemon, systemd-resolve, _apt, ...) are hidden by default — they share PAM plumbing with real SSH logins but are not human sessions.</p>
            ${loginHeatmap(b.user_login_hours, b.user_classes)}
          ` : ''}
          ${Object.keys(b.process_destinations || {}).length > 0 ? `
            <h4 class="baseline-subtitle">Processes that talk to the outside</h4>
            ${topProcessDestinations(b.process_destinations, 6)}
          ` : ''}
          ${lineageCount > 0 ? `
            <h4 class="baseline-subtitle">Learned process lineages</h4>
            ${topProcessLineages(lineages, 6)}
          ` : ''}
        </div>
      </details>`;

    content.innerHTML = html;
    if (statusEl) {
      statusEl.textContent = !b.mature
        ? `Learning (${b.training_days || 0}/7 days)`
        : recent.length === 0
          ? 'All normal'
          : `${recent.length} ${recent.length === 1 ? 'deviation' : 'deviations'} in the last 24h`;
    }
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c">Failed to load Baseline: ${e.message}</p>`;
  }
}

// 2026-05-03 (PR #413): Playbooks sub-tab + loadPlaybooks removed
// alongside the playbook engine. Future declarative orchestration
// belongs to Spec 042 active defense.

// Defender Brain sub-tab removed: the AlphaZero brain was replaced
// by the SecureBERT classifier provider routed through ai::AiRouter.
// Decisions per provider are visible in the Threats journey view.

async function loadMitreCoverage() {
  const content = document.getElementById('intelContent');
  const status = document.getElementById('intelViewStatus');
  if (status) status.textContent = 'Loading MITRE coverage…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const data = await loadJson('/api/mitre/coverage', { signal });
    const pct = data.coverage_pct || 0;
    const pctColor = pct >= 70 ? 'var(--ok)' : pct >= 40 ? 'var(--warn)' : 'var(--danger)';

    // 2026-05-01 (audit finding 3.1): "Coverage" KPI label was
    // misleading — "100%" against `total_techniques = 55` reads as
    // "InnerWarden detects all of MITRE ATT&CK", which is false.
    // The denominator is the number of techniques the agent has a
    // mapped detector for, not the ATT&CK Linux corpus (~200+
    // techniques). Tooltip + relabel to "of mapped" + scope hint
    // below the grid.
    let html = `<div class="kpi-grid" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin-bottom:16px;">
      <div class="kpi-card" title="Percentage of techniques with a detector enabled, out of techniques InnerWarden maps to detectors. NOT the percentage of the full ATT&amp;CK corpus."><div class="kpi-value" style="color:${pctColor}">${pct}%</div><div class="kpi-label">Coverage of mapped</div></div>
      <div class="kpi-card" title="Active vs total mapped techniques. The total is the count of ATT&amp;CK techniques InnerWarden maps to detectors in this build, not the size of the full ATT&amp;CK corpus."><div class="kpi-value">${data.active_techniques}/${data.total_techniques}</div><div class="kpi-label">Mapped techniques</div></div>
      <div class="kpi-card"><div class="kpi-value">${data.enabled_detectors || data.active_detectors}</div><div class="kpi-label">Enabled Detectors</div></div>
      <div class="kpi-card"><div class="kpi-value">${data.fired_today || 0}</div><div class="kpi-label">Fired Today</div></div>
      <div class="kpi-card"><div class="kpi-value"><a href="/api/mitre/navigator" style="color:var(--accent);text-decoration:none;">Export</a></div><div class="kpi-label">Navigator JSON</div></div>
    </div>`;

    html += '<div style="font-size:0.75rem;color:var(--dim);margin-bottom:12px;">Green = detector enabled and covering this technique. The total above is the set of ATT&amp;CK techniques InnerWarden maps to detectors in this build &mdash; full ATT&amp;CK has many more techniques outside this scope.</div>';

    // Tactic breakdown
    if (data.tactics && data.tactics.length) {
      for (const tactic of data.tactics) {
        const tPct = tactic.total > 0 ? Math.round(tactic.covered / tactic.total * 100) : 0;
        const tColor = tPct >= 70 ? 'var(--ok)' : tPct >= 40 ? 'var(--warn)' : 'var(--danger)';
        const barWidth = Math.max(tPct, 2);

        html += `<div style="margin-bottom:12px;border:1px solid var(--border);border-radius:6px;padding:10px;">`;
        html += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">`;
        html += `<strong style="font-size:0.85rem;">${esc(tactic.tactic)}</strong>`;
        html += `<span style="font-size:0.8rem;color:${tColor}">${tactic.covered}/${tactic.total} techniques</span>`;
        html += `</div>`;
        html += `<div style="background:var(--border);border-radius:3px;height:6px;margin-bottom:8px;">`;
        html += `<div style="background:${tColor};height:6px;border-radius:3px;width:${barWidth}%;transition:width 0.3s;"></div></div>`;

        // Technique pills
        html += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
        for (const tech of tactic.techniques) {
          const bg = tech.active ? 'rgba(0,200,0,0.15)' : 'rgba(128,128,128,0.1)';
          const fg = tech.active ? 'var(--ok)' : 'var(--dim)';
          const border = tech.active ? 'rgba(0,200,0,0.3)' : 'var(--border)';
          const status = tech.active ? 'Enabled' : 'Disabled';
          const detList = tech.detectors.join(', ');
          html += `<span title="${esc(tech.technique_name)} (${esc(tech.technique_id)})\nStatus: ${status}\nDetectors: ${esc(detList)}" style="font-size:0.7rem;padding:2px 6px;border-radius:3px;background:${bg};color:${fg};border:1px solid ${border};cursor:help;">${esc(tech.technique_id)}</span>`;
        }
        html += '</div></div>';
      }
    }

    // Recommendations or success message
    if (data.recommendations && data.recommendations.length) {
      html += '<div style="margin-top:16px;border:1px solid var(--warn);border-radius:6px;padding:12px;">';
      html += '<strong style="font-size:0.85rem;">Recommendations to improve coverage</strong>';
      html += '<div style="margin-top:8px;">';
      for (const rec of data.recommendations) {
        html += `<div style="padding:4px 0;font-size:0.8rem;border-bottom:1px solid var(--border);">`;
        html += `<span style="color:var(--warn);margin-right:6px;">+${rec.techniques_gained}</span>`;
        html += `<strong>${esc(rec.action)}</strong>`;
        html += `<span style="color:var(--dim);margin-left:8px;">${esc(rec.impact)}</span>`;
        html += `</div>`;
      }
      html += '</div></div>';
    } else if (pct >= 90) {
      html += '<div style="margin-top:16px;border:1px solid var(--ok);border-radius:6px;padding:12px;text-align:center;">';
      html += '<strong style="color:var(--ok);">All detectors enabled — maximum coverage achieved</strong>';
      html += '</div>';
    }

    content.innerHTML = html;
    if (status) status.textContent = `${pct}% coverage`;
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c">Failed: ${e.message}</p>`;
  }
}


