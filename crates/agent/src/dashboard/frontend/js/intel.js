// ── Intelligence tab ──────────────────────────────────────────────
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
  const tabs = ['Profiles','Campaigns','Chains','Baseline','Playbooks','Mitre'];
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
  else if (tab === 'playbooks') loadPlaybooks();
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
    let html = `<div class="kpi-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${data.total}</div><div class="kpi-label">Attack Chains</div></div>
      <div class="kpi-card"><div class="kpi-value">${data.chains.filter(c=>c.severity==='Critical').length}</div><div class="kpi-label">Critical</div></div>
      <div class="kpi-card"><div class="kpi-value">${new Set(data.chains.flatMap(c=>c.layers_involved||[])).size}</div><div class="kpi-label">Layers Involved</div></div>
    </div>`;
    // 2026-05-01 (audit finding 3.4): the chains list rendered every
    // hit individually, producing 100 identical rows when the same
    // rule fired repeatedly ("Data Exfiltration eBPF Sequence: 2
    // stages 2 layers 5s, 85% confidence, ×100"). Dedup by
    // `(rule_id, summary)` so each fingerprint shows once with a
    // multiplicity count and the time range. Operator can still
    // drill into individual chain_ids by following the link in the
    // expanded view (future surface — for now the deduplication
    // alone removes the wall-of-rows complaint).
    const groups = new Map();
    for (const c of data.chains) {
      const key = (c.rule_id || '') + '|' + (c.summary || '');
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
      const sevRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      if ((sevRank[c.severity] || 0) > (sevRank[g.severity] || 0)) g.severity = c.severity;
      // Track time range across the group.
      if (c.start_ts) g.first_ts = (!g.first_ts || c.start_ts < g.first_ts) ? c.start_ts : g.first_ts;
      if (c.last_ts)  g.last_ts  = (!g.last_ts  || c.last_ts  > g.last_ts)  ? c.last_ts  : g.last_ts;
    }
    const grouped = Array.from(groups.values()).sort((a, b) => b.count - a.count);
    for (const g of grouped) {
      const sevColor = g.severity === 'Critical' ? '#e74c3c' : g.severity === 'High' ? '#f39c12' : '#27ae60';
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
async function loadBaseline() {
  const content = document.getElementById('intelContent');
  const status = document.getElementById('intelViewStatus');
  if (status) status.textContent = 'Loading baseline…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const b = await loadJson('/api/baseline-status', { signal });
    let html = `<div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${b.mature ? lucideIcon('check-circle',{size:14}) + ' Active' : lucideIcon('bar-chart-3',{size:14}) + ' Training'}</div><div class="kpi-label">Status</div></div>
      <div class="kpi-card" title="Days of baseline learning so far. The model needs 7 days minimum before anomaly detection activates; once mature it keeps learning but is no longer in training phase."><div class="kpi-value">${(b.training_days||0) >= 7 ? 'Mature ✓' : ((b.training_days||0) + '/7')}</div><div class="kpi-label">Training Days</div></div>
      <div class="kpi-card"><div class="kpi-value">${b.total_observations?.toLocaleString()||0}</div><div class="kpi-label">Observations</div></div>
      <div class="kpi-card"><div class="kpi-value">${Object.keys(b.process_lineages||{}).length||0}</div><div class="kpi-label">Known Lineages</div></div>
    </div>`;

    // Event rate by hour
    const rates = b.event_rate_by_hour || {};
    if (Object.keys(rates).length > 0) {
      html += '<h3 style="margin:16px 0 8px;">Event Rate Baseline (by hour)</h3>';
      for (const [source, hours] of Object.entries(rates)) {
        const max = Math.max(...hours, 1);
        html += `<div style="margin-bottom:12px;"><div style="font-weight:600;font-size:0.8rem;margin-bottom:4px;">${source}</div>
          <div style="display:flex;align-items:flex-end;gap:1px;height:30px;">
            ${hours.map((v,i)=>`<div title="${i}:00 — ${v.toFixed(0)} events" style="flex:1;background:${v>0?'#3498db':'var(--border)'};height:${Math.max(2,v/max*30)}px;border-radius:1px;"></div>`).join('')}
          </div>
          <div style="display:flex;justify-content:space-between;font-size:0.55rem;color:var(--dim);"><span>0h</span><span>12h</span><span>23h</span></div>
        </div>`;
      }
    }

    // User login hours
    const logins = b.user_login_hours || {};
    if (Object.keys(logins).length > 0) {
      html += '<h3 style="margin:16px 0 8px;">User Login Patterns</h3>';
      html += '<table style="font-size:0.75rem;border-collapse:collapse;"><thead><tr><th style="padding:2px 8px;">User</th><th style="padding:2px 8px;">Active Hours</th></tr></thead><tbody>';
      for (const [user, hours] of Object.entries(logins)) {
        const active = hours.map((v,i)=>v>0?`${i}:00`:null).filter(Boolean).join(', ');
        html += `<tr><td style="padding:2px 8px;font-family:monospace;">${user}</td><td style="padding:2px 8px;">${active||'none'}</td></tr>`;
      }
      html += '</tbody></table>';
    }

    // Process destinations
    const dests = b.process_destinations || {};
    if (Object.keys(dests).length > 0) {
      html += '<h3 style="margin:16px 0 8px;">Known Outbound Destinations</h3>';
      html += '<table style="font-size:0.75rem;border-collapse:collapse;"><thead><tr><th style="padding:2px 8px;">Process</th><th style="padding:2px 8px;">Known Destinations</th></tr></thead><tbody>';
      for (const [proc, ips] of Object.entries(dests)) {
        html += `<tr><td style="padding:2px 8px;font-family:monospace;">${proc}</td><td style="padding:2px 8px;">${Array.isArray(ips)?ips.length:0} IPs</td></tr>`;
      }
      html += '</tbody></table>';
    }

    content.innerHTML = html;
    if (status) status.textContent = b.mature ? 'Anomaly detection active' : `Training: ${b.training_days||0}/7 days`;
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c">Failed: ${e.message}</p>`;
  }
}

// ── Playbooks sub-tab ─────────────────────────────────────────────
async function loadPlaybooks() {
  const content = document.getElementById('intelContent');
  const status = document.getElementById('intelViewStatus');
  if (status) status.textContent = 'Loading playbooks…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    const data = await loadJson('/api/playbook-log', { signal });
    if (!data?.executions?.length) {
      // 2026-04-30: same fix as the chains empty-state path above —
      // single-quoted JS string with embedded ${lucideIcon('clipboard-list',...)}
      // syntax-broke the file. Backtick template literal.
      content.innerHTML = `<div style="text-align:center;padding:40px;"><div>${lucideIcon('clipboard-list',{size:32})}</div><p style="color:var(--dim);">No playbook executions yet.</p><p style="font-size:0.8rem;color:var(--dim);">Playbooks trigger automatically when incidents match predefined patterns (ransomware, reverse shell, data exfil, etc.).</p></div>`;
      if (status) status.textContent = '0 executions';
      return;
    }
    let html = `<div class="kpi-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${data.total}</div><div class="kpi-label">Total Executions</div></div>
      <div class="kpi-card"><div class="kpi-value">${data.executions.filter(e=>e.overall_status==='ok').length}</div><div class="kpi-label">Successful</div></div>
      <div class="kpi-card"><div class="kpi-value">${new Set(data.executions.map(e=>e.playbook_id)).size}</div><div class="kpi-label">Unique Playbooks</div></div>
    </div>`;
    // 2026-05-01 (audit finding 1.5): the playbook engine is an
    // intent-recorder, not a step runner — every step persists with
    // status="pending" and stays that way forever (verified passo-0
    // 2026-05-01: 19 intents since 2026-04-13, 100% pending). The
    // dashboard previously rendered "pending" as if execution were
    // about to happen, which was misleading. Until the executor
    // ships (tracked-spec-playbook-execution), relabel "pending" to
    // "Triggered (no executor)" and append a tooltip explaining
    // why no step ever transitions. Anything else (ok/failed)
    // renders as before.
    const statusLabel = (s) => s === 'pending' ? 'Triggered (no executor)' : s;
    const statusTitle = (s) => s === 'pending'
      ? 'Playbook engine recorded the intent but no step executor is wired yet. Tracked: tracked-spec-playbook-execution.'
      : '';
    for (const exec of data.executions) {
      const statusColor = exec.overall_status === 'ok' ? '#27ae60' : exec.overall_status === 'pending' ? '#f39c12' : '#e74c3c';
      const oTitle = statusTitle(exec.overall_status);
      const oTitleAttr = oTitle ? ` title="${oTitle}"` : '';
      html += `<div class="kpi-card" style="padding:12px;margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div><span style="font-weight:700;">${exec.playbook_name||exec.playbook_id}</span></div>
          <span${oTitleAttr} style="padding:2px 8px;border-radius:4px;background:${statusColor}20;color:${statusColor};font-size:0.75rem;">${statusLabel(exec.overall_status)}</span>
        </div>
        <div style="font-size:0.8rem;color:var(--dim);margin:4px 0;">Incident: ${exec.incident_id}</div>
        <div style="font-size:0.75rem;margin-top:4px;">Steps: ${(exec.steps||[]).map(s => {
          const sTitle = statusTitle(s.status);
          const sTitleAttr = sTitle ? ` title="${sTitle}"` : '';
          return `<span${sTitleAttr} style="padding:1px 6px;border-radius:3px;background:var(--border);margin:1px;font-size:0.7rem;">${s.action} (${statusLabel(s.status)})</span>`;
        }).join(' → ')}</div>
        <div style="font-size:0.65rem;color:var(--dim);margin-top:4px;">${exec.triggered_at ? new Date(exec.triggered_at).toLocaleString() : ''}</div>
      </div>`;
    }
    content.innerHTML = html;
    if (status) status.textContent = `${data.total} executions`;
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = `<p style="color:#e74c3c">Failed: ${e.message}</p>`;
  }
}

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

