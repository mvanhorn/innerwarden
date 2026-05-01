// ── Compliance tab ──────────────────────────────────────────────────
async function loadCompliance() {
  const status = document.getElementById('complianceViewStatus');
  if (status) status.textContent = 'Loading…';
  try {
    // Load all compliance data in parallel
    const [actions, advisories, sessions, compliance] = await Promise.all([
      loadJson('/api/admin-actions'),
      loadJson('/api/advisory-cache'),
      loadJson('/api/auth/sessions').catch(() => []),
      loadJson('/api/compliance'),
    ]);

    // KPI: Admin actions
    document.getElementById('comp-admin-actions').textContent = actions.total || 0;

    // KPI: ISO 27001 score
    const iso = compliance.iso_27001 || {};
    const isoEl = document.getElementById('comp-iso-score');
    if (isoEl) {
      isoEl.textContent = (iso.met || 0) + '/' + (iso.total || 0);
      isoEl.style.color = iso.met === iso.total ? 'var(--ok)' : 'var(--warn)';
    }

    // KPI: Hash chain
    const chain = compliance.hash_chain || {};
    const chainKpi = document.getElementById('comp-chain-status');
    if (chainKpi) {
      if (chain.length === 0) {
        chainKpi.textContent = 'Empty';
        chainKpi.style.color = 'var(--muted)';
      } else if (chain.intact) {
        chainKpi.innerHTML = lucideIcon('check',{size:14}) + ' <span style="margin-left:4px">Intact</span>';
        chainKpi.style.color = 'var(--ok)';
      } else {
        chainKpi.textContent = '\u2717 Broken';
        chainKpi.style.color = 'var(--danger)';
      }
    }

    // Hash Chain Detail
    const chainEl = document.getElementById('comp-chain-detail');
    if (chainEl) {
      const intactBadge = chain.length === 0
        ? '<span style="color:var(--muted)">No decisions recorded today</span>'
        : chain.intact
          ? '<span style="color:var(--ok);font-weight:700;display:inline-flex;align-items:center;gap:6px">' + lucideIcon('check-circle',{size:14}) + ' Chain integrity verified</span>'
          : '<span style="color:var(--warn);font-weight:700;display:inline-flex;align-items:center;gap:6px">' + lucideIcon('alert-triangle',{size:14}) + ' Verification failed \u2014 review recent changes</span>';
      // 2026-05-01: render documented chain breaks alongside the
      // verified-chain summary. Operator viewing the compliance tab
      // sees "audit chain has N documented breaks" with the operator,
      // reason, and rowid range — instead of having to ssh in and
      // query sqlite. The breaks list comes from
      // `compliance.hash_chain.sqlite.breaks` populated by
      // `dashboard/compliance.rs::sqlite_chain_status`.
      const sqliteChain = (chain.sqlite) || {};
      const breaks = sqliteChain.breaks || [];
      const docBreakCount = sqliteChain.documented_breaks || 0;
      let breaksHtml = '';
      if (breaks.length > 0) {
        breaksHtml =
          '<div style="margin-top:8px;padding:8px 10px;border-radius:6px;background:rgba(255,184,77,0.05);border:1px solid rgba(255,184,77,0.18);font-size:0.7rem">' +
          '<div style="font-weight:700;color:var(--warn);margin-bottom:4px;display:flex;align-items:center;gap:6px">' +
          lucideIcon('clipboard-list', { size: 12 }) +
          ' ' + breaks.length + ' documented break' + (breaks.length === 1 ? '' : 's') +
          ' (' + docBreakCount + ' rows tolerated by verifier)' +
          '</div>' +
          '<div style="font-size:0.62rem;color:var(--muted);margin-bottom:6px">Intentional breaks recorded via <code>innerwarden chain-break register</code>. The hourly verifier skips these ranges; only undocumented breaks fire the security alert.</div>' +
          breaks
            .map(b =>
              '<div style="padding:4px 0;border-top:1px solid rgba(255,184,77,0.15)">' +
              '<div><strong>rows ' + b.rowid_start + '..' + b.rowid_end + '</strong> (' + b.rows_documented + ' rows) — by <em>' + esc(b.operator || '?') + '</em></div>' +
              '<div style="font-size:0.62rem;color:var(--muted);margin-top:2px">Registered ' + esc((b.registered_at || '').slice(0, 16)) + '</div>' +
              '<div style="font-size:0.65rem;color:var(--text);margin-top:2px">' + esc(b.reason || '') + '</div>' +
              '</div>'
            )
            .join('') +
          '</div>';
      }
      chainEl.innerHTML =
        '<div style="display:flex;flex-direction:column;gap:8px">' +
        '<div>' + intactBadge + '</div>' +
        '<div style="display:flex;gap:20px;font-size:0.75rem;color:var(--muted)">' +
        '<span>Entries: <strong style="color:var(--text)">' + (chain.length || 0) + '</strong></span>' +
        '<span>Last hash: <code style="color:var(--accent);font-size:0.68rem">' + esc((chain.last_hash || 'none').substring(0, 16)) + '…</code></span>' +
        '</div>' +
        '<div style="font-size:0.65rem;color:var(--muted)">Each decision entry includes a SHA-256 hash of the previous entry, forming a tamper-evident chain.</div>' +
        breaksHtml +
        '</div>';
    }

    // Retention config
    const ret = compliance.retention || {};
    const retEl = document.getElementById('comp-retention');
    if (retEl) {
      const row = (label, days, desc) =>
        '<div style="display:flex;align-items:center;gap:12px;padding:6px 0;border-bottom:1px solid var(--line)">' +
        '<span style="font-size:0.8rem;color:var(--text);min-width:120px;font-weight:600">' + esc(label) + '</span>' +
        '<span style="font-size:0.85rem;color:var(--accent);font-weight:700;min-width:50px">' + days + 'd</span>' +
        '<span style="font-size:0.68rem;color:var(--muted)">' + esc(desc) + '</span>' +
        '</div>';
      retEl.innerHTML =
        row('Events', ret.events_days || 7, 'Raw event JSONL (auth_log, ebpf, docker, etc.)') +
        row('Incidents', ret.incidents_days || 30, 'Detected threat incidents') +
        row('Decisions', ret.decisions_days || 90, 'AI/operator response audit trail (hash-chained)') +
        row('Telemetry', ret.telemetry_days || 14, 'Agent health and performance metrics') +
        row('Reports', ret.reports_days || 30, 'Daily security reports') +
        '<div style="font-size:0.62rem;color:var(--muted);margin-top:8px">Configure in <code>[data]</code> section of agent.toml. GDPR export/erase: <code>innerwarden gdpr export</code> / <code>innerwarden gdpr erase</code></div>';
    }

    // ISO 27001 controls — with progress bar and actionable grouping
    const ctrlEl = document.getElementById('comp-iso-controls');
    if (ctrlEl && iso.controls) {
      const met = iso.controls.filter(c => c.met);
      const notMet = iso.controls.filter(c => !c.met);
      // If hash chain is broken, reduce ISO readiness (audit integrity compromised)
      const hashBroken = compliance.hash_chain && !compliance.hash_chain.intact;
      const effectiveMet = hashBroken ? Math.max(iso.met - 1, 0) : iso.met;
      const pct = iso.total > 0 ? Math.round((effectiveMet / iso.total) * 100) : 0;
      const barColor = hashBroken ? 'var(--danger)' : pct === 100 ? 'var(--ok)' : pct >= 80 ? 'var(--warn)' : 'var(--danger)';

      let isoHtml = '';

      // Progress bar
      isoHtml += '<div style="margin-bottom:16px">' +
        '<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px">' +
        '<span style="font-size:0.78rem;font-weight:700;color:var(--text)">ISO 27001 Readiness</span>' +
        '<span style="font-size:0.85rem;font-weight:800;color:' + barColor + '">' + pct + '%</span></div>' +
        '<div style="height:8px;border-radius:4px;background:var(--line);overflow:hidden">' +
        '<div style="height:100%;width:' + pct + '%;background:' + barColor + ';border-radius:4px;transition:width 0.6s ease"></div>' +
        '</div>' +
        '<div style="font-size:0.62rem;color:var(--muted);margin-top:4px">' + iso.met + ' of ' + iso.total + ' controls met &mdash; <a href="https://www.iso.org/standard/27001" target="_blank" style="color:var(--accent)">What is ISO 27001?</a></div>' +
        '</div>';

      // Actions needed (not met) — shown first, prominent
      if (notMet.length > 0) {
        isoHtml += '<div style="margin-bottom:14px">' +
          '<div style="font-size:0.7rem;font-weight:700;color:var(--warn);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:8px">Actions Needed</div>';
        for (const c of notMet) {
          isoHtml += '<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 12px;margin-bottom:6px;border-radius:8px;background:rgba(255,184,77,0.06);border:1px solid rgba(255,184,77,0.15)">' +
            '<span style="font-size:0.72rem;font-weight:700;color:var(--accent);min-width:50px;padding-top:1px">' + esc(c.id) + '</span>' +
            '<div><div style="font-size:0.78rem;font-weight:600;color:var(--text)">' + esc(c.name) + '</div>' +
            '<div style="font-size:0.68rem;color:var(--warn);margin-top:2px">' + esc(c.reason) + '</div></div></div>';
        }
        isoHtml += '</div>';
      }

      // Met controls — compact, collapsed by default if many
      if (met.length > 0) {
        const showAll = met.length <= 5;
        isoHtml += '<div>' +
          '<div style="font-size:0.7rem;font-weight:700;color:var(--ok);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:8px;cursor:pointer" ' +
          'onclick="var el=document.getElementById(\'isoMetList\');el.style.display=el.style.display===\'none\'?\'block\':\'none\'">' +
          'Controls Met (' + met.length + ') &#9662;</div>' +
          '<div id="isoMetList" style="display:' + (showAll ? 'block' : 'none') + '">';
        for (const c of met) {
          isoHtml += '<div style="display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.03)">' +
            '<span style="font-size:0.85rem">\u2705</span>' +
            '<span style="font-size:0.72rem;font-weight:700;color:var(--accent);min-width:50px">' + esc(c.id) + '</span>' +
            '<span style="font-size:0.75rem;color:var(--text)">' + esc(c.name) + '</span>' +
            '<span style="font-size:0.62rem;color:var(--muted);margin-left:auto">' + esc(c.reason) + '</span>' +
            '</div>';
        }
        isoHtml += '</div></div>';
      }

      ctrlEl.innerHTML = isoHtml;
    }

    // Admin actions list
    const listEl = document.getElementById('comp-admin-list');
    if (actions.items && actions.items.length > 0) {
      listEl.innerHTML = actions.items.map(a => `
        <div style="display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--line);">
          <span style="color:var(--muted);font-size:0.75rem;min-width:70px;">${new Date(a.ts).toLocaleTimeString()}</span>
          <span style="color:var(--accent);font-size:0.75rem;min-width:70px;">${a.source}</span>
          <span style="font-size:0.8rem;color:var(--text);">${a.operator} ${a.action} <span style="color:var(--accent)">${a.target}</span></span>
          <span style="margin-left:auto;font-size:0.7rem;color:${a.result === 'success' ? 'var(--ok)' : 'var(--danger)'};">${a.result}</span>
        </div>
      `).join('');
    } else {
      listEl.innerHTML = '<div class="muted">No admin actions recorded today</div>';
    }

    // Advisory cache
    const advEl = document.getElementById('comp-advisory-list');
    if (advisories.items && advisories.items.length > 0) {
      advEl.innerHTML = advisories.items.map(a => `
        <div style="display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--line);align-items:center;">
          <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600;
            background:${a.recommendation === 'deny' ? 'rgba(244,63,94,0.15)' : 'rgba(255,184,77,0.15)'};
            color:${a.recommendation === 'deny' ? 'var(--danger)' : 'var(--warn)'};">${a.recommendation}</span>
          <code style="font-size:0.75rem;color:var(--accent);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${a.command_preview}</code>
          <span style="font-size:0.7rem;color:var(--muted);">score ${a.risk_score}</span>
        </div>
      `).join('');
    } else {
      advEl.innerHTML = '<div class="muted">No active advisories</div>';
    }

    // Sessions
    const sessCount = Array.isArray(sessions) ? sessions.length : 0;
    document.getElementById('comp-sessions').textContent = sessCount;
    const sessEl = document.getElementById('comp-session-list');
    if (sessCount > 0) {
      sessEl.innerHTML = sessions.map(s => `
        <div style="display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--line);">
          <span style="color:var(--text);font-size:0.8rem;">${s.username}</span>
          <span style="color:var(--muted);font-size:0.75rem;">${s.client_ip}</span>
          <span style="margin-left:auto;font-size:0.7rem;color:var(--muted);">since ${new Date(s.created_at).toLocaleTimeString()}</span>
        </div>
      `).join('');
    } else {
      sessEl.innerHTML = '<div class="muted">No active sessions</div>';
    }

    if (status) status.textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    console.error('Failed to load compliance data:', e);
    if (status) status.textContent = 'Error';
  }
}

