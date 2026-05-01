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

    // 2026-05-01 (audit-ui spec): decision audit-trail records.
    // The hash-chain summary above tells operator the chain is
    // intact + how many entries; this section lets them actually
    // INSPECT the entries. Lazy-loaded (separate fetch from
    // /api/compliance) so the main view stays fast when the
    // operator does not need the trail.
    loadAuditTrail();

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
        '<div style="font-size:0.62rem;color:var(--muted);margin-top:4px" title="In-scope = the controls InnerWarden directly maps to its own audit/decision/log surface. ISO 27001 Annex A has 93 total controls; the rest are organisational policies outside a security tool\'s scope.">' + iso.met + ' of ' + iso.total + ' in-scope controls met (Annex A has 93 total) &mdash; <a href="https://www.iso.org/standard/27001" target="_blank" style="color:var(--accent)">What is ISO 27001?</a></div>' +
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

// ── Decision audit trail (paginated viewer) ─────────────────────────
//
// State + functions are intentionally module-scoped (window) rather
// than enclosed so the "Load more" button's onclick can reach them
// without inline closures (the rest of the dashboard uses the same
// pattern). Cursor-based pagination keeps the viewer correct when
// new decisions arrive between page loads.
window._auditTrailState = { rows: [], beforeId: null, hasMore: true, action: '' };

async function loadAuditTrail() {
  const el = document.getElementById('comp-audit-trail');
  if (!el) return;
  // Reset on every refresh of the parent compliance view.
  window._auditTrailState = { rows: [], beforeId: null, hasMore: true, action: '' };
  el.innerHTML = '<div class="muted">Loading audit trail...</div>';
  await fetchAuditTrailPage(true);
}

async function fetchAuditTrailPage(replace) {
  const el = document.getElementById('comp-audit-trail');
  if (!el) return;
  const st = window._auditTrailState;
  const qs = new URLSearchParams();
  qs.set('limit', '50');
  if (st.beforeId) qs.set('before_id', String(st.beforeId));
  if (st.action) qs.set('action', st.action);
  let data;
  try {
    data = await loadJson('/api/compliance/audit-trail?' + qs.toString());
  } catch (e) {
    el.innerHTML = '<div style="color:var(--danger);font-size:0.8rem">Failed to load audit trail: ' + esc(e.message) + '</div>';
    return;
  }
  if (!data.available) {
    el.innerHTML = '<div class="muted">SQLite store unavailable. Audit trail not persisted on this host.</div>';
    return;
  }
  const incoming = data.items || [];
  if (replace) {
    st.rows = incoming;
  } else {
    st.rows = st.rows.concat(incoming);
  }
  st.beforeId = data.next_before_id || null;
  st.hasMore = incoming.length >= 50 && st.beforeId != null;
  renderAuditTrail();
}

function renderAuditTrail() {
  const el = document.getElementById('comp-audit-trail');
  if (!el) return;
  const st = window._auditTrailState;
  if (st.rows.length === 0) {
    el.innerHTML = '<div class="muted">No decisions recorded' +
      (st.action ? ' for action "' + esc(st.action) + '"' : '') + '.</div>';
    return;
  }
  // Filter toolbar: action_type select. Mirrors the values
  // emitted by the agent (see incident_post_decision +
  // incident_untouchable for the override path that injects
  // "request_confirmation").
  let html = '<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;font-size:0.78rem">' +
    '<span style="color:var(--muted)">Filter:</span>' +
    '<select id="audit-action-filter" onchange="onAuditActionChange(this.value)" ' +
    'style="background:var(--line);border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;font-size:0.75rem">' +
    '<option value="">all actions</option>' +
    '<option value="block_ip">block_ip</option>' +
    '<option value="dismiss">dismiss</option>' +
    '<option value="ignore">ignore</option>' +
    '<option value="monitor">monitor</option>' +
    '<option value="request_confirmation">request_confirmation</option>' +
    '<option value="kill_chain_response">kill_chain_response</option>' +
    '</select>' +
    '<span style="color:var(--muted);margin-left:auto">' + st.rows.length + ' record' + (st.rows.length === 1 ? '' : 's') + ' shown</span>' +
    '</div>';
  // Table.
  html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:0.72rem">' +
    '<thead><tr style="text-align:left;color:var(--muted);border-bottom:1px solid var(--border)">' +
    '<th style="padding:6px 6px;font-weight:700">id</th>' +
    '<th style="padding:6px 6px;font-weight:700">timestamp (UTC)</th>' +
    '<th style="padding:6px 6px;font-weight:700">action</th>' +
    '<th style="padding:6px 6px;font-weight:700">target</th>' +
    '<th style="padding:6px 6px;font-weight:700">conf</th>' +
    '<th style="padding:6px 6px;font-weight:700">auto?</th>' +
    '<th style="padding:6px 6px;font-weight:700">reason</th>' +
    '<th style="padding:6px 6px;font-weight:700" title="SHA-256 row_hash (first 12 chars). Each row also stores prev_hash; the chain is verifiable via the hash-chain status above.">hash</th>' +
    '<th style="padding:6px 6px;font-weight:700" title="Operator override / re-open / label actions. Each writes a hash-chained audit row preserving the operator correction.">actions</th>' +
    '</tr></thead><tbody>';
  for (const r of st.rows) {
    const target = r.target_ip || (r.target_user ? 'user:' + r.target_user : '');
    const conf = (r.confidence == null) ? '' : (r.confidence * 100).toFixed(0) + '%';
    const auto = r.auto_executed ? '✓' : '';
    const reasonShort = (r.reason || '').length > 70 ? (r.reason.substring(0, 70) + '…') : (r.reason || '');
    const hashShort = (r.row_hash || '').substring(0, 12);
    const hashTitle = 'row_hash=' + (r.row_hash || '') + (r.prev_hash ? '\\nprev_hash=' + r.prev_hash : '\\nprev_hash=null (genesis or post-break re-anchor)');
    // Operator override controls. Skip for rows that are themselves
    // operator actions (action_type prefix "operator_"), since
    // overriding an override is rare and would clutter the row.
    const isOperatorRow = (r.action_type || '').startsWith('operator_');
    let opsHtml;
    if (isOperatorRow) {
      opsHtml = '<span style="color:var(--muted);font-size:0.7rem">—</span>';
    } else {
      opsHtml =
        '<button type="button" onclick="openOverrideModal(' + r.id + ',\'' + esc(r.action_type || '') + '\',\'' + esc((r.reason || '').replace(/'/g, "&#39;").substring(0, 100)) + '\')" ' +
        'title="Override this AI decision (audit-only)" ' +
        'style="background:transparent;border:1px solid var(--border);color:var(--warn);padding:2px 6px;border-radius:3px;font-size:0.65rem;cursor:pointer;margin-right:3px">override</button>' +
        '<button type="button" onclick="labelDecision(' + r.id + ',\'TP\')" ' +
        'title="Label as True Positive — AI was right" ' +
        'style="background:transparent;border:1px solid rgba(58,194,126,0.3);color:var(--ok);padding:2px 6px;border-radius:3px;font-size:0.65rem;cursor:pointer;margin-right:3px">✓ TP</button>' +
        '<button type="button" onclick="labelDecision(' + r.id + ',\'FP\')" ' +
        'title="Label as False Positive — AI was wrong" ' +
        'style="background:transparent;border:1px solid rgba(244,63,94,0.3);color:var(--danger);padding:2px 6px;border-radius:3px;font-size:0.65rem;cursor:pointer">✗ FP</button>';
    }
    html += '<tr style="border-bottom:1px solid rgba(255,255,255,0.04)">' +
      '<td style="padding:5px 6px;color:var(--muted)">' + r.id + '</td>' +
      '<td style="padding:5px 6px;color:var(--text)" title="' + esc(r.ts || '') + '">' + esc(fmtUtcFull(r.ts || '')) + '</td>' +
      '<td style="padding:5px 6px"><code style="color:var(--accent);font-size:0.7rem">' + esc(r.action_type || '') + '</code></td>' +
      '<td style="padding:5px 6px">' + esc(target) + '</td>' +
      '<td style="padding:5px 6px;color:var(--accent)">' + conf + '</td>' +
      '<td style="padding:5px 6px;text-align:center">' + auto + '</td>' +
      '<td style="padding:5px 6px;color:var(--muted)" title="' + esc(r.reason || '') + '">' + esc(reasonShort) + '</td>' +
      '<td style="padding:5px 6px"><code style="color:var(--dim);font-size:0.65rem" title="' + esc(hashTitle) + '">' + esc(hashShort) + '…</code></td>' +
      '<td style="padding:5px 6px;white-space:nowrap">' + opsHtml + '</td>' +
      '</tr>';
  }
  html += '</tbody></table></div>';
  if (st.hasMore) {
    html += '<div style="margin-top:10px;text-align:center">' +
      '<button type="button" onclick="fetchAuditTrailPage(false)" ' +
      'style="background:transparent;border:1px solid var(--border);color:var(--accent);padding:5px 14px;border-radius:4px;font-size:0.75rem;cursor:pointer">' +
      'Load 50 more (older)</button>' +
      '</div>';
  }
  el.innerHTML = html;
  // Restore selected action in dropdown after re-render.
  const sel = document.getElementById('audit-action-filter');
  if (sel) sel.value = st.action || '';
}

function onAuditActionChange(value) {
  window._auditTrailState = { rows: [], beforeId: null, hasMore: true, action: value || '' };
  fetchAuditTrailPage(true);
}

// ── Operator override / label workflow (audit-only v1) ──────────────
//
// Three audit primitives:
//   1. Override: operator disagrees with an AI decision → writes a
//      new hash-chained row pointing back to the original.
//   2. Label TP/FP: operator marks the AI's decision correct or
//      not → writes to data_dir/decision-labels.jsonl for future
//      classifier retraining.
//   3. (Re-open lives on Threats journey, not here — incident
//      context, not a decision row context.)
//
// All three are audit-only for v1: they record operator intent
// without mutating the incident state machine. State integration
// (re-routing reopens through AI triage, retraining the classifier
// from labels) is a follow-up spec.

function openOverrideModal(decisionId, originalAction, originalReason) {
  // Inline modal — reusing patterns from existing dashboard
  // (no shared modal helper today, each page builds its own).
  // Body construction is plain DOM rather than innerHTML so the
  // operator's reason can survive < / > characters without a
  // round of escape mistakes.
  const existing = document.getElementById('overrideModal');
  if (existing) existing.remove();
  const modal = document.createElement('div');
  modal.id = 'overrideModal';
  modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center';
  modal.innerHTML =
    '<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:20px;width:520px;max-width:90vw;max-height:85vh;overflow-y:auto">' +
      '<h3 style="margin:0 0 8px;font-size:0.95rem">Override AI decision #' + decisionId + '</h3>' +
      '<div style="font-size:0.72rem;color:var(--muted);margin-bottom:12px">' +
        'Audit-only: writes a new hash-chained row recording the disagreement. Does NOT auto-execute the new action — use the existing block-IP / monitor buttons separately if needed.' +
      '</div>' +
      '<div style="font-size:0.72rem;margin-bottom:10px;padding:8px;background:rgba(255,184,77,0.05);border:1px solid rgba(255,184,77,0.18);border-radius:4px">' +
        '<strong>Original AI action:</strong> <code style="color:var(--accent)">' + esc(originalAction) + '</code><br>' +
        '<strong>Original reason:</strong> <span style="color:var(--muted)">' + esc(originalReason) + '</span>' +
      '</div>' +
      '<label style="display:block;font-size:0.72rem;color:var(--muted);margin-bottom:4px">What the operator would have decided:</label>' +
      '<select id="overrideNewAction" style="width:100%;padding:6px 8px;background:var(--line);border:1px solid var(--border);color:var(--text);border-radius:4px;font-size:0.78rem;margin-bottom:10px">' +
        '<option value="block_ip">block_ip</option>' +
        '<option value="monitor">monitor</option>' +
        '<option value="dismiss">dismiss</option>' +
        '<option value="ignore">ignore</option>' +
        '<option value="request_confirmation">request_confirmation</option>' +
      '</select>' +
      '<label style="display:block;font-size:0.72rem;color:var(--muted);margin-bottom:4px">Reason (mandatory):</label>' +
      '<textarea id="overrideReason" rows="3" placeholder="why did the AI get this wrong?" ' +
        'style="width:100%;padding:6px 8px;background:var(--line);border:1px solid var(--border);color:var(--text);border-radius:4px;font-size:0.78rem;resize:vertical;font-family:inherit"></textarea>' +
      '<div id="overrideStatus" style="font-size:0.72rem;color:var(--muted);margin:8px 0;min-height:1em"></div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">' +
        '<button type="button" onclick="closeOverrideModal()" ' +
          'style="background:transparent;border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:4px;font-size:0.78rem;cursor:pointer">Cancel</button>' +
        '<button type="button" onclick="submitOverride(' + decisionId + ')" ' +
          'style="background:var(--warn);border:1px solid var(--warn);color:#1a1a1a;padding:6px 14px;border-radius:4px;font-size:0.78rem;cursor:pointer;font-weight:600">Record override</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(modal);
  setTimeout(() => {
    const reasonEl = document.getElementById('overrideReason');
    if (reasonEl) reasonEl.focus();
  }, 50);
}

function closeOverrideModal() {
  const m = document.getElementById('overrideModal');
  if (m) m.remove();
}

async function submitOverride(decisionId) {
  const newAction = document.getElementById('overrideNewAction').value;
  const reason = document.getElementById('overrideReason').value.trim();
  const statusEl = document.getElementById('overrideStatus');
  if (!reason) {
    if (statusEl) {
      statusEl.style.color = 'var(--danger)';
      statusEl.textContent = 'Reason is required.';
    }
    return;
  }
  if (statusEl) {
    statusEl.style.color = 'var(--muted)';
    statusEl.textContent = 'Submitting...';
  }
  try {
    const r = await fetch('/api/action/decision/override', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision_id: decisionId, new_action: newAction, reason }),
    });
    const data = await r.json();
    if (data.success) {
      if (statusEl) {
        statusEl.style.color = 'var(--ok)';
        statusEl.textContent = data.message || 'Override recorded.';
      }
      // Refresh the audit trail to show the new row.
      setTimeout(() => {
        closeOverrideModal();
        loadAuditTrail();
      }, 800);
    } else {
      if (statusEl) {
        statusEl.style.color = 'var(--danger)';
        statusEl.textContent = data.message || 'Failed.';
      }
    }
  } catch (e) {
    if (statusEl) {
      statusEl.style.color = 'var(--danger)';
      statusEl.textContent = 'Network error: ' + (e && e.message);
    }
  }
}

async function labelDecision(decisionId, label) {
  // Fast-path: no modal for label, just send. Operator has clicked
  // a TP / FP button; the audit trail records WHO labelled WHEN
  // (via session token), and a future spec will pull the
  // `decision-labels.jsonl` file into classifier retraining.
  try {
    const r = await fetch('/api/action/decision/label', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision_id: decisionId, label, reason: '' }),
    });
    const data = await r.json();
    // Inline visual confirmation. The compliance status pill (top
    // right) is the lowest-noise place to surface this — a toast
    // would compete with the dashboard's existing toast stack.
    const status = document.getElementById('complianceViewStatus');
    if (status) {
      status.style.color = data.success ? 'var(--ok)' : 'var(--danger)';
      status.textContent = data.message || (data.success ? 'Labelled.' : 'Failed.');
      // Reset to the default 'Updated ...' message after 3s so
      // the badge doesn't get stuck on the label confirmation.
      setTimeout(() => {
        if (status) {
          status.style.color = 'var(--muted)';
          status.textContent = 'Updated ' + new Date().toLocaleTimeString();
        }
      }, 3000);
    }
  } catch (e) {
    console.error('label failed:', e);
  }
}

