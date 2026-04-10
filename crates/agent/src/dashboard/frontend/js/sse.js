// ── Tab badge (unseen alerts) ────────────────────────────────────────
let _unseenAlerts = 0;
const _baseTitle = document.title;
function updateTabBadge(delta) {
  _unseenAlerts = Math.max(0, _unseenAlerts + delta);
  if (_unseenAlerts > 0) {
    document.title = '(' + _unseenAlerts + ' \uD83D\uDD34) ' + _baseTitle;
  } else {
    document.title = _baseTitle;
  }
}
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'visible') {
    _unseenAlerts = 0;
    document.title = _baseTitle;
  }
});

// ── Alert toast ──────────────────────────────────────────────────────
function showAlertToast(alert) {
  var alertIp = alert.entity_value || '';
  if (state.hideAllowlisted && alertIp && (isPrivateIp(alertIp) || isIpTrusted(alertIp))) return;
  if (document.hidden) updateTabBadge(1);
  const outcome = alert.outcome || '';
  const isContained = ['blocked','killed','contained','suspended','honeypot'].includes(outcome);
  const title = alert.title || 'Incident detected';
  const evalue = alert.entity_value || '';
  const etype  = alert.entity_type  || 'ip';
  const toastEl = document.getElementById('toast');
  if (isContained) {
    toastEl.innerHTML =
      `<span style="color:var(--ok);font-weight:700;margin-right:6px">CONTAINED</span>` +
      `<span>${esc(title)}</span>` +
      (evalue ? ` <span style="color:var(--muted)">\u2192 ${esc(evalue)}</span>` : '');
    toastEl.className = 'toast ok visible';
  } else {
    const sev = (alert.severity || 'high').toUpperCase();
    const sevColor = sev === 'CRITICAL' ? '#f43f5e' : '#f97316';
    toastEl.innerHTML =
      `<span style="color:${sevColor};font-weight:700;margin-right:6px">${esc(sev)}</span>` +
      `<span>${esc(title)}</span>` +
      (evalue
        ? ` &nbsp;<a href="#" style="color:#78e5ff;text-decoration:none" ` +
          `onclick="event.preventDefault();loadJourney('${esc(etype)}','${esc(evalue)}')"` +
          `>\u2192 ${esc(evalue)}</a>`
        : '');
    toastEl.className = 'toast err visible';
  }
  clearTimeout(toastEl._timer);
  toastEl._timer = setTimeout(() => toastEl.classList.remove('visible'), 8000);
}

// ── Entity search ────────────────────────────────────────────────────
function applyEntitySearch() {
  const q = (document.getElementById('entitySearch').value || '').trim().toLowerCase();
  const cards = document.querySelectorAll('#attackerList .attacker-card');
  let visible = 0;
  cards.forEach(card => {
    const text = card.textContent.toLowerCase();
    const match = !q || text.includes(q);
    card.classList.toggle('hidden', !match);
    if (match) visible++;
  });
  let countEl = document.getElementById('searchCount');
  if (!countEl) {
    countEl = document.createElement('span');
    countEl.id = 'searchCount';
    countEl.style.cssText = 'font-size:0.62rem;color:var(--muted);margin-left:6px';
    const searchBox = document.getElementById('entitySearch');
    if (searchBox && searchBox.parentNode) searchBox.parentNode.appendChild(countEl);
  }
  countEl.textContent = q ? visible + ' of ' + cards.length : '';
  let noRes = document.getElementById('searchNoResults');
  if (!visible && q) {
    if (!noRes) {
      noRes = document.createElement('div');
      noRes.id = 'searchNoResults';
      noRes.className = 'empty';
      noRes.textContent = 'No matches for "' + q + '"';
      document.getElementById('attackerList').appendChild(noRes);
    } else {
      noRes.textContent = 'No matches for "' + q + '"';
    }
  } else if (noRes) {
    noRes.remove();
  }
}

// ══════════════════════════════════════════════════════════════════════
// INIT — runs after all modules are loaded
// ══════════════════════════════════════════════════════════════════════

// Hydrate filters from URL
hydrateStateFromQuery();
document.getElementById('flt-date').value = state.filters.date || today;
document.getElementById('flt-compare-date').value = state.filters.compare_date || '';
document.getElementById('flt-severity').value = state.filters.severity_min || '';
document.getElementById('flt-detector').value = state.filters.detector || '';
document.getElementById('flt-window').value = state.filters.window_seconds || '';
updatePivotUi();
loadActionConfig();
loadReportDates();

// Default view
showView('home');

// Keyboard shortcuts
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') closeActionModal();
});

// Filter event listeners
document.getElementById('flt-apply').addEventListener('click', () => {
  const list = document.getElementById('attackerList');
  if (list) list.innerHTML = '<div class="loading" style="padding:20px">Loading...</div>';
  refreshLeft(true);
});
document.querySelectorAll('.pivot-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    const pivot = tab.dataset.pivot || 'ip';
    state.pivot = pivot;
    state.selected = { type: pivot, value: null };
    updatePivotUi();
    refreshLeft(false);
  });
});
document.getElementById('flt-detector').addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') refreshLeft(true);
});
document.getElementById('flt-severity').addEventListener('change', () => refreshLeft(true));
document.getElementById('flt-date').addEventListener('change', () => refreshLeft(true));
document.getElementById('flt-compare-date').addEventListener('change', () => {
  if (state.selected.value) {
    loadJourney(state.selected.type, state.selected.value);
    return;
  }
  refreshLeft(false);
});
document.getElementById('flt-window').addEventListener('change', () => refreshLeft(true));
document.getElementById('entitySearch').addEventListener('input', applyEntitySearch);

// Initial data load
refreshLeft(false).then(() => {
  applyEntitySearch();
  if (state.selected.value) {
    loadJourney(state.selected.type, state.selected.value);
  }
});

// ── SSE live connection ──────────────────────────────────────────────
(function startSse() {
  let fallbackTimer = null;
  let reconnectTimer = null;

  function armFallback() {
    clearTimeout(fallbackTimer);
    fallbackTimer = setTimeout(() => {
      refreshLeftLive();
      fallbackTimer = setInterval(() => refreshLeftLive(), 30000);
    }, 35000);
  }

  function connect() {
    clearTimeout(reconnectTimer);
    fetch('/api/events/stream', { headers: { 'Accept': 'text/event-stream' } })
      .then(res => {
        if (!res.ok || !res.body) throw new Error('SSE connect failed');
        clearTimeout(fallbackTimer);
        clearInterval(fallbackTimer);
        const el = document.getElementById('refreshStatus');
        if (el) el.innerHTML = '<span style="color:#78e5ff;font-size:0.85rem">&#9679; LIVE</span>';
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        let lastEvent = '';
        function pump() {
          reader.read().then(({ done, value }) => {
            if (done) { scheduleReconnect(); return; }
            buf += dec.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop();
            for (const line of lines) {
              if (line.startsWith('event: ')) {
                lastEvent = line.slice(7).trim();
              } else if (line.startsWith('data: ')) {
                if (lastEvent === 'refresh') {
                  // Throttle: at most 1 refresh per 5 seconds to avoid 429s
                  var now = Date.now();
                  if (!window._lastSSERefresh || now - window._lastSSERefresh > 5000) {
                    window._lastSSERefresh = now;
                    refreshLeftLive();
                    if (document.getElementById('viewHome').style.display !== 'none') loadHome();
                  }
                } else if (lastEvent === 'alert') {
                  try {
                    const outer = JSON.parse(line.slice(6).trim());
                    showAlertToast(outer.data || outer);
                  } catch (_) {}
                }
                lastEvent = '';
              }
            }
            pump();
          }).catch(() => scheduleReconnect());
        }
        pump();
      })
      .catch(() => scheduleReconnect());
  }

  function scheduleReconnect() {
    const el = document.getElementById('refreshStatus');
    if (el) el.innerHTML = '<span style="color:#888;font-size:0.7rem">&#9679; reconnecting</span>';
    armFallback();
    reconnectTimer = setTimeout(connect, 3000);
  }

  armFallback();
  connect();
})();
