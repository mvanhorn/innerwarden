// ── Tab badge (unseen alerts) ────────────────────────────────────────
let _unseenAlerts = 0;
const _baseTitle = document.title;
function updateTabBadge(delta) {
  _unseenAlerts = Math.max(0, _unseenAlerts + delta);
  if (_unseenAlerts > 0) {
    document.title = '(' + _unseenAlerts + ') ' + _baseTitle;
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

// ── Alert toast stack (audit 4.8) ────────────────────────────────────
// Cap visible toasts at MAX_VISIBLE; FIFO eviction. New toasts past
// the cap collapse into a "+N more" badge that links to the threats
// view. Each toast has its own auto-dismiss timer (15 s) so a burst
// drains naturally instead of becoming a manual-close wall.
//
// Audit 2.10: when an alert arrives for the IP whose journey is
// currently open in the Threats view, suppress the toast and reload
// the journey instead. The operator already has the right page on
// screen, no need to interrupt them.
var ALERT_STACK_MAX_VISIBLE = 3;
var _alertStackOverflow = 0;

function _renderAlertStackOverflow() {
  var stack = document.getElementById('alertStack');
  if (!stack) return;
  var existing = stack.querySelector('.alert-overflow');
  if (_alertStackOverflow <= 0) {
    if (existing) existing.remove();
    return;
  }
  if (!existing) {
    existing = document.createElement('button');
    existing.type = 'button';
    existing.className = 'alert-overflow';
    existing.setAttribute('aria-label', 'View additional alerts in threats view');
    existing.onclick = function() {
      _alertStackOverflow = 0;
      _renderAlertStackOverflow();
      showView('investigate');
    };
    stack.appendChild(existing);
  }
  existing.textContent = '+' + _alertStackOverflow + ' more — open threats';
}

// Returns true when the threats view is showing the journey for `ip`
// so the alert can land into the open page instead of as a toast.
function _journeyOpenForIp(ip) {
  if (!ip) return false;
  var threatsView = document.getElementById('viewInvestigate');
  if (!threatsView || threatsView.style.display === 'none') return false;
  var sel = (typeof state !== 'undefined') ? state.selected : null;
  if (!sel || !sel.value) return false;
  var t = String(sel.type || '').toLowerCase();
  if (t !== 'ip') return false;
  return String(sel.value) === String(ip);
}

function showAlertToast(alert) {
  var alertIp = alert.entity_value || '';
  if (state.hideAllowlisted && alertIp && (isPrivateIp(alertIp) || isIpTrusted(alertIp))) return;

  const outcome = alert.outcome || '';
  const isContained = ['blocked','killed','contained','suspended','honeypot'].includes(outcome);
  const sev = (alert.severity || 'medium').toLowerCase();
  const isGrave = sev === 'critical' || sev === 'high';

  // Only surface uncontained high/critical threats. Contained threats
  // and low-severity noise stay silent; dashboard updates live.
  if (isContained || !isGrave) return;

  if (document.hidden) updateTabBadge(1);

  var etype = alert.entity_type || 'ip';
  // Audit 2.10: pivot directly into the open journey when the
  // operator is already looking at it. Reload to fold the new entry
  // into the existing timeline instead of stacking a redundant toast.
  if (alertIp && etype.toLowerCase() === 'ip' && _journeyOpenForIp(alertIp)) {
    if (typeof loadJourney === 'function') {
      loadJourney('ip', alertIp);
    }
    return;
  }

  const stack = document.getElementById('alertStack');
  if (!stack) return;
  const visible = stack.querySelectorAll('.alert-toast');
  if (visible.length >= ALERT_STACK_MAX_VISIBLE) {
    _alertStackOverflow++;
    _renderAlertStackOverflow();
    return;
  }

  const title = alert.title || 'Incident detected';
  const sevLabel = sev.toUpperCase();
  const sevColor = sev === 'critical' ? '#f43f5e' : '#f97316';

  const toastEl = document.createElement('div');
  toastEl.className = 'alert-toast alert-toast-' + sev + ' visible';
  toastEl.setAttribute('role', 'alert');
  toastEl.innerHTML =
    '<div class="alert-toast-body">' +
      '<span class="alert-toast-sev" style="color:' + sevColor + '">' + esc(sevLabel) + '</span>' +
      '<span class="alert-toast-title">' + esc(title) + '</span>' +
      (alertIp ? '<span class="alert-toast-target">' + esc(alertIp) + ' →</span>' : '') +
    '</div>' +
    '<button class="alert-toast-close" type="button" aria-label="Dismiss alert">&times;</button>';

  toastEl._dismiss = function() {
    if (toastEl._timer) clearTimeout(toastEl._timer);
    toastEl.remove();
  };
  toastEl.querySelector('.alert-toast-body').addEventListener('click', function() {
    toastEl._dismiss();
    showView('investigate');
    if (alertIp) handleCardClickByValue(etype, alertIp);
  });
  toastEl.querySelector('.alert-toast-close').addEventListener('click', function(ev) {
    ev.stopPropagation();
    toastEl._dismiss();
  });

  // Critical alerts require explicit acknowledgement; high alerts
  // auto-fade after 15 s like before.
  if (sev !== 'critical') {
    toastEl._timer = setTimeout(function() { toastEl._dismiss(); }, 15000);
  }

  stack.insertBefore(toastEl, stack.querySelector('.alert-overflow') || null);
}

// Backwards-compat: older callers may still invoke dismissToast().
// Drains the alert stack and hides the action toast.
function dismissToast() {
  const stack = document.getElementById('alertStack');
  if (stack) {
    stack.querySelectorAll('.alert-toast').forEach(function(t) {
      if (t._timer) clearTimeout(t._timer);
      t.remove();
    });
    _alertStackOverflow = 0;
    _renderAlertStackOverflow();
  }
  const toastEl = document.getElementById('toast');
  if (toastEl) {
    toastEl.classList.remove('visible');
    clearTimeout(toastEl._timer);
  }
}

// ── Real-time connection state (audit 5.12) ──────────────────────────
// The header already toggles between LIVE and reconnecting based on
// the SSE handshake. The audit asks for richer signal: how long since
// the last event, and a hard-fail badge when the agent has been
// silent for several minutes. We track the timestamp of the last
// observed SSE message in `window._lastSSEEventTs` (any kind of
// event counts as a heartbeat for connection-liveness purposes) and
// a 5 s ticker repaints the header.
var CONN_AMBER_AFTER_SECS = 60;     // amber "stalling" cue
var CONN_RED_AFTER_SECS   = 300;    // hard-fail "silent" cue
var _connStateMode = 'unknown';     // 'live' | 'reconnecting' | 'unknown'

function _markSseEvent() {
  window._lastSSEEventTs = Date.now();
  _renderConnectionStatus();
}

function _setConnState(mode) {
  _connStateMode = mode;
  _renderConnectionStatus();
}

function _renderConnectionStatus() {
  var el = document.getElementById('refreshStatus');
  if (!el) return;
  var lastTs = window._lastSSEEventTs;
  var nowMs = Date.now();
  var ageSecs = lastTs ? Math.max(0, Math.floor((nowMs - lastTs) / 1000)) : null;

  var color, label, ageHtml = '';
  if (_connStateMode === 'reconnecting') {
    color = '#888';
    label = 'reconnecting';
  } else if (ageSecs == null) {
    color = '#78e5ff';
    label = 'LIVE';
  } else if (ageSecs >= CONN_RED_AFTER_SECS) {
    color = '#f43f5e';
    label = 'NO DATA';
  } else if (ageSecs >= CONN_AMBER_AFTER_SECS) {
    color = '#f59e0b';
    label = 'STALLING';
  } else {
    color = '#78e5ff';
    label = 'LIVE';
  }

  if (ageSecs != null) {
    var ageText;
    if (ageSecs < 60) ageText = ageSecs + 's';
    else if (ageSecs < 3600) ageText = Math.floor(ageSecs / 60) + 'm';
    else ageText = Math.floor(ageSecs / 3600) + 'h';
    ageHtml = '<span style="color:var(--muted);font-size:0.65rem;margin-left:6px">last event ' + ageText + ' ago</span>';
  }

  el.innerHTML = '<span style="color:' + color + ';font-size:0.75rem;font-weight:600" title="Real-time connection state">● ' + label + '</span>' + ageHtml;
}

// Background ticker repaints the header every 5 s so the operator
// sees the age tick over and the colour flip on schedule even when
// no new events arrive.
setInterval(_renderConnectionStatus, 5000);

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
document.getElementById('flt-status').value = state.filters.status || '';
updatePivotUi();
loadActionConfig();
loadReportDates();

// Default view
showView('home');

// Keyboard shortcuts
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') closeActionModal();
});

// 2026-04-29: cap the date pickers at today so the calendar widget
// greys out future dates. Browser enforces this only on the calendar
// UI; `syncFiltersFromUi` adds the matching guard against typed-in
// future dates.
(function capDatePickersAtToday() {
  var today = new Date().toISOString().slice(0, 10);
  var el = document.getElementById('flt-date');
  if (el) el.max = today;
  var cmp = document.getElementById('flt-compare-date');
  if (cmp) cmp.max = today;
})();

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
document.getElementById('flt-status').addEventListener('change', () => refreshLeft(true));
document.getElementById('entitySearch').addEventListener('input', applyEntitySearch);

// Initial data load — route first, then load data for visible view
initRouter();
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
      _refreshActiveView();
      fallbackTimer = setInterval(() => {
        refreshLeftLive();
        _refreshActiveView();
      }, 30000);
    }, 35000);
  }

  // 2026-05-02 audit fix: when SSE drops, fallbackTimer is the only
  // pulse keeping live views fresh. Until now it only refreshed the
  // left rail, so the Sensors view stayed frozen on whatever data
  // was first painted. This helper is the single place to add other
  // active-view refreshes (sensors today; report/intel can join later
  // if a similar freeze report comes in).
  function _refreshActiveView() {
    var sensorsView = document.getElementById('viewSensors');
    if (sensorsView && sensorsView.style.display !== 'none' && typeof loadSensors === 'function') {
      loadSensors();
    }
  }

  function connect() {
    clearTimeout(reconnectTimer);
    fetch('/api/events/stream', { headers: { 'Accept': 'text/event-stream' } })
      .then(res => {
        if (!res.ok || !res.body) throw new Error('SSE connect failed');
        clearTimeout(fallbackTimer);
        clearInterval(fallbackTimer);
        _setConnState('live');
        _markSseEvent();
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
                _markSseEvent();
                if (lastEvent === 'refresh') {
                  // Throttle: at most 1 refresh per 5 seconds to avoid 429s
                  var now = Date.now();
                  if (!window._lastSSERefresh || now - window._lastSSERefresh > 5000) {
                    window._lastSSERefresh = now;
                    refreshLeftLive();
                    if (document.getElementById('viewHome').style.display !== 'none') loadHome();
                    // 2026-05-02 audit fix: Sensors view never refreshed after
                    // the initial mount, so its KPIs and three charts stayed
                    // frozen for the entire session. Re-run loadSensors when a
                    // refresh signal arrives and the view is visible. Same
                    // throttle as Home applies via the outer guard.
                    var sensorsView = document.getElementById('viewSensors');
                    if (sensorsView && sensorsView.style.display !== 'none' && typeof loadSensors === 'function') {
                      loadSensors();
                    }
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
    _setConnState('reconnecting');
    armFallback();
    reconnectTimer = setTimeout(connect, 3000);
  }

  armFallback();
  connect();
})();
