// ── Helpers ────────────────────────────────────────────────────────────
const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const fmtTime = (ts) => {
  const d = new Date(ts);
  return isNaN(d) ? String(ts) : d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
};

const fmtDateTime = (ts) => {
  const d = new Date(ts);
  return isNaN(d) ? String(ts) : d.toLocaleString();
};

// 2026-05-01 (audit findings 2.8 + 4.5, `tracked-issue: time format
// unified + timezone label`): the dashboard rendered three different
// timestamps for the same event ("33s ago" hero, "36m ago" sidebar,
// "02:51:31" timeline) with no timezone label anywhere on Home. The
// auditor flagged that an operator looking at one screen could not
// tell which clock or zone the numbers were on. These two helpers
// give every surface ONE rendering style:
//
//   fmtAgo(seconds)        → "33s ago" / "36m ago" / "2h ago" / "3d ago"
//                            for relative time on Home cards.
//
//   fmtUtcShort(ts)        → "13:45 UTC" — for status pills + per-row
//                            hero timestamps where the date is
//                            already implied by the page scope.
//
//   fmtUtcFull(ts)         → "2026-05-01 13:45 UTC" — for table cells
//                            that span dates (audit trail viewer,
//                            playbook log).
//
// All three are pure UTC. The host's local timezone is intentionally
// NOT used: a security operator switching laptops between zones
// must see the same number to correlate against journald and SQLite
// (both UTC). `fmtTime` / `fmtDateTime` legacy helpers above are
// kept for back-compat — new call sites should prefer the helpers
// below.
const fmtAgo = (seconds) => {
  if (seconds == null || isNaN(seconds)) return '';
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
};

const fmtUtcShort = (ts) => {
  const d = new Date(ts);
  if (isNaN(d)) return String(ts);
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  return hh + ':' + mm + ' UTC';
};

const fmtUtcFull = (ts) => {
  const d = new Date(ts);
  if (isNaN(d)) return String(ts);
  const yyyy = d.getUTCFullYear();
  const mo = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mi = String(d.getUTCMinutes()).padStart(2, '0');
  return yyyy + '-' + mo + '-' + dd + ' ' + hh + ':' + mi + ' UTC';
};

const outcomeLabel = (o) => ({blocked:'CONTAINED', active:'OBSERVING', monitoring:'OBSERVING', honeypot:'HONEYPOT', needs_attention:'NEEDS ATTENTION', dismissed:'DISMISSED', unknown:'UNKNOWN'}[o] || o.toUpperCase());
const outcomeCls   = (o) => 'bo bo-' + (o || 'unknown');

const sevCls = (s) => ({'critical':'sc-critical','high':'sc-high','medium':'sc-medium','low':'sc-low','info':'sc-info'}[s] || '');

/** Show a toast notification. */
function toast(msg, type) {
  const t = document.createElement('div');
  t.className = 'toast toast-' + (type || 'info');
  t.textContent = msg;
  t.style.cssText = 'position:fixed;top:16px;right:16px;z-index:9999;padding:12px 20px;border-radius:8px;font-size:0.85rem;max-width:360px;animation:fadeIn .2s;';
  t.style.background = type === 'error' ? 'var(--danger)' : type === 'warn' ? 'var(--warn)' : 'var(--accent)';
  t.style.color = type === 'error' || type === 'warn' ? '#fff' : 'var(--bg0)';
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 4000);
}

async function loadJson(url, opts) {
  // 2026-05-02 audit fix (P7): callers can pass `{ signal }` to bind
  // a fetch to an AbortController so a fast user toggle/IP switch
  // cancels the previous request instead of letting two completions
  // race onto the same DOM target.
  const init = { cache: 'no-store' };
  if (opts && opts.signal) init.signal = opts.signal;
  const r = await fetch(url, init);
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

async function loadText(url, opts) {
  const init = { cache: 'no-store' };
  if (opts && opts.signal) init.signal = opts.signal;
  const r = await fetch(url, init);
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.text();
}

function downloadBlob(name, contentType, text) {
  const blob = new Blob([text], { type: contentType });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

