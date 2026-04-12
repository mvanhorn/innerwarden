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

async function loadJson(url) {
  const r = await fetch(url, {cache: 'no-store'});
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

async function loadText(url) {
  const r = await fetch(url, {cache: 'no-store'});
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

