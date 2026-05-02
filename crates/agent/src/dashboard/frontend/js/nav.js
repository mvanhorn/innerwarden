'use strict';

// ── Hash-based URL routing ────────────────────────────────────────────
function initRouter() {
  var hash = location.hash.replace('#', '') || 'home';
  // Map common aliases
  if (hash === 'threats') hash = 'investigate';
  showView(hash);
}
window.addEventListener('hashchange', function() {
  var hash = location.hash.replace('#', '') || 'home';
  if (hash === 'threats') hash = 'investigate';
  showView(hash);
});

// ── Mobile panel toggle ────────────────────────────────────────────────
let leftPanelOpen = true;
function toggleLeftPanel() {
  const panel = document.querySelector('.left-panel');
  const icon  = document.getElementById('panelToggleIcon');
  leftPanelOpen = !leftPanelOpen;
  panel.classList.toggle('collapsed', !leftPanelOpen);
  if (icon) icon.textContent = leftPanelOpen ? '▲' : '▼';
}

// ── D10 - View switcher ──────────────────────────────────────────────────
// Audit 4.6: `responses` is now a top-level nav button, so it no
// longer needs to live in the More dropdown's secondary list. The
// dropdown only carries review surfaces (no operator-action surfaces).
const _secondaryTabs = ['sensors','report','honeypot','compliance','monthly','graph'];
const _secondaryLabels = { sensors:'Sensors', report:'Report', honeypot:'Honeypot', compliance:'Compliance', monthly:'Monthly', graph:'Graph' };

function toggleMoreMenu() {
  const m = document.getElementById('moreMenu');
  if (m) m.style.display = m.style.display === 'none' ? '' : 'none';
}

function showView(name) {
  const views = { home: 'viewHome', sensors: 'viewSensors', investigate: 'viewInvestigate', report: 'viewReport', status: 'viewStatus', honeypot: 'viewHoneypot', compliance: 'viewCompliance', intel: 'viewIntel', monthly: 'viewMonthly', responses: 'viewResponses', fleet: 'viewFleet', graph: 'viewGraph' };
  const btns  = { home: 'navHome', sensors: 'navSensors', investigate: 'navInvestigate', report: 'navReport', status: 'navStatus', honeypot: 'navHoneypot', compliance: 'navCompliance', intel: 'navIntel', monthly: 'navMonthly', responses: 'navResponses', fleet: 'navFleet', graph: 'navGraph' };
  // Update URL hash (use friendly name for threats)
  var hashName = name === 'investigate' ? 'threats' : name;
  if (location.hash !== '#' + hashName) {
    history.replaceState(null, '', '#' + hashName);
  }
  Object.keys(views).forEach(k => {
    const el = document.getElementById(views[k]);
    const btn = document.getElementById(btns[k]);
    if (el) el.style.display = k === name ? 'flex' : 'none';
    if (btn) btn.classList.toggle('active', k === name);
  });
  const toggleBtn = document.getElementById('panelToggleBtn');
  if (toggleBtn) toggleBtn.classList.toggle('hidden', name !== 'investigate');
  // More dropdown: update label + highlight active item
  const moreLabel = document.getElementById('moreLabel');
  const navMore = document.getElementById('navMore');
  if (_secondaryTabs.includes(name)) {
    if (moreLabel) moreLabel.textContent = _secondaryLabels[name] || 'More';
    if (navMore) navMore.classList.add('active');
  } else {
    if (moreLabel) moreLabel.textContent = 'More';
    if (navMore) navMore.classList.remove('active');
  }
  // Close dropdown on any tab switch
  const moreMenu = document.getElementById('moreMenu');
  if (moreMenu) moreMenu.style.display = 'none';
  // Mark active item inside dropdown
  document.querySelectorAll('.nav-more-item').forEach(item => {
    item.classList.toggle('active', item.id === btns[name]);
  });

  // Clear outcome filter when leaving investigate
  if (name !== 'investigate') state.filterOutcome = null;
  if (name === 'home') loadHome();
  if (name === 'sensors') { loadSensors(); loadTopAction(); }
  if (name === 'report') loadReport();
  if (name === 'status') loadStatus();
  if (name === 'honeypot') loadHoneypot();
  if (name === 'compliance') loadCompliance();
  if (name === 'intel') loadIntel();
  if (name === 'monthly') loadMonthly();
  if (name === 'responses') loadResponses();
  if (name === 'fleet') loadFleet();
  // Graph tab was removed and stats moved to Health; the old loadGraph()
  // module is no longer bundled so we stop dispatching here too.
}

// Click-outside handler for More dropdown
document.addEventListener('click', function(e) {
  var wrap = document.querySelector('.nav-more-wrap');
  if (wrap && !wrap.contains(e.target)) {
    var m = document.getElementById('moreMenu');
    if (m) m.style.display = 'none';
  }
});
