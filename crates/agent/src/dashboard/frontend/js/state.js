// ── Investigation state ────────────────────────────────────────────────
const state = {
  pivot: 'ip',
  selected: { type: 'ip', value: null },
  filters: {
    date: '',
    compare_date: '',
    severity_min: '',
    detector: '',
    window_seconds: ''
  },
  clusters: [],
  knownItemValues: new Set(),  // D7: tracks rendered entity values for diff
  hideAllowlisted: true,
  filterOutcome: null,
  // spec 017 01-home Change 8: consume-once handoff from Home's
  // viewActivity() to Threats. 02-threats.md's responsibility to
  // read-and-clear this flag after selecting the first matching item.
  autoSelectOnThreatsOpen: null,
};

const pivotTitle = (pivot) => ({
  ip: 'Attackers (IP)',
  user: 'Users (Pivot)',
  detector: 'Detectors (Pivot)',
}[pivot] || 'Entities');

function parsePivotToken(token) {
  const i = String(token || '').indexOf(':');
  if (i <= 0) return { type: 'detector', value: String(token || '') };
  return { type: token.slice(0, i), value: token.slice(i + 1) };
}

function buildQuery(params) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v === null || v === undefined) return;
    const val = String(v).trim();
    if (!val) return;
    q.set(k, val);
  });
  return q.toString();
}

function syncFiltersFromUi() {
  state.filters.date = document.getElementById('flt-date').value || '';
  state.filters.compare_date = document.getElementById('flt-compare-date').value || '';
  state.filters.severity_min = document.getElementById('flt-severity').value || '';
  state.filters.detector = (document.getElementById('flt-detector').value || '').trim();
  state.filters.window_seconds = document.getElementById('flt-window').value || '';
}

function hydrateStateFromQuery() {
  const qs = new URLSearchParams(window.location.search || '');
  const pivot = (qs.get('pivot') || '').trim();
  if (pivot === 'ip' || pivot === 'user' || pivot === 'detector') {
    state.pivot = pivot;
  }

  state.filters.date = (qs.get('date') || '').trim();
  state.filters.compare_date = (qs.get('compare_date') || '').trim();
  state.filters.severity_min = (qs.get('severity_min') || '').trim();
  state.filters.detector = (qs.get('detector') || '').trim();
  state.filters.window_seconds = (qs.get('window_seconds') || '').trim();

  const subjectType = (qs.get('subject_type') || '').trim();
  const subject = (qs.get('subject') || '').trim();
  if ((subjectType === 'ip' || subjectType === 'user' || subjectType === 'detector') && subject) {
    state.selected = { type: subjectType, value: subject };
  }
}

function syncUrl() {
  const qs = buildQuery({
    pivot: state.pivot,
    date: state.filters.date,
    compare_date: state.filters.compare_date,
    severity_min: state.filters.severity_min,
    detector: state.filters.detector,
    window_seconds: state.filters.window_seconds,
    subject_type: state.selected.value ? state.selected.type : '',
    subject: state.selected.value ? state.selected.value : '',
  });
  const nextUrl = qs ? ('?' + qs) : window.location.pathname;
  window.history.replaceState({}, '', nextUrl);
}

function updatePivotUi() {
  document.querySelectorAll('.pivot-tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.pivot === state.pivot);
  });
  document.getElementById('entityTitle').textContent = pivotTitle(state.pivot);
}

