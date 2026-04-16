// ── Graph tab ────────────────────────────────────────────────────────
let graphCy = null;
const NODE_COLORS = {
  Process: '#3b82f6', Ip: '#ef4444', File: '#22c55e', User: '#a855f7',
  Domain: '#f59e0b', Port: '#6b7280', Container: '#06b6d4', Device: '#f97316',
  System: '#64748b', Incident: '#dc2626', Campaign: '#ec4899',
};

async function loadGraph() {
  const statusEl = document.getElementById('graphViewStatus');
  if (statusEl) statusEl.textContent = 'Loading...';
  try {
    const [stats, view] = await Promise.all([
      loadJson('/api/graph/stats'),
      loadJson('/api/graph/view'),
    ]);

    // Stats bar
    const statsEl = document.getElementById('graphStats');
    if (statsEl) {
      const mem = stats.memory_bytes ? (stats.memory_bytes / 1024 / 1024).toFixed(1) + ' MB' : '0 MB';
      const byType = stats.nodes_by_type || {};
      const typeParts = Object.entries(byType).map(([k,v]) => `${k}:${v}`).join(' · ');
      statsEl.innerHTML = `<span>Nodes: <b>${stats.node_count||0}</b></span>` +
        `<span>Edges: <b>${stats.edge_count||0}</b></span>` +
        `<span>Memory: <b>${mem}</b></span>` +
        `<span>Threats: <b>${stats.threat_intel_nodes||0}</b></span>` +
        `<span>Incidents: <b>${stats.incident_nodes||0}</b></span>` +
        (typeParts ? `<span style="opacity:0.6">${typeParts}</span>` : '');
    }

    // Render graph
    const container = document.getElementById('graphContainer');
    if (!container || (!view.nodes.length && !view.edges.length)) {
      if (container) container.innerHTML = '<p style="padding:40px;text-align:center;color:var(--dim);">No graph data yet. Events will populate the graph automatically.</p>';
      if (statusEl) statusEl.textContent = '';
      return;
    }

    // Load Cytoscape.js from CDN if not loaded (with offline fallback)
    if (typeof cytoscape === 'undefined') {
      try {
        await new Promise((resolve, reject) => {
          const s = document.createElement('script');
          s.src = 'https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js';
          s.onload = resolve;
          s.onerror = reject;
          s.timeout = 5000;
          document.head.appendChild(s);
          setTimeout(() => reject(new Error('timeout')), 5000);
        });
      } catch (e) {
        container.innerHTML = '<p style="padding:40px;text-align:center;color:var(--dim);">Graph visualization requires internet (Cytoscape.js CDN). Stats are shown above.</p>';
        if (statusEl) statusEl.textContent = 'Cytoscape.js unavailable (offline)';
        return;
      }
    }

    if (graphCy) graphCy.destroy();

    graphCy = cytoscape({
      container: container,
      elements: { nodes: view.nodes, edges: view.edges },
      style: [
        { selector: 'node', style: {
          'label': 'data(label)',
          'background-color': function(ele) { return NODE_COLORS[ele.data('type')] || '#6b7280'; },
          'color': '#e8eef5',
          'text-valign': 'bottom',
          'text-margin-y': 4,
          'font-size': '10px',
          'width': function(ele) { return Math.max(15, Math.min(40, 10 + ele.degree() * 2)); },
          'height': function(ele) { return Math.max(15, Math.min(40, 10 + ele.degree() * 2)); },
          'border-width': function(ele) { return ele.data('type') === 'Incident' ? 3 : 1; },
          'border-color': function(ele) { return ele.data('type') === 'Incident' ? '#dc2626' : '#333'; },
        }},
        { selector: 'edge', style: {
          'width': 1.5,
          'line-color': '#444',
          'target-arrow-color': '#666',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(relation)',
          'font-size': '8px',
          'color': '#666',
          'text-rotation': 'autorotate',
          'text-margin-y': -8,
        }},
        { selector: ':selected', style: {
          'border-color': '#00d9ff',
          'border-width': 3,
          'line-color': '#00d9ff',
          'target-arrow-color': '#00d9ff',
        }},
      ],
      layout: { name: 'cose', animate: false, nodeRepulsion: 8000, idealEdgeLength: 80, padding: 30 },
      minZoom: 0.1, maxZoom: 5,
    });

    // Click handler: show node details
    graphCy.on('tap', 'node', function(evt) {
      const d = evt.target.data();
      const detail = document.getElementById('graphNodeDetail');
      if (detail) {
        detail.style.display = 'block';
        const edges = evt.target.connectedEdges().map(e => {
          const rel = e.data('relation');
          const ts = e.data('ts') ? new Date(e.data('ts')).toLocaleTimeString() : '';
          const other = e.source().id() === evt.target.id() ? e.target().data('label') : e.source().data('label');
          return `<span style="color:var(--dim)">${ts}</span> ${rel} → ${other}`;
        });
        detail.innerHTML = `<b>${d.type}: ${d.label}</b>` +
          (d.sensitive ? ' <span style="color:#ef4444">⚠ sensitive</span>' : '') +
          `<br><span style="color:var(--dim)">${edges.length} connections</span>` +
          (edges.length ? '<br>' + edges.slice(0, 20).join('<br>') : '') +
          (edges.length > 20 ? `<br><span style="color:var(--dim)">...and ${edges.length - 20} more</span>` : '');
      }
    });

    graphCy.on('tap', 'edge', function(evt) {
      const d = evt.target.data();
      const detail = document.getElementById('graphNodeDetail');
      if (detail) {
        detail.style.display = 'block';
        const ts = d.ts ? new Date(d.ts).toLocaleString() : '';
        const src = evt.target.source().data('label') || d.source;
        const tgt = evt.target.target().data('label') || d.target;
        detail.innerHTML = `<b>${d.relation || 'edge'}</b><br>` +
          `<span style="color:var(--dim)">${src}</span> → <span style="color:var(--dim)">${tgt}</span>` +
          (ts ? `<br><span style="color:var(--muted)">${ts}</span>` : '');
      }
    });

    graphCy.on('tap', function(evt) {
      if (evt.target === graphCy) {
        const detail = document.getElementById('graphNodeDetail');
        if (detail) detail.style.display = 'none';
      }
    });

    if (statusEl) statusEl.textContent = `Showing ${view.nodes.length} of ${stats.node_count||'?'} nodes, ${view.edges.length} edges`;
  } catch (e) {
    if (statusEl) statusEl.textContent = 'Error: ' + e.message;
  }
}

function filterGraph() {
  if (!graphCy) return;
  const filter = document.getElementById('graphFilter').value;
  graphCy.nodes().forEach(n => {
    if (filter === 'all') { n.style('display', 'element'); return; }
    if (filter === 'topology') {
      // Hide Incident nodes — show attack topology only
      n.style('display', n.data('type') === 'Incident' ? 'none' : 'element');
      return;
    }
    if (filter === 'threat') {
      const isIp = n.data('type') === 'Ip';
      const connected = n.connectedEdges().some(e => {
        const other = e.source().id() === n.id() ? e.target() : e.source();
        return other.data('type') === 'Ip';
      });
      n.style('display', (isIp || connected) ? 'element' : 'none');
    } else {
      n.style('display', n.data('type') === filter ? 'element' : 'none');
    }
  });
  // Re-layout after filter change
  graphCy.layout({ name: 'cose', animate: true, animationDuration: 300, nodeRepulsion: 8000, idealEdgeLength: 80, padding: 30 }).run();
}

// ── Graph search ─────────────────────────────────────────────────────
function searchGraph() {
  if (!graphCy) return;
  var q = (document.getElementById('graphSearch')?.value || '').trim().toLowerCase();
  if (!q) { graphCy.nodes().style('opacity', 1); return; }
  var found = null;
  graphCy.nodes().forEach(function(n) {
    var label = (n.data('label') || '').toLowerCase();
    var type = (n.data('type') || '').toLowerCase();
    var match = label.includes(q) || type.includes(q);
    n.style('opacity', match ? 1 : 0.15);
    if (match && !found) found = n;
  });
  if (found) graphCy.animate({ center: { eles: found }, zoom: 1.5, duration: 300 });
}

// ── Export graph as PNG ──────────────────────────────────────────────
function exportGraphPng() {
  if (!graphCy) return;
  var png = graphCy.png({ full: true, scale: 2, bg: '#040814' });
  var a = document.createElement('a');
  a.href = png;
  a.download = 'innerwarden-graph-' + new Date().toISOString().slice(0,10) + '.png';
  a.click();
}

