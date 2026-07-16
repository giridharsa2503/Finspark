/**
 * FinSpark — D3.js Fraud Network Graph
 * Force-directed graph visualization of suspicious transaction chains
 */

async function loadFraudNetwork() {
  const container = document.getElementById('fraud-graph');
  if (!container) return;

  try {
    const res = await fetch(`${window.API_BASE || 'http://localhost:8000'}/api/fraud/network`);
    const data = await res.json();
    renderFraudGraph(data.network, data.detected_patterns);
    renderPatternList(data.detected_patterns);
  } catch(e) {
    renderMockFraudGraph();
  }
}

function renderMockFraudGraph() {
  const mockData = generateMockNetwork(22);
  renderFraudGraph(mockData, []);
}

function generateMockNetwork(n) {
  const types = ['CHECKING','SAVINGS','SHELL_CORP','OFFSHORE','CRYPTO_WALLET','MONEY_MULE','LEGITIMATE'];
  const colors = {
    SHELL_CORP:'#ef4444', OFFSHORE:'#f59e0b', CRYPTO_WALLET:'#f59e0b',
    MONEY_MULE:'#ef4444', CHECKING:'#00d4aa', SAVINGS:'#00d4aa', LEGITIMATE:'#22c55e'
  };
  const nodes = Array.from({length:n}, (_, i) => {
    const t = types[Math.floor(Math.random()*types.length)];
    return { id:`ACC${10000+i}`, type:t, color:colors[t], txn_count:Math.floor(Math.random()*100+1) };
  });
  const edges = [];
  const used = new Set();
  for (let i=0; i<Math.min(n*2,40); i++) {
    const src = nodes[Math.floor(Math.random()*n)].id;
    const dst = nodes[Math.floor(Math.random()*n)].id;
    if (src !== dst && !used.has(src+dst)) {
      used.add(src+dst);
      edges.push({
        source: src,
        target: dst,
        amount: Math.random()*2000000,
        suspicious: Math.random()>0.5
      });
    }
  }
  return { nodes, edges };
}

function renderFraudGraph(network, patterns) {
  const container = document.getElementById('fraud-graph');
  if (!container || !window.d3) return;

  container.innerHTML = '';
  const W = container.clientWidth || 600;
  const H = container.clientHeight || 380;

  const svg = d3.select('#fraud-graph')
    .append('svg')
    .attr('width', W)
    .attr('height', H);

  // Definitions: arrow markers
  const defs = svg.append('defs');
  ['normal','suspicious'].forEach(type => {
    defs.append('marker')
      .attr('id', `arrow-${type}`)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', type === 'suspicious' ? '#ef4444' : '#00d4aa');
  });

  const simulation = d3.forceSimulation(network.nodes)
    .force('link', d3.forceLink(network.edges).id(d => d.id).distance(80))
    .force('charge', d3.forceManyBody().strength(-180))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(22));

  // Links
  const link = svg.append('g')
    .selectAll('line')
    .data(network.edges)
    .join('line')
    .attr('stroke', d => d.suspicious ? 'rgba(239,68,68,0.5)' : 'rgba(0,212,170,0.25)')
    .attr('stroke-width', d => d.suspicious ? 2 : 1)
    .attr('marker-end', d => `url(#arrow-${d.suspicious ? 'suspicious' : 'normal'})`);

  // Nodes
  const node = svg.append('g')
    .selectAll('g')
    .data(network.nodes)
    .join('g')
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  (event, d) => { d.fx=event.x; d.fy=event.y; })
      .on('end',   (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx=null; d.fy=null; })
    );

  // Circle glow for high risk
  node.append('circle')
    .attr('r', d => (d.type==='SHELL_CORP'||d.type==='MONEY_MULE') ? 16 : 12)
    .attr('fill', d => d.color + '30')
    .attr('stroke', d => d.color)
    .attr('stroke-width', 2);

  // Inner circle
  node.append('circle')
    .attr('r', d => (d.type==='SHELL_CORP'||d.type==='MONEY_MULE') ? 10 : 7)
    .attr('fill', d => d.color + '80');

  // Labels
  node.append('text')
    .text(d => d.id.slice(-4))
    .attr('text-anchor', 'middle')
    .attr('dy', 28)
    .attr('fill', '#8da8c0')
    .attr('font-size', 9)
    .attr('font-family', 'JetBrains Mono, monospace');

  // Tooltip
  node.append('title')
    .text(d => `${d.id}\nType: ${d.type}\nTransactions: ${d.txn_count}`);

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    node.attr('transform', d => `translate(${d.x},${d.y})`);
  });

  // Stats overlay
  const suspicious = network.edges.filter(e => e.suspicious).length;
  svg.append('text')
    .attr('x', 10).attr('y', 20)
    .attr('fill', '#4a6080').attr('font-size', 10).attr('font-family', 'Inter, sans-serif')
    .text(`${network.nodes.length} accounts · ${network.edges.length} flows · ${suspicious} suspicious`);
}

function renderPatternList(patterns) {
  const list = document.getElementById('pattern-list');
  if (!list) return;

  if (!patterns || patterns.length === 0) {
    list.innerHTML = `<div style="color:var(--text-muted);font-size:0.78rem;padding:8px">No layering patterns detected</div>`;
    return;
  }

  list.innerHTML = patterns.slice(0,5).map(p => `
    <div style="padding:8px 0;border-bottom:1px solid var(--border);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;">
        <span style="font-size:0.78rem;font-weight:600;color:var(--text-primary)">${p.account}</span>
        <span class="severity-badge sev-${p.severity}">${p.severity}</span>
      </div>
      <div style="font-size:0.7rem;color:var(--text-secondary)">${p.description}</div>
    </div>
  `).join('');
}

// Load on page ready
document.addEventListener('DOMContentLoaded', () => {
  loadFraudNetwork();
  // Re-render on refresh button
  document.getElementById('refresh-fraud')?.addEventListener('click', () => {
    document.getElementById('fraud-graph').innerHTML = '';
    loadFraudNetwork();
  });
});
