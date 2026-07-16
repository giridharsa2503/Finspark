/**
 * FinSpark — Main Dashboard Logic
 * Handles: API calls, threat feed, KPI updates, XAI explanations, charts
 */

// ── API Base URL ──────────────────────────────────────────────────────────────
// Dynamically route to local backend or same-origin depending on deploy context
const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
  ? 'http://localhost:8000' 
  : '';
window.API_BASE = API_BASE;

// ── Utility Functions ─────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const fmt$ = (n) => `$${Number(n).toLocaleString('en-US', { minimumFractionDigits: 0 })}`;

function severityColor(level) {
  return { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#3b82f6', LOW: '#22c55e' }[level] || '#888';
}

function scoreClass(score) {
  if (score >= 80) return 'score-critical';
  if (score >= 60) return 'score-high';
  if (score >= 40) return 'score-medium';
  return 'score-low';
}

function timeAgo(isoStr) {
  const diff = Date.now() - new Date(isoStr).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

// ── State ─────────────────────────────────────────────────────────────────────
let threatHistory = [];
let selectedAlert = null;
let eventsChart = null;
let riskDistChart = null;
let teleTypeChart = null;

// ── KPI Dashboard ─────────────────────────────────────────────────────────────
async function loadDashboardKPIs() {
  try {
    const res = await fetch(`${API_BASE}/api/dashboard/summary`);
    const data = await res.json();

    animateCounter('kpi-events', data.total_events_analyzed);
    animateCounter('kpi-threats', data.threats_detected);
    document.getElementById('kpi-fp').textContent = data.false_positive_reduction;
    document.getElementById('kpi-score').textContent = data.avg_risk_score;
    document.getElementById('kpi-accuracy').textContent = data.model_accuracy;
    animateCounter('kpi-eps', data.events_per_second);

    // Severity breakdown
    const breakdown = data.severity_breakdown;
    const total = Object.values(breakdown).reduce((a,b) => a+b, 0);
    updateMiniBar('bar-critical', breakdown.CRITICAL, total, '#ef4444');
    updateMiniBar('bar-high',     breakdown.HIGH,     total, '#f59e0b');
    updateMiniBar('bar-medium',   breakdown.MEDIUM,   total, '#3b82f6');
    updateMiniBar('bar-low',      breakdown.LOW,      total, '#22c55e');

    updateRiskDistChart(breakdown);
  } catch(e) {
    console.warn('API not available, using mock data:', e.message);
    loadMockKPIs();
  }
}

function loadMockKPIs() {
  animateCounter('kpi-events', 50);
  animateCounter('kpi-threats', 12);
  document.getElementById('kpi-fp').textContent = '74%';
  document.getElementById('kpi-score').textContent = '61.3';
  document.getElementById('kpi-accuracy').textContent = '94.3%';
  animateCounter('kpi-eps', 187);
  updateMiniBar('bar-critical', 4, 50, '#ef4444');
  updateMiniBar('bar-high',     8, 50, '#f59e0b');
  updateMiniBar('bar-medium',   18, 50, '#3b82f6');
  updateMiniBar('bar-low',      20, 50, '#22c55e');
  updateRiskDistChart({ CRITICAL:4, HIGH:8, MEDIUM:18, LOW:20 });
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  let current = 0;
  const step = Math.ceil(target / 40);
  const interval = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current.toLocaleString();
    if (current >= target) clearInterval(interval);
  }, 30);
}

function updateMiniBar(id, value, total, color) {
  const el = document.getElementById(id);
  if (!el) return;
  const pct = total > 0 ? (value / total * 100) : 0;
  el.style.width = `${pct}%`;
  el.style.background = color;
  const label = el.parentElement?.previousElementSibling;
  if (label) {
    const countEl = label.querySelector('.bar-count');
    if (countEl) countEl.textContent = value;
  }
}

// ── Live Threat Feed ──────────────────────────────────────────────────────────
async function loadThreats() {
  const feed = document.getElementById('threat-feed');
  if (!feed) return;

  const loadingItem = `<div class="threat-item" style="justify-content:center;opacity:0.5">
    <span class="spinner"></span> Fetching AI threat analysis...
  </div>`;
  feed.innerHTML = loadingItem;

  try {
    const res = await fetch(`${API_BASE}/api/threats/live?count=12`);
    const data = await res.json();
    renderThreatFeed(data.threats);
    threatHistory = data.threats;
  } catch(e) {
    renderMockThreats();
  }
}

function renderThreatFeed(threats) {
  const feed = document.getElementById('threat-feed');
  if (!feed) return;
  feed.innerHTML = '';

  threats.forEach((t, i) => {
    const ai = t.ai_assessment;
    const tel = t.telemetry;
    const txn = t.transaction;

    const item = document.createElement('div');
    item.className = 'threat-item';
    item.style.animationDelay = `${i * 60}ms`;
    item.dataset.alertId = t.id;

    item.innerHTML = `
      <span class="severity-badge sev-${ai.threat_level}">${ai.threat_level}</span>
      <div class="threat-info">
        <div class="threat-title">
          ${tel.event_type.replace(/_/g,' ')} → ${txn.txn_type.replace(/_/g,' ')}
        </div>
        <div class="threat-desc">
          User: ${tel.user_id} · ${tel.country} · ${fmt$(txn.amount)}
          · ${ai.triggered_rules[0] || 'Anomaly detected'}
        </div>
      </div>
      <div class="threat-score ${scoreClass(ai.risk_score)}">
        ${ai.risk_score}<span style="font-size:0.55rem;opacity:0.6">/100</span>
      </div>
    `;

    item.addEventListener('click', () => showAlertDetail(t));
    feed.appendChild(item);
  });
}

function renderMockThreats() {
  const mockThreats = [
    { level:'CRITICAL', title:'DATA_EXFILTRATION → WIRE_TRANSFER', user:'USR4821', country:'RU', amount:2840000, score:94, rule:'Critical telemetry event detected' },
    { level:'CRITICAL', title:'PRIVILEGE_ESCALATION → CRYPTO_PURCHASE', user:'USR7293', country:'CN', amount:890000, score:88, rule:'Privilege escalation precedes financial transaction' },
    { level:'HIGH',     title:'LATERAL_MOVEMENT → FOREX_EXCHANGE',       user:'USR5514', country:'UA', amount:340000, score:72, rule:'Geo-velocity anomaly detected' },
    { level:'HIGH',     title:'FAILED_LOGIN → WIRE_TRANSFER',             user:'USR1903', country:'NG', amount:1200000, score:68, rule:'High-value txn after auth failures' },
    { level:'MEDIUM',   title:'PORT_SCAN → LARGE_CASH_DEPOSIT',          user:'USR8827', country:'BR', amount:95000, score:55, rule:'Statistical anomaly by Isolation Forest' },
    { level:'MEDIUM',   title:'ENDPOINT_ALERT → CRYPTO_PURCHASE',        user:'USR3341', country:'US', amount:48000, score:44, rule:'Geographic location mismatch' },
    { level:'LOW',      title:'VPN_ACCESS → CARD_PAYMENT',               user:'USR6612', country:'DE', amount:220, score:18, rule:'Normal behavior pattern' },
  ];

  const feed = document.getElementById('threat-feed');
  feed.innerHTML = '';
  mockThreats.forEach((t, i) => {
    const item = document.createElement('div');
    item.className = 'threat-item';
    item.style.animationDelay = `${i * 60}ms`;
    item.innerHTML = `
      <span class="severity-badge sev-${t.level}">${t.level}</span>
      <div class="threat-info">
        <div class="threat-title">${t.title.replace(/_/g,' ')}</div>
        <div class="threat-desc">User: ${t.user} · ${t.country} · ${fmt$(t.amount)} · ${t.rule}</div>
      </div>
      <div class="threat-score ${scoreClass(t.score)}">
        ${t.score}<span style="font-size:0.55rem;opacity:0.6">/100</span>
      </div>
    `;
    item.addEventListener('click', () => showMockDetail(t));
    feed.appendChild(item);
  });
}

// ── Alert Detail Modal ────────────────────────────────────────────────────────
async function showAlertDetail(threat) {
  selectedAlert = threat;
  const modal = document.getElementById('alert-modal');
  const overlay = document.getElementById('modal-overlay');

  const ai = threat.ai_assessment;
  const tel = threat.telemetry;
  const txn = threat.transaction;

  document.getElementById('modal-alert-id').textContent = threat.id;
  document.getElementById('modal-risk-score').textContent = ai.risk_score;
  document.getElementById('modal-risk-score').className = scoreClass(ai.risk_score);
  document.getElementById('modal-threat-level').textContent = ai.threat_level;
  document.getElementById('modal-threat-level').className = `severity-badge sev-${ai.threat_level}`;
  document.getElementById('modal-explanation').textContent = ai.explanation;

  // Load XAI
  try {
    const res = await fetch(`${API_BASE}/api/explain/${threat.id}`);
    const xai = await res.json();
    renderXAIFeatures(xai.feature_contributions, xai.recommended_action);
  } catch(e) {
    renderMockXAI();
  }

  overlay.classList.add('open');
}

function showMockDetail(t) {
  const overlay = document.getElementById('modal-overlay');
  document.getElementById('modal-alert-id').textContent = `ALERT-${Math.random().toString(36).substr(2,7).toUpperCase()}`;
  document.getElementById('modal-risk-score').textContent = t.score;
  document.getElementById('modal-risk-score').className = scoreClass(t.score);
  document.getElementById('modal-threat-level').textContent = t.level;
  document.getElementById('modal-threat-level').className = `severity-badge sev-${t.level}`;
  document.getElementById('modal-explanation').textContent = `${t.rule}. AI Isolation Forest model flagged this combination as anomalous. Risk Score: ${t.score}/100.`;
  renderMockXAI();
  overlay.classList.add('open');
}

function renderXAIFeatures(features, recommendation) {
  const container = document.getElementById('xai-features');
  if (!container) return;

  let html = '<div class="feature-bars">';
  const labels = {
    transaction_amount: 'Transaction Amount',
    failed_logins: 'Failed Login Count',
    geo_mismatch: 'Geographic Mismatch',
    cross_border: 'Cross-Border Transfer',
    bytes_transferred: 'Bytes Transferred',
    velocity_score: 'Transaction Velocity'
  };

  for (const [key, feat] of Object.entries(features)) {
    const isRisk = feat.direction === 'increases_risk';
    html += `
      <div class="feature-row">
        <div class="feature-label">
          <span>${labels[key] || key}</span>
          <span>${feat.contribution.toFixed(1)}% contribution</span>
        </div>
        <div class="feature-bar-track">
          <div class="feature-bar-fill ${isRisk ? 'risk' : ''}" style="width:${feat.contribution}%"></div>
        </div>
      </div>`;
  }
  html += '</div>';

  if (recommendation) {
    html += `<div style="margin-top:1rem;padding:10px 12px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:8px;font-size:0.78rem;color:#fca5a5;">
      <strong style="color:#ef4444">Recommended Action:</strong> ${recommendation}
    </div>`;
  }
  container.innerHTML = html;
}

function renderMockXAI() {
  const features = {
    transaction_amount: { contribution: 34.2, direction: 'increases_risk' },
    failed_logins:      { contribution: 28.1, direction: 'increases_risk' },
    geo_mismatch:       { contribution: 18.5, direction: 'increases_risk' },
    cross_border:       { contribution: 12.3, direction: 'increases_risk' },
    bytes_transferred:  { contribution: 4.9,  direction: 'neutral' },
    velocity_score:     { contribution: 2.0,  direction: 'neutral' },
  };
  renderXAIFeatures(features, 'Freeze account and trigger manual review');
}

// ── Charts ────────────────────────────────────────────────────────────────────
function initCharts() {
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#4a6080', font: { size: 10 } } },
      y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#4a6080', font: { size: 10 } } }
    }
  };

  // Events over time chart
  const evCtx = document.getElementById('events-chart');
  if (evCtx) {
    const labels = Array.from({length:12}, (_,i) => `${i*5}m`);
    eventsChart = new Chart(evCtx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Threats',
          data: Array.from({length:12}, () => Math.floor(Math.random()*30+5)),
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239,68,68,0.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          pointBackgroundColor: '#ef4444',
        },{
          label: 'Events',
          data: Array.from({length:12}, () => Math.floor(Math.random()*80+40)),
          borderColor: '#00d4aa',
          backgroundColor: 'rgba(0,212,170,0.06)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          pointBackgroundColor: '#00d4aa',
        }]
      },
      options: {
        ...chartDefaults,
        plugins: {
          legend: { display: true, labels: { color: '#8da8c0', font: { size: 10 } } }
        }
      }
    });
  }

  // Risk distribution doughnut
  const rdCtx = document.getElementById('risk-dist-chart');
  if (rdCtx) {
    riskDistChart = new Chart(rdCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical','High','Medium','Low'],
        datasets: [{
          data: [4, 8, 18, 20],
          backgroundColor: ['#ef4444','#f59e0b','#3b82f6','#22c55e'],
          borderColor: 'transparent',
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            display: true,
            position: 'right',
            labels: { color: '#8da8c0', font: { size: 10 }, boxWidth: 10 }
          }
        }
      }
    });
  }

  // Telemetry type bar chart
  const ttCtx = document.getElementById('tele-type-chart');
  if (ttCtx) {
    const teleLabels = ['Failed Login','Exfiltration','Lateral Mvmt','Privilege Esc','Port Scan','Malware'];
    const teleData   = [42, 18, 12, 9, 7, 5];
    teleTypeChart = new Chart(ttCtx, {
      type: 'bar',
      data: {
        labels: teleLabels,
        datasets: [{
          label: 'Events',
          data: teleData,
          backgroundColor: [
            'rgba(59,130,246,0.7)',
            'rgba(239,68,68,0.7)',
            'rgba(245,158,11,0.7)',
            'rgba(139,92,246,0.7)',
            'rgba(0,212,170,0.7)',
            'rgba(236,72,153,0.7)',
          ],
          borderRadius: 4,
          borderSkipped: false,
        }]
      },
      options: {
        ...chartDefaults,
        indexAxis: 'y',
        plugins: { legend: { display: false } }
      }
    });
  }
}

function updateRiskDistChart(breakdown) {
  if (!riskDistChart) return;
  riskDistChart.data.datasets[0].data = [
    breakdown.CRITICAL, breakdown.HIGH, breakdown.MEDIUM, breakdown.LOW
  ];
  riskDistChart.update();
}

// ── Quantum Panel ─────────────────────────────────────────────────────────────
async function loadQuantumRisks() {
  try {
    const res = await fetch(`${API_BASE}/api/quantum/risks?count=8`);
    const data = await res.json();
    renderQuantumPanel(data);
  } catch(e) {
    renderMockQuantum();
  }
}

function renderQuantumPanel(data) {
  const grid = document.getElementById('quantum-grid');
  const summary = data.summary;
  if (!grid) return;

  // Update meters
  setMeter('meter-hndl', summary.hndl_suspected_count, summary.total_events);
  setMeter('meter-vuln', summary.quantum_vulnerable_cipher_count, summary.total_events);
  setMeter('meter-qrisk', summary.average_quantum_risk, 100);

  document.getElementById('q-posture').textContent = summary.overall_quantum_posture;
  document.getElementById('q-posture').style.color = severityColor(summary.overall_quantum_posture);

  grid.innerHTML = '';
  data.events.slice(0, 6).forEach(e => {
    const div = document.createElement('div');
    div.className = 'quantum-item';
    div.innerHTML = `
      <div class="cipher">${e.cipher_suite}</div>
      ${e.is_hndl_suspected
        ? '<span class="hndl-badge">⚠ HNDL SUSPECTED</span>'
        : e.is_quantum_vulnerable_cipher
          ? '<span class="hndl-badge">VULNERABLE</span>'
          : '<span class="safe-badge">✓ PQ SAFE</span>'
      }
      <div class="q-detail">
        Vol: ${e.encrypted_data_volume_gb.toFixed(1)} GB ·
        Risk: ${e.quantum_risk_score}/100 ·
        ${e.tls_version}
      </div>
    `;
    grid.appendChild(div);
  });
}

function renderMockQuantum() {
  const mockEvents = [
    { cipher:'RSA-2048', hndl:true, vol:'87.3 GB', risk:82, tls:'TLS 1.2', vulnerable:true },
    { cipher:'ECDH-P256', hndl:false, vol:'44.1 GB', risk:58, tls:'TLS 1.3', vulnerable:true },
    { cipher:'CRYSTALS-Kyber', hndl:false, vol:'12.0 GB', risk:15, tls:'TLS 1.3', vulnerable:false },
    { cipher:'RSA-4096', hndl:true, vol:'103.7 GB', risk:91, tls:'TLS 1.2', vulnerable:true },
    { cipher:'FALCON', hndl:false, vol:'8.5 GB', risk:10, tls:'TLS 1.3', vulnerable:false },
    { cipher:'DH-2048', hndl:false, vol:'29.2 GB', risk:45, tls:'TLS 1.2', vulnerable:true },
  ];

  setMeter('meter-hndl', 2, 8);
  setMeter('meter-vuln', 4, 8);
  setMeter('meter-qrisk', 67, 100);
  document.getElementById('q-posture').textContent = 'HIGH';
  document.getElementById('q-posture').style.color = '#f59e0b';

  const grid = document.getElementById('quantum-grid');
  grid.innerHTML = '';
  mockEvents.forEach(e => {
    const div = document.createElement('div');
    div.className = 'quantum-item';
    div.innerHTML = `
      <div class="cipher">${e.cipher}</div>
      ${e.hndl ? '<span class="hndl-badge">⚠ HNDL SUSPECTED</span>'
                : e.vulnerable ? '<span class="hndl-badge">VULNERABLE</span>'
                : '<span class="safe-badge">✓ PQ SAFE</span>'}
      <div class="q-detail">Vol: ${e.vol} · Risk: ${e.risk}/100 · ${e.tls}</div>
    `;
    grid.appendChild(div);
  });
}

function setMeter(id, value, max) {
  const pct = Math.min(100, (value / max) * 100);
  const fill = document.getElementById(id);
  if (!fill) return;
  fill.style.width = `${pct}%`;
  if      (pct >= 75) fill.className = 'meter-fill critical';
  else if (pct >= 50) fill.className = 'meter-fill high';
  else if (pct >= 25) fill.className = 'meter-fill medium';
  else                fill.className = 'meter-fill low';
}

// ── Real-time updates ─────────────────────────────────────────────────────────
let autoRefreshInterval = null;

function startAutoRefresh(intervalMs = 15000) {
  if (autoRefreshInterval) clearInterval(autoRefreshInterval);
  autoRefreshInterval = setInterval(() => {
    loadThreats();
    loadDashboardKPIs();
    updateEventChart();
  }, intervalMs);
}

function updateEventChart() {
  if (!eventsChart) return;
  eventsChart.data.datasets.forEach(ds => {
    ds.data.shift();
    ds.data.push(Math.floor(Math.random() * (ds.label === 'Threats' ? 35 : 90) + 5));
  });
  eventsChart.update('none');
}

// ── Modal Controls ────────────────────────────────────────────────────────────
function initModal() {
  const overlay = document.getElementById('modal-overlay');
  const closeBtn = document.getElementById('modal-close');

  closeBtn?.addEventListener('click', () => overlay.classList.remove('open'));
  overlay?.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.classList.remove('open');
  });
}

// ── Nav Tab Switching ─────────────────────────────────────────────────────────
function initNavTabs() {
  $$('.nav-btn[data-section]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.nav-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      $$('.page-section').forEach(s => s.style.display = 'none');
      const target = document.getElementById(`section-${btn.dataset.section}`);
      if (target) target.style.display = 'block';
    });
  });
}

// ── Refresh Buttons ───────────────────────────────────────────────────────────
function initRefreshButtons() {
  document.getElementById('refresh-threats')?.addEventListener('click', loadThreats);
  document.getElementById('refresh-quantum')?.addEventListener('click', loadQuantumRisks);
  document.getElementById('refresh-kpis')?.addEventListener('click', loadDashboardKPIs);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  initModal();
  initNavTabs();
  initRefreshButtons();

  // Load all data
  loadDashboardKPIs();
  loadThreats();
  loadQuantumRisks();

  // Start live updates
  startAutoRefresh(15000);

  // Update timestamp
  const tsEl = document.getElementById('last-updated');
  if (tsEl) {
    setInterval(() => {
      tsEl.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }, 1000);
  }
});
