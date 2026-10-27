// TrustEdge-CC Dashboard Reactive JavaScript Controller

let ws = null;
let telemetryChart = null;
let anomalyChart = null;
let latestState = null;

// Telemetry buffer for charts (last 30 ticks)
const maxChartPoints = 30;
const chartData = {
  labels: [],
  temperature: [],
  humidity: [],
  anomalyScore: []
};

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  connectWebSocket();
});

// Setup Chart.js
function initCharts() {
  const ctxTel = document.getElementById("telemetryChart").getContext("2d");
  telemetryChart = new Chart(ctxTel, {
    type: "line",
    data: {
      labels: chartData.labels,
      datasets: [
        {
          label: "Temperature (°C)",
          data: chartData.temperature,
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56, 189, 248, 0.1)",
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2,
          fill: true
        },
        {
          label: "Humidity (%)",
          data: chartData.humidity,
          borderColor: "#34d399",
          backgroundColor: "rgba(52, 211, 153, 0.05)",
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2,
          fill: true
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#64748b", font: { size: 10 } } },
        y: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#64748b", font: { size: 10 } } }
      }
    }
  });

  const ctxAnom = document.getElementById("anomalyChart").getContext("2d");
  anomalyChart = new Chart(ctxAnom, {
    type: "line",
    data: {
      labels: chartData.labels,
      datasets: [
        {
          label: "Anomaly Score",
          data: chartData.anomalyScore,
          borderColor: "#f59e0b",
          backgroundColor: "rgba(245, 158, 11, 0.1)",
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          fill: true
        },
        {
          label: "Threshold (0.58)",
          data: [],
          borderColor: "#f43f5e",
          borderDash: [5, 5],
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#64748b", font: { size: 10 } } },
        y: { min: 0.2, max: 1.0, grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { color: "#64748b", font: { size: 10 } } }
      }
    }
  });
}

// WebSocket Connection
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    document.getElementById("orchestrator-status-text").innerText = "ZERO-TRUST ACTIVE";
    console.log("Connected to TrustEdge-CC Orchestrator via WebSocket");
  };

  ws.onmessage = (event) => {
    try {
      const state = JSON.parse(event.data);
      latestState = state;
      updateDashboard(state);
    } catch (e) {
      console.error("Error parsing WS state:", e);
    }
  };

  ws.onclose = () => {
    document.getElementById("orchestrator-status-text").innerText = "RECONNECTING...";
    setTimeout(connectWebSocket, 2000);
  };

  ws.onerror = (err) => {
    console.error("WS error:", err);
    ws.close();
  };
}

// Update UI Components
function updateDashboard(state) {
  // 1. Top Ribbon KPIs
  document.getElementById("kpi-current-round").innerText = state.current_round;
  document.getElementById("kpi-fl-state").innerText = state.is_round_active ? "Round In Progress" : "Aggregated / Idle";
  
  const gm = state.global_model || {};
  document.getElementById("kpi-model-trees").innerText = gm.total_trees || 0;
  const kb = ((gm.memory_bytes || 0) / 1024).toFixed(1);
  document.getElementById("kpi-model-memory").innerText = `RAM: ${kb} KB (< 160 KB constraint)`;

  document.getElementById("kpi-active-nodes").innerText = `${state.active_nodes_count} / 3`;
  document.getElementById("kpi-attacks-prevented").innerText = state.attacks_prevented || 0;
  document.getElementById("kpi-attacks-sim").innerText = `${state.attacks_simulated || 0} Attack Attempts Recorded`;

  // 2. Render Node Topology
  renderNodes(state.nodes);

  // 3. Update Chart Buffers with latest node telemetry
  updateChartData(state.nodes);

  // 4. Update Target Node Dropdown in Attack Simulator
  updateAttackDropdown(state.nodes);

  // 5. Update Audit Logs Console
  renderAuditLogs(state.audit_logs);
}

function renderNodes(nodes) {
  const container = document.getElementById("nodes-list");
  if (!nodes || Object.keys(nodes).length === 0) {
    container.innerHTML = `
      <div class="node-card empty-state">
        <p>No active edge nodes registered yet.<br>Launch the QEMU node or Pico 2 boards to join the topology.</p>
      </div>`;
    return;
  }

  let html = "";
  for (const [nodeId, n] of Object.entries(nodes)) {
    const isOnline = n.is_online;
    const tel = n.latest_telemetry || {};
    const temp = tel.temperature !== undefined ? `${tel.temperature}°C` : "--";
    const hum = tel.humidity !== undefined ? `${tel.humidity}%` : "--";
    const score = tel.anomaly_score !== undefined ? tel.anomaly_score.toFixed(3) : "--";
    const isAnomaly = tel.is_anomaly;
    const teeLatency = tel.tee_latency_ms !== undefined ? `${tel.tee_latency_ms} ms` : "--";

    const isOptee = n.tee_type.includes("OP-TEE");
    const badgeClass = isOptee ? "optee" : "tfm";
    const badgeLabel = isOptee ? "ARM Cortex-A • OP-TEE" : "RP2350 M33 • TF-M";
    const cardClass = `node-card ${isOnline ? "active" : ""} ${isAnomaly ? "anomaly-active" : ""}`;

    html += `
      <div class="${cardClass}">
        <div class="node-header">
          <div class="node-title-group">
            <span class="node-id">${n.node_id}</span>
            <span class="tee-badge ${badgeClass}">${badgeLabel}</span>
          </div>
          <span class="node-status-badge ${isOnline ? "status-online" : "status-offline"}">
            ${isOnline ? "● TEE ATTESTED" : "OFFLINE"}
          </span>
        </div>

        <div class="node-metrics-grid">
          <div class="metric-item">
            <span class="metric-name">DHT11 Temp</span>
            <span class="metric-val">${temp}</span>
          </div>
          <div class="metric-item">
            <span class="metric-name">DHT11 Hum</span>
            <span class="metric-val">${hum}</span>
          </div>
          <div class="metric-item">
            <span class="metric-name">Anomaly Score</span>
            <span class="metric-val" style="color: ${isAnomaly ? '#f43f5e' : '#34d399'}">${score}</span>
          </div>
          <div class="metric-item">
            <span class="metric-name">TEE Latency</span>
            <span class="metric-val">${teeLatency}</span>
          </div>
          <div class="metric-item">
            <span class="metric-name">Updates Accepted</span>
            <span class="metric-val">${n.total_updates_accepted}</span>
          </div>
          <div class="metric-item">
            <span class="metric-name">Updates Rejected</span>
            <span class="metric-val" style="color: ${n.total_updates_rejected > 0 ? '#f43f5e' : '#64748b'}">${n.total_updates_rejected}</span>
          </div>
        </div>

        <div class="node-actions">
          <button class="btn btn-secondary" onclick="toggleSensorAnomaly('${n.node_id}')">
            ⚡ Toggle Sensor Anomaly
          </button>
          <button class="btn btn-danger" onclick="triggerNodePoisoning('${n.node_id}')">
            ⚠️ Poison Update
          </button>
        </div>
      </div>
    `;
  }
  container.innerHTML = html;
}

function updateChartData(nodes) {
  if (!nodes) return;
  // Pick active node with newest telemetry
  let activeTel = null;
  for (const n of Object.values(nodes)) {
    if (n.latest_telemetry) {
      activeTel = n.latest_telemetry;
      break;
    }
  }

  if (activeTel) {
    const timeLabel = new Date(activeTel.timestamp * 1000).toLocaleTimeString([], { hour12: false });
    
    // Avoid duplicate timestamp additions
    if (chartData.labels.length === 0 || chartData.labels[chartData.labels.length - 1] !== timeLabel) {
      chartData.labels.push(timeLabel);
      chartData.temperature.push(activeTel.temperature);
      chartData.humidity.push(activeTel.humidity);
      chartData.anomalyScore.push(activeTel.anomaly_score);

      if (chartData.labels.length > maxChartPoints) {
        chartData.labels.shift();
        chartData.temperature.shift();
        chartData.humidity.shift();
        chartData.anomalyScore.shift();
      }

      // Update telemetry chart
      telemetryChart.update("none");

      // Update anomaly chart with threshold line
      anomalyChart.data.datasets[1].data = chartData.labels.map(() => 0.58);
      anomalyChart.update("none");
    }
  }
}

function updateAttackDropdown(nodes) {
  const sel = document.getElementById("attack-target-node");
  if (!nodes || Object.keys(nodes).length === 0) {
    sel.innerHTML = '<option value="">No nodes available</option>';
    return;
  }
  const currentVal = sel.value;
  let opts = '<option value="">Select target edge node...</option>';
  for (const [nid, n] of Object.entries(nodes)) {
    opts += `<option value="${nid}" ${currentVal === nid ? 'selected' : ''}>${nid} (${n.tee_type})</option>`;
  }
  sel.innerHTML = opts;
}

function renderAuditLogs(logs) {
  if (!logs) return;
  const terminal = document.getElementById("audit-log-terminal");
  let html = "";
  for (const l of logs) {
    const lvlClass = (l.level || "info").toLowerCase();
    html += `<div class="log-line ${lvlClass}">[${l.time_str}] [${l.event_type}] ${l.message}</div>`;
  }
  terminal.innerHTML = html;
}

// Actions
async function triggerFlRound() {
  const btn = document.getElementById("btn-start-fl");
  btn.disabled = true;
  btn.innerText = "Initiating...";
  try {
    const resp = await fetch("/api/fl/start-round", { method: "POST" });
    const data = await resp.json();
    if (!data.success) {
      alert("FL Round could not be started: " + (data.error || "Unknown"));
    }
  } catch (e) {
    alert("Request failed: " + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polygon points="5 3 19 12 5 21 5 3"/>
      </svg> Trigger FL Round`;
  }
}

async function simulatePoisoningAttack() {
  const sel = document.getElementById("attack-target-node");
  const nodeId = sel.value;
  if (!nodeId) {
    alert("Please select a target edge node first.");
    return;
  }
  triggerNodePoisoning(nodeId);
}

async function triggerNodePoisoning(nodeId) {
  const banner = document.getElementById("attack-feedback-banner");
  try {
    const resp = await fetch("/api/attack/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ node_id: nodeId, attack_type: "model_poisoning" })
    });
    const data = await resp.json();
    banner.classList.remove("hidden", "danger", "success");
    if (data.simulation_result === "BLOCKED") {
      banner.classList.add("success");
      banner.innerHTML = `
        <strong>ATTACK NEUTRALIZED:</strong> Zero-Trust Orchestrator rejected forged update from <code>${nodeId}</code>.<br>
        <strong>Reason:</strong> ECDSA TEE Hardware Signature Mismatch. The Global Model was preserved intact.
      `;
    }
  } catch (e) {
    banner.classList.remove("hidden");
    banner.classList.add("danger");
    banner.innerText = "Error launching simulation: " + e.message;
  }
}

async function toggleSensorAnomaly(nodeId) {
  try {
    await fetch("/api/sensor/toggle-anomaly", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ node_id: nodeId, enabled: true })
    });
  } catch (e) {
    console.error(e);
  }
}

function clearAuditLog() {
  document.getElementById("audit-log-terminal").innerHTML = "";
}
