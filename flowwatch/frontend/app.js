const POLL_MS = 2000;
let selectedFlowId = null;
let flowsCache = [];

function fmtBytes(n) {
  if (n > 1e6) return (n / 1e6).toFixed(2) + " MB";
  if (n > 1e3) return (n / 1e3).toFixed(1) + " KB";
  return n + " B";
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

async function refreshStatus() {
  try {
    const s = await fetchJSON("/api/status");
    const dot = document.getElementById("collectorDot");
    const label = document.getElementById("collectorLabel");
    const alive = s.collector.packets_received > 0;
    dot.className = "dot " + (alive ? "live" : "");
    label.textContent = alive
      ? `receiving on UDP :${s.collector.bind.split(":")[1]} - ${s.collector.flows_received} flows total`
      : `listening on UDP :${s.netflow_port} - waiting for an exporter`;

    const summary = document.getElementById("summaryRow");
    summary.innerHTML = `
      ${card("Flows stored", s.total_flows_stored)}
      ${card("Packets received", s.collector.packets_received)}
      ${card("Malformed packets", s.collector.malformed_packets)}
      ${card("Queue depth", s.collector.queue_depth)}
    `;
  } catch (e) { console.error(e); }
}

function card(label, value) {
  return `<div class="summary-card"><div class="label">${label}</div><div class="value">${value}</div></div>`;
}

async function refreshFlows() {
  const tier = document.getElementById("tierFilter").value;
  const url = "/api/flows?limit=100" + (tier ? `&tier=${tier}` : "");
  try {
    const flows = await fetchJSON(url);
    flowsCache = flows;
    const body = document.getElementById("flowsBody");
    body.innerHTML = flows.map(f => `
      <tr data-id="${f.id}">
        <td>${fmtTime(f.observed_at)}</td>
        <td>${f.src_ip}</td>
        <td>${f.dst_ip}</td>
        <td>${f.dst_port}</td>
        <td>${f.protocol}</td>
        <td>${fmtBytes(f.bytes)}</td>
        <td>${f.risk_score}</td>
        <td><span class="tier-badge tier-${f.risk_tier}">${f.risk_tier}</span></td>
      </tr>
    `).join("");
    body.querySelectorAll("tr").forEach(row => {
      row.addEventListener("click", () => showDetail(parseInt(row.dataset.id)));
    });
    if (selectedFlowId) showDetail(selectedFlowId, true);
  } catch (e) { console.error(e); }
}

function showDetail(id, silent) {
  selectedFlowId = id;
  const f = flowsCache.find(x => x.id === id);
  const el = document.getElementById("detailContent");
  if (!f) { if (!silent) el.innerHTML = `<div class="empty-state">Flow no longer in buffer</div>`; return; }

  const violations = JSON.parse(f.violations || "[]");
  const reasons = JSON.parse(f.risk_reasons || "[]");

  el.innerHTML = `
    <h3>Flow</h3>
    <div class="kv"><span>${f.src_ip}:${f.src_port}</span><span>→</span><span>${f.dst_ip}:${f.dst_port}</span></div>
    <div class="kv"><span>Protocol</span><span>${f.protocol}</span></div>
    <div class="kv"><span>Packets / Bytes</span><span>${f.packets} / ${fmtBytes(f.bytes)}</span></div>
    <div class="kv"><span>Duration</span><span>${f.duration_ms} ms</span></div>

    <h3>Engine verdicts</h3>
    <div class="kv"><span>Traffic-only</span><span>${f.traffic_score} ${f.traffic_anomaly ? "⚠️" : "✓"}</span></div>
    <div class="kv"><span>Context-aware</span><span>${f.context_score} ${f.context_anomaly ? "⚠️" : "✓"}</span></div>
    <div class="kv"><span>Risk-informed</span><span>${f.risk_score} - <span class="tier-badge tier-${f.risk_tier}">${f.risk_tier}</span></span></div>

    <h3>Recommended action</h3>
    <div>${f.risk_action}</div>

    ${violations.length ? `<h3>Policy violations</h3><ul>${violations.map(v => `<li>${v}</li>`).join("")}</ul>` : ""}
    <h3>Reasoning</h3>
    <ul>${reasons.map(r => `<li>${r}</li>`).join("")}</ul>
  `;
}

async function refreshMetrics() {
  try {
    const m = await fetchJSON("/api/metrics");
    const es = document.getElementById("engineStats");
    const engines = ["traffic", "context", "risk"];
    const maxScored = Math.max(1, ...engines.map(e => m.engine_stats[e]?.flows_scored || 0));
    es.innerHTML = engines.map(e => {
      const stat = m.engine_stats[e] || { flows_scored: 0, anomalies_flagged: 0 };
      const pct = stat.flows_scored ? (stat.anomalies_flagged / stat.flows_scored * 100).toFixed(1) : "0.0";
      return `<div class="engine-row">
        <span>${e}</span>
        <div class="bar-bg"><div class="bar-fill" style="width:${(stat.flows_scored / maxScored * 100)}%"></div></div>
        <span>${stat.anomalies_flagged}/${stat.flows_scored} flagged (${pct}%)</span>
      </div>`;
    }).join("");

    const tb = document.getElementById("tierBars");
    const tiers = ["Critical", "High", "Medium", "Low"];
    const counts = m.tier_counts_last_hour || {};
    const maxCount = Math.max(1, ...tiers.map(t => counts[t] || 0));
    tb.innerHTML = tiers.map(t => `
      <div class="tbar-row">
        <span class="tbar-label">${t}</span>
        <div class="tbar-bg"><div class="tbar-fill ${t}" style="width:${((counts[t] || 0) / maxCount * 100)}%"></div></div>
        <span>${counts[t] || 0}</span>
      </div>
    `).join("");
  } catch (e) { console.error(e); }
}

function tick() {
  refreshStatus();
  refreshFlows();
  refreshMetrics();
}

document.getElementById("tierFilter").addEventListener("change", refreshFlows);
tick();
setInterval(tick, POLL_MS);
