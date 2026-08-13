const POLL_MS = 3000;

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}
function card(label, value) {
  return `<div class="summary-card"><div class="label">${label}</div><div class="value">${value}</div></div>`;
}

async function refreshHealth() {
  try {
    const h = await fetchJSON("/api/health");
    const chips = document.getElementById("sourceChips");
    const sources = [
      { name: "FlowWatch", status: h.flowwatch },
      { name: "ISE", status: h.ise },
      { name: "Secure Analytics", status: h.secure_analytics },
    ];
    chips.innerHTML = sources.map(s => `
      <div class="source-chip">
        <span class="dot ${s.status.connected ? 'live' : 'dead'}"></span>
        ${s.name}${s.status.mock ? " (mock)" : ""}
      </div>
    `).join("");

    document.getElementById("summaryRow").innerHTML = `
      ${card("Unified incidents", h.incident_count)}
      ${card("Poll interval", h.poll_interval_seconds + "s")}
      ${card("Last poll", h.last_poll ? new Date(h.last_poll * 1000).toLocaleTimeString() : "—")}
    `;
  } catch (e) { console.error(e); }
}

async function refreshIncidents() {
  try {
    const incidents = await fetchJSON("/api/incidents");
    const wrap = document.getElementById("incidentsWrap");
    if (!incidents.length) {
      wrap.innerHTML = `<div class="empty-state">No active incidents. Waiting for alarms from connected sources…</div>`;
      return;
    }
    wrap.innerHTML = incidents.map(inc => `
      <div class="incident-row">
        <div class="incident-top">
          <div>
            <span class="incident-ip">${inc.ip}</span>
            <span class="tier-badge tier-${inc.tier}" style="margin-left:10px">${inc.tier} · ${inc.score}</span>
            <div class="incident-identity">
              ${inc.identity.username ? `${inc.identity.username} · ` : ""}${inc.identity.device_type || "Unknown device"}
              ${inc.identity.posture_status && inc.identity.posture_status !== "Unknown" ? ` · posture: ${inc.identity.posture_status}` : ""}
              ${inc.identity.security_group && inc.identity.security_group !== "Unknown" ? ` · SGT: ${inc.identity.security_group}` : ""}
            </div>
          </div>
          <div class="incident-badges">
            ${inc.sources.map(s => `<span class="source-badge">${s}</span>`).join("")}
            ${inc.corroborated ? `<span class="corroborated-badge">Corroborated</span>` : ""}
          </div>
        </div>
        <div class="evidence-list">
          ${inc.evidence.map(e => `
            <div class="evidence-item"><span class="ev-source">${e.source}</span><span>${e.summary}</span></div>
          `).join("")}
        </div>
      </div>
    `).join("");
  } catch (e) { console.error(e); }
}

function tick() { refreshHealth(); refreshIncidents(); }
tick();
setInterval(tick, POLL_MS);
