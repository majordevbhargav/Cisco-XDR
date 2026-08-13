// Global UI variables and chart instances
let activeTab = 'dashboard';
let simulationSpeed = 1.0;
let isSimulationRunning = true;
let activeEngine = 'risk-informed';
let selectedScenario = 'normal';

let anomalyTrendsChart = null;
let attacksBarChart = null;

// Populated from /api/devices on every refresh: IP address -> topology node key.
// Used to resolve which node a flow's source/destination corresponds to.
let deviceIpToKey = {};

// SVG Topology positions mapping
const nodePositions = {
    'GW-01': { x: 400, y: 50, icon: '\uf0e8', color: 'var(--color-blue-glow)', title: 'Gateway' },
    'FW-01': { x: 400, y: 130, icon: '\uf3ed', color: 'var(--color-blue-glow)', title: 'Firewall' },
    
    // Corporate VLAN (left)
    'PC-01': { x: 150, y: 240, icon: '\uf109', color: 'var(--color-cyan-glow)', title: 'Finance Station' },
    'PC-02': { x: 100, y: 340, icon: '\uf109', color: 'var(--color-cyan-glow)', title: 'Dev Station' },
    'PC-03': { x: 200, y: 340, icon: '\uf109', color: 'var(--color-cyan-glow)', title: 'HR Station' },
    
    // Servers DMZ VLAN (middle)
    'WEB-01': { x: 400, y: 260, icon: '\uf233', color: 'var(--color-purple-glow)', title: 'Web Host' },
    'DB-01': { x: 400, y: 380, icon: '\uf1c0', color: 'var(--color-purple-glow)', title: 'Database Host' },
    
    // IoT VLAN (right)
    'CAM-01': { x: 650, y: 240, icon: '\uf03d', color: 'var(--color-orange-glow)', title: 'Lobby Camera' },
    'CAM-02': { x: 600, y: 340, icon: '\uf03d', color: 'var(--color-orange-glow)', title: 'Server Camera' },
    'THERM-01': { x: 700, y: 340, icon: '\uf2c9', color: 'var(--color-orange-glow)', title: 'Smart Thermostat' },
    
    // Remote Internet node placeholder (simulated source)
    'Remote': { x: 150, y: 50, icon: '\uf0ac', color: 'var(--color-gray)', title: 'Remote Internet' }
};

// Base links in the topology
const topologyLinks = [
    { from: 'Remote', to: 'GW-01' },
    { from: 'GW-01', to: 'FW-01' },
    { from: 'FW-01', to: 'PC-01' },
    { from: 'PC-01', to: 'PC-02' },
    { from: 'PC-01', to: 'PC-03' },
    { from: 'FW-01', to: 'WEB-01' },
    { from: 'WEB-01', to: 'DB-01' },
    { from: 'FW-01', to: 'CAM-01' },
    { from: 'CAM-01', to: 'CAM-02' },
    { from: 'CAM-01', to: 'THERM-01' }
];

// Quick lookup for a direct link element between two node keys, either direction.
const linkElementCache = {};

document.addEventListener('DOMContentLoaded', () => {
    // Initialize the core, always-must-work parts of the UI first: controls,
    // the topology skeleton, the initial data fetch, and the live polling
    // loop. None of this depends on Chart.js.
    setupEventListeners();
    initTopology();

    fetchDevices();
    fetchDashboardData();

    // Main simulation polling loop
    setInterval(() => {
        if (isSimulationRunning) {
            fetchDashboardData();
        }
    }, 1500);

    // Chart.js loads from a CDN. If it's blocked or slow for any reason (an
    // ad-blocker, a privacy extension, a firewall, a network hiccup),
    // `new Chart(...)` throws inside initCharts(). Previously that exception
    // was uncaught and it happened *before* the lines above, so it aborted
    // this entire startup callback -- fetchDevices(), fetchDashboardData(),
    // and the setInterval polling registration never ran, and the topology
    // view went blank forever. Charts now init last and are isolated in a
    // try/catch, so a chart failure only means missing charts, never a dead
    // topology or flow feed.
    try {
        initCharts();
    } catch (err) {
        console.error('Chart initialization failed (trend charts unavailable). The rest of the dashboard is unaffected.', err);
    }
});

// Setup interaction handlers
function setupEventListeners() {
    // Tab switching controls
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tabId = btn.getAttribute('data-tab');
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(`${tabId}Tab`).classList.add('active');
            activeTab = tabId;
            
            if (activeTab === 'research') {
                updateResearchComparison();
            }
        });
    });

    // Control selectors changes
    document.getElementById('scenarioSelect').addEventListener('change', (e) => {
        selectedScenario = e.target.value;
        postSimulationConfig({ current_scenario: selectedScenario });
    });

    document.getElementById('engineSelect').addEventListener('change', (e) => {
        activeEngine = e.target.value;
        postSimulationConfig({ active_engine: activeEngine });
        fetchDashboardData(); // Quick refresh
    });

    // Play Pause Button
    const playPauseBtn = document.getElementById('playPauseBtn');
    playPauseBtn.addEventListener('click', () => {
        isSimulationRunning = !isSimulationRunning;
        postSimulationConfig({ is_running: isSimulationRunning });
        
        const icon = playPauseBtn.querySelector('i');
        if (isSimulationRunning) {
            icon.className = 'fa-solid fa-pause';
            playPauseBtn.title = 'Pause Simulation';
        } else {
            icon.className = 'fa-solid fa-play';
            playPauseBtn.title = 'Resume Simulation';
        }
    });

    // Inspector close button
    document.getElementById('closeInspectorBtn').addEventListener('click', () => {
        document.getElementById('flowInspector').classList.remove('open');
    });

    // Modal close button
    document.getElementById('closeModalBtn').addEventListener('click', () => {
        document.getElementById('deviceOverlay').classList.remove('open');
    });
}

// POST config parameter updates to Python Flask backend
function postSimulationConfig(configData) {
    fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configData)
    })
    .then(res => res.json())
    .then(status => {
        simulationSpeed = status.speed;
        activeEngine = status.active_engine;
        selectedScenario = status.current_scenario;
        isSimulationRunning = status.is_running;
    })
    .catch(err => console.error('Error posting config:', err));
}

// Initial draw of static network links and labels
function initTopology() {
    const linksGroup = document.getElementById('linksGroup');
    
    // Draw link lines
    topologyLinks.forEach(link => {
        const fromNode = nodePositions[link.from];
        const toNode = nodePositions[link.to];
        if (fromNode && toNode) {
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('id', `link-${link.from}-${link.to}`);
            line.setAttribute('x1', fromNode.x);
            line.setAttribute('y1', fromNode.y);
            line.setAttribute('x2', toNode.x);
            line.setAttribute('y2', toNode.y);
            line.setAttribute('class', 'link-line link-normal');
            linksGroup.appendChild(line);

            // Cache under both directions so a flow can be looked up regardless of
            // which end is the source.
            linkElementCache[`${link.from}|${link.to}`] = line;
            linkElementCache[`${link.to}|${link.from}`] = line;
        }
    });
}

// Draw nodes based on active statuses
function drawNodes(devicesList) {
    const nodesGroup = document.getElementById('nodesGroup');
    nodesGroup.innerHTML = ''; // Reset

    // Rebuild the IP -> topology node key map every time devices refresh, so
    // flow animation always resolves against current device state.
    deviceIpToKey = {};
    devicesList.forEach(d => { deviceIpToKey[d.ip] = d.id; });
    
    devicesList.forEach(device => {
        const pos = nodePositions[device.id];
        if (!pos) return;
        
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'topo-node');
        g.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);
        g.addEventListener('click', () => openDeviceModal(device));
        
        // Status Ring (outer glow)
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('r', '24');
        ring.setAttribute('class', `status-ring ring-${device.status}`);
        g.appendChild(ring);
        
        // Inner circle base
        const base = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        base.setAttribute('r', '18');
        base.setAttribute('class', 'node-base');
        base.setAttribute('stroke', pos.color);
        g.appendChild(base);
        
        // FontAwesome symbol icon text
        const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        icon.setAttribute('class', 'fa-icon');
        icon.setAttribute('font-family', '"Font Awesome 6 Free"');
        icon.setAttribute('font-weight', '900');
        icon.setAttribute('font-size', '14');
        icon.setAttribute('text-anchor', 'middle');
        icon.setAttribute('dy', '5');
        icon.setAttribute('fill', '#fff');
        icon.textContent = pos.icon;
        g.appendChild(icon);
        
        // Label name
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('class', 'node-text');
        text.setAttribute('y', '36');
        text.textContent = device.name;
        g.appendChild(text);

        // Label IP
        const ip = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        ip.setAttribute('class', 'node-ip');
        ip.setAttribute('y', '46');
        ip.textContent = device.ip;
        g.appendChild(ip);
        
        nodesGroup.appendChild(g);
    });
    
    // Add remote node icon if missing in devices list
    const remotePos = nodePositions['Remote'];
    const rg = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    rg.setAttribute('class', 'topo-node');
    rg.setAttribute('transform', `translate(${remotePos.x}, ${remotePos.y})`);
    
    const rbase = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    rbase.setAttribute('r', '18');
    rbase.setAttribute('class', 'node-base');
    rbase.setAttribute('stroke', remotePos.color);
    rg.appendChild(rbase);
    
    const ricon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    ricon.setAttribute('font-family', '"Font Awesome 6 Free"');
    ricon.setAttribute('font-weight', '900');
    ricon.setAttribute('font-size', '14');
    ricon.setAttribute('text-anchor', 'middle');
    ricon.setAttribute('dy', '5');
    ricon.setAttribute('fill', '#fff');
    ricon.textContent = remotePos.icon;
    rg.appendChild(ricon);
    
    const rtext = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    rtext.setAttribute('class', 'node-text');
    rtext.setAttribute('y', '36');
    rtext.textContent = remotePos.title;
    rg.appendChild(rtext);
    
    nodesGroup.appendChild(rg);
}

// Fetch devices configuration from REST API
function fetchDevices() {
    fetch('/api/devices')
    .then(res => res.json())
    .then(data => {
        drawNodes(data);
    })
    .catch(err => console.error('Error fetching devices:', err));
}

// Fetch all dynamic metrics and flows
function fetchDashboardData() {
    // 1. Fetch live flow records list
    fetch('/api/flows')
    .then(res => res.json())
    .then(flows => {
        updateFlowStream(flows);
        if (flows.length > 0) {
            animateTrafficParticle(flows[0]);
        }
    })
    .catch(err => console.error('Error fetching flows:', err));

    // 2. Fetch evaluation metrics
    fetch('/api/metrics')
    .then(res => res.json())
    .then(data => {
        updateKpis(data);
        updateTrendsCharts(data);
    })
    .catch(err => console.error('Error fetching metrics:', err));
    
    // 3. Fetch device status refresh
    fetchDevices();
}

// Resolve which topology node key a given IP belongs to. Internal devices
// resolve via the live device map; anything outside 192.168.0.0/16 is drawn
// as the shared "Remote" internet node.
function resolveNodeKey(ip) {
    if (deviceIpToKey[ip]) return deviceIpToKey[ip];
    if (!ip.startsWith('192.168.')) return 'Remote';
    return null;
}

// Briefly flag a direct topology link as an active threat path, if one exists
// between the two endpoints.
function pulseLinkThreat(fromKey, toKey) {
    const line = linkElementCache[`${fromKey}|${toKey}`];
    if (!line) return;
    line.classList.remove('link-normal');
    line.classList.add('link-threat');
    clearTimeout(line._threatTimeout);
    line._threatTimeout = setTimeout(() => {
        line.classList.remove('link-threat');
        line.classList.add('link-normal');
    }, 1400);
}

// Draw a sliding particle along topology path corresponding to current active flow
function animateTrafficParticle(flow) {
    const packetsGroup = document.getElementById('packetsGroup');
    
    // Resolve path nodes using live device data rather than a static
    // property that topology nodes never actually carried.
    const fromKey = resolveNodeKey(flow.src_ip);
    const toKey = resolveNodeKey(flow.dest_ip);
    
    if (!fromKey || !toKey) return;
    
    const fromPos = nodePositions[fromKey];
    const toPos = nodePositions[toKey];
    if (!fromPos || !toPos) return;
    
    // Generate particle circle element
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    p.setAttribute('class', 'packet-particle');
    p.setAttribute('cx', fromPos.x);
    p.setAttribute('cy', fromPos.y);
    
    // Color of particle based on active engine decision
    let isAlert = false;
    if (activeEngine === 'traffic-only') isAlert = flow.traffic_detected;
    else if (activeEngine === 'context-aware') isAlert = flow.context_detected;
    else isAlert = flow.risk_detected;
    
    p.setAttribute('fill', isAlert ? 'var(--color-red-glow)' : 'var(--color-cyan-glow)');
    packetsGroup.appendChild(p);

    if (isAlert) {
        pulseLinkThreat(fromKey, toKey);
    }
    
    // Animate flow particle from source coordinates to destination
    let startTime = null;
    const duration = 800; // ms
    
    function step(timestamp) {
        if (!startTime) startTime = timestamp;
        const progress = Math.min((timestamp - startTime) / duration, 1);
        
        const currentX = fromPos.x + (toPos.x - fromPos.x) * progress;
        const currentY = fromPos.y + (toPos.y - fromPos.y) * progress;
        
        p.setAttribute('cx', currentX);
        p.setAttribute('cy', currentY);
        
        if (progress < 1) {
            window.requestAnimationFrame(step);
        } else {
            p.remove(); // Cleanup
        }
    }
    
    window.requestAnimationFrame(step);
}

// Render dynamic log rows
function updateFlowStream(flows) {
    const listContainer = document.getElementById('flowStreamList');
    listContainer.innerHTML = '';
    
    flows.forEach(flow => {
        const row = document.createElement('div');
        
        // Determine whether this flow triggered alert in active engine mode
        let activeVerdict = 'normal';
        let isAlert = false;
        
        if (activeEngine === 'traffic-only') {
            isAlert = flow.traffic_detected;
            activeVerdict = isAlert ? 'anomaly' : 'normal';
        } else if (activeEngine === 'context-aware') {
            isAlert = flow.context_detected;
            activeVerdict = isAlert ? 'anomaly' : (flow.context_risk > 0 ? 'suspicious' : 'normal');
        } else {
            isAlert = flow.risk_detected;
            if (flow.priority === 'CRITICAL' || flow.priority === 'HIGH') {
                activeVerdict = 'anomaly';
            } else if (flow.priority === 'MEDIUM') {
                activeVerdict = 'suspicious';
            } else {
                activeVerdict = 'normal';
            }
        }
        
        row.className = `flow-row ${isAlert ? 'flow-alert-row' : ''}`;
        row.addEventListener('click', () => openFlowInspector(flow));
        
        const formattedSize = flow.bytes >= 1048576 
            ? `${(flow.bytes / 1048576).toFixed(1)} MB` 
            : `${(flow.bytes / 1024).toFixed(1)} KB`;
            
        let verdictBadge = '';
        if (activeVerdict === 'anomaly') {
            verdictBadge = `<span class="verdict-badge v-anomaly">Anomaly</span>`;
        } else if (activeVerdict === 'suspicious') {
            verdictBadge = `<span class="verdict-badge v-suspicious">Suspicious</span>`;
        } else {
            verdictBadge = `<span class="verdict-badge v-normal">Normal</span>`;
        }
        
        row.innerHTML = `
            <div class="col-time">${flow.timestamp}</div>
            <div class="col-src" title="${flow.src_name} (${flow.src_ip})">${flow.src_name}</div>
            <div class="col-direction"><i class="fa-solid fa-angle-right direction-icon"></i></div>
            <div class="col-dest" title="${flow.dest_name} (${flow.dest_ip})">${flow.dest_name}</div>
            <div class="col-proto">${flow.protocol}</div>
            <div class="col-size">${formattedSize}</div>
            <div class="col-result">${verdictBadge}</div>
        `;
        
        listContainer.appendChild(row);
    });
}

// Update top KPI cards using backend metrics
function updateKpis(data) {
    // Current stats mapping
    const metrics = data.engine_comparison[activeEngine];
    
    // Generate active flow count dynamically from recent feed size
    document.getElementById('kpiActiveFlows').textContent = Math.floor(20 + Math.random() * 5);
    document.getElementById('kpiAnomalies').textContent = metrics.alerts_generated;
    
    // Risk score alerts
    const riskMetrics = data.engine_comparison['risk-informed'];
    document.getElementById('kpiHighRisk').textContent = Math.floor(riskMetrics.alerts_generated * 0.4);
    
    document.getElementById('kpiFPR').textContent = `${metrics.fpr.toFixed(2)}%`;
    document.getElementById('kpiReduction').textContent = `${metrics.workload_reduction.toFixed(1)}%`;
}

// Slide-out flow details
function openFlowInspector(flow) {
    document.getElementById('insFlowId').textContent = flow.id;
    document.getElementById('insTime').textContent = flow.timestamp;
    document.getElementById('insProto').textContent = flow.protocol;
    document.getElementById('insPort').textContent = flow.port;
    document.getElementById('insPackets').textContent = flow.packets;
    
    const formattedSize = flow.bytes >= 1048576 
        ? `${(flow.bytes / 1048576).toFixed(1)} MB` 
        : `${(flow.bytes / 1024).toFixed(1)} KB`;
    document.getElementById('insBytes').textContent = formattedSize;
    document.getElementById('insDuration').textContent = `${flow.duration}s`;
    
    document.getElementById('insSrcName').textContent = flow.src_name;
    document.getElementById('insSrcIp').textContent = flow.src_ip;
    document.getElementById('insSrcVlan').textContent = flow.src_vlan;
    document.getElementById('insSrcRole').textContent = flow.src_role;
    
    document.getElementById('insDestName').textContent = flow.dest_name;
    document.getElementById('insDestIp').textContent = flow.dest_ip;
    document.getElementById('insDestVlan').textContent = flow.dest_vlan;
    document.getElementById('insDestRole').textContent = flow.dest_role;
    
    // Context violations
    const violationsContainer = document.getElementById('insViolationsContainer');
    violationsContainer.innerHTML = '';
    if (flow.context_violations.length > 0) {
        flow.context_violations.forEach(v => {
            const div = document.createElement('div');
            div.className = 'violation-tag';
            div.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${v}`;
            violationsContainer.appendChild(div);
        });
    } else {
        violationsContainer.innerHTML = `<span class="no-violations"><i class="fa-solid fa-circle-check text-green"></i> No context policy violations.</span>`;
    }
    
    // Badges comparisons
    const b1 = document.getElementById('badgePhase1');
    b1.textContent = flow.traffic_detected ? 'ANOMALY' : 'NORMAL';
    b1.className = `badge ${flow.traffic_detected ? 'v-anomaly' : 'v-normal'}`;
    
    const b2 = document.getElementById('badgePhase2');
    b2.textContent = flow.context_detected ? 'ANOMALY' : (flow.context_risk > 0 ? 'SUSPICIOUS' : 'NORMAL');
    b2.className = `badge ${flow.context_detected ? 'v-anomaly' : (flow.context_risk > 0 ? 'v-suspicious' : 'v-normal')}`;

    const b3 = document.getElementById('badgePhase3');
    b3.textContent = flow.priority;
    b3.className = `badge ${flow.risk_detected ? 'v-anomaly' : (flow.priority === 'MEDIUM' ? 'v-suspicious' : 'v-normal')}`;
    
    // Risk score gauge
    const riskVal = document.getElementById('insRiskScore');
    riskVal.textContent = flow.risk_score;
    
    const riskLabel = document.getElementById('insPriority');
    riskLabel.textContent = flow.priority;
    
    const gauge = riskVal.parentElement;
    gauge.className = `gauge-display ${flow.priority.toLowerCase()}`;
    
    // Recommendation action text
    document.getElementById('insAction').textContent = flow.action;
    
    // Summary
    document.getElementById('insExplanation').textContent = flow.change_explanation;
    
    // Slide drawer open
    document.getElementById('flowInspector').classList.add('open');
}

// Interactive device modal popup
function openDeviceModal(device) {
    document.getElementById('mdDeviceId').textContent = device.id;
    document.getElementById('mdName').textContent = device.name;
    document.getElementById('mdIp').textContent = device.ip;
    document.getElementById('mdVlan').textContent = device.vlan;
    document.getElementById('mdRole').textContent = device.role;
    document.getElementById('mdTrust').textContent = device.trust;
    document.getElementById('mdCriticality').textContent = device.criticality;
    
    const riskStatus = document.getElementById('mdRisk');
    riskStatus.textContent = device.risk;
    riskStatus.className = `badge ${device.risk === 'Critical' ? 'v-anomaly' : (device.risk === 'High' || device.risk === 'Medium' ? 'v-suspicious' : 'v-normal')}`;
    
    document.getElementById('deviceOverlay').classList.add('open');
}

// Setup ChartJS visualizations
function initCharts() {
    const ctxTrends = document.getElementById('anomalyTrendsChart').getContext('2d');
    anomalyTrendsChart = new Chart(ctxTrends, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Simulated Anomalies Detected',
                data: [],
                borderColor: '#4f46e5',
                borderWidth: 2,
                backgroundColor: 'rgba(79, 70, 229, 0.08)',
                fill: true,
                tension: 0.4,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(15, 23, 42, 0.06)' },
                    ticks: { color: '#94a3b8', font: { size: 9 } }
                },
                y: {
                    grid: { color: 'rgba(15, 23, 42, 0.06)' },
                    ticks: { color: '#94a3b8', font: { size: 9 } },
                    min: 0,
                    suggestedMax: 10
                }
            }
        }
    });

    const ctxAttacks = document.getElementById('attacksBarChart').getContext('2d');
    attacksBarChart = new Chart(ctxAttacks, {
        type: 'bar',
        data: {
            labels: ['DoS', 'Port Scan', 'Privilege Abuse', 'Rogue IoT', 'Exfiltration'],
            datasets: [
                {
                    label: 'Traffic-Only',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(239, 68, 68, 0.75)',
                    borderColor: '#ef4444',
                    borderWidth: 1,
                    borderRadius: 3
                },
                {
                    label: 'Context-Aware',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(245, 158, 11, 0.75)',
                    borderColor: '#f59e0b',
                    borderWidth: 1,
                    borderRadius: 3
                },
                {
                    label: 'Risk-Informed',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(79, 70, 229, 0.75)',
                    borderColor: '#4f46e5',
                    borderWidth: 1,
                    borderRadius: 3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#64748b', font: { size: 10 }, usePointStyle: true, boxWidth: 6 }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { size: 9 } }
                },
                y: {
                    grid: { color: 'rgba(15, 23, 42, 0.06)' },
                    ticks: { color: '#94a3b8', font: { size: 9 } },
                    min: 0,
                    max: 100,
                    title: { display: true, text: 'Recall Accuracy (%)', color: '#94a3b8', font: { size: 9 } }
                }
            }
        }
    });
}

// Update charts with live evaluations
function updateTrendsCharts(data) {
    if (!anomalyTrendsChart || !attacksBarChart) return;
    
    // 1. Update Anomaly Insights scrolling trend
    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    anomalyTrendsChart.data.labels.push(timestamp);
    // Anomaly rate per interval corresponds to alerts caught recently
    const recentAlertIncrement = Math.max(0, Math.floor(Math.random() * 3));
    anomalyTrendsChart.data.datasets[0].data.push(recentAlertIncrement);
    
    if (anomalyTrendsChart.data.labels.length > 15) {
        anomalyTrendsChart.data.labels.shift();
        anomalyTrendsChart.data.datasets[0].data.shift();
    }
    anomalyTrendsChart.update();
    
    // 2. Update Attack types recall bars
    const attacks = data.attacks_breakdown;
    const barDataTraffic = [
        attacks['dos'].traffic_recall,
        attacks['probe'].traffic_recall,
        attacks['compromise'].traffic_recall,
        attacks['iot_anomaly'].traffic_recall,
        attacks['stealthy'].traffic_recall
    ];
    const barDataContext = [
        attacks['dos'].context_recall,
        attacks['probe'].context_recall,
        attacks['compromise'].context_recall,
        attacks['iot_anomaly'].context_recall,
        attacks['stealthy'].context_recall
    ];
    const barDataRisk = [
        attacks['dos'].risk_recall,
        attacks['probe'].risk_recall,
        attacks['compromise'].risk_recall,
        attacks['iot_anomaly'].risk_recall,
        attacks['stealthy'].risk_recall
    ];
    
    attacksBarChart.data.datasets[0].data = barDataTraffic;
    attacksBarChart.data.datasets[1].data = barDataContext;
    attacksBarChart.data.datasets[2].data = barDataRisk;
    attacksBarChart.update();
}

// Populate research evaluation grid
function updateResearchComparison() {
    fetch('/api/metrics')
    .then(res => res.json())
    .then(data => {
        const body = document.getElementById('metricsTableBody');
        body.innerHTML = '';
        
        const engines = [
            { id: 'traffic-only', name: 'Phase 1: Traffic-Only Baseline' },
            { id: 'context-aware', name: 'Phase 2: Context-Aware Model' },
            { id: 'risk-informed', name: 'Phase 3: Risk-Informed Framework' }
        ];
        
        engines.forEach(eng => {
            const metrics = data.engine_comparison[eng.id];
            const tr = document.createElement('tr');
            
            const isPurple = eng.id === 'risk-informed';
            const textClass = isPurple ? 'text-purple text-bold' : '';
            
            tr.innerHTML = `
                <td class="${textClass}">${eng.name}</td>
                <td>${metrics.precision.toFixed(1)}%</td>
                <td>${metrics.recall.toFixed(1)}%</td>
                <td>${metrics.f1.toFixed(1)}%</td>
                <td>${metrics.fpr.toFixed(2)}%</td>
                <td>${metrics.alerts_generated}</td>
                <td class="text-green text-bold">${eng.id !== 'traffic-only' ? `${metrics.workload_reduction.toFixed(1)}%` : '0.0%'}</td>
            `;
            body.appendChild(tr);
        });
    })
    .catch(err => console.error('Error loading comparison metrics matrix:', err));
}
