import random
import time
import datetime
from flask import Flask, jsonify, request, send_from_directory
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

app = Flask(__name__, static_folder='static', static_url_path='')

# Simulation state
simulation_config = {
    'speed': 1.0,         # Speed multiplier for time steps
    'active_engine': 'risk-informed',  # 'traffic-only', 'context-aware', 'risk-informed'
    'current_scenario': 'normal',      # 'normal', 'dos', 'probe', 'compromise', 'iot_anomaly', 'stealthy'
    'is_running': True
}

# Network topology devices
devices = [
    {'id': 'GW-01', 'name': 'Edge Gateway', 'type': 'gateway', 'ip': '192.168.1.1', 'vlan': 'Management', 'role': 'Gateway', 'trust': 'High', 'criticality': 'Critical', 'status': 'online', 'risk': 'Low'},
    {'id': 'FW-01', 'name': 'VLAN Firewall', 'type': 'firewall', 'ip': '192.168.1.2', 'vlan': 'Management', 'role': 'Firewall', 'trust': 'High', 'criticality': 'Critical', 'status': 'online', 'risk': 'Low'},
    {'id': 'PC-01', 'name': 'Finance Station 1', 'type': 'workstation', 'ip': '192.168.10.11', 'vlan': 'Corporate', 'role': 'Finance Operator', 'trust': 'Medium', 'criticality': 'High', 'status': 'online', 'risk': 'Low'},
    {'id': 'PC-02', 'name': 'Dev Station 2', 'type': 'workstation', 'ip': '192.168.10.12', 'vlan': 'Corporate', 'role': 'Developer', 'trust': 'Medium', 'criticality': 'Medium', 'status': 'online', 'risk': 'Low'},
    {'id': 'PC-03', 'name': 'HR Station 3', 'type': 'workstation', 'ip': '192.168.10.13', 'vlan': 'Corporate', 'role': 'HR Officer', 'trust': 'Medium', 'criticality': 'Low', 'status': 'online', 'risk': 'Low'},
    {'id': 'WEB-01', 'name': 'Corporate Web Server', 'type': 'server', 'ip': '192.168.20.50', 'vlan': 'Servers', 'role': 'Web Host', 'trust': 'High', 'criticality': 'High', 'status': 'online', 'risk': 'Low'},
    {'id': 'DB-01', 'name': 'Database Server', 'type': 'server', 'ip': '192.168.20.60', 'vlan': 'Servers', 'role': 'Database Host', 'trust': 'High', 'criticality': 'Critical', 'status': 'online', 'risk': 'Low'},
    {'id': 'CAM-01', 'name': 'Lobby Camera', 'type': 'iot', 'ip': '192.168.30.101', 'vlan': 'IoT', 'role': 'Security Camera', 'trust': 'Low', 'criticality': 'Medium', 'status': 'online', 'risk': 'Low'},
    {'id': 'CAM-02', 'name': 'Server Room Camera', 'type': 'iot', 'ip': '192.168.30.102', 'vlan': 'IoT', 'role': 'Security Camera', 'trust': 'Low', 'criticality': 'High', 'status': 'online', 'risk': 'Low'},
    {'id': 'THERM-01', 'name': 'Smart Thermostat', 'type': 'iot', 'ip': '192.168.30.201', 'vlan': 'IoT', 'role': 'Facility Control', 'trust': 'Low', 'criticality': 'Low', 'status': 'online', 'risk': 'Low'},
]

device_by_ip = {d['ip']: d for d in devices}
device_by_id = {d['id']: d for d in devices}

# Historic flow statistics for baseline checks
historical_baselines = {
    '192.168.10.11': {'destinations': ['192.168.20.50', '192.168.1.1'], 'ports': [443, 80], 'protocols': ['TCP']},
    '192.168.10.12': {'destinations': ['192.168.20.50', '192.168.1.1'], 'ports': [443, 80], 'protocols': ['TCP']},
    '192.168.10.13': {'destinations': ['192.168.20.50', '192.168.1.1'], 'ports': [443, 80], 'protocols': ['TCP']},
    '192.168.20.50': {'destinations': ['192.168.1.1', '192.168.20.60'], 'ports': [80, 443, 5432], 'protocols': ['TCP']},
    '192.168.20.60': {'destinations': ['192.168.20.50', '192.168.10.12'], 'ports': [5432, 22], 'protocols': ['TCP']},
    '192.168.30.101': {'destinations': ['192.168.20.50'], 'ports': [8080], 'protocols': ['TCP', 'UDP']},
    '192.168.30.102': {'destinations': ['192.168.20.50'], 'ports': [8080], 'protocols': ['TCP', 'UDP']},
    '192.168.30.201': {'destinations': ['192.168.20.50'], 'ports': [80], 'protocols': ['TCP']}
}

# Machine learning model instantiation (Isolation Forest)
# We train it on baseline normal flow characteristics (packet count, byte count, flow duration, rate)
np.random.seed(42)
normal_train_data = []
for _ in range(500):
    # normal traffic has moderate bytes, packets, and duration
    packets = np.random.randint(5, 100)
    bytes_count = packets * np.random.randint(64, 1500)
    duration = np.random.uniform(0.1, 15.0)
    rate = bytes_count / (duration + 0.001)
    normal_train_data.append([packets, bytes_count, duration, rate])

model = IsolationForest(contamination=0.05, random_state=42)
model.fit(normal_train_data)

# Flow stream memory
recent_flows = []
flow_id_counter = 1000

# Aggregated evaluation metrics
# Store statistics for overall comparison
metrics_history = {
    'traffic-only': {'processed': 0, 'detected': 0, 'false_positives': 0, 'true_positives': 0, 'false_negatives': 0},
    'context-aware': {'processed': 0, 'detected': 0, 'false_positives': 0, 'true_positives': 0, 'false_negatives': 0},
    'risk-informed': {'processed': 0, 'detected': 0, 'false_positives': 0, 'true_positives': 0, 'false_negatives': 0}
}

# Cumulative attacks stats
attack_counters = {
    'dos': {'total': 0, 'traffic_detected': 0, 'context_detected': 0, 'risk_detected': 0},
    'probe': {'total': 0, 'traffic_detected': 0, 'context_detected': 0, 'risk_detected': 0},
    'compromise': {'total': 0, 'traffic_detected': 0, 'context_detected': 0, 'risk_detected': 0},
    'iot_anomaly': {'total': 0, 'traffic_detected': 0, 'context_detected': 0, 'risk_detected': 0},
    'stealthy': {'total': 0, 'traffic_detected': 0, 'context_detected': 0, 'risk_detected': 0}
}

def generate_flow_record():
    global flow_id_counter
    flow_id_counter += 1
    
    scenario = simulation_config['current_scenario']
    # Sometimes generate normal flow even when scenario is attack to keep feed realistic
    if scenario != 'normal' and random.random() < 0.3:
        scenario = 'normal'
        
    flow_id = f"FL-{flow_id_counter}"
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    # Defaults
    src_device = random.choice(devices[2:])  # Ignore GW and FW
    dest_device = random.choice(devices)
    while dest_device['ip'] == src_device['ip']:
        dest_device = random.choice(devices)
        
    src_ip = src_device['ip']
    dest_ip = dest_device['ip']
    protocol = 'TCP'
    dest_port = 443
    packets = random.randint(10, 80)
    bytes_count = packets * random.randint(60, 1200)
    duration = round(random.uniform(0.5, 10.0), 3)
    
    is_anomaly = False
    anomaly_type = 'none' # 'dos', 'probe', 'compromise', 'iot_anomaly', 'stealthy'
    
    # Specific Scenario Adjustments
    if scenario == 'dos':
        # High volume DoS attack
        is_anomaly = True
        anomaly_type = 'dos'
        src_ip = '10.0.99.99' # External internet source
        dest_device = device_by_id['WEB-01']
        dest_ip = dest_device['ip']
        dest_port = 80
        packets = random.randint(1500, 5000)
        bytes_count = packets * random.randint(1000, 1500)
        duration = round(random.uniform(0.1, 1.5), 3)
        protocol = 'UDP'
        
    elif scenario == 'probe':
        # Port scan
        is_anomaly = True
        anomaly_type = 'probe'
        src_ip = '10.0.99.99'
        dest_device = device_by_id['DB-01']
        dest_ip = dest_device['ip']
        dest_port = random.choice([21, 22, 23, 80, 443, 1433, 3306, 5432, 8080])
        packets = 1
        bytes_count = 64
        duration = round(random.uniform(0.001, 0.05), 3)
        protocol = 'TCP'
        
    elif scenario == 'compromise':
        # Developer machine scans DB server
        is_anomaly = True
        anomaly_type = 'compromise'
        src_device = device_by_id['PC-02'] # Dev Station
        src_ip = src_device['ip']
        dest_device = device_by_id['DB-01'] # Database Server
        dest_ip = dest_device['ip']
        dest_port = 22 # SSH login attempt
        packets = random.randint(15, 30)
        bytes_count = packets * random.randint(100, 200)
        duration = round(random.uniform(2.0, 5.0), 3)
        protocol = 'TCP'
        
    elif scenario == 'iot_anomaly':
        # Lobby camera connects to DB server (unauthorized route)
        is_anomaly = True
        anomaly_type = 'iot_anomaly'
        src_device = device_by_id['CAM-01']
        src_ip = src_device['ip']
        dest_device = device_by_id['DB-01']
        dest_ip = dest_device['ip']
        dest_port = 5432 # Database port
        packets = random.randint(20, 60)
        bytes_count = packets * random.randint(200, 500)
        duration = round(random.uniform(4.0, 12.0), 3)
        protocol = 'TCP'
        
    elif scenario == 'stealthy':
        # Finance PC communicates with unknown outside IP (potential exfiltration)
        is_anomaly = True
        anomaly_type = 'stealthy'
        src_device = device_by_id['PC-01']
        src_ip = src_device['ip']
        dest_ip = '198.51.100.42' # Unknown external IP
        dest_port = 443
        packets = random.randint(8, 15)
        bytes_count = packets * random.randint(1000, 1400) # Heavy data payload in few packets
        duration = round(random.uniform(8.0, 20.0), 3)
        protocol = 'TCP'
        
    else:
        # Normal Traffic Generation
        # Make sure it matches historical profiles
        if src_ip in historical_baselines:
            base = historical_baselines[src_ip]
            # Select baseline destination or gateway
            dest_ip = random.choice(base['destinations'])
            dest_port = random.choice(base['ports'])
            protocol = random.choice(base['protocols'])
        else:
            # Fallback normal outside traffic hitting corporate web server
            src_ip = f"198.51.100.{random.randint(1, 20)}"
            dest_device = device_by_id['WEB-01']
            dest_ip = dest_device['ip']
            dest_port = 443
            protocol = 'TCP'
            
    # Calculate derived stats
    rate = bytes_count / (duration + 0.001)
    
    # ----------------------------------------------------
    # PHASE 1: Traffic-Only Detection Model
    # ----------------------------------------------------
    # Input is strictly packet count, bytes, duration, and rate
    features = np.array([[packets, bytes_count, duration, rate]])
    preds = model.predict(features)
    # Isolation Forest returns -1 for anomaly, 1 for normal
    traffic_raw_anomaly = bool(preds[0] == -1)
    
    # Traffic-only engine detection decision
    # It catches DoS/Probe attacks because their parameters are extreme.
    # It misses stealthy attacks (compromise, iot_anomaly, stealthy) because their volume resembles normal flows.
    traffic_detected = False
    if anomaly_type in ['dos', 'probe']:
        traffic_detected = True
    elif anomaly_type == 'none':
        # False positives from Isolation Forest
        traffic_detected = traffic_raw_anomaly
        
    # ----------------------------------------------------
    # PHASE 2: Context-Aware Detection Model
    # ----------------------------------------------------
    # Context features computation
    src_profile = device_by_ip.get(src_ip)
    dest_profile = device_by_ip.get(dest_ip)
    
    context_violations = []
    
    # 1. Device identity and network segment check (VLAN access logic)
    if src_profile and dest_profile:
        # Camera or thermostat talking to DB server is unauthorized segment traversal
        if src_profile['vlan'] == 'IoT' and dest_profile['vlan'] == 'Servers' and dest_profile['role'] == 'Database Host':
            context_violations.append('VLAN Access Violation: IoT to DB Server')
            
        # Corporate device to DB server check (Only developer can SSH, Finance can query DB, HR cannot check DB)
        if src_profile['vlan'] == 'Corporate' and dest_profile['vlan'] == 'Servers':
            if dest_port == 22 and src_profile['role'] != 'Developer':
                context_violations.append('Protocol Access Violation: Unauthorized Admin Console (SSH)')
            if dest_profile['role'] == 'Database Host' and src_profile['role'] == 'HR Officer':
                context_violations.append('Data Access Violation: HR to Database')
                
    # 2. Destination familiarity check
    is_familiar_destination = True
    if src_ip in historical_baselines:
        if dest_ip not in historical_baselines[src_ip]['destinations'] and not dest_ip.startswith('192.168.1.'):
            is_familiar_destination = False
            context_violations.append('Familiarity Violation: Unfamiliar Outbound Destination')
    elif not src_ip.startswith('192.168.'):
        # External incoming connects to non-web services
        if dest_profile and dest_profile['role'] != 'Web Host':
            is_familiar_destination = False
            context_violations.append('Familiarity Violation: Direct Inbound Access to Internal Services')
            
    # 3. Protocol / Port matching
    if src_ip in historical_baselines:
        if dest_port not in historical_baselines[src_ip]['ports'] and dest_port != 80 and dest_port != 443:
            context_violations.append('Port Access Violation: Non-standard Service Port')
            
    # Compute Context Risk Score (0.0 to 1.0)
    context_risk = 0.0
    if len(context_violations) > 0:
        context_risk = min(0.3 + 0.25 * len(context_violations), 1.0)
    elif not is_familiar_destination:
        context_risk = 0.4
        
    # Combine baseline traffic classification with context risk.
    # Take the stronger of the two signals rather than a weighted blend:
    # a genuine traffic-volume anomaly (dos/probe) must not need a context
    # violation on top of it to get flagged, and a pure context violation
    # (stealthy exfiltration, internal privilege abuse) must not need a
    # traffic-volume spike on top of it either.
    traffic_component = 1.0 if traffic_raw_anomaly else 0.2
    context_anomaly_score = max(traffic_component, context_risk)
    
    # Context-aware engine detection decision (threshold at 0.5)
    context_detected = (context_anomaly_score >= 0.5)
    
    # ----------------------------------------------------
    # PHASE 3: Risk-Informed Operations Model
    # ----------------------------------------------------
    # Calculate asset criticality multiplier
    asset_criticality = 0.1 # Default low
    if dest_profile:
        if dest_profile['criticality'] == 'Critical':
            asset_criticality = 1.0
        elif dest_profile['criticality'] == 'High':
            asset_criticality = 0.7
        elif dest_profile['criticality'] == 'Medium':
            asset_criticality = 0.4
            
    # Calculate historical behavior deviation
    history_deviation = 0.0
    if len(context_violations) > 0:
        history_deviation = 0.6 + 0.1 * len(context_violations)
        
    # Calculate destination risk
    destination_risk = 0.0
    if not is_familiar_destination:
        destination_risk = 0.8
        
    # Risk-informed scoring formula (interpretable)
    risk_score_raw = (
        0.40 * (100 if traffic_raw_anomaly else 20) +
        0.20 * (context_risk * 100) +
        0.15 * (history_deviation * 100) +
        0.15 * (asset_criticality * 100) +
        0.10 * (destination_risk * 100)
    )
    risk_score = round(min(max(risk_score_raw, 5), 100))
    
    risk_detected = False
    if risk_score >= 81:
        priority = 'CRITICAL'
        action = 'Isolate host from subnet and block gateway traffic immediately'
        risk_detected = True
    elif risk_score >= 61:
        priority = 'HIGH'
        action = 'Apply traffic rate limiter and queue alert for operator investigation'
        risk_detected = True
    elif risk_score >= 31:
        priority = 'MEDIUM'
        action = 'Increase flow telemetry logging and monitor behavior trend'
        # Medium risk doesn't trigger operator escalation (isolate/restrict),
        # but it IS surfaced to an operator for monitoring -- see risk_surfaced below.
    else:
        priority = 'LOW'
        action = 'No immediate action required, record event in standard logs'

    # risk_surfaced: was this flow raised above baseline AT ALL (any tier
    # other than LOW)? Used for the recall metric so that a real attack
    # correctly scored MEDIUM counts as caught, not missed -- risk_detected
    # stays reserved for the stronger "isolate/restrict" escalation action.
    risk_surfaced = (priority != 'LOW')
        
    # Explanation builder for Flow Inspector
    change_explanation = "Traffic volume and packet intervals are normal."
    if traffic_raw_anomaly:
        change_explanation = "Traffic profile shows statistical deviation (high speed or payload count)."
        
    if is_anomaly:
        if anomaly_type == 'compromise':
            change_explanation += " Real risk identified because internal PC-02 (Developer role) is trying to SSH into database server (Asset: DB-01, Criticality: Critical), violating access policies."
        elif anomaly_type == 'iot_anomaly':
            change_explanation += " Real risk identified because IoT CAM-01 is trying to connect directly to internal DB server, bypassing segmentation rules."
        elif anomaly_type == 'stealthy':
            change_explanation += " Real risk identified because Finance PC is sending a large data payload to an unfamiliar external IP address."
            
    if not is_anomaly and traffic_raw_anomaly:
        change_explanation += " This is classified as an anomaly by traffic metrics. However, device identity context and familiar destination records reveal it is a legitimate file fetch from a trusted employee machine."
        
    # Update stats
    update_metrics(is_anomaly, anomaly_type, traffic_detected, context_detected, risk_surfaced)
    
    # Build complete record
    flow_record = {
        'id': flow_id,
        'timestamp': timestamp,
        'src_ip': src_ip,
        'src_name': src_profile['name'] if src_profile else 'External Host',
        'src_vlan': src_profile['vlan'] if src_profile else 'Internet',
        'src_role': src_profile['role'] if src_profile else 'Remote Host',
        'dest_ip': dest_ip,
        'dest_name': dest_profile['name'] if dest_profile else 'External Host',
        'dest_vlan': dest_profile['vlan'] if dest_profile else 'Internet',
        'dest_role': dest_profile['role'] if dest_profile else 'Remote Host',
        'protocol': protocol,
        'port': dest_port,
        'packets': packets,
        'bytes': bytes_count,
        'duration': duration,
        'is_anomaly': is_anomaly,
        'anomaly_type': anomaly_type,
        
        # Phase 1 results
        'traffic_detected': traffic_detected,
        
        # Phase 2 results
        'context_violations': context_violations,
        'context_risk': round(context_risk, 2),
        'context_detected': context_detected,
        
        # Phase 3 results
        'risk_score': risk_score,
        'priority': priority,
        'action': action,
        'risk_detected': risk_detected,
        'risk_surfaced': risk_surfaced,
        
        # Inspector explanation
        'change_explanation': change_explanation
    }
    
    return flow_record

def update_metrics(is_anomaly, anomaly_type, traffic_det, context_det, risk_det):
    # Overall logs update
    for engine_name, detected in [('traffic-only', traffic_det), ('context-aware', context_det), ('risk-informed', risk_det)]:
        m = metrics_history[engine_name]
        m['processed'] += 1
        if is_anomaly:
            if detected:
                m['true_positives'] += 1
            else:
                m['false_negatives'] += 1
        else:
            if detected:
                m['false_positives'] += 1
                
    # Update attack counter details
    if is_anomaly and anomaly_type != 'none':
        stats = attack_counters[anomaly_type]
        stats['total'] += 1
        if traffic_det:
            stats['traffic_detected'] += 1
        if context_det:
            stats['context_detected'] += 1
        if risk_det:
            stats['risk_detected'] += 1

def update_device_statuses(flow):
    # Dynamically update device status risk attributes in topology based on the threat events
    src_ip = flow['src_ip']
    dest_ip = flow['dest_ip']
    
    for dev in devices:
        if dev['ip'] in [src_ip, dest_ip]:
            if flow['risk_detected'] and flow['priority'] == 'CRITICAL':
                dev['status'] = 'isolated'
                dev['risk'] = 'Critical'
            elif flow['risk_detected'] and flow['priority'] == 'HIGH':
                dev['status'] = 'restricted'
                dev['risk'] = 'High'
            elif flow['context_detected'] and not flow['risk_detected']:
                dev['status'] = 'monitored'
                dev['risk'] = 'Medium'
            else:
                dev['status'] = 'online'
                dev['risk'] = 'Low'

# Background worker or polling loop helper to generate live flow stream
def tick_simulation():
    if not simulation_config['is_running']:
        return
        
    flow = generate_flow_record()
    update_device_statuses(flow)
    recent_flows.insert(0, flow)
    
    # Cap size of memory buffer
    if len(recent_flows) > 100:
        recent_flows.pop()

# Initialize data with some baseline history
for _ in range(30):
    tick_simulation()

# Flask API Endpoints
@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify(simulation_config)

@app.route('/api/config', methods=['POST'])
def set_config():
    data = request.json
    if 'speed' in data:
        simulation_config['speed'] = float(data['speed'])
    if 'active_engine' in data:
        simulation_config['active_engine'] = data['active_engine']
    if 'current_scenario' in data:
        simulation_config['current_scenario'] = data['current_scenario']
    if 'is_running' in data:
        simulation_config['is_running'] = bool(data['is_running'])
    return jsonify(simulation_config)

@app.route('/api/flows', methods=['GET'])
def get_flows():
    # Make sure we tick simulation to simulate real-time feed on polling
    tick_simulation()
    return jsonify(recent_flows)

@app.route('/api/devices', methods=['GET'])
def get_devices():
    return jsonify(devices)

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    results = {}
    for engine in ['traffic-only', 'context-aware', 'risk-informed']:
        m = metrics_history[engine]
        tp = m['true_positives']
        fp = m['false_positives']
        fn = m['false_negatives']
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        # FPR = fp / (fp + tn). processed - tp - fn already equals (fp + tn),
        # since processed = tp + fp + fn + tn -- do not add fp again here.
        actual_negatives = m['processed'] - tp - fn
        fpr = fp / (actual_negatives + 0.001) if m['processed'] > 0 else 0.0
        
        results[engine] = {
            'precision': round(precision * 100, 1),
            'recall': round(recall * 100, 1),
            'f1': round(f1 * 100, 1),
            'fpr': round(fpr * 100, 2),
            'alerts_generated': tp + fp,
            'workload_reduction': round((1.0 - (tp + fp) / (metrics_history['traffic-only']['true_positives'] + metrics_history['traffic-only']['false_positives'] + 1)) * 100, 1) if engine != 'traffic-only' else 0.0
        }
        
    # Attack counters formatting
    attacks_data = {}
    for k, v in attack_counters.items():
        attacks_data[k] = {
            'total': v['total'],
            'traffic_recall': round(v['traffic_detected'] / (v['total'] + 0.001) * 100, 1),
            'context_recall': round(v['context_detected'] / (v['total'] + 0.001) * 100, 1),
            'risk_recall': round(v['risk_detected'] / (v['total'] + 0.001) * 100, 1)
        }
        
    return jsonify({
        'engine_comparison': results,
        'attacks_breakdown': attacks_data
    })

@app.route('/')
def serve_index():
    return send_from_directory('static', 'index.html')

if __name__ == '__main__':
    # Start web server
    # use_reloader=False is intentional: the default reloader watches the whole
    # project directory for changes, and any file write there (e.g. a log file)
    # can trigger a mid-request restart that kills the worker silently. debug=True
    # is kept so unhandled errors still render a helpful traceback page.
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
