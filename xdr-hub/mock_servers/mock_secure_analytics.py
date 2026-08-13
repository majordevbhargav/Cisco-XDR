"""
Mock Cisco Secure Network Analytics (formerly Stealthwatch) server.

Simulates the SNA REST API's token auth flow and alarm-listing endpoint so
secure_analytics_connector.py can be developed/demoed against it, then
pointed at a real Stealthwatch Management Console (SMC) later with zero
code changes.

Real SNA auth: POST /token/v2/authenticate -> sets a session cookie/XSRF
token used on subsequent tenant-scoped calls like:
    GET /sw-reporting/v2/tenants/{tenantId}/alarms

Run standalone on :443-equivalent dev port 8443:
    python3 mock_servers/mock_secure_analytics.py
"""

from flask import Flask, jsonify, request
import random
import time

app = Flask(__name__)
TENANT_ID = "1"

ALARM_TEMPLATES = [
    {"type": "Data Hoarding", "host": "10.0.20.10", "severity": "Major",
     "detail": "Host received unusually high response byte volume from Internet"},
    {"type": "High Total Traffic", "host": "10.0.20.11", "severity": "Minor",
     "detail": "Sustained traffic volume 3x above baseline"},
    {"type": "Suspect Data Loss", "host": "10.0.20.10", "severity": "Critical",
     "detail": "Large outbound transfer to a host with no prior history"},
    {"type": "New Flows Initiated", "host": "10.0.30.21", "severity": "Minor",
     "detail": "IoT device initiated connections outside its normal role"},
    {"type": "Watchlist Host Activity", "host": "10.0.20.10", "severity": "Major",
     "detail": "Communication observed with a host on the internal watchlist"},
]


@app.route("/token/v2/authenticate", methods=["POST"])
def authenticate():
    # real SNA returns a session cookie; we return a bearer-style token for simplicity
    return jsonify({"token": "mock-sna-session-token", "expires_in": 3600})


@app.route(f"/sw-reporting/v2/tenants/{TENANT_ID}/alarms")
def alarms():
    auth = request.headers.get("Authorization", "")
    if "mock-sna-session-token" not in auth:
        return jsonify({"error": "unauthorized"}), 401

    now = time.time()
    n = random.randint(1, 3)
    chosen = random.sample(ALARM_TEMPLATES, n)
    out = []
    for i, a in enumerate(chosen):
        out.append({
            "id": f"alarm-{int(now)}-{i}",
            "alarmType": a["type"],
            "sourceIp": a["host"],
            "severity": a["severity"],
            "detail": a["detail"],
            "startActiveTime": int(now - random.randint(0, 300)),
        })
    return jsonify({"data": out})


@app.route(f"/sw-reporting/v1/tenants/{TENANT_ID}/hosts/<ip>/snapshot")
def host_snapshot(ip):
    auth = request.headers.get("Authorization", "")
    if "mock-sna-session-token" not in auth:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({
        "ipAddress": ip,
        "hostGroups": ["Servers", "Data Center"] if ip.startswith("10.0.20") else ["Trusted Internal"],
        "cts": random.choice(["Low", "Medium", "High"]),  # concern index tier
        "fileShareIndex": random.randint(0, 20),
    })


if __name__ == "__main__":
    print("Mock Secure Network Analytics server on http://127.0.0.1:8443")
    print("  Auth:   POST /token/v2/authenticate")
    print(f"  Alarms: GET /sw-reporting/v2/tenants/{TENANT_ID}/alarms")
    app.run(host="0.0.0.0", port=8443)
