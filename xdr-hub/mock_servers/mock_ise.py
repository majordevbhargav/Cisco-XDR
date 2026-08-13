"""
Mock Cisco ISE server.

Simulates the two ISE API surfaces xdr-hub actually needs, using the same
response shapes as the real appliance, so ise_connector.py can be pointed
at this in dev and at a real ISE PSN in production with zero code changes:

  - ERS API   (https://<ise>:9060/ers/config/endpoint)  -- endpoint inventory
  - MnT API   (https://<ise>:9060/admin/API/mnt/Session/ActiveList) -- live
    session directory: which user/device is *currently* using which IP,
    their posture status, and assigned Security Group Tag (SGT).

Run standalone on :9060 to develop/demo against without a real ISE box:
    python3 mock_servers/mock_ise.py
"""

from flask import Flask, jsonify
import random

app = Flask(__name__)

# Simulated endpoint inventory + live sessions, keyed by IP -- mirrors what
# you'd actually get back from a lab ISE PSN for a handful of devices.
FAKE_SESSIONS = {
    "10.0.10.11": {"username": "jsmith", "mac": "AA:BB:CC:00:01:11", "device_type": "Windows10-Workstation",
                   "posture_status": "Compliant", "security_group": "Employees", "endpoint_group": "Corporate-Managed"},
    "10.0.10.12": {"username": "rpatel", "mac": "AA:BB:CC:00:01:12", "device_type": "MacOS-Workstation",
                   "posture_status": "Compliant", "security_group": "Employees", "endpoint_group": "Corporate-Managed"},
    "10.0.10.13": {"username": "unknown", "mac": "AA:BB:CC:00:01:13", "device_type": "Unknown",
                   "posture_status": "NonCompliant", "security_group": "Quarantine", "endpoint_group": "Unmanaged"},
    "10.0.20.10": {"username": "svc-db", "mac": "AA:BB:CC:00:02:10", "device_type": "Linux-Server",
                   "posture_status": "N/A", "security_group": "Servers", "endpoint_group": "Data-Center"},
    "10.0.20.11": {"username": "svc-app", "mac": "AA:BB:CC:00:02:11", "device_type": "Linux-Server",
                   "posture_status": "N/A", "security_group": "Servers", "endpoint_group": "Data-Center"},
    "10.0.30.21": {"username": "N/A", "mac": "AA:BB:CC:00:03:21", "device_type": "IoT-Camera",
                   "posture_status": "N/A", "security_group": "IoT-Untrusted", "endpoint_group": "IoT-Devices"},
    "10.0.30.22": {"username": "N/A", "mac": "AA:BB:CC:00:03:22", "device_type": "IoT-Sensor",
                   "posture_status": "N/A", "security_group": "IoT-Untrusted", "endpoint_group": "IoT-Devices"},
}


@app.route("/ers/config/endpoint")
def ers_endpoints():
    """Mirrors ERS's list-endpoints response shape."""
    resources = [
        {"id": str(i), "name": data["mac"], "description": data["device_type"]}
        for i, (ip, data) in enumerate(FAKE_SESSIONS.items())
    ]
    return jsonify({"SearchResult": {"total": len(resources), "resources": resources}})


@app.route("/admin/API/mnt/Session/ActiveList")
def active_sessions():
    """Mirrors the MnT live session directory: the actual thing xdr-hub
    polls to resolve 'who/what is this IP right now'."""
    sessions = []
    for ip, data in FAKE_SESSIONS.items():
        sessions.append({
            "framed_ip_address": ip,
            "user_name": data["username"],
            "calling_station_id": data["mac"],
            "endpoint_profile": data["device_type"],
            "posture_status": data["posture_status"],
            "security_group": data["security_group"],
            "endpoint_group": data["endpoint_group"],
            "nas_ip_address": f"10.0.{random.choice([1,2,3])}.1",
        })
    return jsonify({"activeSessionList": sessions})


if __name__ == "__main__":
    print("Mock ISE server on http://127.0.0.1:9060")
    print("  ERS:  GET /ers/config/endpoint")
    print("  MnT:  GET /admin/API/mnt/Session/ActiveList")
    app.run(host="0.0.0.0", port=9060)
