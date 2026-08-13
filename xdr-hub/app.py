import os
import sys
import threading
import time

from flask import Flask, jsonify, send_from_directory

sys.path.insert(0, os.path.dirname(__file__))

from connectors.flowwatch_connector import FlowWatchConnector
from connectors.ise_connector import ISEConnector
from connectors.secure_analytics_connector import SecureAnalyticsConnector
from correlation.engine import correlate

STATIC_DIR = os.path.join(os.path.dirname(__file__), "frontend")
HTTP_PORT = int(os.environ.get("XDR_HTTP_PORT", 6000))
POLL_INTERVAL = int(os.environ.get("XDR_POLL_INTERVAL", 10))

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

flowwatch = FlowWatchConnector()
ise = ISEConnector()
sna = SecureAnalyticsConnector()

_incidents_cache = []
_last_poll = 0
_started = threading.Event()


def poll_loop():
    global _incidents_cache, _last_poll
    while True:
        try:
            fw_alarms = flowwatch.get_alarms()
            sna_alarms = sna.get_alarms()
            _incidents_cache = correlate(fw_alarms, sna_alarms, ise)
            _last_poll = time.time()
        except Exception as e:
            print(f"[xdr-hub] poll error: {e}", file=sys.stderr)
        time.sleep(POLL_INTERVAL)


def ensure_started():
    if not _started.is_set():
        _started.set()
        threading.Thread(target=poll_loop, daemon=True).start()


@app.route("/")
def index():
    ensure_started()
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/incidents")
def api_incidents():
    ensure_started()
    return jsonify(_incidents_cache)


@app.route("/api/health")
def api_health():
    ensure_started()
    return jsonify({
        "flowwatch": flowwatch.health(),
        "ise": ise.health(),
        "secure_analytics": sna.health(),
        "last_poll": _last_poll,
        "poll_interval_seconds": POLL_INTERVAL,
        "incident_count": len(_incidents_cache),
    })


if __name__ == "__main__":
    ensure_started()
    print(f"XDR Hub dashboard: http://127.0.0.1:{HTTP_PORT}")
    print(f"Polling FlowWatch ({flowwatch.base_url}), ISE ({ise.base_url}), "
          f"Secure Analytics ({sna.base_url}) every {POLL_INTERVAL}s")
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=HTTP_PORT, threads=8)
    except ImportError:
        app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, use_reloader=False)
