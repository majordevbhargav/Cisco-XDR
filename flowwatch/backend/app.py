import os
import sys
import threading
import queue
import time

from flask import Flask, jsonify, request, send_from_directory

sys.path.insert(0, os.path.dirname(__file__))

from collector.netflow_v5 import NetFlowV5Collector
from detection.traffic_engine import TrafficOnlyEngine
from detection.context_engine import ContextAwareEngine
from detection.risk_engine import RiskInformedEngine
from inventory import Inventory
from db import Store

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
NETFLOW_PORT = int(os.environ.get("FLOWWATCH_NETFLOW_PORT", 2055))
HTTP_PORT = int(os.environ.get("FLOWWATCH_HTTP_PORT", 5000))

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

flow_queue = queue.Queue(maxsize=200_000)
collector = NetFlowV5Collector(port=NETFLOW_PORT, out_queue=flow_queue)
inventory = Inventory()
traffic_engine = TrafficOnlyEngine()
context_engine = ContextAwareEngine(inventory)
risk_engine = RiskInformedEngine()
store = Store()

_worker_started = threading.Event()


def worker_loop():
    while True:
        try:
            flow = flow_queue.get(timeout=1)
        except queue.Empty:
            continue
        try:
            traffic_result = traffic_engine.score(flow)
            context_result = context_engine.score(flow, traffic_result)
            risk_result = risk_engine.score(flow, traffic_result, context_result)
            store.insert_flow(flow, traffic_result, context_result, risk_result)
        except Exception as e:
            # never let one malformed/edge-case flow kill the worker thread
            print(f"[worker] error scoring flow: {e}", file=sys.stderr)


def ensure_started():
    if not _worker_started.is_set():
        _worker_started.set()
        collector.start()
        threading.Thread(target=worker_loop, daemon=True).start()


@app.route("/")
def index():
    ensure_started()
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/status")
def api_status():
    ensure_started()
    return jsonify({
        "collector": collector.stats(),
        "total_flows_stored": store.total_flows(),
        "engine_stats": store.engine_stats(),
        "netflow_port": NETFLOW_PORT,
    })


@app.route("/api/flows")
def api_flows():
    ensure_started()
    limit = int(request.args.get("limit", 100))
    tier = request.args.get("tier")
    return jsonify(store.recent_flows(limit=limit, tier=tier))


@app.route("/api/metrics")
def api_metrics():
    ensure_started()
    since = int(request.args.get("since_seconds", 3600))
    return jsonify({
        "engine_stats": store.engine_stats(),
        "tier_counts_last_hour": store.tier_counts(since_seconds=since),
    })


@app.route("/api/alarms")
def api_alarms():
    ensure_started()
    limit = int(request.args.get("limit", 25))
    since_seconds = int(request.args.get("since_seconds", 3600))
    return jsonify(store.alarms(limit=limit, since_seconds=since_seconds))


@app.route("/api/inventory", methods=["GET"])
def api_inventory_get():
    return jsonify(inventory.data)


@app.route("/api/inventory/reload", methods=["POST"])
def api_inventory_reload():
    inventory.reload()
    return jsonify({"status": "reloaded"})


if __name__ == "__main__":
    ensure_started()
    print(f"FlowWatch listening for NetFlow v5 on UDP :{NETFLOW_PORT}")
    print(f"Dashboard: http://127.0.0.1:{HTTP_PORT}")
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, use_reloader=False)