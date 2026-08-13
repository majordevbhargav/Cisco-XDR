import sqlite3
import json
import os
import threading
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "flowwatch.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at REAL,
    src_ip TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER,
    protocol TEXT, packets INTEGER, bytes INTEGER, duration_ms INTEGER,
    exporter_ip TEXT,
    traffic_score REAL, traffic_anomaly INTEGER,
    context_score REAL, context_anomaly INTEGER, violations TEXT,
    risk_score REAL, risk_tier TEXT, risk_action TEXT, risk_reasons TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(observed_at);
CREATE INDEX IF NOT EXISTS idx_flows_tier ON flows(risk_tier);

CREATE TABLE IF NOT EXISTS engine_stats (
    engine TEXT PRIMARY KEY,
    flows_scored INTEGER DEFAULT 0,
    anomalies_flagged INTEGER DEFAULT 0
);
"""


class Store:
    def __init__(self, path=DB_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        for engine in ("traffic", "context", "risk"):
            self._conn.execute(
                "INSERT OR IGNORE INTO engine_stats(engine, flows_scored, anomalies_flagged) VALUES (?,0,0)",
                (engine,),
            )
        self._conn.commit()

    def insert_flow(self, flow, traffic, context, risk):
        with self._lock:
            self._conn.execute(
                """INSERT INTO flows (
                    observed_at, src_ip, dst_ip, src_port, dst_port, protocol,
                    packets, bytes, duration_ms, exporter_ip,
                    traffic_score, traffic_anomaly,
                    context_score, context_anomaly, violations,
                    risk_score, risk_tier, risk_action, risk_reasons
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    flow.get("observed_at", time.time()), flow["src_ip"], flow["dst_ip"],
                    flow["src_port"], flow["dst_port"], flow["protocol"],
                    flow["packets"], flow["bytes"], flow["duration_ms"], flow.get("exporter_ip", ""),
                    traffic["score"], int(traffic["anomaly"]),
                    context["score"], int(context["anomaly"]), json.dumps(context["violations"]),
                    risk["score"], risk["tier"], risk["recommended_action"], json.dumps(risk["reasons"]),
                ),
            )
            for engine, result in (("traffic", traffic), ("context", context), ("risk", risk)):
                self._conn.execute(
                    "UPDATE engine_stats SET flows_scored = flows_scored + 1, "
                    "anomalies_flagged = anomalies_flagged + ? WHERE engine = ?",
                    (1 if result["anomaly"] else 0, engine),
                )
            self._conn.commit()

    def recent_flows(self, limit=100, tier=None):
        with self._lock:
            q = "SELECT * FROM flows"
            params = ()
            if tier:
                q += " WHERE risk_tier = ?"
                params = (tier,)
            q += " ORDER BY id DESC LIMIT ?"
            params = params + (limit,)
            cur = self._conn.execute(q, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def engine_stats(self):
        with self._lock:
            cur = self._conn.execute("SELECT engine, flows_scored, anomalies_flagged FROM engine_stats")
            return {row[0]: {"flows_scored": row[1], "anomalies_flagged": row[2]} for row in cur.fetchall()}

    def tier_counts(self, since_seconds=3600):
        with self._lock:
            cutoff = time.time() - since_seconds
            cur = self._conn.execute(
                "SELECT risk_tier, COUNT(*) FROM flows WHERE observed_at >= ? GROUP BY risk_tier", (cutoff,)
            )
            return {row[0]: row[1] for row in cur.fetchall()}

    def total_flows(self):
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
