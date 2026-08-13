"""
Traffic-Only engine: pure statistical outlier detection on flow metrics.
No notion of identity, VLAN, or history -- catches volumetric attacks
(DoS, scans) and nothing else. This is the baseline the other two engines
are measured against.
"""

import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest

FEATURES = ["packets", "bytes", "duration_ms", "pkt_rate", "byte_rate", "avg_pkt_size"]


def extract_features(flow: dict) -> list:
    duration_s = max(flow.get("duration_ms", 0) / 1000.0, 0.001)
    packets = flow.get("packets", 0)
    byts = flow.get("bytes", 0)
    return [
        packets,
        byts,
        duration_s * 1000.0,
        packets / duration_s,
        byts / duration_s,
        byts / max(packets, 1),
    ]


class TrafficOnlyEngine:
    """Maintains a sliding window of recent flows, periodically refits an
    Isolation Forest, and scores new flows against it. Cold-starts with a
    fixed heuristic threshold until enough flows have been seen."""

    def __init__(self, window_size=2000, retrain_every=200, contamination=0.05):
        self.window = deque(maxlen=window_size)
        self.retrain_every = retrain_every
        self.contamination = contamination
        self.model = None
        self._since_retrain = 0
        self.min_flows_to_train = 100

    def _maybe_retrain(self):
        self._since_retrain += 1
        if len(self.window) < self.min_flows_to_train:
            return
        if self.model is None or self._since_retrain >= self.retrain_every:
            X = np.array(self.window)
            self.model = IsolationForest(
                n_estimators=100, contamination=self.contamination, random_state=42
            ).fit(X)
            self._since_retrain = 0

    def score(self, flow: dict) -> dict:
        feats = extract_features(flow)
        self.window.append(feats)
        self._maybe_retrain()

        if self.model is None:
            # cold start heuristic: flag flows with extreme rate/volume
            is_anomaly = feats[3] > 500 or feats[4] > 2_000_000  # pkt/s, bytes/s
            score = 0.8 if is_anomaly else 0.1
            return {"anomaly": is_anomaly, "score": round(score, 3), "method": "cold-start-heuristic"}

        raw = self.model.decision_function([feats])[0]  # higher = more normal
        pred = self.model.predict([feats])[0]  # -1 = anomaly, 1 = normal
        # map decision_function (~[-0.5,0.5]) to a 0-1 anomaly score
        norm_score = float(np.clip(0.5 - raw, 0, 1))
        return {
            "anomaly": bool(pred == -1),
            "score": round(norm_score, 3),
            "method": "isolation-forest",
        }
