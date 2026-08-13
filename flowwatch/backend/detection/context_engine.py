"""
Context-Aware engine: layers device identity, VLAN segmentation, and
role-based access policy on top of the traffic signal. This is what catches
policy violations that have no volume signature at all -- an IoT device
reaching the database server, or a workstation SSHing into a domain
controller it has no business touching -- which the traffic-only engine is
structurally blind to.

Design choice (carried over from the SentinelX research sandbox, and kept
here deliberately): context can only ADD detection coverage on top of the
traffic score, never subtract from it. A genuine volumetric attack must
still be caught even if it happens to also be policy-compliant traffic.
"""

import time
from collections import defaultdict, deque

# well-known "sensitive" destination ports worth extra scrutiny cross-VLAN
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 3306: "MySQL",
                    5432: "Postgres", 1433: "MSSQL", 23: "Telnet"}

SCAN_WINDOW_SECONDS = 20
SCAN_PORT_THRESHOLD = 12  # distinct dst ports from one src in the window = scan


class ContextAwareEngine:
    def __init__(self, inventory, history_size=5000):
        self.inventory = inventory
        # per-src-IP set of destination IPs seen before -> "familiarity" baseline
        self._history = defaultdict(set)
        self._history_size = history_size
        self._total_seen = 0
        # per-src-IP recent (timestamp, dst_port) events, for scan detection
        self._recent_ports = defaultdict(deque)

    def _is_port_scan(self, src_ip, dst_port, now):
        events = self._recent_ports[src_ip]
        events.append((now, dst_port))
        cutoff = now - SCAN_WINDOW_SECONDS
        while events and events[0][0] < cutoff:
            events.popleft()
        distinct_ports = {p for _, p in events}
        return len(distinct_ports) >= SCAN_PORT_THRESHOLD

    def _record(self, src_ip, dst_ip):
        self._history[src_ip].add(dst_ip)
        self._total_seen += 1
        if self._total_seen > self._history_size:
            # simple decay: drop the smallest history bucket
            if self._history:
                smallest = min(self._history, key=lambda k: len(self._history[k]))
                self._history.pop(smallest, None)
            self._total_seen = 0

    def score(self, flow: dict, traffic_result: dict) -> dict:
        src = self.inventory.lookup(flow["src_ip"])
        dst = self.inventory.lookup(flow["dst_ip"])

        violations = []
        context_score = 0.0

        # port-scan signature: many distinct destination ports from one source
        # in a short window -- invisible to a single-flow view, since each
        # individual probe can look like an unremarkable tiny flow.
        if self._is_port_scan(flow["src_ip"], flow["dst_port"], flow.get("observed_at", time.time())):
            violations.append(f"Port scan pattern: {flow['src_ip']} probed {SCAN_PORT_THRESHOLD}+ ports recently")
            context_score = max(context_score, 0.9)

        # VLAN-crossing check: IoT/unmapped devices reaching Server/Management is high-risk
        if src["vlan"] == "IoT" and dst["vlan"] in ("Server", "Management"):
            violations.append(f"IoT device crossed into {dst['vlan']} VLAN")
            context_score = max(context_score, 0.85)

        if src["vlan"] == "unmapped-internal":
            violations.append("Traffic from an unrecognized internal device")
            context_score = max(context_score, 0.5)

        # role-based access policy
        allowed = self.inventory.allowed_roles_for(dst["role"])
        if allowed is not None and src["role"] not in allowed and src["role"] != "unknown":
            violations.append(f"Role '{src['role']}' not authorized to reach role '{dst['role']}'")
            context_score = max(context_score, 0.9)

        # sensitive port to a known-critical asset from a non-admin role
        if flow["dst_port"] in SENSITIVE_PORTS and dst["criticality"] >= 4 and src["role"] not in (
                "admin-workstation", "server", "unknown"):
            violations.append(
                f"{SENSITIVE_PORTS[flow['dst_port']]} to critical asset from role '{src['role']}'"
            )
            context_score = max(context_score, 0.75)

        # destination familiarity: first-time-ever destination for this source
        seen_before = flow["dst_ip"] in self._history[flow["src_ip"]]
        self._record(flow["src_ip"], flow["dst_ip"])
        if not seen_before and dst["known"] and dst["vlan"] != "Internet":
            violations.append("First contact with this internal destination")
            context_score = max(context_score, 0.35)

        # context can only ADD to detection, never subtract from the traffic signal
        combined = max(traffic_result["score"], context_score)
        anomaly = combined >= 0.5

        return {
            "anomaly": anomaly,
            "score": round(combined, 3),
            "context_score": round(context_score, 3),
            "violations": violations,
            "src_context": src,
            "dst_context": dst,
        }
