"""
FlowWatch connector.

Pulls active High/Critical alarms from a running FlowWatch instance (the
NetFlow-based detector built earlier in this project) via its own REST API.
This is the "your own telemetry" leg of the XDR correlation -- the other
two connectors bring in Cisco's identity and analytics context.
"""

import os
import requests

DEFAULT_BASE_URL = "http://127.0.0.1:5000"  # FlowWatch's own dashboard/API port


class FlowWatchConnector:
    def __init__(self):
        self.base_url = os.environ.get("FLOWWATCH_BASE_URL", DEFAULT_BASE_URL)

    def get_alarms(self, limit=25, since_seconds=3600) -> list:
        url = f"{self.base_url}/api/alarms"
        try:
            resp = requests.get(url, params={"limit": limit, "since_seconds": since_seconds}, timeout=5)
            resp.raise_for_status()
            alarms = resp.json()
            for a in alarms:
                a["source"] = "FlowWatch"
            return alarms
        except requests.RequestException as e:
            print(f"[flowwatch_connector] failed to fetch alarms: {e}")
            return []

    def health(self) -> dict:
        try:
            resp = requests.get(f"{self.base_url}/api/status", timeout=3)
            resp.raise_for_status()
            return {"connected": True, "base_url": self.base_url}
        except requests.RequestException as e:
            return {"connected": False, "base_url": self.base_url, "error": str(e)}
