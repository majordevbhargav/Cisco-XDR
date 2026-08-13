"""
Cisco Secure Network Analytics (Secure Analytics / Stealthwatch) connector.

Authenticates via the SNA token endpoint and polls tenant-scoped alarms,
which supplements FlowWatch's own detection with Cisco's flow-analytics
alarm types (Data Hoarding, Suspect Data Loss, Watchlist Activity, etc.)
that come from SNA's much larger historical baseline.

Configuration (env vars):
    SNA_BASE_URL   e.g. https://smc.mycorp.local        (default: mock server)
    SNA_USERNAME, SNA_PASSWORD
    SNA_TENANT_ID  (default: "1", matches the mock)
    SNA_VERIFY_SSL "true"/"false"
"""

import os
import time
import threading
import requests

DEFAULT_BASE_URL = "http://127.0.0.1:8443"  # mock server (real SNA uses https://<smc-host>)


class SecureAnalyticsConnector:
    def __init__(self):
        self.base_url = os.environ.get("SNA_BASE_URL", DEFAULT_BASE_URL)
        self.username = os.environ.get("SNA_USERNAME", "mock")
        self.password = os.environ.get("SNA_PASSWORD", "mock")
        self.tenant_id = os.environ.get("SNA_TENANT_ID", "1")
        self.verify_ssl = os.environ.get("SNA_VERIFY_SSL", "false").lower() == "true"
        self.is_mock = "127.0.0.1" in self.base_url or "localhost" in self.base_url

        self._token = None
        self._token_expiry = 0
        self._lock = threading.Lock()

    def _authenticate(self):
        url = f"{self.base_url}/token/v2/authenticate"
        try:
            resp = requests.post(
                url,
                json={"username": self.username, "password": self.password} if not self.is_mock else {},
                verify=self.verify_ssl, timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            with self._lock:
                self._token = data.get("token")
                self._token_expiry = time.time() + data.get("expires_in", 3600) - 30
        except requests.RequestException as e:
            print(f"[secure_analytics_connector] auth failed: {e}")

    def _ensure_token(self):
        if not self._token or time.time() > self._token_expiry:
            self._authenticate()

    def get_alarms(self) -> list:
        """Returns recent SNA alarms across the monitored network."""
        self._ensure_token()
        if not self._token:
            return []
        url = f"{self.base_url}/sw-reporting/v2/tenants/{self.tenant_id}/alarms"
        try:
            resp = requests.get(url, headers={"Authorization": f"Bearer {self._token}"},
                                 verify=self.verify_ssl, timeout=5)
            resp.raise_for_status()
            alarms = resp.json().get("data", [])
            for a in alarms:
                a["source"] = "SecureAnalytics"
            return alarms
        except requests.RequestException as e:
            print(f"[secure_analytics_connector] failed to fetch alarms: {e}")
            return []

    def get_host_snapshot(self, ip: str) -> dict:
        self._ensure_token()
        if not self._token:
            return {}
        url = f"{self.base_url}/sw-reporting/v1/tenants/{self.tenant_id}/hosts/{ip}/snapshot"
        try:
            resp = requests.get(url, headers={"Authorization": f"Bearer {self._token}"},
                                 verify=self.verify_ssl, timeout=5)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            return {}

    def health(self) -> dict:
        self._ensure_token()
        return {"connected": bool(self._token), "base_url": self.base_url, "mock": self.is_mock}
