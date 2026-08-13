"""
Cisco ISE connector.

Resolves 'who/what is behind this IP right now' by polling ISE's live
session directory (MnT API). Works against a real ISE PSN, or against the
bundled mock server for development.

Configuration (env vars):
    ISE_BASE_URL   e.g. https://ise.mycorp.local:9060   (default: mock server)
    ISE_USERNAME, ISE_PASSWORD                            (ERS/MnT basic auth)
    ISE_VERIFY_SSL  "true"/"false"  (ISE appliances commonly use self-signed
                     certs in lab environments; default false for the mock,
                     you should set this true against a real CA-signed PSN)
"""

import os
import time
import threading
import requests
from requests.auth import HTTPBasicAuth

DEFAULT_BASE_URL = "http://127.0.0.1:9060"  # mock server (real ISE uses https://<host>:9060)


class ISEConnector:
    def __init__(self):
        self.base_url = os.environ.get("ISE_BASE_URL", DEFAULT_BASE_URL)
        self.username = os.environ.get("ISE_USERNAME", "mock")
        self.password = os.environ.get("ISE_PASSWORD", "mock")
        self.verify_ssl = os.environ.get("ISE_VERIFY_SSL", "false").lower() == "true"
        self.is_mock = "127.0.0.1" in self.base_url or "localhost" in self.base_url

        self._cache = {}  # ip -> identity dict
        self._cache_ts = 0
        self._cache_ttl = 15  # seconds; live session data changes, so keep this short
        self._lock = threading.Lock()

    def _refresh_sessions(self):
        """Pull the full active session list and rebuild the IP->identity cache.
        One call covers every IP, which is far cheaper than a lookup per-flow."""
        url = f"{self.base_url}/admin/API/mnt/Session/ActiveList"
        try:
            resp = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password) if not self.is_mock else None,
                verify=self.verify_ssl, timeout=5,
            )
            resp.raise_for_status()
            sessions = resp.json().get("activeSessionList", [])
            new_cache = {}
            for s in sessions:
                ip = s.get("framed_ip_address")
                if not ip:
                    continue
                new_cache[ip] = {
                    "username": s.get("user_name", "unknown"),
                    "mac": s.get("calling_station_id", ""),
                    "device_type": s.get("endpoint_profile", "Unknown"),
                    "posture_status": s.get("posture_status", "Unknown"),
                    "security_group": s.get("security_group", "Unknown"),
                    "endpoint_group": s.get("endpoint_group", "Unknown"),
                    "source": "ISE",
                }
            with self._lock:
                self._cache = new_cache
                self._cache_ts = time.time()
        except requests.RequestException as e:
            print(f"[ise_connector] failed to refresh sessions: {e}")

    def get_identity(self, ip: str) -> dict:
        """Returns identity/posture context for an IP, or a not-found stub.
        Refreshes the session cache automatically if it's stale."""
        if time.time() - self._cache_ts > self._cache_ttl:
            self._refresh_sessions()
        with self._lock:
            return self._cache.get(ip, {
                "username": None, "mac": None, "device_type": "Unknown",
                "posture_status": "Unknown", "security_group": "Unknown",
                "endpoint_group": "Unknown", "source": "ISE", "found": False,
            })

    def health(self) -> dict:
        try:
            requests.get(f"{self.base_url}/admin/API/mnt/Session/ActiveList", timeout=3,
                         verify=self.verify_ssl,
                         auth=HTTPBasicAuth(self.username, self.password) if not self.is_mock else None)
            return {"connected": True, "base_url": self.base_url, "mock": self.is_mock}
        except requests.RequestException as e:
            return {"connected": False, "base_url": self.base_url, "mock": self.is_mock, "error": str(e)}
