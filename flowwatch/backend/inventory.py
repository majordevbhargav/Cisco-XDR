"""
Asset inventory: maps IPs seen on the wire to identity/context.

In a real deployment this would sync from DHCP leases, an NAC system,
a CMDB, or DNS/ARP tables. Here it's a simple editable JSON file so you can
describe your own network without touching code. Unknown IPs (anything not
listed, including all internet destinations) are treated as "unknown" /
external and scored accordingly by the context engine.
"""

import json
import ipaddress
import os
import threading

DEFAULT_INVENTORY_PATH = os.path.join(os.path.dirname(__file__), "inventory.json")

DEFAULT_INVENTORY = {
    "subnets": {
        # CIDR -> vlan name, used when an IP isn't individually listed
        "10.0.10.0/24": {"vlan": "Corporate", "criticality": 2},
        "10.0.20.0/24": {"vlan": "Server", "criticality": 4},
        "10.0.30.0/24": {"vlan": "IoT", "criticality": 1},
        "10.0.90.0/24": {"vlan": "Management", "criticality": 5},
    },
    "devices": {
        # explicit overrides per IP
        # "10.0.20.10": {"name": "DB-01", "role": "database", "vlan": "Server", "criticality": 5,
        #                "allowed_roles_inbound": ["app-server", "admin-workstation"]}
    },
    "policies": {
        # role -> list of roles allowed to initiate connections to it
        "database": ["app-server", "admin-workstation"],
        "domain-controller": ["admin-workstation", "server"],
    },
}


class Inventory:
    def __init__(self, path=DEFAULT_INVENTORY_PATH):
        self.path = path
        self._lock = threading.Lock()
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path) as f:
                return json.load(f)
        with open(self.path, "w") as f:
            json.dump(DEFAULT_INVENTORY, f, indent=2)
        return json.loads(json.dumps(DEFAULT_INVENTORY))

    def reload(self):
        with self._lock:
            self.data = self._load()

    def lookup(self, ip: str) -> dict:
        """Return context for an IP: name, role, vlan, criticality (0-5).
        Falls back to subnet match, then to 'unknown/external'."""
        dev = self.data.get("devices", {}).get(ip)
        if dev:
            return {
                "ip": ip, "known": True,
                "name": dev.get("name", ip),
                "role": dev.get("role", "unknown"),
                "vlan": dev.get("vlan", "unknown"),
                "criticality": dev.get("criticality", 1),
            }

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None

        if addr and not addr.is_global:
            for cidr, meta in self.data.get("subnets", {}).items():
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return {
                        "ip": ip, "known": True,
                        "name": ip, "role": "unclassified",
                        "vlan": meta.get("vlan", "unknown"),
                        "criticality": meta.get("criticality", 1),
                    }
            return {"ip": ip, "known": False, "name": ip, "role": "unclassified",
                     "vlan": "unmapped-internal", "criticality": 1}

        return {"ip": ip, "known": False, "name": ip, "role": "external",
                 "vlan": "Internet", "criticality": 0}

    def allowed_roles_for(self, role: str):
        return self.data.get("policies", {}).get(role, None)  # None = no restriction defined
