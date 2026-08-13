# Cisco-XDR

A lab-scale build-up of what Cisco Stealthwatch and XDR actually do under
the hood. Score raw network flows for anomalies, add identity and policy
context, then correlate findings across multiple sources into one
prioritized incident feed. Three stages, three folders, each one runnable
on its own.

![python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)
![backend](https://img.shields.io/badge/backend-Flask-000000?logo=flask)
![license](https://img.shields.io/badge/license-MIT-green)

---

## The three components

| Folder | What it is | Data source |
|---|---|---|
| [`sentinelx/`](./sentinelx) | Research sandbox, where the three-engine detection design was prototyped and tested | Simulated flow feed |
| [`flowwatch/`](./flowwatch) | The real sensor, same three engines but wired to real network traffic | Live NetFlow v5 (UDP) |
| [`xdr-hub/`](./xdr-hub) | The correlation layer, fuses FlowWatch alarms with identity and flow-analytics context | FlowWatch, ISE, Secure Analytics |

Read them in that order. SentinelX proves the detection approach works,
FlowWatch productionizes it against real traffic, and XDR Hub sits on top
turning per-flow alerts into per-host incidents.

### `sentinelx/`: where the detection logic was designed

A self-contained Flask app with a simulated 10-device network across four
VLANs, five switchable attack scenarios, and a live topology view. No real
traffic touches this one. It exists to compare three detection approaches
side by side and prove the core idea: adding identity, VLAN, and policy
context on top of raw traffic stats catches stealthy attacks a
traffic-only model misses, without losing recall on loud ones.

```bash
cd sentinelx
pip install -r requirements.txt
python3 app.py
# opens at http://127.0.0.1:5000 (check its own README if that's taken)
```

### `flowwatch/`: the real collector

Takes SentinelX's three-engine design and points it at real traffic
instead of a simulation. Listens for genuine NetFlow v5 packets on UDP
`:2055`, exported from a router, firewall, or `softflowd` on a mirrored
port, and scores every flow through the same three lenses:

1. **Traffic-Only**: an Isolation Forest over packet, byte, and rate
   features. Catches volumetric attacks like DoS and high-volume scans.
   Blind to anything that looks normal-sized.
2. **Context-Aware**: layers `inventory.json` (your own map of subnets to
   VLAN, role, and criticality) on top. Catches VLAN-crossing, role-policy
   violations, a sliding-window port-scan pattern, sensitive-port access
   to critical assets, and first-contact destinations.
3. **Risk-Informed**: fuses both into a single 0-100 score with hard
   floors, so a confirmed policy violation against a critical asset always
   lands at Critical no matter how the weighted average comes out. Maps to
   a tier and a recommended action.

```bash
cd flowwatch
pip install -r requirements.txt
python3 backend/app.py
# opens at http://127.0.0.1:5000

# in another terminal, test without a router:
python3 tools/replay_generator.py --scenario portscan
```

Full setup for wiring a real exporter, editing `inventory.json`, and the
full API surface is in [`flowwatch/README.md`](./flowwatch/README.md).

### `xdr-hub/`: the correlation layer

FlowWatch's dashboard answers "what flows happened?", one row per flow.
XDR Hub answers a different question: "which hosts should I actually care
about, and why?"

It polls three sources every 10 seconds:
- **FlowWatch** (`/api/alarms`): your own High/Critical NetFlow detections
- **Cisco ISE**: device identity, posture status, security group (mocked
  by default, real ERS/MnT API underneath)
- **Cisco Secure Network Analytics**: flow-analytics alarms (also mocked
  by default, real SNA token-auth and tenant alarms API underneath)

Then it merges everything by IP into one incident per host:

- Each source's severity maps to a 0-100 base score
- An IP flagged by two independent sources gets a +15 corroboration bonus
- ISE context (non-compliant posture, untrusted or quarantine SGT) can
  escalate a finding that already exists, but never generates or
  suppresses one on its own
- Final tiers: Critical (85+), High (65+), Medium (35+), Low

```bash
# terminal 1: FlowWatch
cd flowwatch && python3 backend/app.py
# terminal 2: feed it traffic
cd flowwatch && python3 tools/replay_generator.py --scenario iot_lateral

# terminal 3: mock ISE
cd xdr-hub && python3 mock_servers/mock_ise.py
# terminal 4: mock Secure Analytics
cd xdr-hub && python3 mock_servers/mock_secure_analytics.py
# terminal 5: XDR Hub
cd xdr-hub && pip install -r requirements.txt && python3 app.py
# opens at http://127.0.0.1:6100 (port 6000 is blocked by most browsers as unsafe)
```

Both mocks speak the real Cisco API shapes, so pointing at actual
infrastructure later is an env-var change, not a code change. Details in
[`xdr-hub/README.md`](./xdr-hub/README.md).

---

## Architecture at a glance

```
      real traffic
      (NetFlow v5)
            |
            v
      +----------------+
      |    FlowWatch    |
      |  3 detection    |
      |    engines      |
      +----------------+
            |
            | /api/alarms (High/Critical flows)
            v
      +----------------+       +----------------+       +----------------+
      |   Cisco ISE    |------>|    XDR Hub     |<------| Secure Network |
      |   (identity)   |       |  correlation   |       |   Analytics    |
      +----------------+       |     engine     |       | (flow alarms)  |
                               +----------------+       +----------------+
                                        |
                                        v
                          unified incidents, one per IP,
                            with a full evidence trail
```

## Honest limitations

- FlowWatch only speaks NetFlow v5 for now. v9/IPFIX, which newer
  Cisco/Juniper gear prefers, isn't implemented yet.
- XDR Hub's ISE and Secure Analytics connectors run against mocks until
  you have real lab access. The mocks match the real API response shapes,
  so no code changes are needed to point at real infrastructure later.
- No cross-restart persistence in XDR Hub. Incidents live in memory.
- This is defensive tooling for networks you own or are authorized to
  monitor.

## License

MIT
