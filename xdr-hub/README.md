# XDR Hub

A unified incident correlation layer over three sources — your own
NetFlow-based detection (FlowWatch), Cisco ISE identity/posture, and Cisco
Secure Network Analytics (Secure Analytics / Stealthwatch) flow-analytics
alarms. This is the "XDR" idea in miniature: instead of three separate
alert streams an analyst has to mentally merge, every IP with activity
becomes one incident with combined severity and full evidence trail.

## Why mocks

You don't have live ISE/Secure Analytics lab access yet, so both
connectors ship with a **mock server that speaks the real API shapes**
(ERS/MnT for ISE, the SNA token-auth + tenant alarms REST API). Everything
downstream — the correlation engine, the dashboard — is identical whether
it's talking to the mocks or real appliances. Point at real infrastructure
later by setting env vars; zero code changes required.

## Architecture

```
xdr-hub/
├── connectors/
│   ├── flowwatch_connector.py         # pulls /api/alarms from your FlowWatch instance
│   ├── ise_connector.py               # ISE MnT live session directory (identity/posture/SGT)
│   └── secure_analytics_connector.py  # SNA token auth + tenant alarms
├── correlation/
│   └── engine.py                      # merges all three by IP into unified incidents
├── mock_servers/
│   ├── mock_ise.py                    # real ERS/MnT response shapes, 7 simulated devices
│   └── mock_secure_analytics.py       # real SNA auth + alarm response shapes
├── frontend/                          # dashboard: incident feed with source badges + evidence
├── app.py                             # polls connectors every 10s, serves REST API + dashboard
└── requirements.txt
```

## How severity fusion works

- Each FlowWatch tier and each SNA severity maps to a 0–100 base score
- An IP flagged by **two independent sources** gets a +15 corroboration
  bonus — two tools agreeing is stronger signal than either alone
- ISE context (non-compliant posture, an untrusted/quarantine SGT) can
  **escalate** a finding that already exists from another source, but
  never generates an incident by itself and never suppresses a finding
- Final tiers: Critical (≥85) / High (≥65) / Medium (≥35) / Low

This mirrors FlowWatch's own "context can only add, never subtract"
design principle, applied one layer up across sources instead of within one.

## Running it

You need FlowWatch running first (it's the actual telemetry source):

```bash
# terminal 1 — FlowWatch
cd flowwatch && python3 backend/app.py
# terminal 2 — feed it some traffic
cd flowwatch && python3 tools/replay_generator.py --scenario portscan

# terminal 3 — mock ISE
cd xdr-hub && python3 mock_servers/mock_ise.py
# terminal 4 — mock Secure Analytics
cd xdr-hub && python3 mock_servers/mock_secure_analytics.py
# terminal 5 — XDR Hub itself
cd xdr-hub && pip install -r requirements.txt && python3 app.py
```

Open **http://127.0.0.1:6000**. Within one poll cycle (10s) you'll see
correlated incidents — try the `iot_lateral` scenario in FlowWatch's
replay generator to see the ISE escalation bump in action (the simulated
IoT camera is in ISE's `IoT-Untrusted` security group).

## Pointing at real Cisco infrastructure

**ISE** (env vars):
```bash
export ISE_BASE_URL="https://your-ise-psn.corp.local:9060"
export ISE_USERNAME="ers-api-user"
export ISE_PASSWORD="..."
export ISE_VERIFY_SSL="true"
```
Requires ERS API enabled on the PSN and the MnT (Monitoring) API reachable
for the live session directory. The connector polls the full active
session list once every 15s rather than looking up per-IP, which is far
cheaper against a real appliance.

**Secure Network Analytics** (env vars):
```bash
export SNA_BASE_URL="https://your-smc.corp.local"
export SNA_USERNAME="api-user"
export SNA_PASSWORD="..."
export SNA_TENANT_ID="1"
export SNA_VERIFY_SSL="true"
```

**FlowWatch** (if not on localhost:5000):
```bash
export FLOWWATCH_BASE_URL="http://your-flowwatch-host:5000"
```

## Honest limitations

- The identity resolution is IP-based (matches ISE's live session
  directory at poll time). If your network reassigns IPs quickly via DHCP,
  identity can lag — the same tradeoff real XDR tools handle with shorter
  poll intervals or event-driven pxGrid subscriptions instead of polling.
- No persistence yet — incidents live in memory and reset on restart.
  FlowWatch's SQLite pattern (`db.py`) would be the natural thing to reuse
  here if you want incident history.
- pxGrid (Cisco's real-time pub/sub for ISE) would remove the 15s polling
  lag entirely but needs a certificate-based trust setup that's overkill
  until you have a real ISE box to test against — ERS/MnT polling was the
  pragmatic starting point.
- This is defensive tooling for infrastructure you own or are authorized
  to monitor.

## Where SDWAN-SIM and the NAIST research repo could plug in later

Neither is wired in yet, but both have a natural landing spot:

- **SDWAN-SIM**'s z-score link-health anomaly detector could become a
  fourth connector (`sdwan_connector.py`) feeding link-degradation events
  into the same correlation engine — "this host's traffic looks
  suspicious AND its WAN link is simultaneously degraded" is a real
  correlation an analyst would want.
- **Context-Aware-Network-Anomaly-Detection**'s risk-tiering methodology
  (Phase 3) is conceptually the direct ancestor of both FlowWatch's risk
  engine and this project's severity fusion — worth citing if you ever
  write this up, but it's offline research code (notebooks/scripts against
  a static CSV), not a running service, so there's nothing to connect at
  the infrastructure level without first turning it into one.

## License

MIT
