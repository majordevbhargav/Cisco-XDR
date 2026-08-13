# FlowWatch

A lightweight, self-hosted network anomaly detection tool — a small,
transparent take on what Cisco Stealthwatch does: ingest real NetFlow from
your network, score every flow through multiple detection lenses, and
surface prioritized alerts instead of raw noise.

Unlike a sandbox/demo, this one is wired to receive **real flow exports**
from your router, switch, or firewall. No agents on endpoints required —
NetFlow is exported by whatever device already sees your traffic.

## How it's different from a single-model IDS

Every flow is scored by three engines at once, so you can see exactly what
context buys you over raw traffic stats:

1. **Traffic-Only** — Isolation Forest over packet/byte/duration/rate.
   Catches volumetric attacks (DoS, scans with enough volume). Blind to
   anything that looks like normal-sized traffic.
2. **Context-Aware** — adds device identity, VLAN, role-based access
   policy, destination familiarity, and a real port-scan detector (many
   distinct ports from one source in a rolling window). Catches policy
   violations with no volume signature — an IoT device reaching the
   database server, for instance.
3. **Risk-Informed** — fuses both signals with asset criticality into a
   0–100 score, an operational tier (Low/Medium/High/Critical), and a
   recommended action. This is what you'd actually triage from.

## Architecture

```
flowwatch/
├── backend/
│   ├── app.py                  # Flask app: wires everything together, serves REST API + dashboard
│   ├── collector/
│   │   └── netflow_v5.py       # Real NetFlow v5 UDP listener + wire-format parser
│   ├── detection/
│   │   ├── traffic_engine.py   # Isolation Forest, retrains on a sliding window
│   │   ├── context_engine.py   # VLAN/role policy + port-scan + familiarity checks
│   │   └── risk_engine.py      # Composite score, tiering, recommended action
│   ├── inventory.py            # IP -> device/VLAN/role/criticality lookups
│   ├── inventory.json          # YOUR network map (edit this — see below)
│   └── db.py                   # SQLite storage for flows + engine stats
├── frontend/                   # Dashboard: live flow log, inspector, engine comparison
├── tools/
│   └── replay_generator.py     # Sends real NetFlow v5 packets for testing, no router needed
└── requirements.txt
```

## Quickstart (with synthetic traffic — no router needed)

```bash
pip install -r requirements.txt
python3 backend/app.py
```

Open **http://127.0.0.1:5000**. In a second terminal, generate real
wire-format NetFlow v5 traffic to test the whole pipeline:

```bash
python3 tools/replay_generator.py --scenario normal
# in other terminals, try: --scenario dos | portscan | iot_lateral | exfil
```

You'll see flows land in the live log within ~2 seconds and get scored by
all three engines. Click any flow to see why it was (or wasn't) flagged.

## Wiring up real traffic

FlowWatch listens for **NetFlow v5** on UDP port **2055** by default
(`FLOWWATCH_NETFLOW_PORT` env var to change it). Point one of these at
`<flowwatch-host>:2055`:

- **Router/firewall with native NetFlow export** (most enterprise/SMB
  gear — Cisco IOS, MikroTik, Ubiquiti EdgeRouter, pfSense/OPNcense with
  the softflowd package, Fortinet, etc.): enable NetFlow v5 export in its
  admin UI/CLI and set the collector address.
- **No exporter-capable hardware?** Run
  [`softflowd`](https://github.com/irino/softflowd) on any Linux box that
  can see the traffic (e.g. plugged into a SPAN/mirror port, or on the
  router itself):
  ```bash
  sudo apt install softflowd
  sudo softflowd -i eth0 -n <flowwatch-host>:2055 -v 5
  ```
- **Cloud VPC flow logs** (AWS/GCP/Azure) use different formats and would
  need a small adapter to reformat them into NetFlow v5 UDP records — not
  included here, but the collector/parser is isolated in
  `netflow_v5.py` specifically so it's easy to add a sibling parser
  (`vpc_flow_logs.py`) that feeds the same `flow_queue`.

> NetFlow v9 and IPFIX (template-based, used by newer Cisco/Juniper gear)
> aren't implemented yet — v5 is the safest universal starting point. If
> your gear only speaks v9/IPFIX, that's the natural next module to add
> (the parser just needs to handle the template negotiation before
> decoding records; everything downstream — engines, storage, dashboard —
> is already format-agnostic).

## Describing your network (`backend/inventory.json`)

This is what turns raw IP traffic into context. It's auto-created with a
placeholder example on first run — edit it to match your actual network:

```json
{
  "subnets": {
    "10.0.10.0/24": { "vlan": "Corporate", "criticality": 2 },
    "10.0.20.0/24": { "vlan": "Server", "criticality": 4 }
  },
  "devices": {
    "10.0.20.10": {
      "name": "DB-01", "role": "database", "vlan": "Server", "criticality": 5
    }
  },
  "policies": {
    "database": ["app-server", "admin-workstation"]
  }
}
```

- `subnets` — fallback context for any IP in that CIDR without an explicit entry.
- `devices` — per-IP overrides: name, role, VLAN, criticality (0–5).
- `policies` — `role -> [roles allowed to initiate connections to it]`. Any
  source whose role isn't in the allow-list for a destination's role gets
  flagged as a policy violation.

Reload after editing without restarting the server:
```bash
curl -X POST http://127.0.0.1:5000/api/inventory/reload
```

IPs with no entry and no matching subnet are treated as unmapped-internal
(if private) or external/Internet (if public) — both get scored, just with
less context to work with.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Collector health, packet/flow counts, queue depth |
| `/api/flows` | GET | Recent scored flows (`?limit=`, `?tier=Critical\|High\|Medium\|Low`) |
| `/api/metrics` | GET | Cumulative per-engine stats + tier distribution (`?since_seconds=`) |
| `/api/inventory` | GET | Current network map |
| `/api/inventory/reload` | POST | Reload `inventory.json` after editing |

## Notes on running this for real

- The dev server (`app.run`) is fine for a home lab or small office. For
  anything with real production traffic, run behind `gunicorn`/`waitress`
  and put it on a network segment that can actually receive the exported
  UDP flows (check firewall rules — NetFlow is UDP and often blocked by
  default).
- SQLite is fine up to a few million flows; if you're monitoring
  a busy network 24/7, plan to either prune old rows on a schedule or swap
  `db.py` for Postgres/TimescaleDB — the storage layer is a single small
  file specifically so that swap is contained.
- The Isolation Forest retrains periodically on a sliding window of recent
  flows, so it adapts to your network's normal baseline over the first
  hour or so of runtime — expect noisier traffic-only scoring right after
  a fresh start.
- This is defensive tooling for monitoring networks you own or are
  authorized to monitor. Exporting and analyzing flow data from a network
  without authorization may violate policy or law depending on your
  jurisdiction.

## License

MIT
