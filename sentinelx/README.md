# SentinelX

A research sandbox for comparing three approaches to network anomaly
detection — **traffic-only**, **context-aware**, and **risk-informed** — on
a simulated corporate network. Built to demonstrate a core research
hypothesis: adding device identity, VLAN segmentation, and behavioral
history to raw traffic metrics improves detection of stealthy attacks and
cuts down alert fatigue, without sacrificing recall on loud, high-volume
attacks.

The backend generates a live, simulated flow feed across five attack
scenarios and scores every flow through all three detection engines
simultaneously, so their outputs can be compared side by side in real time.

![engine](https://img.shields.io/badge/backend-Flask-000000?logo=flask)
![python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)
![license](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Live topology view** — an interactive network diagram of 10 simulated
  devices across Management, Corporate, Server, and IoT VLANs, with
  real-time status rings and animated packet flow.
- **Three parallel detection engines**, run on every flow at once:
  - **Traffic-Only** — an Isolation Forest model trained on packet count,
    byte volume, duration, and rate. Catches high-volume attacks, blind to
    anything that looks volumetrically normal.
  - **Context-Aware** — layers in device role, VLAN, and destination
    familiarity to catch policy violations traffic volume alone can't see
    (e.g. an IoT camera reaching the database server).
  - **Risk-Informed** — an interpretable weighted score combining traffic
    anomaly, context risk, historical deviation, and asset criticality into
    a single actionable priority tier (Low / Medium / High / Critical).
- **Five attack scenarios** — DoS, port scan, internal privilege abuse
  (compromised host), rogue IoT traversal, and stealthy data exfiltration —
  switchable live from the header.
- **Flow Inspector** — click any flow in the live log to see its full
  feature breakdown, which context policies it violated (if any), how each
  of the three engines classified it, and the plain-language reasoning
  behind the verdict.
- **Research Mode** — a cumulative precision / recall / F1 / false-positive
  rate / alert-workload comparison table across all three engines, for
  quantifying the value of context and risk scoring over a raw baseline.

---

## Getting started

### Requirements

- Python 3.10+
- pip

### Install & run

```bash
git clone https://github.com/<your-username>/sentinelx.git
cd sentinelx
pip install -r requirements.txt
python3 app.py
```

Then open **http://127.0.0.1:5000** in a browser.

The dashboard starts with 30 pre-generated flows and the **risk-informed**
engine active. Use the **Scenario** dropdown to trigger an attack type, and
the **Detection Engine** dropdown to see how each engine independently
classifies the exact same live traffic.

> Charts (Anomaly Insights, Recall by Attack Type) load Chart.js from a
> CDN. If your network blocks the CDN, the rest of the dashboard —
> topology, live flow log, and metrics — keeps working normally; only the
> two chart widgets will stay empty. See [Fixed bugs](#fixed-bugs) below
> for why that matters.

---

## Project structure

```
sentinelx/
├── app.py              # Flask backend: simulation engine + 3 detection models + REST API
├── requirements.txt
├── README.md
└── static/
    ├── index.html       # Dashboard + Research Mode markup
    ├── styles.css        # Design tokens + component styles
    └── app.js             # Topology rendering, live polling, charts, flow inspector
```

### API

| Endpoint         | Method | Description                                              |
|-------------------|--------|-----------------------------------------------------------|
| `/api/status`      | GET    | Current simulation config                                  |
| `/api/config`       | POST   | Update speed / active engine / scenario / running state    |
| `/api/flows`         | GET    | Ticks the simulation and returns the last 100 flows         |
| `/api/devices`        | GET    | Current device list with live status/risk                    |
| `/api/metrics`         | GET    | Cumulative precision/recall/F1/FPR per engine + per-attack recall |

---

## How detection works

Every simulated flow is scored by all three engines at once, so the same
event can be compared across approaches:

1. **Traffic-Only** flags a flow only if its packet/byte/duration profile
   is a statistical outlier (Isolation Forest) — it has no notion of *who*
   is talking to *whom*.
2. **Context-Aware** takes the stronger of the traffic signal and a
   context-violation score built from VLAN-crossing rules, role-based
   access rules (e.g. only a Developer may SSH into the database server),
   and destination-familiarity checks against each device's historical
   baseline.
3. **Risk-Informed** combines traffic anomaly, context risk, historical
   deviation, destination risk, and asset criticality into a single 0–100
   score, mapped to an operational priority tier with a recommended
   response action.

The design is deliberate: a genuine volumetric attack (DoS, port scan)
must be caught by every engine, and a genuine policy violation with no
volume spike (privilege abuse, rogue IoT traffic, slow exfiltration) must
also be caught by the two smarter engines even though the traffic-only
model misses it. Comparing recall per attack type across the three engines
is how the research hypothesis gets tested.

---

## Fixed bugs

The app went through a full debugging pass — running it end-to-end,
exercising every scenario/engine combination repeatedly, and reproducing
issues in a real browser rather than relying on code review alone. Two
categories of bugs were found and fixed:

### UI / frontend

**The topology view went permanently blank after any interaction, and
never recovered.**
Chart.js is loaded from a CDN. `initCharts()` ran synchronously during
page startup with no error handling — if the CDN request was blocked or
slow for *any* reason (ad-blocker, privacy extension, firewall, brief
network hiccup), `new Chart(...)` threw an uncaught exception. Because
that exception happened *inside* the same `DOMContentLoaded` callback that
also called `fetchDevices()`, `fetchDashboardData()`, and registered the
polling `setInterval`, the whole callback aborted right there — the
topology never rendered, live polling never started, and nothing on the
page updated again for the rest of the session, even though the backend
was working fine the whole time.

*Fix:* chart initialization now runs **last**, wrapped in `try/catch`, and
happens after the topology, initial data fetch, and polling loop are
already up and running. A blocked or slow CDN now only means the two
trend charts stay empty — everything else keeps working exactly as
before. Verified by re-running the exact reproduction with the CDN
request blocked in a real browser.

**Packet-flow particles and threat-link highlighting never actually
worked.** The animation code tried to resolve a flow's source/destination
by matching `flow.src_ip` against an `.ip` property on the topology
position map — but that map never stored an `.ip` field, so the lookup
always failed silently and the function returned early on every single
flow. The dashed red "threat path" link styling in the stylesheet was
similarly defined but never applied by any code.

*Fix:* node lookup now uses a live IP → device-ID map rebuilt from
`/api/devices` on every refresh, with external/unknown IPs correctly
routed to the shared "Remote Internet" node. Flagged flows now also pulse
the relevant topology link red when a direct connection exists between
the two endpoints.

### Backend / detection logic

- **`/api/flows` crashed on every request** — a raw `numpy.bool_` from the
  Isolation Forest prediction isn't JSON-serializable; cast to a native
  `bool`.
- **8 device lookups indexed the wrong dictionary** (`device_by_ip`, keyed
  by IP, was queried with device IDs like `'WEB-01'`), raising `KeyError`
  on roughly 70% of attack-scenario ticks. Added a proper `device_by_id`
  map and fixed every call site.
- **The dev server's auto-reloader could kill the worker mid-request** —
  any file write anywhere in the project directory could trigger a silent
  restart. Disabled the reloader; kept `debug=True` for tracebacks.
- **The "internal privilege abuse" scenario was undetectable by design**
  — the historical baseline used to judge "familiar" destinations
  accidentally *included* the exact attack traffic pattern (Dev Station →
  Database Server, port 22) as normal, so no engine could ever flag it.
  Removed it from the baseline.
- **The context-aware engine was *less* sensitive than the traffic-only
  baseline it's supposed to improve on** — a weighted blend
  (`0.45 * traffic + 0.55 * context`) meant an obvious traffic-volume
  attack with no context violation could score *below* the detection
  threshold. Replaced with the stronger of the two signals, so context can
  only add detection coverage, never remove it.
- **False-positive rate was under-reported by roughly half** — the
  denominator double-counted false positives. Fixed the formula.
- **Risk-informed recall unfairly penalized correctly-triaged MEDIUM-tier
  alerts** — a real attack scored MEDIUM (a legitimate, graduated
  response) was counted as a miss for recall purposes. Separated "should
  this escalate a device to isolated/restricted" from "did this get
  surfaced to an operator at all" so the recall metric reflects what the
  engine actually caught.

All of the above were confirmed fixed by running the full scenario cycle
(DoS → probe → compromise → IoT anomaly → stealthy → normal) against the
live server with zero failures, and by re-verifying attack-type recall
climbs from 0% to 100% for the three attack types the traffic-only
baseline is designed to miss.

**Not a bug, worth knowing:** `workload_reduction` can show a negative
value if you cycle rapidly through attack-only scenarios — that's
mathematically correct, since the smarter engines are catching several
attack types the baseline misses entirely, which means *more* true-positive
alerts, not fewer. The "reduces workload" story is meant to be observed
under realistic mixed traffic (mostly normal, occasional attacks) over
sustained operation, where the benefit comes from suppressing false alarms
on legitimate traffic. Likewise, running a single loud attack type (DoS)
in isolation can make all three engines' metrics converge, since a
high-volume attack is the one case where they're all expected to agree.

---

## Design

The UI was rebuilt around a light, clinical look — white surfaces, a soft
gray canvas, and a single accent color reserved for primary actions and
the highest-trust detection tier — rather than the dense neon-on-black
aesthetic more common in security tooling, to keep the focus on the data
during a live research demo.

---

## License

MIT
