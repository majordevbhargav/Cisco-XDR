# Cisco XDR Lab

A lab-scale security analytics project that explores how network-flow anomaly detection, endpoint identity, posture, and security-analytics signals can be correlated into prioritized incidents.

## Architecture

```text
Real / Simulated Flow Data
          ↓
       FlowWatch
   ┌──────┼──────┐
   ↓      ↓      ↓
Traffic Context Risk
          ↓
       XDR Hub
      ↙       ↘
 Cisco ISE   Secure Network Analytics
      \       /
       Unified Incident
```

## Components

### SentinelX

A simulated environment used to design and compare traffic-only, context-aware, and risk-informed detection.

### FlowWatch

The real-flow collector. It receives NetFlow v5, applies the same detection concepts to network traffic, and exposes scored flows and alarms.

### XDR Hub

The correlation layer. It combines FlowWatch findings with identity/posture context and Secure Network Analytics-style alerts to create host-oriented incidents.

## Getting Started

Each component can be run independently. Start with the component README for its dependencies and configuration.

Typical development flow:

```bash
# FlowWatch
cd flowwatch
pip install -r requirements.txt
python3 backend/app.py
```

Then run the XDR Hub and its lab mocks according to its local configuration.

## Detection Model

- Traffic anomalies identify unusual flow behavior.
- Context adds device, VLAN, role, policy, and destination information.
- Risk scoring prioritizes events using contextual importance.
- Correlation combines independent signals into a single host-oriented incident.

## Current Limitations

- FlowWatch currently centers on NetFlow v5.
- Some Cisco integrations use lab/mock connectors.
- XDR Hub state is not intended as a persistent production incident store.
- Thresholds and scoring are research/prototype choices and require validation before operational deployment.

## Security

This project is intended for defensive security research and authorized lab environments. Never commit real Cisco ISE credentials, tokens, flow data, or private infrastructure details.

## License

MIT

## Author

**Dev Bhargav**

- GitHub: https://github.com/majordevbhargav
- LinkedIn: https://www.linkedin.com/in/devbhargav100
