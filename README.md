# Cisco XDR Lab

> **A lab-scale security analytics project exploring network telemetry, endpoint context, identity, posture, and incident correlation.**

![Status](https://img.shields.io/badge/status-research%20%2F%20lab-informational)
![Focus](https://img.shields.io/badge/focus-network%20security-blue)

## Goal

Understand how raw network telemetry can be enriched with endpoint and identity context and transformed into prioritized, host-oriented security incidents.

This is a learning and architecture project, not a production XDR platform. Integrations may be simulated or lab-specific.

## Architecture

```text
Network / Lab Flow Data
          │
          ▼
      FlowWatch
   ┌──────┼──────┐
 Traffic Context Risk
   └──────┼──────┘
          │
          ▼
       XDR Hub
       /     \
      ▼       ▼
 Cisco ISE   Security Analytics
       \     /
        ▼   ▼
   Unified Incident
          │
          ▼
   Investigation View
```

## Signal Pipeline

| Layer | Purpose |
|---|---|
| **Traffic** | Identify unusual flow behaviour |
| **Context** | Add device, VLAN, role, policy, and destination information |
| **Risk** | Prioritize findings using asset importance |
| **Correlation** | Combine related signals into host-centric incidents |

## Components

### FlowWatch
Network-flow collection and detection layer producing scored flows and alerts.

### SentinelX
Research environment for comparing traffic-only, context-aware, and risk-informed detection approaches.

### XDR Hub
Correlation layer that combines network findings with identity and posture context.

### Cisco ISE
Represents the identity and endpoint-policy context available in an enterprise security environment.

## Learning Objectives

- NetFlow and network telemetry
- Context-aware network detection
- Cisco ISE concepts
- Endpoint posture
- Security analytics
- Incident correlation
- Risk modelling
- Defensive security architecture
- Python application engineering

## Development Direction

- NetFlow v9 / IPFIX
- Persistent PostgreSQL / TimescaleDB storage
- Stronger event correlation
- Detection tuning and baseline analysis
- Additional Cisco security integrations
- Better incident investigation workflows
- Reproducible attack/normal-traffic lab scenarios

## Security

Use only with systems, networks, and telemetry that you own or are explicitly authorized to monitor. Never commit credentials, tokens, or private infrastructure information.

## Author

**Dev Bhargav**  
[GitHub](https://github.com/majordevbhargav) · [LinkedIn](https://www.linkedin.com/in/devbhargav100)
