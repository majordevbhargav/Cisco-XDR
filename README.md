# Cisco XDR Lab

A lab-scale security analytics project exploring how network-flow telemetry, endpoint identity, posture, and security signals can be correlated into prioritized incidents.

> **Goal:** understand how raw network telemetry can become useful security context.

## Architecture

```text
Network / Lab Flow Data
          |
          v
      FlowWatch
   +------+------+ 
   |      |      |
Traffic Context Risk
   |      |      |
   +------+------+ 
          |
          v
       XDR Hub
       /     \
      v       v
 Cisco ISE   Security Analytics
       \     /
        \   /
         v v
   Unified Incident
```

## Components

### SentinelX
A simulated research environment for comparing traffic-only, context-aware, and risk-informed detection approaches.

### FlowWatch
The network-flow collection and detection layer. It receives NetFlow telemetry and produces scored flows and alerts.

### XDR Hub
The correlation layer. It combines network findings with identity and posture context to build host-oriented incidents.

## Detection Approach

| Layer | Purpose |
|---|---|
| Traffic | Identify unusual flow behaviour |
| Context | Add device, VLAN, role, policy, and destination information |
| Risk | Prioritize findings using asset importance |
| Correlation | Combine related signals into an incident view |

## Learning Goals

This project is helping me connect:

- Network security
- NetFlow
- Cisco ISE
- Endpoint posture
- Security analytics
- Incident correlation
- Python application development
- Enterprise security architecture

## Current Scope

This is a learning and lab project, not a production XDR platform. Some integrations are simulated or lab-specific and require further validation before operational use.

## Development Direction

- NetFlow v9 / IPFIX support
- Stronger event correlation
- Persistent PostgreSQL/TimescaleDB storage
- Detection tuning and baseline analysis
- Additional Cisco security integrations
- Better incident investigation workflows

## Security

Use only with systems, networks, and telemetry that you own or are explicitly authorized to monitor. Never commit credentials, tokens, or private infrastructure information.

## Author

**Dev Bhargav**

[GitHub](https://github.com/majordevbhargav) · [LinkedIn](https://www.linkedin.com/in/devbhargav100)
