"""
Correlation engine — the actual "XDR" part.

Takes raw alarms from FlowWatch (NetFlow-based detection) and Secure
Network Analytics (Cisco's flow-analytics alarms), groups them by IP, and
enriches each group with ISE identity/posture context. The result is a
unified incident per IP instead of three disconnected alert streams an
analyst would otherwise have to mentally merge themselves.

Severity fusion is deliberately conservative and explainable:
  - each source alarm maps to a 0-100 base severity
  - an IP with alarms from MULTIPLE independent sources gets a
    corroboration bonus (two tools agreeing is stronger signal than one)
  - ISE context can escalate (non-compliant posture, quarantine/untrusted
    SGT) but never suppress a finding from the other two sources
"""

import time

FW_TIER_SCORE = {"Critical": 90, "High": 70, "Medium": 40, "Low": 10}
SNA_SEVERITY_SCORE = {"Critical": 95, "Major": 65, "Minor": 30}


def _fw_base_score(alarm):
    return FW_TIER_SCORE.get(alarm.get("risk_tier"), 20)


def _sna_base_score(alarm):
    return SNA_SEVERITY_SCORE.get(alarm.get("severity"), 20)


def _ise_escalation(identity):
    """ISE context never generates an incident by itself, but a clear risk
    signal (non-compliant posture, an untrusted/quarantine SGT) bumps
    severity on top of a finding that already exists from another source."""
    bump = 0
    reasons = []
    if identity.get("posture_status") == "NonCompliant":
        bump += 15
        reasons.append("Device posture is Non-Compliant per ISE")
    if identity.get("security_group") in ("Quarantine", "IoT-Untrusted"):
        bump += 10
        reasons.append(f"ISE security group '{identity['security_group']}' is untrusted/quarantined")
    return bump, reasons


def severity_tier(score):
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def correlate(flowwatch_alarms, sna_alarms, ise_connector):
    """Returns a list of unified incidents, one per IP with at least one
    alarm, sorted by severity score descending."""
    by_ip = {}

    for a in flowwatch_alarms:
        ip = a.get("src_ip")
        if not ip:
            continue
        by_ip.setdefault(ip, {"ip": ip, "fw_alarms": [], "sna_alarms": []})
        by_ip[ip]["fw_alarms"].append(a)

    for a in sna_alarms:
        ip = a.get("sourceIp")
        if not ip:
            continue
        by_ip.setdefault(ip, {"ip": ip, "fw_alarms": [], "sna_alarms": []})
        by_ip[ip]["sna_alarms"].append(a)

    incidents = []
    for ip, bucket in by_ip.items():
        fw_alarms, sna_alarms_for_ip = bucket["fw_alarms"], bucket["sna_alarms"]

        fw_score = max((_fw_base_score(a) for a in fw_alarms), default=0)
        sna_score = max((_sna_base_score(a) for a in sna_alarms_for_ip), default=0)
        base_score = max(fw_score, sna_score)

        sources_hit = sum([bool(fw_alarms), bool(sna_alarms_for_ip)])
        corroboration_bonus = 15 if sources_hit >= 2 else 0

        identity = ise_connector.get_identity(ip)
        ise_bump, ise_reasons = _ise_escalation(identity)

        total_score = min(100, base_score + corroboration_bonus + ise_bump)

        evidence = []
        seen_fw_summaries = set()
        for a in fw_alarms:
            reason = None
            try:
                import json
                reasons_list = json.loads(a.get("risk_reasons", "[]"))
                reason = reasons_list[0] if reasons_list else a.get("risk_action")
            except Exception:
                reason = a.get("risk_action")
            reason = reason or "Anomalous flow detected"
            if reason in seen_fw_summaries:
                continue  # multiple flows often share the same violation text (e.g. a port scan);
            seen_fw_summaries.add(reason)  # one line per distinct reason keeps this readable
            evidence.append({"source": "FlowWatch", "summary": reason, "tier": a.get("risk_tier")})
        if len(fw_alarms) > len(seen_fw_summaries):
            evidence.append({"source": "FlowWatch", "summary": f"({len(fw_alarms)} flows total from this host)",
                              "tier": None})
        for a in sna_alarms_for_ip:
            evidence.append({"source": "SecureAnalytics", "summary": f"{a.get('alarmType')}: {a.get('detail')}",
                              "tier": a.get("severity")})
        for r in ise_reasons:
            evidence.append({"source": "ISE", "summary": r, "tier": "context"})

        incidents.append({
            "ip": ip,
            "score": total_score,
            "tier": severity_tier(total_score),
            "sources": [s for s, present in
                        (("FlowWatch", fw_alarms), ("SecureAnalytics", sna_alarms_for_ip)) if present],
            "corroborated": sources_hit >= 2,
            "identity": {
                "username": identity.get("username"),
                "device_type": identity.get("device_type"),
                "posture_status": identity.get("posture_status"),
                "security_group": identity.get("security_group"),
            },
            "evidence": evidence,
            "observed_at": time.time(),
        })

    incidents.sort(key=lambda i: i["score"], reverse=True)
    return incidents
