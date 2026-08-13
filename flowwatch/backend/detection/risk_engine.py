"""
Risk-Informed engine: fuses traffic anomaly, context risk, and asset
criticality into a single 0-100 operational score with a priority tier and
a recommended response -- the thing an analyst actually acts on, instead of
a raw model score.
"""

TIER_THRESHOLDS = [
    (85, "Critical", "Isolate host and page on-call immediately"),
    (65, "High", "Open incident, restrict host network access"),
    (35, "Medium", "Flag for analyst review this shift"),
    (0, "Low", "Log only, no action required"),
]


def tier_for(score: float):
    for threshold, tier, action in TIER_THRESHOLDS:
        if score >= threshold:
            return tier, action
    return "Low", "Log only, no action required"


class RiskInformedEngine:
    def score(self, flow: dict, traffic_result: dict, context_result: dict) -> dict:
        traffic_component = traffic_result["score"] * 100
        context_component = context_result["context_score"] * 100
        dst_criticality = context_result["dst_context"]["criticality"] / 5.0 * 100
        src_unknown_penalty = 20 if not context_result["src_context"]["known"] else 0

        weighted = (
            0.35 * traffic_component +
            0.35 * context_component +
            0.20 * dst_criticality +
            0.10 * src_unknown_penalty
        )

        # Hard floors: certain signals are deterministic escalations regardless
        # of how the weighted blend comes out, because averaging them away
        # would hide a real policy breach or a slam-dunk volumetric attack.
        if context_result["context_score"] >= 0.8:
            weighted = max(weighted, 75)  # confirmed policy/VLAN violation -> at least High
        if traffic_result["score"] >= 0.8:
            weighted = max(weighted, 65)  # unambiguous volumetric outlier -> at least High
        if context_result["context_score"] >= 0.8 and dst_criticality >= 80:
            weighted = max(weighted, 85)  # policy violation against a critical asset -> Critical

        score = round(min(100.0, weighted), 1)
        tier, action = tier_for(score)

        reasons = []
        if traffic_result["anomaly"]:
            reasons.append(f"Traffic pattern is statistically anomalous ({traffic_result['method']})")
        reasons.extend(context_result["violations"])
        if context_result["dst_context"]["criticality"] >= 4:
            reasons.append(f"Destination is a high-criticality asset ({context_result['dst_context']['name']})")
        if not reasons:
            reasons.append("No anomaly or policy signal detected")

        return {
            "score": score,
            "tier": tier,
            "recommended_action": action,
            "reasons": reasons,
            "anomaly": tier in ("High", "Critical"),
        }
