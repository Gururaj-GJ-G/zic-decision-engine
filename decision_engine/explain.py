"""
ZICExplain Generator — policy_path builder + human summary.

All policy_path step prefixes follow policy_path_conventions.md:
  BAND_   — scoring band step
  RULE_   — composite rule step
  TRUST_  — trust/memory context step
  ML_     — ML feature step (future)
  GRAPH_  — graph intelligence step
  SIM_    — simulation prefix (prepended when simulation_mode=True)
"""

from __future__ import annotations
from typing import Any
from rules import FiredSignal
from composite import FiredCompositeRule


# Ordered action severity for display
ACTION_LABEL = {
    "ALLOW": "Allow",
    "MONITOR": "Monitor",
    "STEP_UP": "Step-Up Verification",
    "VELOCITY_LIMIT": "Velocity Limit",
    "MANUAL_REVIEW": "Manual Review",
    "SOFT_BLOCK": "Soft Block",
    "BLOCK": "Block",
    "SUSPEND": "Account Suspend",
    "TERMINATE": "Account Terminate",
    "ESCALATE_SAR": "Escalate — SAR",
}

TYPOLOGY_NAMES = {
    "ATO_001": ("Account Takeover", "CRITICAL"),
    "SYN_001": ("Synthetic Identity Fraud", "HIGH"),
    "FAK_001": ("Fake Account Networks", "HIGH"),
    "PRO_001": ("Promotional Abuse", "HIGH"),
    "MUL_001": ("Mule Account Activity", "CRITICAL"),
    "TXF_001": ("Transaction Fraud", "HIGH"),
    "INT_001": ("Internal / Agent Fraud", "HIGH"),
    "INV_001": ("Investment / Recovery Scam", "HIGH"),
}


def build_policy_path(
    band: str,
    final_action: str,
    composite_rules: list[FiredCompositeRule],
    graph_features: dict,
    memory_score: float | None,
    simulation_mode: bool = False,
) -> list[str]:
    """
    Build the ordered policy_path trace for this decision.
    Each step is a string with a governed prefix.
    """
    steps: list[str] = []
    prefix = "SIM_" if simulation_mode else ""

    # 1. Band step
    band_labels = {
        "BAND_01": "CLEAR", "BAND_02": "ELEVATED",
        "BAND_03": "SUSPICIOUS", "BAND_04": "HIGH_RISK", "BAND_05": "CRITICAL",
    }
    steps.append(f"{prefix}BAND_{band_labels.get(band, band)}")

    # 2. Trust/memory context step
    if memory_score is not None:
        if memory_score >= 60:
            steps.append(f"{prefix}TRUST_PRIOR_HIGH_RISK_MEMORY_{int(memory_score)}")
        elif memory_score >= 40:
            steps.append(f"{prefix}TRUST_PRIOR_ELEVATED_MEMORY_{int(memory_score)}")

    # 3. Graph step if graph signals are meaningful
    if graph_features.get("fraud_ring_probability", 0) > 0.7:
        steps.append(f"{prefix}GRAPH_FRAUD_RING_PROBABILITY_{int(graph_features['fraud_ring_probability']*100)}")
    if graph_features.get("circular_flow_detected"):
        steps.append(f"{prefix}GRAPH_CIRCULAR_FLOW_DETECTED")
    if graph_features.get("shared_device_account_count", 0) >= 3:
        steps.append(f"{prefix}GRAPH_SHARED_DEVICE_{graph_features['shared_device_account_count']}_ACCOUNTS")

    # 4. Composite rule steps
    for rule in composite_rules:
        rule_slug = rule.rule_name.upper().replace(" ", "_").replace("/", "_").replace("-", "_")
        steps.append(f"{prefix}RULE_{rule.rule_id}_{rule_slug}")

    # 5. Final action step
    steps.append(f"{prefix}ACTION_{final_action}")

    return steps


def build_human_summary(
    band: str,
    final_action: str,
    fired_signals: list[FiredSignal],
    composite_rules: list[FiredCompositeRule],
    score: float,
    typologies: list[str],
) -> str:
    """
    Generate a plain-English explanation suitable for investigators and audit.
    """
    band_desc = {
        "BAND_01": "no significant risk indicators",
        "BAND_02": "low-level signals present",
        "BAND_03": "multiple suspicious signals detected",
        "BAND_04": "strong fraud indicators present",
        "BAND_05": "high-confidence fraud pattern detected",
    }.get(band, band)

    action_desc = ACTION_LABEL.get(final_action, final_action)
    top_3 = sorted(fired_signals, key=lambda s: s.score_contribution, reverse=True)[:3]
    signal_list = ", ".join(f"{s.signal_name} ({s.signal_id})" for s in top_3)

    typ_names = [TYPOLOGY_NAMES.get(t, (t, ""))[0] for t in typologies[:3]]
    typ_str = ", ".join(typ_names) if typ_names else "no specific typology matched"

    summary = (
        f"Risk score {score:.0f}/100 — {band_desc}. "
        f"Decision: {action_desc}. "
    )
    if signal_list:
        summary += f"Primary signals: {signal_list}. "
    if composite_rules:
        rule_names = ", ".join(r.rule_name for r in composite_rules)
        summary += f"Composite rules triggered: {rule_names}. "
    summary += f"Fraud typologies indicated: {typ_str}."
    return summary


def build_evidence(fired_signals: list[FiredSignal]) -> list[str]:
    """Return evidence strings for top signals, ordered by contribution."""
    top = sorted(fired_signals, key=lambda s: s.score_contribution, reverse=True)[:5]
    return [f"{s.signal_name}: {s.reason}" for s in top]


def build_explain(
    band: str,
    final_action: str,
    score: float,
    fired_signals: list[FiredSignal],
    composite_rules: list[FiredCompositeRule],
    typologies: list[str],
    graph_features: dict,
    memory_score: float | None,
    simulation_mode: bool = False,
) -> dict:
    """
    Assemble the full ZICExplain object.
    """
    policy_path = build_policy_path(
        band, final_action, composite_rules,
        graph_features, memory_score, simulation_mode,
    )

    top_signals = sorted(fired_signals, key=lambda s: s.score_contribution, reverse=True)[:5]

    return {
        "policy_path": policy_path,
        "human_summary": build_human_summary(
            band, final_action, fired_signals, composite_rules, score, typologies
        ),
        "top_signals": [
            {
                "signal_id": s.signal_id,
                "signal_name": s.signal_name,
                "contribution": s.score_contribution,
                "reason": s.reason,
            }
            for s in top_signals
        ],
        "typologies_triggered": [
            {
                "pattern_id": t,
                "pattern_name": TYPOLOGY_NAMES.get(t, (t, ""))[0],
                "severity": TYPOLOGY_NAMES.get(t, ("", "UNKNOWN"))[1],
            }
            for t in typologies
        ],
        "graph_summary": {
            k: v for k, v in graph_features.items()
            if k in {
                "shared_device_account_count",
                "shared_beneficiary_account_count",
                "fraud_ring_probability",
                "network_density_score",
                "circular_flow_detected",
                "inbound_source_count",
                "outbound_drain_minutes",
            }
        },
        "evidence": build_evidence(fired_signals),
        "recommended_next_action": _recommended_next(final_action, typologies),
    }


def _recommended_next(action: str, typologies: list[str]) -> str:
    if action in ("SUSPEND", "TERMINATE"):
        if "MUL_001" in typologies:
            return "Initiate SAR review. Check linked entities for mule ring membership."
        return "Open fraud investigation case. Preserve all session and transaction logs."
    if action == "BLOCK":
        return "Review device and IP for shared account indicators. Consider device-level block."
    if action == "MANUAL_REVIEW":
        return "Assign to fraud analyst queue. SLA: 4 hours. Check entity memory for prior incidents."
    if action == "STEP_UP":
        return "Trigger step-up authentication flow. Log outcome for memory update."
    if action == "ESCALATE_SAR":
        return "File STR/SAR with compliance team within 24 hours."
    return "No immediate investigator action required. Continue monitoring."
