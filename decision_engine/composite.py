"""
ZIC Composite Rule Evaluator.

Composite rules are applied AFTER individual signal scoring.
All rule_ids must match ZIC decision_logic.rules[].rule_id.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Sequence


@dataclass
class FiredCompositeRule:
    rule_id: str
    rule_name: str
    score_addition: float
    action_override: str
    priority: int


def evaluate(
    fired_signal_ids: set[str],
    composite_score: float,
    zic: dict,
) -> list[FiredCompositeRule]:
    """
    Evaluate ZIC composite decision rules against fired signal IDs and running score.

    fired_signal_ids — set of signal_id strings that fired
    composite_score  — running score before composite additions
    zic              — loaded ZIC core dict
    """
    rules = zic["decision_logic"]["rules"]
    fired_rules: list[FiredCompositeRule] = []

    for rule in sorted(rules, key=lambda r: r["priority"]):
        rid = rule["rule_id"]

        matched = False

        # DL_001 — ATO Compound: headless browser AND paste credentials
        if rid == "DL_001":
            matched = "BEH_002" in fired_signal_ids and "BEH_004" in fired_signal_ids

        # DL_002 — Mule Drain Compound: outbound drain AND layering
        elif rid == "DL_002":
            matched = "NET_005" in fired_signal_ids and "MUL_001" in fired_signal_ids

        # DL_003 — Synthetic Identity Compound: document velocity AND KYC anomaly
        elif rid == "DL_003":
            matched = "IDN_002" in fired_signal_ids and "IDN_005" in fired_signal_ids

        # DL_004 — Promo Network Compound: shared device AND rapid promo redemption
        elif rid == "DL_004":
            matched = "NET_001" in fired_signal_ids and "NET_003" in fired_signal_ids

        # DL_005 — High Score Auto-Block: any score above threshold
        elif rid == "DL_005":
            threshold = 85
            running = composite_score + sum(r.score_addition for r in fired_rules)
            matched = running > threshold

        if matched:
            fired_rules.append(FiredCompositeRule(
                rule_id=rid,
                rule_name=rule["rule_name"],
                score_addition=rule["score_addition"],
                action_override=rule["action_override"],
                priority=rule["priority"],
            ))

    return fired_rules


def highest_priority_action(
    band_default_action: str,
    composite_rules: list[FiredCompositeRule],
) -> str:
    """
    Return the most severe action across band default + composite rule overrides.
    Action severity order (ascending): ALLOW < MONITOR < STEP_UP < VELOCITY_LIMIT
                                       < MANUAL_REVIEW < SOFT_BLOCK < BLOCK
                                       < SUSPEND < TERMINATE < ESCALATE_SAR
    """
    severity_order = [
        "ALLOW", "MONITOR", "STEP_UP", "VELOCITY_LIMIT",
        "MANUAL_REVIEW", "SOFT_BLOCK", "SUSPEND", "BLOCK",
        "TERMINATE", "ESCALATE_SAR",
    ]
    all_actions = [band_default_action] + [r.action_override for r in composite_rules]
    indices = [severity_order.index(a) for a in all_actions if a in severity_order]
    return severity_order[max(indices)] if indices else band_default_action
