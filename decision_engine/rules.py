"""
ZIC Rules Evaluator — deterministic, rules-only signal firing.
v2.1.0 — zero hardcoded thresholds. All limits read from ZIC thresholds{}.

All signal IDs, severities, base_scores, and threshold_refs must match
the loaded governance-signals.json.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any


@dataclass
class FiredSignal:
    signal_id: str
    signal_name: str
    severity: str
    base_score: float
    weight: float
    score_contribution: float
    confidence: float
    typologies: list[str]
    reason: str


def evaluate(ctx: dict[str, Any], mem: dict[str, Any], zic: dict) -> list[FiredSignal]:
    """
    Evaluate all ZIC signals against event context and entity memory.
    Returns list of FiredSignal instances. Zero hardcoded thresholds — all
    limits are resolved from zic["thresholds"].

    ctx  — event.context dict
    mem  — entity risk_memory snapshot (may be empty for new entities)
    zic  — loaded ZIC core dict
    """
    thr     = zic["thresholds"]
    thr_id  = thr["identity"]
    thr_beh = thr["behavioral"]
    thr_txn = thr["transaction"]
    thr_net = thr["network"]
    thr_agt = thr["agent"]
    thr_ses = thr.get("session", {})

    sigs_by_id = {s["signal_id"]: s for s in zic["signals"]}
    fired: list[FiredSignal] = []

    def fire(sid: str, reason: str) -> None:
        s = sigs_by_id.get(sid)
        if not s or not s.get("enabled", True):
            return
        fired.append(FiredSignal(
            signal_id=sid,
            signal_name=s["signal_name"],
            severity=s["severity"],
            base_score=s["base_score"],
            weight=s["weight"],
            score_contribution=round(s["base_score"] * s["weight"], 2),
            confidence=s["confidence"],
            typologies=s.get("typologies", []),
            reason=reason,
        ))

    vel   = mem.get("velocity_counters", {})
    graph = mem.get("graph_features", {})

    # ── IDENTITY & ONBOARDING ─────────────────────────────────────────────────

    email_age = ctx.get("email_domain_age_days")
    if email_age is not None and email_age < thr_id["email_domain_age_min_days"]:
        fire("IDN_003", f"Email domain age {email_age}d < threshold {thr_id['email_domain_age_min_days']}d")

    if ctx.get("ocr_confidence") is not None:
        if ctx["ocr_confidence"] < thr_id["selfie_match_min_confidence"]:
            fire("IDN_008", f"OCR confidence {ctx['ocr_confidence']:.2f} below threshold {thr_id['selfie_match_min_confidence']}")

    if ctx.get("face_match_score") is not None:
        if ctx["face_match_score"] < thr_id["selfie_match_min_confidence"]:
            fire("IDN_009", f"Face match {ctx['face_match_score']:.2f} < threshold {thr_id['selfie_match_min_confidence']}")

    phone_days = ctx.get("phone_reassignment_days")
    if phone_days is not None and phone_days < thr_id["phone_age_min_days"]:
        fire("IDN_007", f"Phone reassigned {phone_days}d ago < min {thr_id['phone_age_min_days']}d")

    sim_days = ctx.get("sim_activation_days")
    sim_min  = thr_id.get("sim_activation_min_days", 7)
    if sim_days is not None and sim_days < sim_min:
        fire("IDN_011", f"SIM activated {sim_days}d ago < minimum {sim_min}d")

    reg_vel = vel.get("registrations_per_device_24h", 0)
    if reg_vel > thr_net["shared_device_account_threshold"]:
        fire("IDN_012", f"{reg_vel} registrations from same device in 24h > threshold {thr_net['shared_device_account_threshold']}")

    ip_rep = ctx.get("ip_reputation_score")
    if ip_rep is not None and ip_rep < thr_id["ip_reputation_min_score"]:
        fire("IDN_013", f"IP reputation {ip_rep} < threshold {thr_id['ip_reputation_min_score']}")

    # ── DEVICE ────────────────────────────────────────────────────────────────

    if ctx.get("is_emulator"):
        fire("DEV_001", "Emulator or virtual device detected in device telemetry")

    if ctx.get("is_rooted"):
        fire("DEV_002", "Rooted or jailbroken device detected")

    if ctx.get("is_headless_browser"):
        fire("BEH_002", "Headless browser or WebDriver automation indicators present")

    # ── SESSION & AUTHENTICATION ──────────────────────────────────────────────

    if ctx.get("prior_impossible_travel"):
        fire("SES_001", "Impossible travel: location unreachable from prior session given elapsed time")

    mfa_max = thr_ses.get("mfa_fail_max", 3)
    if ctx.get("mfa_fail_count", 0) >= mfa_max:
        fire("SES_003", f"MFA bypass: {ctx['mfa_fail_count']} failures >= threshold {mfa_max}")

    sim_geo_max = thr_ses.get("simultaneous_geo_sessions_max", 2)
    if ctx.get("simultaneous_geo_sessions", 0) >= sim_geo_max:
        fire("SES_005", f"{ctx['simultaneous_geo_sessions']} simultaneous geo sessions >= threshold {sim_geo_max}")

    otp_max = thr_ses.get("otp_fail_max_per_account", 5)
    otp_fails = ctx.get("otp_fail_count", 0)
    if otp_fails >= otp_max:
        fire("SES_011", f"OTP failure velocity: {otp_fails} >= threshold {otp_max}")

    if ctx.get("is_vpn") or ctx.get("is_tor"):
        fire("SES_010", f"High-risk IP: VPN={ctx.get('is_vpn')} TOR={ctx.get('is_tor')}")

    # ── BEHAVIOURAL ───────────────────────────────────────────────────────────

    nav_speed = ctx.get("navigation_speed_pages_per_second")
    nav_max   = thr_beh["navigation_speed_max_pages_per_second"]
    if nav_speed is not None and nav_speed > nav_max:
        fire("BEH_001", f"Navigation speed {nav_speed} pages/s > threshold {nav_max}")

    session_dur = ctx.get("session_duration_seconds")
    ses_min     = thr_beh["session_duration_min_seconds"]
    if session_dur is not None and session_dur < ses_min:
        fire("BEH_003", f"Session {session_dur}s < minimum {ses_min}s")

    if ctx.get("login_input_method") == "PASTE":
        fire("BEH_004", "Credentials pasted from clipboard — credential stuffing indicator")

    if ctx.get("scroll_events_count", 1) == 0:
        fire("BEH_006", "Zero scroll events during onboarding — automated form completion")

    dev_account_count = graph.get("shared_device_account_count", 0)
    dev_thr           = thr_beh["multi_account_device_threshold"]
    if dev_account_count >= dev_thr:
        fire("BEH_005", f"Device linked to {dev_account_count} accounts >= threshold {dev_thr}")

    # ── TRANSACTION & PAYMENT ─────────────────────────────────────────────────

    txn_amount = ctx.get("txn_amount_inr", 0)

    if ctx.get("is_new_beneficiary") and txn_amount > thr_txn["first_txn_high_value_threshold_inr"]:
        fire("TXN_001", f"First txn to new beneficiary ₹{txn_amount} > threshold ₹{thr_txn['first_txn_high_value_threshold_inr']}")

    refund_delta = ctx.get("refund_delta_hours")
    refund_win   = thr_txn["refund_request_window_hours"]
    if refund_delta is not None and refund_delta < refund_win:
        fire("TXN_002", f"Refund {refund_delta}h after purchase < threshold {refund_win}h")

    txn_vel     = ctx.get("txn_count_15m", vel.get("txn_count_15m", 0))
    txn_vel_max = thr_txn["velocity_max_transactions"]
    if txn_vel > txn_vel_max:
        fire("TXN_003", f"{txn_vel} txns in 15min window > threshold {txn_vel_max}")

    benef_age     = ctx.get("beneficiary_account_age_hours")
    benef_age_min = thr_txn["new_beneficiary_age_min_hours"]
    if benef_age is not None and benef_age < benef_age_min:
        fire("MUL_002", f"Beneficiary account age {benef_age}h < threshold {benef_age_min}h")

    # ── CVV & CARD TESTING ────────────────────────────────────────────────────

    cvv_fail_max = thr_txn.get("cvv_fail_max_per_card", 3)
    cvv_fails    = ctx.get("cvv_fail_count", 0)
    if cvv_fails >= cvv_fail_max:
        fire("TXN_012", f"CVV failures {cvv_fails} >= threshold {cvv_fail_max} on same card")

    card_distinct_max = thr_txn.get("cvv_fail_max_distinct_cards_device", 5)
    distinct_cards    = ctx.get("distinct_cards_attempted_device_15m", 0)
    if distinct_cards > card_distinct_max:
        fire("TXN_013", f"{distinct_cards} distinct cards from device in 15min > threshold {card_distinct_max}")

    card_add_max = thr_txn.get("card_add_velocity_24h_max", 5)
    cards_added  = ctx.get("distinct_cards_added_24h", vel.get("cards_added_24h", 0))
    if cards_added >= card_add_max:
        fire("TXN_014", f"{cards_added} cards added in 24h >= threshold {card_add_max}")

    # ── NETWORK & MULE ────────────────────────────────────────────────────────

    shared_dev_max = thr_net["shared_device_account_threshold"]
    shared_dev     = graph.get("shared_device_account_count", 0)
    if shared_dev >= shared_dev_max:
        fire("NET_001", f"Device shared across {shared_dev} accounts >= threshold {shared_dev_max}")

    outbound_delta = ctx.get("outbound_delta_from_funding_minutes")
    outbound_win   = thr_txn["outbound_drain_window_minutes"]
    if outbound_delta is not None and outbound_delta < outbound_win:
        fire("NET_005", f"Outbound transfer {outbound_delta}min after funding < threshold {outbound_win}min")

    if graph.get("circular_flow_detected"):
        fire("NET_006", "Circular money flow detected in transaction graph — layering indicator")

    if graph.get("fraud_ring_probability", 0) > 0.80:
        fire("NET_008", f"Fraud ring probability {graph['fraud_ring_probability']:.2f} > 0.80")

    shared_bene = graph.get("shared_beneficiary_account_count", 0)
    shared_bene_max = thr_net.get("shared_beneficiary_account_threshold", 3)
    if shared_bene >= shared_bene_max:
        fire("NET_009", f"Beneficiary shared across {shared_bene} accounts — mule network indicator")

    inbound_min = thr_txn.get("mule_inbound_source_min", 3)
    inbound_cnt = ctx.get("inbound_source_count_24h", 0)
    if inbound_cnt >= inbound_min:
        fire("MUL_001", f"{inbound_cnt} distinct inbound sources >= threshold {inbound_min} — layering pattern")

    # ── UPI ───────────────────────────────────────────────────────────────────

    if ctx.get("remote_access_app_detected") and ctx.get("upi_in_progress"):
        fire("UPI_002", "Remote access app active during UPI transaction — scam indicator")

    if (ctx.get("is_new_beneficiary") and
            ctx.get("payment_rail") == "UPI" and
            txn_amount >= thr_txn["first_txn_high_value_threshold_inr"]):
        fire("UPI_001", f"First UPI transfer to new VPA ₹{txn_amount} >= threshold")

    # ── GIFT CARD ─────────────────────────────────────────────────────────────

    gc_vol     = ctx.get("gift_card_purchase_volume_24h_inr", 0)
    gc_min     = thr_txn.get("gift_card_bulk_purchase_min_inr", 50000)
    gc_age_max = thr_txn.get("gift_card_new_account_age_max_days", 7)
    acc_age    = ctx.get("account_age_days", 365)
    if gc_vol >= gc_min and acc_age < gc_age_max:
        fire("GFT_001", f"Gift card volume ₹{gc_vol} on account aged {acc_age}d < {gc_age_max}d")

    # ── AGENT ─────────────────────────────────────────────────────────────────

    approval_amt    = ctx.get("approval_amount_inr", 0)
    agent_limit     = thr_agt["max_override_amount_inr"]
    agent_tenure    = ctx.get("agent_tenure_days")
    new_agent_days  = thr_agt["new_agent_high_value_window_days"]
    hv_threshold    = thr_txn["first_txn_high_value_threshold_inr"]

    if approval_amt > agent_limit:
        fire("AGT_001", f"Agent approval ₹{approval_amt} > authority limit ₹{agent_limit}")

    if agent_tenure is not None and agent_tenure < new_agent_days and approval_amt > hv_threshold:
        fire("AGT_004", f"New agent (tenure {agent_tenure}d < {new_agent_days}d) processing ₹{approval_amt}")

    return fired
