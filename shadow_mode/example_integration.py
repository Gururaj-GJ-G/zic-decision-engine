"""
ZIC Shadow Mode — Integration Example
======================================
Shows exactly how to add one line to your existing Fraud Pattern Detector.

BEFORE (your current code):
    def check_transaction(txn):
        decision = your_existing_fraud_check(txn)
        return decision

AFTER (with shadow mode):
    def check_transaction(txn):
        decision = your_existing_fraud_check(txn)
        shadow.evaluate(your_decision=decision, ...)   # ← add this one line
        return decision                                 # ← nothing else changes

Your production path is unchanged. Shadow runs in a background thread.
"""

import time
from shadow_client import ShadowClient, build_context

# ── Initialise shadow client once at startup ──────────────────────────────────
# Point these at your running engine and memory service.
shadow = ShadowClient(
    zic_url     = "http://localhost:8000",
    memory_url  = "http://localhost:8001",
    log_dir     = "shadow_mode/logs",
    zic_version = "2.1.0",
    enabled     = True,
)

print("✓ Shadow client initialised\n")


# ── Example 1: UPI transfer ───────────────────────────────────────────────────
# This simulates what your Fraud Pattern Detector calls after its own check.

def your_existing_upi_check(account_id, txn_amount, is_new_vpa, device_id, ip):
    """Placeholder for your existing fraud logic."""
    # Your current system only checks basic velocity
    if txn_amount > 100000:
        return "MANUAL_REVIEW"
    return "ALLOW"


def process_upi_transfer(account_id, txn_amount, is_new_vpa, device_id, ip_addr,
                          ip_score, outbound_delay_min, inbound_count, bene_age_hrs):

    # 1. Your existing check (unchanged)
    your_decision = your_existing_upi_check(
        account_id, txn_amount, is_new_vpa, device_id, ip_addr
    )

    # 2. Shadow evaluation — ONE line added, non-blocking
    shadow.evaluate(
        your_decision    = your_decision,
        event_type       = "TXN_ATTEMPT",
        primary_entity   = {"entity_type": "ACCOUNT", "entity_id": account_id},
        related_entities = [
            {"entity_type": "DEVICE",      "entity_id": device_id},
            {"entity_type": "IP",          "entity_id": f"ip:{ip_addr}"},
            {"entity_type": "BENEFICIARY", "entity_id": "bene_unknown"},
        ],
        context = build_context(
            payment_rail                       = "UPI",
            txn_amount_inr                     = txn_amount,
            is_new_beneficiary                 = is_new_vpa,
            beneficiary_account_age_hours      = bene_age_hrs,
            device_fingerprint                 = device_id,
            ip_address                         = ip_addr,
            ip_reputation_score                = ip_score,
            outbound_delta_from_funding_minutes= outbound_delay_min,
            inbound_source_count_24h           = inbound_count,
            upi_in_progress                    = True,
            account_age_days                   = 14,
        ),
        metadata = {
            "source_system": "FraudPatternDetector",
            "rail":          "UPI",
            "account_id":    account_id,
        }
    )

    # 3. Return your existing decision — production path unchanged
    return your_decision


# ── Example 2: Card payment ───────────────────────────────────────────────────

def process_card_payment(account_id, device_id, ip_addr, ip_score,
                          is_emulator, is_headless, nav_speed,
                          txn_count_15m, distinct_cards, session_dur):

    # Your existing decision (simplified)
    your_decision = "ALLOW" if txn_count_15m < 5 else "MANUAL_REVIEW"

    shadow.evaluate(
        your_decision    = your_decision,
        event_type       = "TXN_ATTEMPT",
        primary_entity   = {"entity_type": "DEVICE", "entity_id": device_id},
        related_entities = [
            {"entity_type": "ACCOUNT", "entity_id": account_id},
            {"entity_type": "IP",      "entity_id": f"ip:{ip_addr}"},
        ],
        context = build_context(
            payment_rail                       = "CARD_DEBIT",
            txn_amount_inr                     = 1,
            is_emulator                        = is_emulator,
            is_headless_browser                = is_headless,
            ip_address                         = ip_addr,
            ip_reputation_score                = ip_score,
            navigation_speed_pages_per_second  = nav_speed,
            txn_count_15m                      = txn_count_15m,
            distinct_cards_attempted_device_15m= distinct_cards,
            session_duration_seconds           = session_dur,
            scroll_events_count                = 0,
            login_input_method                 = "PASTE",
        ),
        metadata = {"source_system": "FraudPatternDetector", "rail": "CARD"}
    )

    return your_decision


# ── Run examples ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("── Test 1: UPI mule-style transfer ──────────────────────────")
    result1 = process_upi_transfer(
        account_id      = "acct_9f3a1c",
        txn_amount      = 48500,
        is_new_vpa      = True,
        device_id       = "dev_fp_8b2e44",
        ip_addr         = "103.21.244.7",
        ip_score        = 28,
        outbound_delay_min = 12,
        inbound_count   = 4,
        bene_age_hrs    = 18,
    )
    print(f"  Your system decided: {result1}")

    print("\n── Test 2: Card testing attack ───────────────────────────────")
    result2 = process_card_payment(
        account_id      = "acct_anon_4421",
        device_id       = "dev_fp_c7f923",
        ip_addr         = "45.33.32.156",
        ip_score        = 12,
        is_emulator     = True,
        is_headless     = True,
        nav_speed       = 8.5,
        txn_count_15m   = 18,
        distinct_cards  = 14,
        session_dur     = 2,
    )
    print(f"  Your system decided: {result2}")

    print("\n── Test 3: Normal legitimate payment ─────────────────────────")
    result3 = process_card_payment(
        account_id      = "acct_trusted_user",
        device_id       = "dev_fp_known_iphone",
        ip_addr         = "49.36.105.200",
        ip_score        = 82,
        is_emulator     = False,
        is_headless     = False,
        nav_speed       = 0.4,
        txn_count_15m   = 1,
        distinct_cards  = 1,
        session_dur     = 145,
    )
    print(f"  Your system decided: {result3}")

    # Wait for shadow queue to drain
    print("\nWaiting for shadow evaluations to complete...")
    time.sleep(8)

    # Print stats
    stats = shadow.stats()
    print(f"\n── Shadow Client Stats ──────────────────────────────────────")
    print(f"  Events queued:     {stats['events_queued']}")
    print(f"  Events processed:  {stats['events_processed']}")
    print(f"  ZIC errors:        {stats['zic_errors']}")
    print(f"  Divergences:       {stats['divergences']}")
    print(f"    ZIC stricter:    {stats['divergences_looser']}")
    print(f"    ZIC looser:      {stats['divergences_stricter']}")
    print(f"  Queue drops:       {stats['queue_drops']}")

    if stats['zic_errors'] > 0:
        print(f"\n  ⚠ {stats['zic_errors']} ZIC errors — is the engine running on port 8000?")
        print(f"    Start it with: cd decision_engine_mvp && uvicorn main:app --port 8000")
    elif stats['events_processed'] == 0:
        print(f"\n  ⚠ No events processed — engine not reachable (running in offline mode)")
        print(f"    Events are saved to dead-letter queue: shadow_mode/logs/dlq_*.jsonl")
    else:
        print(f"\n  Check shadow_mode/logs/ for decision and divergence logs")
        print(f"  Run: python shadow_report.py --log-dir shadow_mode/logs")
