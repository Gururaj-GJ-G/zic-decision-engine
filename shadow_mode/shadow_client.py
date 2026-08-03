"""
ZIC Shadow Mode Client
======================
Drop-in wrapper that sits between your existing Fraud Pattern Detector
and the ZIC /decide endpoint.

In shadow mode:
  - Your existing fraud logic continues to make real decisions (no impact)
  - Every event is ALSO sent to ZIC /decide in the background
  - All ZIC decisions are logged to JSONL for replay analysis
  - Divergences (ZIC vs your system) are flagged and reported
  - Zero latency impact on your production path (async, non-blocking)

Usage — drop into your existing code:
    from shadow_client import ShadowClient

    # Initialise once at startup
    shadow = ShadowClient(
        zic_url="http://localhost:8000",
        memory_url="http://localhost:8001",
        log_dir="shadow_mode/logs",
        zic_version="2.1.0",
    )

    # In your existing fraud check function, add ONE line:
    shadow.evaluate(
        your_decision="ALLOW",          # what YOUR system decided
        event_type="TXN_ATTEMPT",
        primary_entity={"entity_type": "ACCOUNT", "entity_id": account_id},
        related_entities=[
            {"entity_type": "DEVICE", "entity_id": device_fp},
            {"entity_type": "IP",     "entity_id": f"ip:{ip_address}"},
        ],
        context={
            "payment_rail":       "UPI",
            "txn_amount_inr":     txn_amount,
            "is_new_beneficiary": is_new_bene,
            "ip_reputation_score": ip_score,
            # ... add any fields from ZICEvent.v1.json context schema
        }
    )
    # Your existing logic continues unchanged — shadow runs in background thread.
"""

from __future__ import annotations

import json
import logging
import queue
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Optional requests import ──────────────────────────────────────────────────
try:
    import requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False
    print("⚠ 'requests' not installed. Run: pip install requests")

# ── Logger ────────────────────────────────────────────────────────────────────
log = logging.getLogger("zic.shadow")

# ── Action severity for divergence scoring ────────────────────────────────────
ACTION_SEVERITY = {
    "ALLOW": 0, "MONITOR": 1, "STEP_UP": 2, "VELOCITY_LIMIT": 3,
    "MANUAL_REVIEW": 4, "SOFT_BLOCK": 5, "BLOCK": 6,
    "SUSPEND": 7, "TERMINATE": 8, "ESCALATE_SAR": 9,
}


class ShadowClient:
    """
    Non-blocking shadow mode client.

    All ZIC calls run in a background worker thread — your production
    path has zero added latency. Events are queued and processed
    asynchronously. If ZIC is unavailable, events are logged to
    the dead-letter queue and processing continues.
    """

    def __init__(
        self,
        zic_url: str = "http://localhost:8000",
        memory_url: str = "http://localhost:8001",
        log_dir: str = "shadow_mode/logs",
        zic_version: str = "2.1.0",
        timeout_seconds: float = 2.0,
        queue_max_size: int = 10_000,
        worker_threads: int = 2,
        enabled: bool = True,
    ):
        self.zic_url      = zic_url.rstrip("/")
        self.memory_url   = memory_url.rstrip("/")
        self.zic_version  = zic_version
        self.timeout      = timeout_seconds
        self.enabled      = enabled

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # JSONL log files — one per day
        self._decision_log_path = None
        self._divergence_log_path = None
        self._dlq_path = None       # dead-letter queue for failed calls

        # Internal work queue
        self._q: queue.Queue = queue.Queue(maxsize=queue_max_size)
        self._shutdown = threading.Event()

        # Stats
        self._stats = {
            "events_queued": 0,
            "events_processed": 0,
            "zic_errors": 0,
            "divergences": 0,
            "divergences_looser": 0,    # ZIC stricter than your system
            "divergences_stricter": 0,  # ZIC looser than your system (watch these)
            "queue_drops": 0,
        }
        self._stats_lock = threading.Lock()

        # Start background workers
        if enabled:
            for _ in range(worker_threads):
                t = threading.Thread(target=self._worker, daemon=True)
                t.start()
            log.info(
                f"ZIC Shadow Client started — {worker_threads} workers, "
                f"ZIC={zic_url}, version={zic_version}"
            )
        else:
            log.info("ZIC Shadow Client initialised but DISABLED")

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        your_decision: str,
        event_type: str,
        primary_entity: dict,
        context: dict,
        related_entities: list[dict] | None = None,
        memory_snapshot: dict | None = None,
        event_id: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """
        Queue an event for shadow evaluation. Non-blocking — returns immediately.

        your_decision   — the action your existing system decided
                          (ALLOW, BLOCK, MANUAL_REVIEW, etc.)
        event_type      — ZICEvent event_type string
        primary_entity  — {"entity_type": "ACCOUNT", "entity_id": "acct_123"}
        context         — ZICEvent context fields (see ZICEvent.v1.json schema)
        related_entities— list of entity dicts (device, IP, card, beneficiary)
        memory_snapshot — pre-fetched ZICEntityMemory (optional; client will
                          fetch from memory service if not provided)
        event_id        — your own event ID (auto-generated if not provided)
        metadata        — arbitrary dict attached to the log entry for correlation
        """
        if not self.enabled:
            return

        payload = {
            "event_id":         event_id or f"shadow_{uuid.uuid4().hex[:12]}",
            "event_type":       event_type,
            "your_decision":    your_decision,
            "primary_entity":   primary_entity,
            "related_entities": related_entities or [],
            "context":          context,
            "memory_snapshot":  memory_snapshot,
            "metadata":         metadata or {},
            "queued_at":        datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._q.put_nowait(payload)
            with self._stats_lock:
                self._stats["events_queued"] += 1
        except queue.Full:
            with self._stats_lock:
                self._stats["queue_drops"] += 1
            log.warning(f"Shadow queue full — dropped event {payload['event_id']}")

    def stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def flush(self, timeout: float = 10.0) -> None:
        """Block until queue is empty or timeout. Use during graceful shutdown."""
        self._q.join() if not self._q.empty() else None

    def shutdown(self) -> None:
        self._shutdown.set()

    # ── Internal worker ───────────────────────────────────────────────────────

    def _worker(self) -> None:
        while not self._shutdown.is_set():
            try:
                payload = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._process(payload)
            except Exception as e:
                log.error(f"Shadow worker error on {payload.get('event_id')}: {e}")
                self._write_dlq(payload, str(e))
            finally:
                self._q.task_done()

    def _process(self, payload: dict) -> None:
        """
        Full shadow evaluation pipeline for one event:
        1. Fetch entity memory (if not pre-supplied)
        2. Call ZIC /decide in simulation_mode=True
        3. Log the decision
        4. Detect and log divergence vs your_decision
        5. Call memory /update to persist the decision
        """
        event_id      = payload["event_id"]
        your_decision = payload["your_decision"]
        primary       = payload["primary_entity"]

        # 1. Fetch memory snapshot if not supplied
        memory_snapshot = payload.get("memory_snapshot")
        if memory_snapshot is None:
            memory_snapshot = self._fetch_memory(
                primary, payload.get("related_entities", [])
            )

        # 2. Build ZICEvent
        zic_event = {
            "event_id":          event_id,
            "event_type":        payload["event_type"],
            "ts":                payload["queued_at"],
            "zic_version":       self.zic_version,
            "simulation_mode":   True,
            "primary_entity":    primary,
            "related_entities":  payload.get("related_entities", []),
            "context":           payload["context"],
            "memory_snapshot":   memory_snapshot,
        }

        # 3. Call /decide
        decision = self._call_decide(zic_event)
        if decision is None:
            self._write_dlq(payload, "decide_call_failed")
            with self._stats_lock:
                self._stats["zic_errors"] += 1
            return

        # 4. Build log record
        zic_action  = decision.get("final_decision", {}).get("action", "UNKNOWN")
        zic_score   = decision.get("final_decision", {}).get("capped_score", 0)
        zic_band    = decision.get("final_decision", {}).get("band", "UNKNOWN")
        divergence  = self._detect_divergence(your_decision, zic_action)

        log_record = {
            "event_id":       event_id,
            "event_type":     payload["event_type"],
            "ts":             payload["queued_at"],
            "processed_at":   datetime.now(timezone.utc).isoformat(),
            "entity":         primary,
            "your_decision":  your_decision,
            "zic_action":     zic_action,
            "zic_score":      zic_score,
            "zic_band":       zic_band,
            "divergence":     divergence,
            "fired_signals":  [s["signal_id"] for s in decision.get("fired_signals", [])],
            "typologies":     decision.get("typologies", []),
            "policy_path":    decision.get("explain", {}).get("policy_path", []),
            "human_summary":  decision.get("explain", {}).get("human_summary", ""),
            "composite_rules":[r["rule_id"] for r in decision.get("composite_rules", [])],
            "metadata":       payload.get("metadata", {}),
            "full_decision":  decision,
        }

        self._write_decision_log(log_record)

        if divergence["is_divergent"]:
            self._write_divergence_log(log_record)
            with self._stats_lock:
                self._stats["divergences"] += 1
                if divergence["direction"] == "ZIC_STRICTER":
                    self._stats["divergences_looser"] += 1
                elif divergence["direction"] == "ZIC_LOOSER":
                    self._stats["divergences_stricter"] += 1

        with self._stats_lock:
            self._stats["events_processed"] += 1

        # 5. Update entity memory asynchronously (best-effort)
        self._update_memory(decision, primary, payload.get("related_entities", []))

    # ── Divergence detection ──────────────────────────────────────────────────

    def _detect_divergence(
        self, your_action: str, zic_action: str
    ) -> dict:
        """
        Classify divergence between your system's decision and ZIC's decision.

        ZIC_STRICTER:  ZIC blocks/suspends where you allowed — potential missed fraud
        ZIC_LOOSER:    ZIC allows where you blocked — potential false positive
        AGREE:         Both systems reached same action
        BAND_DIFF:     Same action class but different specifics
        """
        your_sev = ACTION_SEVERITY.get(your_action.upper(), -1)
        zic_sev  = ACTION_SEVERITY.get(zic_action.upper(), -1)

        if your_action.upper() == zic_action.upper():
            return {"is_divergent": False, "direction": "AGREE",
                    "your_action": your_action, "zic_action": zic_action,
                    "severity_delta": 0}

        delta = zic_sev - your_sev
        if delta > 0:
            direction = "ZIC_STRICTER"   # ZIC wants to block harder — review these
        elif delta < 0:
            direction = "ZIC_LOOSER"     # ZIC is more permissive than you
        else:
            direction = "DIFFERENT_ACTION"

        return {
            "is_divergent":  True,
            "direction":     direction,
            "your_action":   your_action,
            "zic_action":    zic_action,
            "severity_delta": delta,
            "review_priority": "HIGH" if direction == "ZIC_STRICTER" and delta >= 3 else "NORMAL",
        }

    # ── HTTP calls ────────────────────────────────────────────────────────────

    def _call_decide(self, event: dict) -> dict | None:
        if not _REQUESTS_OK:
            return None
        try:
            r = requests.post(
                f"{self.zic_url}/decide",
                json=event,
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json()
        except requests.exceptions.Timeout:
            log.warning(f"ZIC /decide timeout for {event['event_id']}")
        except requests.exceptions.ConnectionError:
            log.warning("ZIC /decide unreachable — is the engine running?")
        except Exception as e:
            log.error(f"ZIC /decide error: {e}")
        return None

    def _fetch_memory(
        self, primary: dict, related: list[dict]
    ) -> dict:
        """Fetch entity memory from memory service. Returns empty dict on failure."""
        if not _REQUESTS_OK:
            return {}
        entities = [primary] + related
        try:
            r = requests.post(
                f"{self.memory_url}/snapshot",
                json={"entities": entities},
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            # Return the primary entity's risk_memory as the snapshot
            for ent in data.get("entities", []):
                if (ent["entity_type"] == primary["entity_type"] and
                        ent["entity_id"] == primary["entity_id"]):
                    return {"risk_memory": ent.get("risk_memory", {})}
        except Exception as e:
            log.debug(f"Memory fetch failed (non-critical): {e}")
        return {}

    def _update_memory(
        self, decision: dict, primary: dict, related: list[dict]
    ) -> None:
        """Push decision outcome to memory service (best-effort, fire-and-forget)."""
        if not _REQUESTS_OK:
            return
        fd = decision.get("final_decision", {})
        update_payload = {
            "event_id":        decision.get("event_id", ""),
            "ts":              decision.get("ts", ""),
            "zic_version":     decision.get("zic_version", self.zic_version),
            "primary_entity":  primary,
            "related_entities": related,
            "fired_signals": [
                {
                    "signal_id":         s["signal_id"],
                    "score_contribution": s["score_contribution"],
                    "confidence":        s["confidence"],
                    "severity":          s["severity"],
                    "typologies":        s.get("typologies", []),
                }
                for s in decision.get("fired_signals", [])
            ],
            "composite_rules": decision.get("composite_rules", []),
            "final_decision":  {
                "capped_score": fd.get("capped_score", 0),
                "band":         fd.get("band", "BAND_01"),
                "action":       fd.get("action", "ALLOW"),
            },
            "graph_features": decision.get("explain", {}).get("graph_summary", {}),
        }
        try:
            requests.post(
                f"{self.memory_url}/update",
                json=update_payload,
                timeout=self.timeout,
            )
        except Exception as e:
            log.debug(f"Memory update failed (non-critical): {e}")

    # ── File I/O ──────────────────────────────────────────────────────────────

    def _today_str(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _decision_log(self) -> Path:
        return self.log_dir / f"decisions_{self._today_str()}.jsonl"

    def _divergence_log(self) -> Path:
        return self.log_dir / f"divergences_{self._today_str()}.jsonl"

    def _dlq_log(self) -> Path:
        return self.log_dir / f"dlq_{self._today_str()}.jsonl"

    def _write_decision_log(self, record: dict) -> None:
        # Strip full_decision from main log to keep it compact
        compact = {k: v for k, v in record.items() if k != "full_decision"}
        with open(self._decision_log(), "a") as f:
            f.write(json.dumps(compact) + "\n")

    def _write_divergence_log(self, record: dict) -> None:
        with open(self._divergence_log(), "a") as f:
            f.write(json.dumps(record) + "\n")

    def _write_dlq(self, payload: dict, reason: str) -> None:
        entry = {"reason": reason, "payload": payload,
                 "ts": datetime.now(timezone.utc).isoformat()}
        with open(self._dlq_log(), "a") as f:
            f.write(json.dumps(entry) + "\n")


# ── Convenience: build context from common payment fields ─────────────────────

def build_context(
    payment_rail: str = "CARD_DEBIT",
    txn_amount_inr: float = 0,
    is_new_beneficiary: bool = False,
    beneficiary_account_age_hours: float | None = None,
    device_fingerprint: str | None = None,
    device_first_seen: bool = False,
    is_emulator: bool = False,
    is_rooted: bool = False,
    is_headless_browser: bool = False,
    ip_address: str | None = None,
    ip_reputation_score: float | None = None,
    is_vpn: bool = False,
    is_tor: bool = False,
    geo_country: str | None = None,
    session_duration_seconds: float | None = None,
    scroll_events_count: int | None = None,
    navigation_speed_pages_per_second: float | None = None,
    login_input_method: str | None = None,
    otp_fail_count: int = 0,
    cvv_fail_count: int = 0,
    distinct_cards_attempted_device_15m: int = 0,
    distinct_cards_added_24h: int = 0,
    txn_count_15m: int = 0,
    outbound_delta_from_funding_minutes: float | None = None,
    inbound_source_count_24h: int = 0,
    remote_access_app_detected: bool = False,
    upi_in_progress: bool = False,
    account_age_days: float = 365,
    refund_delta_hours: float | None = None,
    prior_impossible_travel: bool = False,
    simultaneous_geo_sessions: int = 0,
    **extra,
) -> dict:
    """
    Helper to build a ZICEvent context dict from named payment fields.
    Only non-None values are included. Pass **extra for any additional
    fields defined in ZICEvent.v1.json context schema.
    """
    ctx: dict = {}

    def _set(key, val):
        if val is not None:
            ctx[key] = val

    _set("payment_rail", payment_rail)
    _set("txn_amount_inr", txn_amount_inr)
    _set("is_new_beneficiary", is_new_beneficiary)
    _set("beneficiary_account_age_hours", beneficiary_account_age_hours)
    _set("device_fingerprint", device_fingerprint)
    _set("device_first_seen", device_first_seen)
    _set("is_emulator", is_emulator)
    _set("is_rooted", is_rooted)
    _set("is_headless_browser", is_headless_browser)
    _set("ip_address", ip_address)
    _set("ip_reputation_score", ip_reputation_score)
    _set("is_vpn", is_vpn)
    _set("is_tor", is_tor)
    _set("geo_country", geo_country)
    _set("session_duration_seconds", session_duration_seconds)
    _set("scroll_events_count", scroll_events_count)
    _set("navigation_speed_pages_per_second", navigation_speed_pages_per_second)
    _set("login_input_method", login_input_method)
    _set("otp_fail_count", otp_fail_count)
    _set("cvv_fail_count", cvv_fail_count)
    _set("distinct_cards_attempted_device_15m", distinct_cards_attempted_device_15m)
    _set("distinct_cards_added_24h", distinct_cards_added_24h)
    _set("txn_count_15m", txn_count_15m)
    _set("outbound_delta_from_funding_minutes", outbound_delta_from_funding_minutes)
    _set("inbound_source_count_24h", inbound_source_count_24h)
    _set("remote_access_app_detected", remote_access_app_detected)
    _set("upi_in_progress", upi_in_progress)
    _set("account_age_days", account_age_days)
    _set("refund_delta_hours", refund_delta_hours)
    _set("prior_impossible_travel", prior_impossible_travel)
    _set("simultaneous_geo_sessions", simultaneous_geo_sessions)
    ctx.update(extra)
    return ctx
