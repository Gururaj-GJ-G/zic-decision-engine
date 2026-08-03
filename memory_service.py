"""
ZIC Entity Memory Service MVP.

In-memory store (swap dict for Redis/Mongo in production).
All entity memory conforms to ZICEntityMemory.v1 schema.

Endpoints:
  POST /snapshot   — fetch memory for multiple entities
  POST /update     — update entity memory after a decision event
  GET  /entity/{type}/{id}  — fetch single entity memory
  DELETE /entity/{type}/{id} — reset entity (testing/simulation)
"""

import json
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any

app = FastAPI(
    title="ZIC Entity Memory Service",
    version="1.0.0",
)

# CORS — allows browser (localhost:3000 badge demo or any origin) to call :8001
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store: key = (entity_type, entity_id)
STORE: dict[tuple[str, str], dict] = {}

ZIC_VERSION = "2.1.0"

# ── Pydantic ──────────────────────────────────────────────────────────────────

class EntityRef(BaseModel):
    entity_type: str
    entity_id: str

class SnapshotRequest(BaseModel):
    entities: list[EntityRef]

class FiredSignalIn(BaseModel):
    signal_id: str
    score_contribution: float
    confidence: float
    severity: str
    typologies: list[str] = []

class CompositeRuleIn(BaseModel):
    rule_id: str
    score_addition: float
    action_override: str

class FinalDecisionIn(BaseModel):
    capped_score: float
    band: str
    action: str

class UpdateRequest(BaseModel):
    event_id: str
    ts: str
    zic_version: str
    primary_entity: EntityRef
    related_entities: list[EntityRef] = []
    fired_signals: list[FiredSignalIn]
    composite_rules: list[CompositeRuleIn] = []
    final_decision: FinalDecisionIn
    graph_features: dict[str, Any] = {}

# ── Helpers ───────────────────────────────────────────────────────────────────

def entity_key(entity_type: str, entity_id: str) -> tuple[str, str]:
    return (entity_type.upper(), entity_id)

def empty_memory(entity_type: str, entity_id: str) -> dict:
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "zic_version": ZIC_VERSION,
        "last_update_ts": datetime.now(timezone.utc).isoformat(),
        "links": {"devices":[],"cards":[],"ips":[],"beneficiaries":[],"merchants":[],"agents":[]},
        "risk_memory": {
            "current_score": 0,
            "current_band": "BAND01",
            "current_action": "ALLOW",
            "band_history": [],
            "signal_stats": {},
            "typology_stats": {},
            "decayed_scores": {"overall": {"value": 0.0, "half_life_hours": 72}},
            "velocity_counters": {},
            "graph_features": {},
        },
    }

def update_decayed_score(
    current_value: float,
    new_score: float,
    half_life_hours: float,
    last_updated_ts: str,
    now_ts: str,
) -> float:
    """Exponential decay: V(t) = V0 * 2^(-Δt/half_life) + new_score * weight"""
    try:
        last = datetime.fromisoformat(last_updated_ts.replace("Z", "+00:00"))
        now = datetime.fromisoformat(now_ts.replace("Z", "+00:00"))
        delta_hours = (now - last).total_seconds() / 3600
    except Exception:
        delta_hours = 0
    decayed = current_value * math.pow(2, -delta_hours / half_life_hours)
    return round(decayed + new_score * 0.3, 2)  # new score contributes 30%

HALF_LIVES = {
    "ATO_001": 168, "SYN_001": 336, "FAK_001": 336,
    "PRO_001": 72,  "MUL_001": 720, "TXF_001": 168,
    "INT_001": 720, "INV_001": 336,
}

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/snapshot")
def get_snapshot(req: SnapshotRequest) -> dict:
    """Fetch memory for multiple entities in one call."""
    result = []
    for ref in req.entities:
        key = entity_key(ref.entity_type, ref.entity_id)
        mem = STORE.get(key, empty_memory(ref.entity_type, ref.entity_id))
        result.append({
            "entity_type": ref.entity_type,
            "entity_id": ref.entity_id,
            "risk_memory": mem["risk_memory"],
        })
    return {"entities": result}

@app.get("/entity/{entity_type}/{entity_id}")
def get_entity(entity_type: str, entity_id: str) -> dict:
    key = entity_key(entity_type, entity_id)
    return STORE.get(key, empty_memory(entity_type, entity_id))

@app.post("/update")
def update_memory(req: UpdateRequest) -> dict:
    """
    Update entity memory after a ZICDecision event.
    Updates primary entity and links related entities.
    """
    entities_to_update = [req.primary_entity] + req.related_entities
    now_ts = req.ts or datetime.now(timezone.utc).isoformat()

    updated_ids = []

    for entity_ref in entities_to_update:
        key = entity_key(entity_ref.entity_type, entity_ref.entity_id)
        if key not in STORE:
            STORE[key] = empty_memory(entity_ref.entity_type, entity_ref.entity_id)

        mem = STORE[key]
        rm = mem["risk_memory"]

        # Update links
        for related in req.related_entities:
            link_key = related.entity_type.lower() + "s"
            if link_key in mem["links"]:
                if related.entity_id not in mem["links"][link_key]:
                    mem["links"][link_key].append(related.entity_id)

        # Update band + action
        rm["current_score"] = req.final_decision.capped_score
        rm["current_band"] = req.final_decision.band
        rm["current_action"] = req.final_decision.action

        # Band history (keep last 20)
        rm["band_history"].append({
            "ts": now_ts,
            "score": req.final_decision.capped_score,
            "band": req.final_decision.band,
            "action": req.final_decision.action,
            "event_id": req.event_id,
            "reason_signals": [s.signal_id for s in req.fired_signals],
        })
        rm["band_history"] = rm["band_history"][-20:]

        # Update signal stats
        for sig in req.fired_signals:
            sid = sig.signal_id
            if sid not in rm["signal_stats"]:
                rm["signal_stats"][sid] = {
                    "signal_id": sid,
                    "severity": sig.severity,
                    "last_fired_ts": now_ts,
                    "fire_count_total": 0,
                    "fire_count_24h": 0,
                    "fire_count_7d": 0,
                    "fire_count_30d": 0,
                    "last_score_contribution": 0,
                    "max_score_30d": 0,
                    "avg_confidence_30d": 0,
                }
            ss = rm["signal_stats"][sid]
            ss["last_fired_ts"] = now_ts
            ss["fire_count_total"] += 1
            ss["fire_count_24h"] = ss.get("fire_count_24h", 0) + 1
            ss["fire_count_7d"] = ss.get("fire_count_7d", 0) + 1
            ss["fire_count_30d"] = ss.get("fire_count_30d", 0) + 1
            ss["last_score_contribution"] = sig.score_contribution
            ss["max_score_30d"] = max(ss.get("max_score_30d", 0), sig.score_contribution)
            # Rolling avg confidence
            prev_avg = ss.get("avg_confidence_30d", sig.confidence)
            ss["avg_confidence_30d"] = round((prev_avg + sig.confidence) / 2, 3)

        # Update typology stats
        seen_typologies: set[str] = set()
        for sig in req.fired_signals:
            for t in sig.typologies:
                seen_typologies.add(t)
        for t in seen_typologies:
            if t not in rm["typology_stats"]:
                rm["typology_stats"][t] = {
                    "pattern_id": t,
                    "last_seen_ts": now_ts,
                    "incidents_total": 0,
                    "incidents_90d": 0,
                    "incidents_365d": 0,
                    "last_signals": [],
                }
            ts_stat = rm["typology_stats"][t]
            ts_stat["last_seen_ts"] = now_ts
            ts_stat["incidents_total"] += 1
            ts_stat["incidents_90d"] = ts_stat.get("incidents_90d", 0) + 1
            ts_stat["incidents_365d"] = ts_stat.get("incidents_365d", 0) + 1
            ts_stat["last_signals"] = list({s.signal_id for s in req.fired_signals if t in s.typologies})

        # Update decayed score
        overall = rm["decayed_scores"].get("overall", {"value": 0, "half_life_hours": 72})
        new_decayed = update_decayed_score(
            current_value=overall.get("value", 0),
            new_score=req.final_decision.capped_score,
            half_life_hours=overall.get("half_life_hours", 72),
            last_updated_ts=overall.get("last_updated_ts", now_ts),
            now_ts=now_ts,
        )
        rm["decayed_scores"]["overall"] = {
            "value": new_decayed,
            "half_life_hours": 72,
            "last_updated_ts": now_ts,
        }

        # Update graph features
        if req.graph_features:
            rm["graph_features"].update(req.graph_features)

        mem["last_update_ts"] = now_ts
        mem["zic_version"] = req.zic_version
        updated_ids.append(f"{entity_ref.entity_type}:{entity_ref.entity_id}")

    return {"status": "updated", "entities": updated_ids}

@app.delete("/entity/{entity_type}/{entity_id}")
def reset_entity(entity_type: str, entity_id: str) -> dict:
    """Reset entity memory. For testing and simulation use only."""
    key = entity_key(entity_type, entity_id)
    STORE.pop(key, None)
    return {"status": "reset", "entity": f"{entity_type}:{entity_id}"}

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "entities_in_store": len(STORE),
            "zic_version": ZIC_VERSION}
