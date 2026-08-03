"""
ZIC Decision Engine MVP — FastAPI application.

Endpoints:
  POST /decide        — evaluate a ZICEvent, return ZICDecision
  GET  /health        — engine health + ZIC version
  GET  /zic/signals   — list all loaded signals (for debugging)
  GET  /zic/bands     — list scoring bands

Run:
  uvicorn main:app --host 0.0.0.0 --port 8000

Environment:
  ZIC_PATH — path to governance-signals.json
             default: ../../governance-signals.json
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent))

import rules as rules_mod
import composite as composite_mod
import explain as explain_mod

# ── Load ZIC ─────────────────────────────────────────────────────────────────

ZIC_PATH = os.getenv(
    "ZIC_PATH",
    str(Path(__file__).parent.parent / "governance-signals.json"),
)

def load_zic(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    print(f"✓ ZIC v{data['_meta']['version']} loaded — {len(data['signals'])} signals")
    return data

ZIC: dict = {}
try:
    ZIC = load_zic(ZIC_PATH)
except FileNotFoundError:
    print(f"⚠ ZIC not found at {ZIC_PATH} — engine will fail on /decide until ZIC is loaded")

ENGINE_VERSION = "1.0.0"

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="ZIC Decision Engine",
    description="Rules-only deterministic ZIC decision engine. All signals, bands, and actions reference ZIC core.",
    version=ENGINE_VERSION,
)

# ── CORS — allows browser (file:// or any origin) to call localhost:8000 ──────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic models ───────────────────────────────────────────────────────────

class Entity(BaseModel):
    entity_type: str
    entity_id: str

class ZICEventIn(BaseModel):
    event_id: str
    event_type: str
    ts: str
    zic_version: str
    simulation_mode: bool = False
    primary_entity: Entity
    related_entities: list[Entity] = []
    context: dict[str, Any] = {}
    memory_snapshot: dict[str, Any] = {}

# ── Scoring helpers ───────────────────────────────────────────────────────────

def score_to_band(score: float, zic: dict) -> tuple[str, str]:
    """Return (band_id, default_action) for a capped score."""
    for band in zic["scoring_bands"]:
        if band["score_min"] <= score <= band["score_max"]:
            return band["band_id"], band["action"]
    return "BAND_05", "BLOCK"

def collect_typologies(fired_signals: list) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for s in fired_signals:
        for t in s.typologies:
            if t not in seen:
                seen.add(t)
                result.append(t)
    return result

# ── /decide endpoint ──────────────────────────────────────────────────────────

@app.post("/decide")
def decide(event: ZICEventIn) -> dict:
    if not ZIC:
        raise HTTPException(503, "ZIC core not loaded")

    if event.zic_version != ZIC["_meta"]["version"]:
        raise HTTPException(
            400,
            f"ZIC version mismatch: event={event.zic_version} engine={ZIC['_meta']['version']}",
        )

    ctx = event.context
    mem = event.memory_snapshot.get("risk_memory", {})
    graph_features = mem.get("graph_features", {})
    memory_score = mem.get("current_score")

    # 1. Evaluate individual signals
    fired_signals = rules_mod.evaluate(ctx, mem, ZIC)
    fired_ids = {s.signal_id for s in fired_signals}

    # 2. Compute raw score
    raw_score = sum(s.score_contribution for s in fired_signals)

    # Add memory context (decayed prior risk)
    decayed = mem.get("decayed_scores", {}).get("overall", {}).get("value", 0)
    raw_score += decayed * 0.15  # prior risk contributes 15% weight

    # 3. Evaluate composite rules
    composite_rules = composite_mod.evaluate(fired_ids, raw_score, ZIC)
    for rule in composite_rules:
        raw_score += rule.score_addition

    # 4. Cap score, determine band and default action
    capped_score = min(100.0, max(0.0, raw_score))
    band, band_action = score_to_band(capped_score, ZIC)

    # 5. Resolve final action (most severe across band + composite)
    final_action = composite_mod.highest_priority_action(band_action, composite_rules)

    # 6. Collect typologies
    typologies = collect_typologies(fired_signals)

    # 7. Build explainability
    explain_obj = explain_mod.build_explain(
        band=band,
        final_action=final_action,
        score=capped_score,
        fired_signals=fired_signals,
        composite_rules=composite_rules,
        typologies=typologies,
        graph_features=graph_features,
        memory_score=memory_score,
        simulation_mode=event.simulation_mode,
    )

    # 8. Assemble ZICDecision
    decision = {
        "decision_id": f"dec_{uuid.uuid4().hex}",
        "event_id": event.event_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "zic_version": ZIC["_meta"]["version"],
        "engine_version": ENGINE_VERSION,
        "simulation_mode": event.simulation_mode,
        "fired_signals": [
            {
                "signal_id": s.signal_id,
                "signal_name": s.signal_name,
                "severity": s.severity,
                "base_score": s.base_score,
                "weight": s.weight,
                "score_contribution": s.score_contribution,
                "confidence": s.confidence,
                "typologies": s.typologies,
            }
            for s in fired_signals
        ],
        "composite_rules": [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "score_addition": r.score_addition,
                "action_override": r.action_override,
            }
            for r in composite_rules
        ],
        "typologies": typologies,
        "final_decision": {
            "raw_score": round(raw_score, 2),
            "capped_score": round(capped_score, 2),
            "band": band,
            "band_label": {"BAND_01":"Clear","BAND_02":"Elevated","BAND_03":"Suspicious","BAND_04":"High Risk","BAND_05":"Critical"}[band],
            "action": final_action,
        },
        "explain": explain_obj,
    }

    return decision


# ── Utility endpoints ─────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "zic_version": ZIC.get("_meta", {}).get("version", "not_loaded"),
        "signal_count": len(ZIC.get("signals", [])),
        "ts": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/zic/signals")
def list_signals() -> dict:
    return {
        "count": len(ZIC.get("signals", [])),
        "signals": [
            {"signal_id": s["signal_id"], "severity": s["severity"],
             "base_score": s["base_score"], "category": s["category"]}
            for s in ZIC.get("signals", [])
        ],
    }

@app.get("/zic/bands")
def list_bands() -> dict:
    return {"bands": ZIC.get("scoring_bands", [])}

@app.post("/zic/reload")
def reload_zic() -> dict:
    global ZIC
    ZIC = load_zic(ZIC_PATH)
    return {"status": "reloaded", "version": ZIC["_meta"]["version"]}
