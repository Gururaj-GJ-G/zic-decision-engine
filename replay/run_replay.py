#!/usr/bin/env python3
"""
ZIC Replay Runner
-----------------
Posts every event in events.jsonl to the ZIC decision engine,
compares actual vs expected outcome, measures latency, writes
replay_results.json and replay_report.html.

Usage:
    python run_replay.py [--host http://localhost:8000] [--events events.jsonl]
"""

import argparse
import json
import time
import statistics
from datetime import datetime, timezone
from pathlib import Path

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass


# ── CLI ───────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="ZIC Batch Replay Runner")
parser.add_argument("--host",   default="http://localhost:8000", help="Engine base URL")
parser.add_argument("--events", default="events.jsonl",          help="Path to JSONL events file")
parser.add_argument("--out",    default="replay_results.json",   help="Output results file")
args = parser.parse_args()

SCRIPT_DIR  = Path(__file__).parent
EVENTS_FILE = SCRIPT_DIR / args.events
OUT_FILE    = SCRIPT_DIR / args.out
REPORT_FILE = SCRIPT_DIR / "replay_report.html"
ENGINE_URL  = args.host.rstrip("/")

BAND_ORDER  = ["BAND_01", "BAND_02", "BAND_03", "BAND_04", "BAND_05"]

# ── helpers ───────────────────────────────────────────────────────────────────

def post_json(url: str, payload: dict) -> tuple[dict, float]:
    """POST JSON, return (response_dict, latency_ms). Raises on HTTP error."""
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read()
    latency_ms = (time.perf_counter() - t0) * 1000
    return json.loads(body), round(latency_ms, 1)


def outcome_match(actual_band: str, actual_action: str,
                  exp_band: str, exp_action: str) -> str:
    """EXACT / DRIFT / DIVERGE"""
    if actual_band == exp_band and actual_action == exp_action:
        return "EXACT"
    ai = BAND_ORDER.index(actual_band) if actual_band in BAND_ORDER else -1
    ei = BAND_ORDER.index(exp_band)    if exp_band    in BAND_ORDER else -1
    if abs(ai - ei) <= 1:
        return "DRIFT"
    return "DIVERGE"


# ── health check ─────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print(f"  ZIC Replay Runner")
print(f"  Engine : {ENGINE_URL}")
print(f"  Events : {EVENTS_FILE.name}")
print(f"{'='*60}\n")

try:
    req = urllib.request.Request(f"{ENGINE_URL}/health")
    with urllib.request.urlopen(req, timeout=5) as r:
        health = json.loads(r.read())
    print(f"✓ Engine online  — ZIC {health.get('zic_version','?')} · "
          f"{health.get('signal_count','?')} signals · {health.get('status','?')}\n")
except Exception as e:
    print(f"✗ Engine unreachable at {ENGINE_URL}: {e}")
    print("  Start uvicorn then re-run:")
    print("  cd decision_engine_mvp && uvicorn main:app --port 8000")
    raise SystemExit(1)


# ── load events ───────────────────────────────────────────────────────────────

events = []
with open(EVENTS_FILE) as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"  [WARN] Line {i} parse error: {e}")

print(f"Loaded {len(events)} events\n")
cats = {}
for e in events:
    cats[e.get("category","?")] = cats.get(e.get("category","?"),0)+1
for c,n in sorted(cats.items()):
    print(f"  {c:15s} {n} events")
print()


# ── replay ────────────────────────────────────────────────────────────────────

results   = []
latencies = []
totals    = {"EXACT":0,"DRIFT":0,"DIVERGE":0,"ERROR":0}

print(f"{'#':<4} {'EVENT_ID':<20} {'CAT':<14} {'EXP':>10} {'ACT':>10} {'MATCH':<8} {'MS':>7}  SIGNALS")
print("─"*90)

for idx, event in enumerate(events, 1):
    event_id   = event.get("event_id", f"evt_{idx}")
    label      = event.get("label", "")
    category   = event.get("category", "?")
    expected   = event.pop("expected", {})
    exp_band   = expected.get("band",  "?")
    exp_action = expected.get("action","?")
    exp_str    = f"{exp_band[-2:]}:{exp_action[:3]}"

    try:
        decision, latency_ms = post_json(f"{ENGINE_URL}/decide", event)

        fd         = decision["final_decision"]
        act_band   = fd["band"]
        act_action = fd["action"]
        act_score  = fd["capped_score"]
        raw_score  = fd["raw_score"]
        n_signals  = len(decision.get("fired_signals", []))
        top_sig    = (decision["fired_signals"][0]["signal_id"]
                      if n_signals else "—")

        match_str  = outcome_match(act_band, act_action, exp_band, exp_action)
        totals[match_str] += 1
        latencies.append(latency_ms)

        act_str = f"{act_band[-2:]}:{act_action[:3]}"
        flag    = "✓" if match_str=="EXACT" else ("~" if match_str=="DRIFT" else "✗")

        print(f"{idx:<4} {event_id:<20} {category:<14} {exp_str:>10} {act_str:>10} "
              f"{flag}{match_str:<7} {latency_ms:>6.1f}ms  {n_signals}sig/{top_sig}")

        results.append({
            "idx":         idx,
            "event_id":    event_id,
            "label":       label,
            "category":    category,
            "expected":    {"band": exp_band, "action": exp_action},
            "actual":      {
                "band":        act_band,
                "action":      act_action,
                "raw_score":   raw_score,
                "capped_score":act_score,
            },
            "match":       match_str,
            "latency_ms":  latency_ms,
            "n_signals":   n_signals,
            "top_signal":  top_sig,
            "decision_id": decision.get("decision_id",""),
            "policy_path": decision.get("explain",{}).get("policy_path",[]),
            "fired_signals": [
                {"signal_id":s["signal_id"],"signal_name":s["signal_name"],
                 "severity":s["severity"],"score_contribution":s["score_contribution"]}
                for s in decision.get("fired_signals",[])
            ],
        })

    except Exception as e:
        totals["ERROR"] += 1
        print(f"{idx:<4} {event_id:<20} {category:<14} {exp_str:>10} {'ERROR':>10} "
              f"✗{'ERROR':<7} {'—':>7}ms  {str(e)[:40]}")
        results.append({
            "idx": idx, "event_id": event_id, "label": label,
            "category": category, "expected": expected,
            "actual": None, "match": "ERROR",
            "latency_ms": None, "n_signals": 0,
            "error": str(e),
        })


# ── summary ───────────────────────────────────────────────────────────────────

total = len(events)
p50   = round(statistics.median(latencies), 1) if latencies else 0
p95   = round(sorted(latencies)[int(len(latencies)*0.95)] if len(latencies)>1 else (latencies[0] if latencies else 0), 1)
p99   = round(sorted(latencies)[int(len(latencies)*0.99)] if len(latencies)>1 else (latencies[0] if latencies else 0), 1)
avg   = round(statistics.mean(latencies), 1) if latencies else 0

print("\n" + "─"*90)
print(f"\nSUMMARY")
print(f"  Total events : {total}")
print(f"  EXACT match  : {totals['EXACT']} ({totals['EXACT']/total*100:.0f}%)")
print(f"  DRIFT (+-1)  : {totals['DRIFT']} ({totals['DRIFT']/total*100:.0f}%)")
print(f"  DIVERGE      : {totals['DIVERGE']} ({totals['DIVERGE']/total*100:.0f}%)")
print(f"  ERRORS       : {totals['ERROR']}")
print(f"\n  Latency — p50:{p50}ms  p95:{p95}ms  p99:{p99}ms  avg:{avg}ms")
print()

print("  Category breakdown:")
cat_results = {}
for r in results:
    c = r["category"]
    cat_results.setdefault(c, {"EXACT":0,"DRIFT":0,"DIVERGE":0,"ERROR":0,"n":0})
    cat_results[c][r["match"]] += 1
    cat_results[c]["n"] += 1
for cat, cr in sorted(cat_results.items()):
    n = cr["n"]
    print(f"    {cat:<14} n={n}  EXACT={cr['EXACT']}  DRIFT={cr['DRIFT']}  "
          f"DIVERGE={cr['DIVERGE']}  ERR={cr['ERROR']}")


# ── write results JSON ────────────────────────────────────────────────────────

run_meta = {
    "run_ts":    datetime.now(timezone.utc).isoformat(),
    "engine":    ENGINE_URL,
    "zic":       health.get("zic_version","?"),
    "signals":   health.get("signal_count","?"),
    "total":     total,
    "totals":    totals,
    "latency":   {"p50":p50,"p95":p95,"p99":p99,"avg":avg},
    "category_breakdown": cat_results,
}

with open(OUT_FILE,"w") as f:
    json.dump({"meta": run_meta, "results": results}, f, indent=2)
print(f"\n✓ Results saved  -> {OUT_FILE.name}")


# ── write HTML report ─────────────────────────────────────────────────────────

MATCH_COL = {"EXACT":"#22C55E","DRIFT":"#F59E0B","DIVERGE":"#EF4444","ERROR":"#888"}
SEV_COL   = {"CRITICAL":"#EF4444","HIGH":"#F97316","MEDIUM":"#F59E0B","LOW":"#22C55E","INFO":"#3B82F6"}

def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def band_color(band):
    m = {"BAND_01":"#22C55E","BAND_02":"#3B82F6","BAND_03":"#F59E0B","BAND_04":"#F97316","BAND_05":"#EF4444"}
    return m.get(band,"#888")

cat_rows = ""
for cat,cr in sorted(cat_results.items()):
    n   = cr["n"]
    acc = cr["EXACT"]/n*100 if n else 0
    bg  = "#22C55E22" if acc==100 else ("#F59E0B22" if acc>=80 else "#EF444422")
    cat_rows += (
        f'<tr style="background:{bg}">'
        f'<td style="font-weight:600">{esc(cat)}</td>'
        f'<td>{n}</td>'
        f'<td style="color:#22C55E">{cr["EXACT"]}</td>'
        f'<td style="color:#F59E0B">{cr["DRIFT"]}</td>'
        f'<td style="color:#EF4444">{cr["DIVERGE"]}</td>'
        f'<td style="color:#888">{cr["ERROR"]}</td>'
        f'<td style="font-weight:700;color:{"#22C55E" if acc>=90 else "#F59E0B" if acc>=70 else "#EF4444"}">{acc:.0f}%</td>'
        f'</tr>'
    )

detail_rows = ""
for r in results:
    mc   = MATCH_COL.get(r["match"],"#888")
    bc_e = band_color(r["expected"]["band"])
    bc_a = band_color(r["actual"]["band"] if r["actual"] else "")
    sigs_html = ""
    for s in r.get("fired_signals",[]):
        sc = SEV_COL.get(s["severity"],"#888")
        sigs_html += (
            f'<span style="display:inline-block;margin:1px 2px;padding:1px 5px;'
            f'border-radius:3px;font-size:10px;background:{sc}1A;color:{sc};'
            f'border:1px solid {sc}33">'
            f'{esc(s["signal_id"])} +{s["score_contribution"]}</span>'
        )
    path_html = ""
    for step in r.get("policy_path",[]):
        path_html += (
            f'<span style="font-family:monospace;font-size:10px;margin:1px;'
            f'padding:1px 4px;background:#253F5988;border-radius:3px;color:#7A96B0">'
            f'{esc(step)}</span> '
        )
    act = r["actual"] or {}
    lat = f"{r['latency_ms']:.1f}ms" if r.get("latency_ms") is not None else "—"
    detail_rows += (
        f'<tr>'
        f'<td style="color:#7A96B0;font-size:11px">{r["idx"]}</td>'
        f'<td><div style="font-weight:500;font-size:12px">{esc(r["label"])}</div>'
        f'<div style="font-family:monospace;font-size:10px;color:#5A6F82">{esc(r["event_id"])}</div></td>'
        f'<td><span style="font-size:11px;padding:2px 6px;border-radius:3px;background:#253F5988;color:#7A96B0">{esc(r["category"])}</span></td>'
        f'<td><div style="font-size:11px;color:{bc_e};font-weight:600">{esc(r["expected"]["band"])}</div>'
        f'<div style="font-size:10px;color:#5A6F82">{esc(r["expected"]["action"])}</div></td>'
        f'<td><div style="font-size:11px;color:{bc_a};font-weight:600">{esc(act.get("band","—"))}</div>'
        f'<div style="font-size:10px;color:#5A6F82">{esc(act.get("action","—"))}</div>'
        f'<div style="font-family:monospace;font-size:10px;color:#3B82F6">{act.get("capped_score","—")}/100</div></td>'
        f'<td><span style="padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;'
        f'background:{mc}1A;color:{mc};border:1px solid {mc}44">{r["match"]}</span></td>'
        f'<td style="font-family:monospace;font-size:11px;color:#7A96B0">{lat}</td>'
        f'<td>{sigs_html}</td>'
        f'<td>{path_html}</td>'
        f'</tr>'
    )


exact_pct = totals['EXACT']/total*100 if total else 0
run_ts    = run_meta["run_ts"][:19].replace("T"," ") + " UTC"

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ZIC Replay Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{--navy:#1B3A5C;--orange:#E8953A;--bg:#0D1B29;--card:#19304A;--border:#253F59;--text:#DDE8F4;--dim:#7A96B0;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
.hdr{{background:var(--navy);border-bottom:1px solid #1a3552;padding:0 1.5rem;height:52px;display:flex;align-items:center;justify-content:space-between}}
.brand{{display:flex;align-items:center;gap:10px}}
.mark{{width:30px;height:30px;background:var(--orange);border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;color:#fff}}
.bn{{font-size:14px;font-weight:700}}
.bs{{font-size:11px;color:rgba(255,255,255,0.4);margin-top:1px}}
.zv{{background:rgba(232,149,58,.15);border:1px solid rgba(232,149,58,.3);color:var(--orange);font-size:11px;font-weight:600;padding:3px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace}}
main{{padding:1.5rem;max-width:1600px}}
.kpi-row{{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}}
.kpi{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 20px;flex:1;min-width:140px}}
.kpi-v{{font-size:32px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}}
.kpi-l{{font-size:11px;color:var(--dim);margin-top:4px;text-transform:uppercase;letter-spacing:.6px}}
.section{{background:var(--card);border:1px solid var(--border);border-radius:10px;margin-bottom:1.5rem;overflow:hidden}}
.sh{{padding:11px 16px;border-bottom:1px solid var(--border);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--dim)}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:8px 12px;color:var(--dim);font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);white-space:nowrap}}
td{{padding:8px 12px;border-bottom:1px solid rgba(37,63,89,.35);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
.lat-row{{display:flex;gap:1.5rem;padding:14px 16px;font-size:12px;border-bottom:1px solid var(--border)}}
.lat-k{{color:var(--dim)}}
.lat-v{{font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;margin-left:4px}}
.foot{{text-align:center;font-size:10.5px;color:var(--dim);padding:16px;opacity:.4;font-family:monospace}}
</style>
</head>
<body>
<div class="hdr">
  <div class="brand">
    <div class="mark">ZIC</div>
    <div><div class="bn">ZIC Decision Engine</div>
    <div class="bs">Replay Validation Report &middot; {run_ts}</div></div>
  </div>
  <span class="zv">v{run_meta['zic']} &middot; {run_meta['signals']} signals</span>
</div>
<main>
<div class="kpi-row">
  <div class="kpi"><div class="kpi-v" style="color:#DDE8F4">{total}</div><div class="kpi-l">Events Replayed</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#22C55E">{totals['EXACT']}</div><div class="kpi-l">Exact Match</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#F59E0B">{totals['DRIFT']}</div><div class="kpi-l">Drift (+/-1 Band)</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#EF4444">{totals['DIVERGE']}</div><div class="kpi-l">Diverge</div></div>
  <div class="kpi"><div class="kpi-v" style="color:{'#22C55E' if exact_pct>=90 else '#F59E0B' if exact_pct>=70 else '#EF4444'}">{exact_pct:.0f}%</div><div class="kpi-l">Accuracy</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#3B82F6">{p50}ms</div><div class="kpi-l">p50 Latency</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#3B82F6">{p95}ms</div><div class="kpi-l">p95 Latency</div></div>
</div>
<div class="section">
  <div class="sh">Category Breakdown</div>
  <div class="lat-row">
    <span class="lat-k">Latency</span>
    <span><span class="lat-k">p50</span><span class="lat-v">{p50}ms</span></span>
    <span><span class="lat-k">p95</span><span class="lat-v">{p95}ms</span></span>
    <span><span class="lat-k">p99</span><span class="lat-v">{p99}ms</span></span>
    <span><span class="lat-k">avg</span><span class="lat-v">{avg}ms</span></span>
  </div>
  <table>
    <thead><tr><th>Category</th><th>N</th><th style="color:#22C55E">Exact</th><th style="color:#F59E0B">Drift</th><th style="color:#EF4444">Diverge</th><th>Error</th><th>Accuracy</th></tr></thead>
    <tbody>{cat_rows}</tbody>
  </table>
</div>
<div class="section">
  <div class="sh">Decision Detail &middot; {total} events</div>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>#</th><th>Event</th><th>Category</th><th>Expected</th><th>Actual</th><th>Match</th><th>Latency</th><th>Signals Fired</th><th>Policy Path</th></tr></thead>
    <tbody>{detail_rows}</tbody>
  </table>
  </div>
</div>
</main>
<div class="foot">ZIC v{run_meta['zic']} &middot; Engine {ENGINE_URL} &middot; {run_ts}</div>
</body>
</html>"""

with open(REPORT_FILE,"w", encoding="utf-8") as f:
    f.write(html)
print(f"✓ HTML report    -> {REPORT_FILE.name}")
print(f"\nOpen: http://localhost:3000/replay/replay_report.html\n")
