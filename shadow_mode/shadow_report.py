"""
ZIC Shadow Mode Report Generator
=================================
Reads shadow_mode/logs/decisions_*.jsonl and divergences_*.jsonl
and produces a human-readable analysis report.

Usage:
    python shadow_report.py --log-dir shadow_mode/logs --days 1
    python shadow_report.py --log-dir shadow_mode/logs --output report.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    except FileNotFoundError:
        pass
    return records


def load_recent(log_dir: Path, prefix: str, days: int) -> list[dict]:
    records = []
    for i in range(days):
        date = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        records.extend(load_jsonl(log_dir / f"{prefix}_{date}.jsonl"))
    return records


def generate_report(log_dir: Path, days: int = 1) -> dict:
    decisions   = load_recent(log_dir, "decisions", days)
    divergences = load_recent(log_dir, "divergences", days)

    if not decisions:
        return {"error": f"No decision logs found in {log_dir} for last {days} day(s)", "generated_at": "", "period_days": days}

    total = len(decisions)
    div_total = len(divergences)

    # ── Band distribution ─────────────────────────────────────────────────────
    band_dist = Counter(d["zic_band"] for d in decisions)

    # ── Action distribution ───────────────────────────────────────────────────
    zic_action_dist  = Counter(d["zic_action"] for d in decisions)
    your_action_dist = Counter(d["your_decision"] for d in decisions)

    # ── Score percentiles ─────────────────────────────────────────────────────
    scores = sorted(d["zic_score"] for d in decisions)
    def pct(p):
        idx = int(len(scores) * p / 100)
        return scores[min(idx, len(scores)-1)]

    score_stats = {
        "min": scores[0], "p25": pct(25), "p50": pct(50),
        "p75": pct(75), "p90": pct(90), "p95": pct(95),
        "p99": pct(99), "max": scores[-1],
        "mean": round(sum(scores) / len(scores), 1),
    }

    # ── Divergence analysis ───────────────────────────────────────────────────
    div_by_direction = Counter(d["divergence"]["direction"] for d in divergences)

    # ── Top signals ───────────────────────────────────────────────────────────
    all_signals: list[str] = []
    for d in decisions:
        all_signals.extend(d.get("fired_signals", []))
    top_signals = Counter(all_signals).most_common(15)

    # ── Top typologies ────────────────────────────────────────────────────────
    all_typs: list[str] = []
    for d in decisions:
        all_typs.extend(d.get("typologies", []))
    top_typologies = Counter(all_typs).most_common(10)

    # ── High priority divergences ─────────────────────────────────────────────
    high_pri = [
        d for d in divergences
        if d.get("divergence", {}).get("review_priority") == "HIGH"
    ]

    # ── ZIC_STRICTER cases (ZIC wants to block but your system allowed) ───────
    zic_stricter = [
        d for d in divergences
        if d.get("divergence", {}).get("direction") == "ZIC_STRICTER"
    ]
    missed_fraud_candidates = [
        {
            "event_id":      d["event_id"],
            "event_type":    d["event_type"],
            "your_decision": d["your_decision"],
            "zic_action":    d["zic_action"],
            "zic_score":     d["zic_score"],
            "zic_band":      d["zic_band"],
            "top_signals":   d.get("fired_signals", [])[:5],
            "typologies":    d.get("typologies", []),
            "human_summary": d.get("human_summary", "")[:200],
        }
        for d in sorted(zic_stricter, key=lambda x: x["zic_score"], reverse=True)[:20]
    ]

    # ── Composite rule frequency ──────────────────────────────────────────────
    all_rules: list[str] = []
    for d in decisions:
        all_rules.extend(d.get("composite_rules", []))
    composite_rule_freq = Counter(all_rules).most_common(10)

    report = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "log_dir":          str(log_dir),
        "period_days":      days,
        "summary": {
            "total_events":           total,
            "total_divergences":      div_total,
            "divergence_rate_pct":    round(div_total / total * 100, 1) if total else 0,
            "zic_stricter_count":     div_by_direction.get("ZIC_STRICTER", 0),
            "zic_looser_count":       div_by_direction.get("ZIC_LOOSER", 0),
            "agree_count":            total - div_total,
            "high_priority_divs":     len(high_pri),
            "missed_fraud_candidates": len(zic_stricter),
        },
        "score_distribution": score_stats,
        "band_distribution":  dict(band_dist.most_common()),
        "zic_action_distribution":  dict(zic_action_dist.most_common()),
        "your_action_distribution": dict(your_action_dist.most_common()),
        "divergence_by_direction":  dict(div_by_direction.most_common()),
        "top_signals":     [{"signal_id": sid, "count": cnt} for sid, cnt in top_signals],
        "top_typologies":  [{"typology": t, "count": cnt} for t, cnt in top_typologies],
        "composite_rule_frequency": [{"rule_id": r, "count": cnt} for r, cnt in composite_rule_freq],
        "missed_fraud_candidates":  missed_fraud_candidates,
        "recommendations":  _build_recommendations(
            total, div_total, div_by_direction, zic_stricter, score_stats
        ),
    }
    return report


def _build_recommendations(
    total: int,
    div_total: int,
    div_by_direction: Counter,
    zic_stricter: list,
    score_stats: dict,
) -> list[str]:
    recs = []
    div_rate = div_total / total * 100 if total else 0
    stricter = div_by_direction.get("ZIC_STRICTER", 0)
    looser   = div_by_direction.get("ZIC_LOOSER", 0)

    if div_rate < 2:
        recs.append(
            "Divergence rate is low (<2%). ZIC decisions are closely aligned "
            "with your system. Consider promoting ZIC to active mode on low-risk rails."
        )
    elif div_rate > 20:
        recs.append(
            f"High divergence rate ({div_rate:.1f}%). Review threshold calibration "
            "in ZIC — thresholds may be mis-tuned for your traffic profile."
        )

    if stricter > 0:
        recs.append(
            f"{stricter} events where ZIC is stricter than your system. "
            "Review 'missed_fraud_candidates' — these are potential fraud cases "
            "your system allowed but ZIC would have blocked."
        )

    if looser > 0:
        recs.append(
            f"{looser} events where ZIC is looser than your system. "
            "These are potential false positives in your current system — "
            "review whether your existing rules are over-blocking."
        )

    if score_stats.get("p95", 0) < 30:
        recs.append(
            "95th percentile score is below 30. ZIC signals may not be matching "
            "your traffic — verify context fields are being populated correctly."
        )

    if score_stats.get("p50", 0) > 60:
        recs.append(
            "Median score above 60 — your traffic is unusually high risk or "
            "signal thresholds need recalibration. Review ZIC thresholds[] settings."
        )

    if not recs:
        recs.append("No immediate action recommended. Continue collecting shadow data.")

    return recs


def print_report(report: dict) -> None:
    if "error" in report:
        print(f"\n⚠ Report error: {report['error']}")
        return
    s = report.get("summary", {})
    print(f"\n{'═'*60}")
    print(f"ZIC SHADOW MODE REPORT")
    print(f"Generated: {report.get('generated_at', 'unknown')}")
    print(f"Period:    last {report.get('period_days', 1)} day(s)")
    print(f"{'═'*60}")
    print(f"\n── Summary ──────────────────────────────────────────────")
    print(f"  Total events:             {s['total_events']:,}")
    print(f"  Divergences:              {s['total_divergences']:,} ({s['divergence_rate_pct']}%)")
    print(f"  ZIC stricter:             {s['zic_stricter_count']}  ← review these")
    print(f"  ZIC looser:               {s['zic_looser_count']}")
    print(f"  Missed fraud candidates:  {s['missed_fraud_candidates']}")
    print(f"  High priority divs:       {s['high_priority_divs']}")

    sd = report.get("score_distribution", {})
    print(f"\n── Risk Score Distribution ───────────────────────────────")
    print(f"  p50={sd.get('p50')}  p75={sd.get('p75')}  p90={sd.get('p90')}  p99={sd.get('p99')}  max={sd.get('max')}")

    print(f"\n── ZIC Action Distribution ───────────────────────────────")
    for action, cnt in report.get("zic_action_distribution", {}).items():
        pct = round(cnt / s['total_events'] * 100, 1) if s['total_events'] else 0
        bar = "█" * int(pct / 2)
        print(f"  {action:<15} {cnt:>6}  {pct:5.1f}%  {bar}")

    print(f"\n── Top Signals Fired ─────────────────────────────────────")
    for item in report.get("top_signals", [])[:10]:
        print(f"  {item['signal_id']:<12}  {item['count']:>5}x")

    print(f"\n── Recommendations ───────────────────────────────────────")
    for rec in report.get("recommendations", []):
        print(f"  • {rec}")

    if report.get("missed_fraud_candidates"):
        print(f"\n── Top Missed Fraud Candidates (ZIC stricter) ────────────")
        for c in report["missed_fraud_candidates"][:5]:
            print(f"  {c['event_id']}  score={c['zic_score']}  {c['your_decision']}→{c['zic_action']}")
            print(f"    {c['human_summary'][:100]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="ZIC Shadow Mode Report")
    parser.add_argument("--log-dir", default="shadow_mode/logs")
    parser.add_argument("--days",    type=int, default=1)
    parser.add_argument("--output",  default=None, help="Save JSON report to file")
    parser.add_argument("--quiet",   action="store_true")
    args = parser.parse_args()

    report = generate_report(Path(args.log_dir), days=args.days)

    if not args.quiet:
        print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report saved → {args.output}")


if __name__ == "__main__":
    main()
