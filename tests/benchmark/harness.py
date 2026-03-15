#!/usr/bin/env python3
"""Benchmark harness — runs red-team scenarios with timing and produces reports.

Usage::

    ./tests/benchmark/run.sh                       # auto-detects venv
    .venv/bin/python -m tests.benchmark.harness     # explicit
    .venv/bin/python -m tests.benchmark.harness 200  # custom iterations
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is importable when running directly
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root / "src"))
    sys.path.insert(0, str(_project_root))

from tests.benchmark.red_team import run_all_scenarios, compute_scores  # noqa: E402
from tests.benchmark.report import generate_report  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"

DEFAULT_ITERATIONS = 100


def run(iterations: int = DEFAULT_ITERATIONS) -> dict:
    """Execute all scenarios with benchmarking and return results."""
    print("=" * 72)
    print("  Hermes Aegis — Security Effectiveness Benchmark")
    print("=" * 72)
    print(f"  Iterations per scenario: {iterations}")
    print()

    t_start = time.perf_counter()
    results = run_all_scenarios(iterations=iterations)
    t_total = time.perf_counter() - t_start
    scores = compute_scores(results)

    # ---- Security Results Table ----
    hdr = f"{'#':<3} {'SCENARIO':<30} {'BARE':<8} {'AEGIS':<8} {'MEAN':>8} {'MED':>8} {'P95':>8}"
    print(hdr)
    print("-" * len(hdr))
    for i, r in enumerate(results, 1):
        icon = "✅" if r.aegis_result == "blocked" else "❌"
        mean = f"{r.mean_us:.0f}μs"
        med = f"{r.median_us:.0f}μs"
        p95 = f"{r.p95_us:.0f}μs"
        print(f"{i:<3} {r.name:<30} {r.bare_result:<8} {r.aegis_result:<8} {mean:>8} {med:>8} {p95:>8} {icon}")
    print("-" * len(hdr))
    print()

    # ---- Summary Stats ----
    lat = scores["scan_latency"]
    print("SECURITY")
    print(f"  Block rate:       {scores['aegis_block_rate']*100:.0f}% "
          f"({scores['aegis_blocked']}/{scores['total_scenarios']}) — "
          f"bare: {scores['bare_block_rate']*100:.0f}%")
    print()
    print("SCAN LATENCY (per request, across all scenarios)")
    print(f"  Mean:             {lat['mean_us']:.0f} μs")
    print(f"  Median:           {lat['median_us']:.0f} μs")
    print(f"  Fastest scenario: {lat['fastest_scenario_us']:.0f} μs")
    print(f"  Slowest scenario: {lat['slowest_scenario_us']:.0f} μs")
    print()

    # Per-scenario breakdown
    print("PER-SCENARIO LATENCY (μs)")
    print(f"  {'SCENARIO':<30} {'MEAN':>8} {'MEDIAN':>8} {'P95':>8} {'MIN':>8} {'MAX':>8}")
    for r in results:
        print(f"  {r.name:<30} {r.mean_us:>8.0f} {r.median_us:>8.0f} "
              f"{r.p95_us:>8.0f} {r.min_us:>8.0f} {r.max_us:>8.0f}")
    print()
    print(f"Total benchmark time: {t_total:.2f}s "
          f"({iterations} iterations × {len(results)} scenarios)")
    print()

    # ---- Build payload ----
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "timestamp": timestamp,
        "iterations": iterations,
        "total_time_s": round(t_total, 3),
        "scores": scores,
        "scenarios": [
            {
                "name": r.name,
                "description": r.description,
                "bare_result": r.bare_result,
                "aegis_result": r.aegis_result,
                "mean_us": round(r.mean_us, 1),
                "median_us": round(r.median_us, 1),
                "p95_us": round(r.p95_us, 1),
                "min_us": round(r.min_us, 1),
                "max_us": round(r.max_us, 1),
                "iterations": r.iterations,
            }
            for r in results
        ],
    }

    # Persist
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = RESULTS_DIR / f"results_{ts_str}.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Results saved to {json_path}")

    latest_path = RESULTS_DIR / "latest.json"
    latest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md_path = RESULTS_DIR / "latest.md"
    generate_report(latest_path, md_path)
    print(f"Report saved to {md_path}")

    return payload


if __name__ == "__main__":
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ITERATIONS
    run(iterations=iters)
