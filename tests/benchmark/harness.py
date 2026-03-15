#!/usr/bin/env python3
"""Benchmark harness — runs all red-team scenarios and produces reports.

Usage::

    python -m tests.benchmark.harness          # from project root
    python tests/benchmark/harness.py          # direct execution
"""
from __future__ import annotations

import json
import sys
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


def run() -> dict:
    """Execute all scenarios and return the full results dict."""
    print("=" * 64)
    print("  Hermes Aegis — Red-Team Benchmark")
    print("=" * 64)
    print()

    results = run_all_scenarios()
    scores = compute_scores(results)

    # Console table
    hdr = f"{'#':<4} {'SCENARIO':<35} {'BARE':<10} {'AEGIS':<10}"
    print(hdr)
    print("-" * len(hdr))
    for i, r in enumerate(results, 1):
        status = "✅" if r.aegis_result == "blocked" else "❌"
        print(f"{i:<4} {r.name:<35} {r.bare_result:<10} {r.aegis_result:<10} {status}")
    print("-" * len(hdr))
    rate = scores["aegis_block_rate"] * 100
    print(f"Aegis block rate: {rate:.0f}% "
          f"({scores['aegis_blocked']}/{scores['total_scenarios']})")
    print()

    # Build payload
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "timestamp": timestamp,
        "scenarios": [asdict(r) for r in results],
        "scores": scores,
    }

    # Persist JSON
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Results saved to {json_path}")

    # Also write a latest symlink / copy
    latest_path = RESULTS_DIR / "latest.json"
    latest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Generate markdown report
    md_path = RESULTS_DIR / "latest.md"
    generate_report(latest_path, md_path)
    print(f"Report saved to {md_path}")

    return payload


if __name__ == "__main__":
    run()
