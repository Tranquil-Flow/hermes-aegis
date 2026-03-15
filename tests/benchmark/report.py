"""Generate a Markdown report from benchmark results."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_report(results_path: str | Path, output_path: str | Path | None = None) -> str:
    """Read a results JSON file and produce a Markdown report.

    Args:
        results_path: Path to the JSON results file produced by the harness.
        output_path: Where to write the .md file.  If None, writes next to results_path.

    Returns:
        The generated Markdown as a string.
    """
    results_path = Path(results_path)
    with open(results_path) as f:
        data = json.load(f)

    scenarios = data.get("scenarios", [])
    scores = data.get("scores", {})
    timestamp = data.get("timestamp", "unknown")

    lines: list[str] = []
    lines.append("# Hermes Aegis — Red-Team Benchmark Report")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}")
    lines.append("")

    # Summary
    total = scores.get("total_scenarios", len(scenarios))
    aegis_blocked = scores.get("aegis_blocked", 0)
    aegis_rate = scores.get("aegis_block_rate", 0.0)
    bare_blocked = scores.get("bare_blocked", 0)

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total scenarios | {total} |")
    lines.append(f"| Bare blocked | {bare_blocked}/{total} |")
    lines.append(f"| Aegis blocked | {aegis_blocked}/{total} |")
    lines.append(f"| **Aegis block rate** | **{aegis_rate*100:.0f}%** |")
    lines.append("")

    # Detailed table
    lines.append("## Scenario Results")
    lines.append("")
    lines.append("| # | Scenario | Description | Bare | Aegis | Status |")
    lines.append("|---|----------|-------------|------|-------|--------|")
    for i, s in enumerate(scenarios, 1):
        name = s.get("name", "?")
        desc = s.get("description", "")
        bare = s.get("bare_result", "?")
        aegis = s.get("aegis_result", "?")
        status = "PASS" if aegis == "blocked" else "FAIL"
        icon = "✅" if status == "PASS" else "❌"
        lines.append(f"| {i} | `{name}` | {desc} | {bare} | {aegis} | {icon} {status} |")
    lines.append("")

    # Comparison
    lines.append("## Bare vs Aegis Comparison")
    lines.append("")
    lines.append(f"- **Without Aegis (bare):** {bare_blocked}/{total} attacks blocked "
                 f"({scores.get('bare_block_rate', 0)*100:.0f}%)")
    lines.append(f"- **With Aegis:** {aegis_blocked}/{total} attacks blocked "
                 f"({aegis_rate*100:.0f}%)")
    lines.append("")

    if aegis_rate >= 1.0:
        lines.append("> 🛡️ **All attack scenarios were successfully blocked by Aegis.**")
    else:
        leaked = [s["name"] for s in scenarios if s.get("aegis_result") != "blocked"]
        lines.append(f"> ⚠️ **{len(leaked)} scenario(s) were NOT blocked:** {', '.join(leaked)}")
    lines.append("")

    md = "\n".join(lines)

    if output_path is None:
        output_path = results_path.with_suffix(".md")
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")
    return md
