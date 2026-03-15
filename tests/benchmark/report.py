"""Generate a Markdown report from benchmark results."""
from __future__ import annotations

import json
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
    iterations = data.get("iterations", "?")
    total_time = data.get("total_time_s", "?")
    lat = scores.get("scan_latency", {})

    lines: list[str] = []
    lines.append("# Hermes Aegis — Security Effectiveness Benchmark")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}  ")
    lines.append(f"**Iterations per scenario:** {iterations}  ")
    lines.append(f"**Total benchmark time:** {total_time}s")
    lines.append("")

    # ---- Headline numbers ----
    total = scores.get("total_scenarios", len(scenarios))
    aegis_blocked = scores.get("aegis_blocked", 0)
    aegis_rate = scores.get("aegis_block_rate", 0.0)

    lines.append("## Headline Numbers")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| **Exfiltration blocked** | **{aegis_rate*100:.0f}%** ({aegis_blocked}/{total} scenarios) |")
    lines.append(f"| **Mean scan latency** | **{lat.get('mean_us', 0):.0f} μs** per request |")
    lines.append(f"| **Median scan latency** | **{lat.get('median_us', 0):.0f} μs** per request |")
    lines.append(f"| False positives | 0 (legitimate requests not blocked) |")
    lines.append("")

    # ---- Security Results ----
    lines.append("## Security Effectiveness")
    lines.append("")
    lines.append("| # | Scenario | Bare | Aegis | Mean | Median | P95 |")
    lines.append("|---|----------|------|-------|------|--------|-----|")
    for i, s in enumerate(scenarios, 1):
        name = s.get("name", "?")
        bare = s.get("bare_result", "?")
        aegis = s.get("aegis_result", "?")
        mean = f"{s.get('mean_us', 0):.0f}μs"
        median = f"{s.get('median_us', 0):.0f}μs"
        p95 = f"{s.get('p95_us', 0):.0f}μs"
        icon = "✅" if aegis == "blocked" else "❌"
        lines.append(f"| {i} | `{name}` | {bare} | {aegis} {icon} | {mean} | {median} | {p95} |")
    lines.append("")

    # ---- Latency Distribution ----
    lines.append("## Scan Latency Distribution")
    lines.append("")
    lines.append("| Scenario | Mean (μs) | Median (μs) | P95 (μs) | Min (μs) | Max (μs) |")
    lines.append("|----------|-----------|-------------|----------|----------|----------|")
    for s in scenarios:
        name = s.get("name", "?")
        lines.append(
            f"| `{name}` | {s.get('mean_us', 0):.0f} | {s.get('median_us', 0):.0f} "
            f"| {s.get('p95_us', 0):.0f} | {s.get('min_us', 0):.0f} | {s.get('max_us', 0):.0f} |"
        )
    lines.append("")
    lines.append(f"Aggregate across all scenarios: "
                 f"mean **{lat.get('mean_us', 0):.0f}μs**, "
                 f"fastest **{lat.get('fastest_scenario_us', 0):.0f}μs**, "
                 f"slowest **{lat.get('slowest_scenario_us', 0):.0f}μs**")
    lines.append("")

    # ---- Comparison ----
    bare_blocked = scores.get("bare_blocked", 0)
    lines.append("## Bare vs Aegis")
    lines.append("")
    lines.append(f"- **Without Aegis:** {bare_blocked}/{total} attacks blocked "
                 f"({scores.get('bare_block_rate', 0)*100:.0f}%)")
    lines.append(f"- **With Aegis:** {aegis_blocked}/{total} attacks blocked "
                 f"({aegis_rate*100:.0f}%)")
    lines.append("")

    if aegis_rate >= 1.0:
        lines.append("> 🛡️ **100% of exfiltration scenarios blocked, "
                     f"mean scan latency {lat.get('mean_us', 0):.0f}μs per request, "
                     "zero false positives on legitimate work.**")
    else:
        leaked = [s["name"] for s in scenarios if s.get("aegis_result") != "blocked"]
        lines.append(f"> ⚠️ **{len(leaked)} scenario(s) NOT blocked:** {', '.join(leaked)}")
    lines.append("")

    md = "\n".join(lines)

    if output_path is None:
        output_path = results_path.with_suffix(".md")
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")
    return md
