"""Report generator — reads audit entries and computes statistics for report prompts."""
from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hermes_aegis.audit.trail import AuditTrail


AEGIS_DIR = Path.home() / ".hermes-aegis"
LAST_REPORT_FILE = AEGIS_DIR / ".last-report-timestamp"


def get_last_report_time() -> float:
    """Return the timestamp of the last generated report, or 0."""
    if LAST_REPORT_FILE.exists():
        try:
            return float(LAST_REPORT_FILE.read_text().strip())
        except (ValueError, OSError):
            pass
    return 0.0


def set_last_report_time(ts: float | None = None) -> None:
    """Record the current time as the last report timestamp."""
    LAST_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_REPORT_FILE.write_text(str(ts or time.time()))


def compute_audit_stats(entries: list[Any]) -> dict[str, Any]:
    """Compute statistics from a list of audit entries."""
    decision_counts: Counter[str] = Counter()
    middleware_counts: Counter[str] = Counter()
    tool_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    timestamps: list[float] = []

    for e in entries:
        if hasattr(e, "decision"):
            decision = e.decision
            middleware = e.middleware
            tool = e.tool_name
            args = e.args_redacted
            ts = e.timestamp
        else:
            decision = e.get("decision", "")
            middleware = e.get("middleware", "")
            tool = e.get("tool_name", "")
            args = e.get("args_redacted", {})
            ts = e.get("timestamp", 0)

        decision_counts[decision] += 1
        middleware_counts[middleware] += 1
        tool_counts[tool] += 1

        host = args.get("host", args.get("domain", ""))
        if host:
            host_counts[str(host)] += 1

        if isinstance(ts, (int, float)):
            timestamps.append(ts)

    stats: dict[str, Any] = {
        "total_events": len(entries),
        "decisions": dict(decision_counts.most_common(20)),
        "middlewares": dict(middleware_counts.most_common(10)),
        "tools": dict(tool_counts.most_common(10)),
        "top_hosts": dict(host_counts.most_common(20)),
    }

    if timestamps:
        stats["time_range"] = {
            "start": datetime.fromtimestamp(min(timestamps), tz=timezone.utc).isoformat(),
            "end": datetime.fromtimestamp(max(timestamps), tz=timezone.utc).isoformat(),
            "duration_hours": round((max(timestamps) - min(timestamps)) / 3600, 1),
        }

    return stats


def build_report_prompt(
    audit_path: Path,
    since: float | None = None,
) -> str:
    """Build a prompt for the report agent with pre-computed statistics."""
    trail = AuditTrail(audit_path)
    all_entries = trail.read_all()

    if since is not None:
        entries = [
            e for e in all_entries
            if isinstance(e.timestamp, (int, float)) and e.timestamp > since
        ]
    else:
        entries = all_entries

    if not entries:
        return (
            "No new audit events since the last report. "
            "Write a brief report confirming no security events occurred."
        )

    stats = compute_audit_stats(entries)

    return f"""You are a security analyst for hermes-aegis, a security hardening layer
for the Hermes AI agent. Generate a concise security digest report based on the
following audit trail statistics.

## Audit Statistics (since last report)

```json
{json.dumps(stats, indent=2)}
```

## Instructions

Write a markdown security digest report covering:
1. **Summary**: Key findings in 2-3 sentences
2. **Event Breakdown**: Notable patterns in the data
3. **Blocked Requests**: If any BLOCKED events, summarize what was caught
4. **Anomalies**: If any ANOMALY events, assess risk level
5. **Recommendations**: Action items for the operator (if any)

Keep the report concise and actionable. Focus on security-relevant patterns,
not routine events.
"""
