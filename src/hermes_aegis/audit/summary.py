"""Audit trail summarization helpers.

This module provides time-windowed grouping for the audit UX. It deliberately
reads existing AuditTrail rows without changing their hash-chain format, so it
can summarize old v0.2.x logs and future normalized events alike.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_aegis.audit.trail import AuditTrail


_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([smhd])?$", re.IGNORECASE)
_DURATION_UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}


@dataclass
class AuditSummary:
    """Time-windowed audit summary."""

    total: int
    since: str
    window_seconds: float | None
    group_by: str
    group_counts: dict[str, int] = field(default_factory=dict)
    decision_counts: dict[str, int] = field(default_factory=dict)
    middleware_counts: dict[str, int] = field(default_factory=dict)
    host_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "total": self.total,
            "since": self.since,
            "window_seconds": self.window_seconds,
            "group_by": self.group_by,
            "group_counts": self.group_counts,
            "decision_counts": self.decision_counts,
            "middleware_counts": self.middleware_counts,
            "host_counts": self.host_counts,
        }

    def to_json(self) -> str:
        """Serialize the summary as stable pretty JSON."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def parse_since(value: str | None) -> float | None:
    """Parse a duration such as '24h' into seconds.

    Returns None for 'all' or None.
    """
    if value is None:
        return 24 * 60 * 60
    text = value.strip().lower()
    if text in {"all", "lifetime"}:
        return None
    match = _DURATION_RE.fullmatch(text)
    if not match:
        raise ValueError(f"Invalid duration: {value!r}")
    amount = float(match.group(1))
    unit = match.group(2) or "s"
    return amount * _DURATION_UNITS[unit]


def _entry_timestamp(entry) -> float | None:
    try:
        return float(entry.timestamp)
    except (TypeError, ValueError):
        return None


def _count(mapping: dict[str, int], key: str) -> None:
    mapping[key] = mapping.get(key, 0) + 1


def _group_key(entry, group_by: str) -> str:
    if group_by == "decision":
        return entry.decision or "<none>"
    if group_by == "middleware":
        return entry.middleware or "<none>"
    if group_by == "host":
        host = entry.args_redacted.get("host") if isinstance(entry.args_redacted, dict) else None
        return str(host) if host else "<none>"
    raise ValueError(f"Unsupported group_by: {group_by!r}")


def summarize_audit(
    audit_path: Path | str,
    *,
    since: str = "24h",
    group_by: str = "middleware",
    now: float | None = None,
) -> AuditSummary:
    """Summarize audit rows by decision, middleware, host, and selected group.

    Args:
        audit_path: Path to audit.jsonl.
        since: Duration window such as '1h', '24h', '7d', or 'all'.
        group_by: One of 'middleware', 'decision', or 'host'.
        now: Optional clock override for deterministic tests.
    """
    if group_by not in {"middleware", "decision", "host"}:
        raise ValueError("group_by must be one of: middleware, decision, host")

    current_time = time.time() if now is None else now
    window_seconds = parse_since(since)
    cutoff = None if window_seconds is None else current_time - window_seconds

    group_counts: dict[str, int] = {}
    decision_counts: dict[str, int] = {}
    middleware_counts: dict[str, int] = {}
    host_counts: dict[str, int] = {}
    total = 0

    for entry in AuditTrail(audit_path).read_all():
        timestamp = _entry_timestamp(entry)
        if cutoff is not None and timestamp is not None and timestamp < cutoff:
            continue

        total += 1
        _count(decision_counts, entry.decision or "<none>")
        _count(middleware_counts, entry.middleware or "<none>")
        if isinstance(entry.args_redacted, dict) and entry.args_redacted.get("host"):
            _count(host_counts, str(entry.args_redacted["host"]))
        _count(group_counts, _group_key(entry, group_by))

    return AuditSummary(
        total=total,
        since=since,
        window_seconds=window_seconds,
        group_by=group_by,
        group_counts=dict(sorted(group_counts.items())),
        decision_counts=dict(sorted(decision_counts.items())),
        middleware_counts=dict(sorted(middleware_counts.items())),
        host_counts=dict(sorted(host_counts.items())),
    )
