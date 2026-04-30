"""Aegis audit logging for completed tool calls."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

try:
    from .._deps import ensure_local_dependency_paths
except ImportError:
    from _deps import ensure_local_dependency_paths

ensure_local_dependency_paths()


def _stable_args_hash(args: dict[str, Any] | None) -> str:
    payload = json.dumps(args or {}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _correlation_id() -> str | None:
    try:
        from aegis_core.correlation import generate_correlation_id

        return generate_correlation_id()
    except Exception:
        return None


def aegis_post_tool_call(
    tool_name: str,
    args: dict[str, Any] | None,
    result: str = "",
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    blocked: bool = False,
    **kwargs: Any,
) -> None:
    """Record an audit entry for dashboard and tests."""
    try:
        from ..state import record_audit_entry
    except ImportError:
        from state import record_audit_entry

    record_audit_entry(
        {
            "timestamp": time.time(),
            "tool_name": tool_name,
            "args_hash": _stable_args_hash(args),
            "result_hash": hashlib.sha256((result or "").encode("utf-8")).hexdigest()[:16],
            "task_id": task_id,
            "session_id": session_id,
            "tool_call_id": tool_call_id,
            "correlation_id": _correlation_id(),
            "decision": "BLOCKED" if blocked else "ALLOWED",
            "reason": "",
        }
    )
