"""Aegis pre_tool_call hook with fail-closed enforcement."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .._deps import ensure_local_dependency_paths
except ImportError:
    from _deps import ensure_local_dependency_paths

ensure_local_dependency_paths()

logger = logging.getLogger(__name__)


def _load_local_patterns():
    """Load the plugin's patterns.py without being shadowed by repo test packages."""
    spec = importlib.util.spec_from_file_location(
        "hermes_aegis_plugin_patterns",
        Path(__file__).resolve().parents[1] / "patterns.py",
    )
    if spec is None or spec.loader is None:
        raise ImportError("could not load local Aegis plugin patterns")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _extract_command(tool_name: str, args: dict[str, Any]) -> str:
    if tool_name not in {"terminal", "run_command", "execute_shell"}:
        return ""
    for key in ("command", "cmd"):
        value = args.get(key)
        if isinstance(value, str):
            return value
    return ""


def _check_patterns(command: str) -> str | None:
    try:
        from ..patterns import check_command
    except ImportError:
        check_command = _load_local_patterns().check_command

    return check_command(command)


def _check_args_for_secrets(args: dict[str, Any]) -> str | None:
    try:
        from ..patterns import scan_secrets
    except ImportError:
        scan_secrets = _load_local_patterns().scan_secrets

    payload = json.dumps(args or {}, sort_keys=True, default=str)
    matches = scan_secrets(payload)
    if not matches:
        return None
    names = ", ".join(sorted({match.name for match in matches}))
    return f"raw secret material in tool arguments: {names}"


def _record_block(
    *,
    tool_name: str,
    args: dict[str, Any] | None,
    reason: str,
    task_id: str,
    session_id: str,
    tool_call_id: str,
) -> None:
    try:
        try:
            from ..state import record_audit_entry
        except ImportError:
            from state import record_audit_entry

        payload = json.dumps(args or {}, sort_keys=True, default=str)
        record_audit_entry(
            {
                "timestamp": time.time(),
                "tool_name": tool_name,
                "args_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16],
                "result_hash": "",
                "task_id": task_id,
                "session_id": session_id,
                "tool_call_id": tool_call_id,
                "correlation_id": _correlation_id(),
                "decision": "BLOCKED",
                "reason": reason,
            }
        )
    except Exception:
        logger.debug("Aegis block audit persistence failed", exc_info=True)


def _correlation_id() -> str | None:
    try:
        from aegis_core.correlation import generate_correlation_id

        return generate_correlation_id()
    except Exception:
        return None


def aegis_pre_tool_call(
    tool_name: str,
    args: dict[str, Any] | None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **kwargs: Any,
) -> dict[str, str] | None:
    """Block dangerous tool calls and raw secrets. Fail closed on scanner errors."""
    try:
        normalized_args = args or {}
        command = _extract_command(tool_name, normalized_args)
        reason = _check_patterns(command) if command else None
        if reason is None:
            reason = _check_args_for_secrets(normalized_args)
        if reason is None:
            return None

        logger.warning(
            "Aegis blocked tool call: tool=%s task_id=%s session_id=%s tool_call_id=%s reason=%s",
            tool_name,
            task_id,
            session_id,
            tool_call_id,
            reason,
        )
        _record_block(
            tool_name=tool_name,
            args=normalized_args,
            reason=reason,
            task_id=task_id,
            session_id=session_id,
            tool_call_id=tool_call_id,
        )
        return {"action": "block", "message": f"Aegis blocked tool call: {reason}"}
    except Exception as exc:
        logger.error("Aegis pre_tool_call internal error", exc_info=True)
        return {
            "action": "block",
            "message": f"Aegis internal error; blocking tool call as precaution: {exc}",
        }
