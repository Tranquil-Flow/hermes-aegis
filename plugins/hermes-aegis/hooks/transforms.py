"""Aegis output transforms for secret redaction."""

from __future__ import annotations

import logging
import importlib.util
import sys
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


def _secret_replacement(name: str) -> str:
    normalized = name.replace("_", "-")
    return f"[AEGIS:REDACTED:{normalized}]"


def aegis_secret_scan(
    tool_name: str = "",
    args: dict[str, Any] | None = None,
    result: str = "",
    output: str | None = None,
    **kwargs: Any,
) -> str:
    """Redact secret-looking spans from tool results and terminal output."""
    text = result if result else (output or "")
    if not text:
        return text

    try:
        from ..patterns import scan_secrets
    except ImportError:
        scan_secrets = _load_local_patterns().scan_secrets

    matches = scan_secrets(text)
    if not matches:
        return text

    redacted = text
    for match in sorted(matches, key=lambda item: item.start, reverse=True):
        redacted = redacted[: match.start] + _secret_replacement(match.name) + redacted[match.end :]
    logger.info("Aegis redacted %d secret span(s) from %s", len(matches), tool_name or "output")
    return redacted


def register_transforms(ctx: Any) -> None:
    """Register Aegis transforms before privacy redaction."""
    from aegis_core.transforms import TransformRegistry

    TransformRegistry.register("transform_tool_result", "aegis_secret_scan", priority=10, fn=aegis_secret_scan)
    TransformRegistry.register("transform_terminal_output", "aegis_secret_scan", priority=10, fn=aegis_secret_scan)
    TransformRegistry.ensure_hook_registered("transform_tool_result", ctx)
    TransformRegistry.ensure_hook_registered("transform_terminal_output", ctx)
