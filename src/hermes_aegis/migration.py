"""Hermes v0.11 hybrid-mode migration helpers."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

PLUGIN_TARGET = Path.home() / ".hermes" / "plugins" / "hermes-aegis"
DEFAULT_PLUGIN_SOURCE = Path(__file__).resolve().parents[2] / "plugins" / "hermes-aegis"
REPLACED_PATCHES = (
    "terminal_tool_audit_forward",
    "terminal_tool_command_scan",
    "hermes_banner_aegis_status",
)


def is_v011_or_later() -> bool:
    """Return True when the local Hermes checkout exposes v0.11 plugin APIs."""
    try:
        from hermes_cli.plugins import VALID_HOOKS

        required = {
            "pre_tool_call",
            "post_tool_call",
            "transform_tool_result",
            "transform_terminal_output",
            "pre_llm_call",
            "post_api_request",
        }
        return required.issubset(set(VALID_HOOKS))
    except Exception:
        return False


def install_plugin(plugin_source: Path | None = None) -> bool:
    """Install the Aegis Hermes plugin when a source directory is available."""
    if PLUGIN_TARGET.exists():
        return True
    if plugin_source is None:
        plugin_source = DEFAULT_PLUGIN_SOURCE

    plugin_source = plugin_source.expanduser().resolve()
    if not plugin_source.exists() or not plugin_source.is_dir():
        return False

    try:
        shutil.copytree(
            plugin_source,
            PLUGIN_TARGET,
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"),
        )
        return True
    except Exception as exc:
        logger.error("Aegis plugin install failed: %s", exc)
        return False


def migrate_to_hybrid(plugin_source: Path | None = None) -> str:
    """Install the v0.11 plugin and report the retained patch model."""
    if not is_v011_or_later():
        return "Hermes v0.11 plugin APIs not detected; keeping legacy patch-only mode."

    lines = ["Aegis Hermes v0.11 hybrid migration:"]
    if install_plugin(plugin_source):
        lines.append(f"  - Plugin present at {PLUGIN_TARGET}")
        lines.append("  - MITM proxy retained for network-level security")
        lines.append(
            "  - Source patches reduced; replaced by plugin hooks: "
            + ", ".join(REPLACED_PATCHES)
        )
    else:
        lines.append(
            "  - WARNING: Plugin source not found; plugin hook enforcement unavailable"
        )
        lines.append(
            "  - Re-run from a checkout containing plugins/hermes-aegis or install the plugin manually"
        )
    return "\n".join(lines)


__all__ = [
    "PLUGIN_TARGET",
    "DEFAULT_PLUGIN_SOURCE",
    "REPLACED_PATCHES",
    "install_plugin",
    "is_v011_or_later",
    "migrate_to_hybrid",
]
