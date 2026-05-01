"""Shared types for the patching framework.

PatchResult, HERMES_AGENT_DIR, and _invalidate_pyc are used by both
FilePatch (in patches.py) and SemanticPatch (in patching/semantic_patch.py).
Extracting them here avoids circular imports.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from pathlib import Path


def _resolve_hermes_agent_dir() -> Path:
    """Return the Hermes checkout used by the active hermes CLI."""
    try:
        import hermes_cli

        return Path(inspect.getfile(hermes_cli)).resolve().parent.parent
    except Exception:
        return Path.home() / ".hermes" / "hermes-agent"


HERMES_AGENT_DIR = _resolve_hermes_agent_dir()


def _invalidate_pyc(source_path: Path) -> None:
    """Delete cached .pyc files for a patched source file.

    Python may use stale bytecode from __pycache__/ instead of re-reading
    the modified .py file. Remove all matching .pyc entries to force
    recompilation on next import.
    """
    cache_dir = source_path.parent / "__pycache__"
    if not cache_dir.is_dir():
        return
    stem = source_path.stem
    for pyc in cache_dir.glob(f"{stem}.*.pyc"):
        try:
            pyc.unlink()
        except OSError:
            pass


@dataclass
class PatchResult:
    """Result of applying or reverting a single patch."""

    name: str
    # "applied" | "already_applied" | "incompatible" | "skipped" | "error"
    status: str
    detail: str = ""

    def ok(self) -> bool:
        return self.status in ("applied", "already_applied")

    def summary(self) -> str:
        icons = {
            "applied": "✓",
            "already_applied": "·",
            "incompatible": "⚠",
            "skipped": "·",
            "error": "✗",
        }
        icon = icons.get(self.status, "?")
        msg = f"  {icon} {self.name}: {self.status}"
        if self.detail:
            msg += f" — {self.detail}"
        return msg
