# hermes-aegis/src/hermes_aegis/patterns/shared_registry.py
"""Shared pattern registry that merges aegis patterns with hermes-agent's redact patterns."""
from __future__ import annotations

import importlib
import re
import sys
import threading
from pathlib import Path
from typing import Optional

from hermes_aegis.patterns.secrets import (
    SECRET_PATTERNS,
    PatternMatch,
    scan_for_secrets,
)

# ---------------------------------------------------------------------------
# Hermes-agent discovery
# ---------------------------------------------------------------------------

_HERMES_SEARCH_PATHS = [
    Path.home() / ".hermes" / "hermes-agent",
    Path.home() / ".hermes" / "hermes-agent" / "security",
]

_HERMES_PATTERN_ATTR_NAMES = [
    "SECRET_PATTERNS",
    "REDACT_PATTERNS",
    "PATTERNS",
]

_hermes_patterns: Optional[list[tuple[str, re.Pattern]]] = None
_hermes_available: bool = False
_discovery_done: bool = False
_discovered: bool = False
_discovery_lock = threading.Lock()


def _discover_hermes_patterns() -> Optional[list[tuple[str, re.Pattern]]]:
    """Try to import hermes-agent's redact module and extract patterns.

    Adds candidate directories to sys.path temporarily while importing,
    then removes them to avoid polluting the path.
    """
    # Strategy 1: try direct import (works if hermes is installed as a package)
    try:
        mod = importlib.import_module("hermes.security.redact")
        return _extract_patterns(mod)
    except (ImportError, ModuleNotFoundError):
        pass

    # Strategy 2: probe well-known filesystem locations
    added_paths: list[str] = []
    try:
        for search_dir in _HERMES_SEARCH_PATHS:
            if not search_dir.is_dir():
                continue
            # Walk up to find redact.py
            candidates = list(search_dir.rglob("redact.py"))
            for candidate in candidates:
                parent = str(candidate.parent)
                if parent not in sys.path:
                    sys.path.insert(0, parent)
                    added_paths.append(parent)
                try:
                    # Import redact as a standalone module
                    spec = importlib.util.spec_from_file_location("_hermes_redact", str(candidate))
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)  # type: ignore[union-attr]
                        result = _extract_patterns(mod)
                        if result:
                            return result
                except Exception:
                    continue
    finally:
        # Clean up sys.path
        for p in added_paths:
            try:
                sys.path.remove(p)
            except ValueError:
                pass

    return None


def _extract_patterns(module: object) -> Optional[list[tuple[str, re.Pattern]]]:
    """Extract pattern list from a module, looking for known attribute names."""
    for attr_name in _HERMES_PATTERN_ATTR_NAMES:
        val = getattr(module, attr_name, None)
        if val is None:
            continue
        if isinstance(val, list) and len(val) > 0:
            # Validate shape: list of (str, compiled_regex)
            first = val[0]
            if (
                isinstance(first, (list, tuple))
                and len(first) == 2
                and isinstance(first[0], str)
                and isinstance(first[1], re.Pattern)
            ):
                return list(val)
    return None


def _run_discovery() -> None:
    """Run discovery once and cache results."""
    global _hermes_patterns, _hermes_available, _discovery_done
    if _discovery_done:
        return
    _hermes_patterns = _discover_hermes_patterns()
    _hermes_available = _hermes_patterns is not None
    _discovery_done = True


def _ensure_discovered() -> None:
    """Ensure discovery has been run (thread-safe, lazy)."""
    global _discovered
    if _discovered:
        return
    with _discovery_lock:
        if not _discovered:
            _run_discovery()
            _discovered = True

# ---------------------------------------------------------------------------
# Merging logic
# ---------------------------------------------------------------------------


def _merge_patterns(
    aegis: list[tuple[str, re.Pattern]],
    hermes: Optional[list[tuple[str, re.Pattern]]],
) -> list[tuple[str, re.Pattern]]:
    """Merge aegis and hermes patterns, deduplicating by name.

    Aegis patterns take priority — if both define a pattern with the same
    name, the aegis version wins.
    """
    seen: set[str] = set()
    merged: list[tuple[str, re.Pattern]] = []

    # Aegis first (higher priority)
    for name, pattern in aegis:
        if name not in seen:
            seen.add(name)
            merged.append((name, pattern))

    # Then hermes
    if hermes:
        for name, pattern in hermes:
            if name not in seen:
                seen.add(name)
                merged.append((name, pattern))

    return merged


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_all_patterns() -> list[tuple[str, re.Pattern]]:
    """Return merged set of all patterns (aegis + hermes), deduplicated by name."""
    _ensure_discovered()
    return _merge_patterns(SECRET_PATTERNS, _hermes_patterns)


def scan_all(
    text: str,
    exact_values: list[str] | None = None,
) -> list[PatternMatch]:
    """Scan text using merged pattern set plus exact value matching.

    Uses the same scanning logic as aegis's scan_for_secrets but with
    the merged pattern set.
    """
    _ensure_discovered()
    matches: list[PatternMatch] = []
    merged = get_all_patterns()

    for name, pattern in merged:
        for m in pattern.finditer(text):
            matches.append(
                PatternMatch(
                    pattern_name=name,
                    matched_text=m.group(),
                    start=m.start(),
                    end=m.end(),
                )
            )

    # Exact value matching — delegate to the original implementation
    if exact_values:
        exact_matches = scan_for_secrets("", exact_values=[])  # no-op, just for type
        # Re-use the exact-value logic from scan_for_secrets
        exact_only = scan_for_secrets(text, exact_values=exact_values)
        # Filter to only exact_match* patterns (avoid double-counting regex matches)
        for em in exact_only:
            if em.pattern_name.startswith("exact_match"):
                matches.append(em)

    return matches


def get_hermes_patterns() -> Optional[list[tuple[str, re.Pattern]]]:
    """Return hermes-agent patterns if discovered, else None."""
    _ensure_discovered()
    return _hermes_patterns


def is_hermes_available() -> bool:
    """Return True if hermes-agent patterns were successfully discovered."""
    _ensure_discovered()
    return _hermes_available


def reset_discovery() -> None:
    """Reset discovery state — useful for testing."""
    global _hermes_patterns, _hermes_available, _discovery_done, _discovered
    _hermes_patterns = None
    _hermes_available = False
    _discovery_done = False
    _discovered = False
