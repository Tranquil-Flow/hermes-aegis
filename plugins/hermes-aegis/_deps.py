"""Optional local dependency resolution for development checkouts."""

from __future__ import annotations

import sys
from pathlib import Path


_LOCAL_SRC_PATHS = (
    Path.home() / "Projects" / "aegis-core" / "src",
    Path.home() / "Projects" / "hermes-aegis" / "src",
)


def ensure_local_dependency_paths() -> None:
    """Add local source checkouts to sys.path when packages are not installed."""
    for path in reversed(_LOCAL_SRC_PATHS):
        if path.exists():
            value = str(path)
            if value not in sys.path:
                sys.path.insert(0, value)
