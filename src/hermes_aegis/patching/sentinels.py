"""Fast sentinel detection and target grouping for semantic patches.

sentinels.py provides the fast path for checking whether a patch has already
been applied — string-based sentinel lookup that avoids the ~200ms LibCST parse
when the answer is already known.

Also provides:
- ``line_pattern_prefilter``: regex check that can short-circuit the LibCST parse
  for ``line_pattern`` anchors when the target text isn't present at all.
- ``batch_sentinel_check``: check all patches against a file in a single read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hermes_aegis.patches import FilePatch, SemanticPatch


class SentinelStatus(str, Enum):
    """Result of a sentinel check against a single file."""
    APPLIED = "applied"           # sentinel found — patch already applied
    NOT_APPLIED = "not_applied"   # sentinel absent — patch not yet applied
    FILE_MISSING = "file_missing"  # target file does not exist


@dataclass
class SentinelResult:
    """Outcome of checking one patch's sentinel against a file."""
    patch_name: str
    status: SentinelStatus
    file: str
    line_pattern_ok: bool | None = None  # None = not checked


def check_sentinel(
    file_path: Path,
    sentinel: str,
) -> SentinelStatus:
    """Fast sentinel check — string search, no AST parsing.

    Returns APPLIED if the sentinel string is found in the file,
    NOT_APPLIED if the file exists but the sentinel is absent,
    FILE_MISSING if the file doesn't exist.
    """
    if not file_path.exists():
        return SentinelStatus.FILE_MISSING
    content = file_path.read_text()
    if sentinel in content:
        return SentinelStatus.APPLIED
    return SentinelStatus.NOT_APPLIED


def line_pattern_prefilter(
    file_path: Path,
    pattern: str,
) -> bool | None:
    """Check whether a line_pattern regex matches any line in the file.

    Returns True if the pattern matches, False if the file exists but
    no match, None if the file doesn't exist.

    This is a cheap pre-filter: if the line_pattern anchor doesn't match
    at all, there's no point doing the expensive LibCST parse.
    """
    if not file_path.exists():
        return None
    content = file_path.read_text()
    return re.search(pattern, content) is not None


def batch_sentinel_check(
    patches: list[FilePatch | SemanticPatch],
    base_dir: Path,
) -> list[SentinelResult]:
    """Check all patches against their target files, reading each file once.

    Groups patches by target file, reads each file once, then checks all
    sentinels for that file. Also runs line_pattern pre-filtering for
    SemanticPatches that use line_pattern anchors.

    Returns one SentinelResult per patch, in the same order as input.
    """
    # Group patches by file for single-read efficiency
    file_contents: dict[str, str | None] = {}
    results: list[SentinelResult] = []

    for patch in patches:
        file_str = patch.file
        if file_str not in file_contents:
            fpath = base_dir / file_str
            if fpath.exists():
                file_contents[file_str] = fpath.read_text()
            else:
                file_contents[file_str] = None

        content = file_contents[file_str]
        if content is None:
            results.append(SentinelResult(
                patch_name=patch.name,
                status=SentinelStatus.FILE_MISSING,
                file=file_str,
            ))
            continue

        sentinel_found = patch.sentinel in content
        lp_ok: bool | None = None

        # Pre-filter line_pattern for SemanticPatches
        if hasattr(patch, "anchor") and getattr(patch.anchor, "line_pattern", None):
            lp_ok = re.search(patch.anchor.line_pattern, content) is not None

        results.append(SentinelResult(
            patch_name=patch.name,
            status=SentinelStatus.APPLIED if sentinel_found else SentinelStatus.NOT_APPLIED,
            file=file_str,
            line_pattern_ok=lp_ok,
        ))

    return results
