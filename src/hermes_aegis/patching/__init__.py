"""Semantic patching framework for hermes-aegis.

Uses LibCST to apply patches that anchor on code structure (class name,
method name, assignment target) rather than exact string matching.

FilePatch (exact string) and SemanticPatch (AST-based) coexist. Both
implement the same apply()/revert() interface so the patch list can
contain a mix of both types.

Submodules:
- sentinels: Fast sentinel detection (string-based, no AST parse needed)
- targets: Per-file grouping and diagnostic helpers
"""

from hermes_aegis.patching.semantic_patch import (
    AnchorSpec,
    SemanticPatch,
    TransformSpec,
)
from hermes_aegis.patching.sentinels import (
    SentinelResult,
    SentinelStatus,
    batch_sentinel_check,
    check_sentinel,
    line_pattern_prefilter,
)
from hermes_aegis.patching.targets import (
    AnchorDiagnostic,
    FileTarget,
    diagnose_file,
    format_diagnostics,
    group_patches_by_file,
)
from hermes_aegis.patching.types import (
    HERMES_AGENT_DIR,
    PatchResult,
    _invalidate_pyc,
)

__all__ = [
    # Semantic patching
    "AnchorSpec",
    "SemanticPatch",
    "TransformSpec",
    # Sentinel detection
    "SentinelResult",
    "SentinelStatus",
    "batch_sentinel_check",
    "check_sentinel",
    "line_pattern_prefilter",
    # Target grouping and diagnostics
    "AnchorDiagnostic",
    "FileTarget",
    "diagnose_file",
    "format_diagnostics",
    "group_patches_by_file",
    # Shared types
    "HERMES_AGENT_DIR",
    "PatchResult",
    "_invalidate_pyc",
]
