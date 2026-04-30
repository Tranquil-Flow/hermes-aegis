"""Per-file target definitions and diagnostic helpers for semantic patches.

targets.py groups patches by target file, enabling:
- Batch file operations (parse once, apply all patches for that file)
- Diagnostic output listing all discoverable anchors in a file
- Patch compatibility reports per file
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

if TYPE_CHECKING:
    from hermes_aegis.patches import FilePatch, SemanticPatch


@dataclass
class FileTarget:
    """All patches targeting a single file."""
    file: str
    patches: list[FilePatch | SemanticPatch]

    @property
    def semantic_count(self) -> int:
        """Number of SemanticPatch entries."""
        return sum(1 for p in self.patches if hasattr(p, "anchor"))

    @property
    def filepatch_count(self) -> int:
        """Number of FilePatch entries."""
        return sum(1 for p in self.patches if not hasattr(p, "anchor"))


def group_patches_by_file(
    patches: list[FilePatch | SemanticPatch],
) -> list[FileTarget]:
    """Group patches by their target file, preserving order of first appearance.

    Returns one FileTarget per unique file, with patches in registry order.
    """
    by_file: dict[str, list[FilePatch | SemanticPatch]] = defaultdict(list)
    file_order: list[str] = []

    for patch in patches:
        if patch.file not in by_file:
            file_order.append(patch.file)
        by_file[patch.file].append(patch)

    return [
        FileTarget(file=f, patches=by_file[f])
        for f in file_order
    ]


@dataclass
class AnchorDiagnostic:
    """A single discoverable anchor point in a file."""
    kind: str           # "class", "method", "assignment", "call"
    name: str           # e.g. "DockerEnvironment", "_start", "self._container_id"
    line: int           # 1-indexed line number
    parent_class: str | None = None
    parent_method: str | None = None


class _DiagnosticVisitor(cst.CSTVisitor):
    """Extract all anchorable code structures from a file."""
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, module: cst.Module):
        self.module = module
        self.anchors: list[AnchorDiagnostic] = []
        self._class_stack: list[str] = []
        self._func_stack: list[str] = []

    def visit_ClassDef(self, node: cst.ClassDef) -> None:
        pos = self.get_metadata(PositionProvider, node)
        self.anchors.append(AnchorDiagnostic(
            kind="class",
            name=node.name.value,
            line=pos.start.line,
        ))
        self._class_stack.append(node.name.value)

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        self._class_stack.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        pos = self.get_metadata(PositionProvider, node)
        self.anchors.append(AnchorDiagnostic(
            kind="method",
            name=node.name.value,
            line=pos.start.line,
            parent_class=self._class_stack[-1] if self._class_stack else None,
        ))
        self._func_stack.append(node.name.value)

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        self._func_stack.pop()

    def visit_SimpleStatementLine(self, node: cst.SimpleStatementLine) -> None:
        for stmt in node.body:
            if isinstance(stmt, cst.Assign):
                pos = self.get_metadata(PositionProvider, node)
                for target in stmt.targets:
                    target_code = self.module.code_for_node(target.target).strip()
                    self.anchors.append(AnchorDiagnostic(
                        kind="assignment",
                        name=target_code,
                        line=pos.start.line,
                        parent_class=self._class_stack[-1] if self._class_stack else None,
                        parent_method=self._func_stack[-1] if self._func_stack else None,
                    ))
            elif isinstance(stmt, cst.AnnAssign):
                # Annotated assignment: `x: int = 1`
                pos = self.get_metadata(PositionProvider, node)
                target_code = self.module.code_for_node(stmt.target).strip()
                self.anchors.append(AnchorDiagnostic(
                    kind="assignment",
                    name=target_code,
                    line=pos.start.line,
                    parent_class=self._class_stack[-1] if self._class_stack else None,
                    parent_method=self._func_stack[-1] if self._func_stack else None,
                ))
            elif isinstance(stmt, cst.Expr) and isinstance(stmt.value, cst.Call):
                pos = self.get_metadata(PositionProvider, node)
                func_code = self.module.code_for_node(stmt.value.func).strip()
                self.anchors.append(AnchorDiagnostic(
                    kind="call",
                    name=func_code,
                    line=pos.start.line,
                    parent_class=self._class_stack[-1] if self._class_stack else None,
                    parent_method=self._func_stack[-1] if self._func_stack else None,
                ))


def diagnose_file(
    content: str,
    file: str = "<unknown>",
) -> list[AnchorDiagnostic]:
    """Parse a file and return all discoverable anchor points.

    Useful for diagnostics when a SemanticPatch anchor fails to match:
    shows what classes, methods, assignments, and calls are actually present.
    """
    try:
        module = cst.parse_module(content)
    except cst.ParserSyntaxError:
        return []

    wrapper = MetadataWrapper(module)
    visitor = _DiagnosticVisitor(module)
    wrapper.visit(visitor)
    return visitor.anchors


def format_diagnostics(
    anchors: list[AnchorDiagnostic],
    file: str = "<unknown>",
) -> str:
    """Format anchor diagnostics as a human-readable report."""
    if not anchors:
        return f"No parseable anchors found in {file} (file may have syntax errors)"

    lines = [f"Anchors in {file}:"]
    for a in anchors:
        parts = [f"  L{a.line:4d} {a.kind:12s} {a.name}"]
        if a.parent_class:
            parts.append(f" (in {a.parent_class}")
            if a.parent_method:
                parts.append(f".{a.parent_method}")
            parts.append(")")
        lines.append("".join(parts))

    return "\n".join(lines)
