"""LibCST-based semantic patching.

SemanticPatch anchors on code structure (class/method/assignment target)
instead of exact text. This makes patches resilient to whitespace changes,
comment additions, and upstream RHS refactors.

This initial implementation focuses on statement-level insertion around
assignment anchors, which is enough to migrate the most fragile patches
first. Other anchor/transform types can be added incrementally.
"""

from __future__ import annotations

import logging
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path

import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

import hermes_aegis.patching.types as patch_types
from hermes_aegis.patching.types import PatchResult, _invalidate_pyc

logger = logging.getLogger(__name__)


@dataclass
class AnchorSpec:
    """Structural description of where to apply a patch."""

    class_name: str | None = None
    method_name: str | None = None
    anchor_type: str = "assignment"
    assign_target: str | None = None
    call_func: str | None = None
    call_arg_contains: str | None = None
    line_pattern: str | None = None
    position: str = "after"
    occurrence: int = 1


@dataclass
class TransformSpec:
    """Description of what code to inject."""

    code: str
    replace_extent: str | None = None
    wrapper_template: str | None = None


@dataclass
class _AnchorMatch:
    start_line: int
    end_line: int
    indent: str
    statement_code: str


class _AnchorFinder(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, module: cst.Module, anchor: AnchorSpec, source_lines: list[str]):
        self.module = module
        self.anchor = anchor
        self.source_lines = source_lines
        self.matches: list[_AnchorMatch] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []

    def visit_ClassDef(self, node: cst.ClassDef) -> None:
        self._class_stack.append(node.name.value)

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        self._class_stack.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        self._function_stack.append(node.name.value)

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        self._function_stack.pop()

    def visit_SimpleStatementLine(self, node: cst.SimpleStatementLine) -> None:
        if self.anchor.class_name is not None:
            if not self._class_stack or self._class_stack[-1] != self.anchor.class_name:
                return
        if self.anchor.method_name is not None:
            if not self._function_stack or self._function_stack[-1] != self.anchor.method_name:
                return

        if not self._matches_anchor(node):
            return

        pos = self.get_metadata(PositionProvider, node)
        statement_code = self.module.code_for_node(node).rstrip("\n")
        source_line = self.source_lines[pos.start.line - 1]
        indent = re.match(r"\s*", source_line).group(0)
        self.matches.append(
            _AnchorMatch(
                start_line=pos.start.line,
                end_line=pos.end.line,
                indent=indent,
                statement_code=statement_code,
            )
        )

    def _matches_anchor(self, node: cst.SimpleStatementLine) -> bool:
        if self.anchor.anchor_type == "assignment":
            if not self.anchor.assign_target:
                return False
            for stmt in node.body:
                if isinstance(stmt, cst.Assign):
                    for target in stmt.targets:
                        target_code = self.module.code_for_node(target.target).strip()
                        if target_code == self.anchor.assign_target:
                            return True
            return False

        if self.anchor.anchor_type == "call":
            if not self.anchor.call_func:
                return False
            for stmt in node.body:
                # A bare call statement is Expr(value=Call(...))
                if isinstance(stmt, cst.Expr) and isinstance(stmt.value, cst.Call):
                    func_code = self.module.code_for_node(stmt.value.func).strip()
                    if func_code == self.anchor.call_func:
                        if self.anchor.call_arg_contains:
                            # Check if any argument's string repr contains the substring
                            for arg in stmt.value.args:
                                arg_code = self.module.code_for_node(arg).strip()
                                if self.anchor.call_arg_contains in arg_code:
                                    return True
                            return False
                        return True
            return False

        if self.anchor.anchor_type == "line_pattern":
            if not self.anchor.line_pattern:
                return False
            return re.search(self.anchor.line_pattern, self.module.code_for_node(node)) is not None

        return False

    def get_match(self) -> _AnchorMatch | None:
        if len(self.matches) < self.anchor.occurrence:
            return None
        return self.matches[self.anchor.occurrence - 1]


@dataclass
class SemanticPatch:
    """A patch that locates its target via AST structure, not exact text."""

    name: str
    file: str
    sentinel: str
    anchor: AnchorSpec
    transform: TransformSpec
    critical: bool = True

    def path(self) -> Path:
        return patch_types.HERMES_AGENT_DIR / self.file

    def is_compatible_content(self, content: str) -> bool:
        try:
            module = cst.parse_module(content)
            wrapper = MetadataWrapper(module)
            finder = _AnchorFinder(module, self.anchor, content.splitlines())
            wrapper.visit(finder)
            return finder.get_match() is not None
        except Exception:
            logger.debug("is_compatible_content failed for %s", self.file, exc_info=True)
            return False

    def apply(self) -> PatchResult:
        path = self.path()
        if not path.exists():
            status = "error" if self.critical else "skipped"
            return PatchResult(self.name, status, f"file not found: {self.file}")

        content = path.read_text()
        if self.sentinel in content:
            _invalidate_pyc(path)
            return PatchResult(self.name, "already_applied")

        try:
            patched = self._apply_to_content(content)
        except ValueError as exc:
            status = "error" if self.critical else "incompatible"
            return PatchResult(self.name, status, str(exc))
        except Exception as exc:
            return PatchResult(self.name, "error", f"semantic patch failed: {exc}")

        path.write_text(patched)
        _invalidate_pyc(path)
        return PatchResult(self.name, "applied", self.file)

    def revert(self) -> PatchResult:
        path = self.path()
        if not path.exists():
            return PatchResult(self.name, "skipped", f"file not found: {self.file}")

        content = path.read_text()
        if self.sentinel not in content:
            return PatchResult(self.name, "already_applied", "not present, nothing to revert")

        try:
            reverted = self._revert_content(content)
        except ValueError as exc:
            return PatchResult(self.name, "error", str(exc))
        except Exception as exc:
            return PatchResult(self.name, "error", f"semantic revert failed: {exc}")

        path.write_text(reverted)
        _invalidate_pyc(path)
        return PatchResult(self.name, "applied", f"reverted {self.file}")

    def _apply_to_content(self, content: str) -> str:
        module = cst.parse_module(content)
        wrapper = MetadataWrapper(module)
        finder = _AnchorFinder(module, self.anchor, content.splitlines())
        wrapper.visit(finder)
        match = finder.get_match()
        if match is None:
            from hermes_aegis.patching.targets import diagnose_file, format_diagnostics
            diag = format_diagnostics(diagnose_file(content, self.file), self.file)
            raise ValueError(
                f"anchor not found in {self.file} — class={self.anchor.class_name!r} "
                f"method={self.anchor.method_name!r} type={self.anchor.anchor_type!r} "
                f"target={self.anchor.assign_target!r}\n{diag}"
            )

        lines = content.splitlines()
        injected_lines = self._indented_transform_lines(match.indent)

        insert_at = match.start_line - 1
        if self.anchor.position == "after":
            insert_at = match.end_line
        elif self.anchor.position == "before":
            insert_at = match.start_line - 1
        else:
            raise ValueError(f"unsupported anchor position: {self.anchor.position}")

        new_lines = lines[:insert_at] + injected_lines + lines[insert_at:]
        return "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")

    def _revert_content(self, content: str) -> str:
        module = cst.parse_module(content)
        wrapper = MetadataWrapper(module)
        finder = _AnchorFinder(module, self.anchor, content.splitlines())
        wrapper.visit(finder)
        match = finder.get_match()
        if match is None:
            raise ValueError(
                f"anchor not found in patched file {self.file} during revert"
            )

        lines = content.splitlines()
        injected_lines = self._indented_transform_lines(match.indent)

        if self.anchor.position == "after":
            start = match.end_line
            end = start + len(injected_lines)
        elif self.anchor.position == "before":
            start = match.start_line - 1 - len(injected_lines)
            end = match.start_line - 1
        else:
            raise ValueError(f"unsupported anchor position: {self.anchor.position}")

        if start < 0 or lines[start:end] != injected_lines:
            raise ValueError(
                f"patched block not found verbatim in {self.file} — file may have been manually edited; revert manually"
            )

        new_lines = lines[:start] + lines[end:]
        return "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")

    def _indented_transform_lines(self, indent: str) -> list[str]:
        code = textwrap.dedent(self.transform.code).strip("\n")
        return [indent + line if line else "" for line in code.splitlines()]
