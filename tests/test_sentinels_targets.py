"""Tests for patching/sentinels.py and patching/targets.py.

TDD: these tests define the contract for the sentinel detection
and target grouping modules before they are wired into the main
patch pipeline.
"""
from __future__ import annotations

from textwrap import dedent

import pytest

from hermes_aegis.patching.sentinels import (
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


# ---------------------------------------------------------------------------
# sentinels.py tests
# ---------------------------------------------------------------------------

class TestCheckSentinel:
    """Fast sentinel detection — string-based, no AST."""

    def test_returns_applied_when_sentinel_present(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n_aegis_marker\ny = 2\n")
        assert check_sentinel(f, "_aegis_marker") == SentinelStatus.APPLIED

    def test_returns_not_applied_when_sentinel_absent(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\ny = 2\n")
        assert check_sentinel(f, "_aegis_marker") == SentinelStatus.NOT_APPLIED

    def test_returns_file_missing_when_no_file(self, tmp_path):
        f = tmp_path / "nonexistent.py"
        assert check_sentinel(f, "_aegis_marker") == SentinelStatus.FILE_MISSING

    def test_empty_file_not_applied(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("")
        assert check_sentinel(f, "anything") == SentinelStatus.NOT_APPLIED


class TestLinePatternPrefilter:
    """Regex pre-filter for line_pattern anchors."""

    def test_returns_true_when_pattern_matches(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("self._container_id = result.stdout.strip()\n")
        assert line_pattern_prefilter(f, r"self\._container_id\s*=") is True

    def test_returns_false_when_no_match(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        assert line_pattern_prefilter(f, r"container_id") is False

    def test_returns_none_when_file_missing(self, tmp_path):
        f = tmp_path / "nope.py"
        assert line_pattern_prefilter(f, r"anything") is None


class TestBatchSentinelCheck:
    """Batch check all patches, one file read per unique target."""

    def test_groups_patches_by_file(self, tmp_path):
        from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec
        from hermes_aegis.patching.types import PatchResult

        # Create two patches targeting the same file
        f = tmp_path / "docker.py"
        f.write_text("x = 1\n_aegis_sentinel_1\n_aegis_sentinel_2\n")

        # Patch sentinel files
        import hermes_aegis.patching.types as pt
        import hermes_aegis.patches as pm

        monkey = pytest.MonkeyPatch()
        monkey.setattr(pt, "HERMES_AGENT_DIR", tmp_path)
        monkey.setattr(pm, "HERMES_AGENT_DIR", tmp_path)

        try:
            p1 = SemanticPatch(
                name="patch_1",
                file="docker.py",
                sentinel="_aegis_sentinel_1",
                anchor=AnchorSpec(assign_target="x", position="after"),
                transform=TransformSpec(code="pass"),
            )
            p2 = SemanticPatch(
                name="patch_2",
                file="docker.py",
                sentinel="_aegis_sentinel_2",
                anchor=AnchorSpec(assign_target="x", position="after"),
                transform=TransformSpec(code="pass"),
            )
            p3 = SemanticPatch(
                name="patch_3",
                file="docker.py",
                sentinel="_aegis_missing",
                anchor=AnchorSpec(assign_target="x", position="after"),
                transform=TransformSpec(code="pass"),
            )

            results = batch_sentinel_check([p1, p2, p3], tmp_path)
            assert len(results) == 3
            assert results[0].status == SentinelStatus.APPLIED
            assert results[1].status == SentinelStatus.APPLIED
            assert results[2].status == SentinelStatus.NOT_APPLIED
        finally:
            monkey.undo()

    def test_file_missing_in_batch(self, tmp_path):
        from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

        p = SemanticPatch(
            name="missing_file",
            file="nope.py",
            sentinel="anything",
            anchor=AnchorSpec(assign_target="x", position="after"),
            transform=TransformSpec(code="pass"),
        )

        results = batch_sentinel_check([p], tmp_path)
        assert results[0].status == SentinelStatus.FILE_MISSING

    def test_line_pattern_prefilter_in_batch(self, tmp_path):
        from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

        f = tmp_path / "test.py"
        f.write_text("exec_env[key] = value\n")

        p = SemanticPatch(
            name="with_line_pattern",
            file="test.py",
            sentinel="_missing_sentinel",
            anchor=AnchorSpec(
                assign_target="exec_env[key]",
                line_pattern=r"exec_env\[key\]\s*=",
                position="before",
            ),
            transform=TransformSpec(code="pass"),
        )

        results = batch_sentinel_check([p], tmp_path)
        assert results[0].status == SentinelStatus.NOT_APPLIED
        assert results[0].line_pattern_ok is True

    def test_filepatch_in_batch(self, tmp_path):
        from hermes_aegis.patches import FilePatch
        import hermes_aegis.patching.types as pt
        import hermes_aegis.patches as pm

        f = tmp_path / "test.py"
        f.write_text("before_text\n_aegis_sentinel\nafter_text\n")

        monkey = pytest.MonkeyPatch()
        monkey.setattr(pt, "HERMES_AGENT_DIR", tmp_path)
        monkey.setattr(pm, "HERMES_AGENT_DIR", tmp_path)

        try:
            p = FilePatch(
                name="file_patch",
                file="test.py",
                sentinel="_aegis_sentinel",
                before="before_text\n",
                after="before_text\n_aegis_sentinel\n",
            )

            results = batch_sentinel_check([p], tmp_path)
            assert results[0].status == SentinelStatus.APPLIED
            assert results[0].line_pattern_ok is None  # FilePatch has no anchor
        finally:
            monkey.undo()


# ---------------------------------------------------------------------------
# targets.py tests
# ---------------------------------------------------------------------------

class TestGroupPatchesByFile:
    """Group patches by target file."""

    def test_groups_correctly(self):
        from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec
        from hermes_aegis.patches import FilePatch

        patches = [
            SemanticPatch(
                name="sp1", file="a.py", sentinel="s1",
                anchor=AnchorSpec(assign_target="x"), transform=TransformSpec(code="pass"),
            ),
            SemanticPatch(
                name="sp2", file="b.py", sentinel="s2",
                anchor=AnchorSpec(assign_target="y"), transform=TransformSpec(code="pass"),
            ),
            SemanticPatch(
                name="sp3", file="a.py", sentinel="s3",
                anchor=AnchorSpec(assign_target="z"), transform=TransformSpec(code="pass"),
            ),
            FilePatch(
                name="fp1", file="a.py", sentinel="s4",
                before="before", after="after",
            ),
        ]

        targets = group_patches_by_file(patches)
        assert len(targets) == 2
        assert targets[0].file == "a.py"
        assert len(targets[0].patches) == 3  # sp1, sp3, fp1
        assert targets[0].semantic_count == 2
        assert targets[0].filepatch_count == 1
        assert targets[1].file == "b.py"
        assert len(targets[1].patches) == 1

    def test_empty_patches(self):
        targets = group_patches_by_file([])
        assert targets == []

    def test_preserves_first_appearance_order(self):
        from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

        patches = [
            SemanticPatch(name="a", file="z.py", sentinel="s",
                anchor=AnchorSpec(assign_target="x"), transform=TransformSpec(code="pass")),
            SemanticPatch(name="b", file="a.py", sentinel="s",
                anchor=AnchorSpec(assign_target="x"), transform=TransformSpec(code="pass")),
            SemanticPatch(name="c", file="z.py", sentinel="s2",
                anchor=AnchorSpec(assign_target="y"), transform=TransformSpec(code="pass")),
        ]

        targets = group_patches_by_file(patches)
        assert [t.file for t in targets] == ["z.py", "a.py"]


class TestDiagnoseFile:
    """AST diagnostics — extract anchorable structures from a file."""

    def test_finds_class_and_method(self):
        code = dedent('''\
            class Foo:
                def bar(self):
                    x = 1
        ''')
        anchors = diagnose_file(code)
        classes = [a for a in anchors if a.kind == "class"]
        methods = [a for a in anchors if a.kind == "method"]
        assigns = [a for a in anchors if a.kind == "assignment"]

        assert len(classes) == 1
        assert classes[0].name == "Foo"
        assert classes[0].line == 1

        assert len(methods) == 1
        assert methods[0].name == "bar"
        assert methods[0].parent_class == "Foo"

        assert len(assigns) == 1
        assert assigns[0].name == "x"
        assert assigns[0].parent_class == "Foo"
        assert assigns[0].parent_method == "bar"

    def test_finds_calls(self):
        code = dedent('''\
            class DockerEnv:
                def run(self):
                    logger.info(f"running {args}")
        ''')
        anchors = diagnose_file(code)
        calls = [a for a in anchors if a.kind == "call"]
        assert len(calls) == 1
        assert calls[0].name == "logger.info"
        assert calls[0].parent_class == "DockerEnv"
        assert calls[0].parent_method == "run"

    def test_handles_syntax_error(self):
        anchors = diagnose_file("def :\n")
        assert anchors == []

    def test_multiple_classes(self):
        code = dedent('''\
            class Alpha:
                x = 1

            class Beta:
                y = 2
        ''')
        anchors = diagnose_file(code)
        classes = [a for a in anchors if a.kind == "class"]
        assert len(classes) == 2
        assert classes[0].name == "Alpha"
        assert classes[1].name == "Beta"

    def test_module_level_assignments(self):
        code = dedent('''\
            VERSION = "1.0"
            _cache: dict = {}
        ''')
        anchors = diagnose_file(code)
        assigns = [a for a in anchors if a.kind == "assignment"]
        names = {a.name for a in assigns}
        assert "VERSION" in names
        assert "_cache" in names
        for a in assigns:
            assert a.parent_class is None
            assert a.parent_method is None


class TestFormatDiagnostics:
    """Human-readable diagnostic output."""

    def test_formats_anchors(self):
        anchors = [
            AnchorDiagnostic(kind="class", name="Foo", line=1),
            AnchorDiagnostic(kind="method", name="bar", line=2, parent_class="Foo"),
            AnchorDiagnostic(kind="assignment", name="x", line=3, parent_class="Foo", parent_method="bar"),
        ]
        report = format_diagnostics(anchors, "test.py")
        assert "Anchors in test.py:" in report
        assert "class" in report
        assert "Foo" in report
        assert "bar" in report
        assert "assignment" in report

    def test_empty_anchors(self):
        report = format_diagnostics([], "empty.py")
        assert "No parseable anchors" in report
