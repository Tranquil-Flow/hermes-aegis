"""Comprehensive tests for hermes_aegis.patches module."""
from __future__ import annotations

import pytest
from hermes_aegis.patches import (
    FilePatch,
    PatchResult,
    apply_patches,
    patches_status,
    revert_patches,
)
import hermes_aegis.patches as patches_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_agent_dir(tmp_path, monkeypatch):
    """Point HERMES_AGENT_DIR to a tmp directory and return it."""
    monkeypatch.setattr(patches_mod, "HERMES_AGENT_DIR", tmp_path)
    return tmp_path


def _make_patch(
    name="test_patch",
    file="some/file.py",
    sentinel="# PATCHED",
    before="original_code()",
    after="# PATCHED\npatched_code()",
    critical=True,
):
    return FilePatch(
        name=name, file=file, sentinel=sentinel,
        before=before, after=after, critical=critical,
    )


# ---------------------------------------------------------------------------
# PatchResult.ok()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,expected", [
    ("applied", True),
    ("already_applied", True),
    ("incompatible", False),
    ("skipped", False),
    ("error", False),
])
def test_patch_result_ok(status, expected):
    r = PatchResult(name="x", status=status)
    assert r.ok() is expected


# ---------------------------------------------------------------------------
# PatchResult.summary()
# ---------------------------------------------------------------------------

def test_summary_icons():
    icons = {
        "applied": "✓",
        "already_applied": "·",
        "incompatible": "⚠",
        "skipped": "·",
        "error": "✗",
    }
    for status, icon in icons.items():
        r = PatchResult(name="my_patch", status=status)
        s = r.summary()
        assert s.startswith(f"  {icon} my_patch: {status}")


def test_summary_with_detail():
    r = PatchResult(name="p", status="error", detail="something broke")
    s = r.summary()
    assert "something broke" in s
    assert "—" in s


def test_summary_without_detail():
    r = PatchResult(name="p", status="applied")
    s = r.summary()
    assert "—" not in s


def test_summary_unknown_status():
    r = PatchResult(name="p", status="unknown_thing")
    s = r.summary()
    assert "?" in s


# ---------------------------------------------------------------------------
# FilePatch.apply()
# ---------------------------------------------------------------------------

def test_apply_file_not_found_critical(fake_agent_dir):
    patch = _make_patch(critical=True)
    result = patch.apply()
    assert result.status == "error"
    assert "file not found" in result.detail


def test_apply_file_not_found_non_critical(fake_agent_dir):
    patch = _make_patch(critical=False)
    result = patch.apply()
    assert result.status == "skipped"
    assert "file not found" in result.detail


def test_apply_already_applied(fake_agent_dir):
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# PATCHED\npatched_code()")

    patch = _make_patch()
    result = patch.apply()
    assert result.status == "already_applied"
    assert result.ok()


def test_apply_pattern_not_found_critical(fake_agent_dir):
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("completely_different_content()")

    patch = _make_patch(critical=True)
    result = patch.apply()
    assert result.status == "error"
    assert "target pattern not found" in result.detail


def test_apply_pattern_not_found_non_critical(fake_agent_dir):
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("completely_different_content()")

    patch = _make_patch(critical=False)
    result = patch.apply()
    assert result.status == "incompatible"
    assert "target pattern not found" in result.detail


def test_apply_success(fake_agent_dir):
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("header\noriginal_code()\nfooter")

    patch = _make_patch()
    result = patch.apply()
    assert result.status == "applied"
    assert result.ok()

    content = target.read_text()
    assert "# PATCHED" in content
    assert "patched_code()" in content
    assert "original_code()" not in content


# ---------------------------------------------------------------------------
# FilePatch.revert()
# ---------------------------------------------------------------------------

def test_revert_file_not_found(fake_agent_dir):
    patch = _make_patch()
    result = patch.revert()
    assert result.status == "skipped"
    assert "file not found" in result.detail


def test_revert_not_present(fake_agent_dir):
    """When sentinel is not in file, revert reports already_applied (nothing to do)."""
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("original_code()")

    patch = _make_patch()
    result = patch.revert()
    assert result.status == "already_applied"
    assert "not present" in result.detail


def test_revert_success(fake_agent_dir):
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("header\n# PATCHED\npatched_code()\nfooter")

    patch = _make_patch()
    result = patch.revert()
    assert result.status == "applied"
    assert "reverted" in result.detail

    content = target.read_text()
    assert "original_code()" in content
    assert "# PATCHED" not in content


def test_revert_sentinel_present_but_after_text_modified(fake_agent_dir):
    """Sentinel is present but the exact `after` text isn't — manual edit scenario."""
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    # Sentinel present but `after` text has been manually modified
    target.write_text("# PATCHED\nmanually_edited_code()")

    patch = _make_patch()
    result = patch.revert()
    assert result.status == "error"
    assert "manually edited" in result.detail


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_apply_idempotent(fake_agent_dir):
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("original_code()")

    patch = _make_patch()

    r1 = patch.apply()
    assert r1.status == "applied"

    r2 = patch.apply()
    assert r2.status == "already_applied"

    # File content unchanged after second apply
    content_after_first = target.read_text()
    patch.apply()
    assert target.read_text() == content_after_first


def test_revert_idempotent(fake_agent_dir):
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# PATCHED\npatched_code()")

    patch = _make_patch()

    r1 = patch.revert()
    assert r1.status == "applied"

    r2 = patch.revert()
    assert r2.status == "already_applied"


def test_apply_then_revert_roundtrip(fake_agent_dir):
    """Apply and revert restores original content."""
    original = "header\noriginal_code()\nfooter"
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(original)

    patch = _make_patch()
    patch.apply()
    patch.revert()

    assert target.read_text() == original


# ---------------------------------------------------------------------------
# apply_patches() / revert_patches() with monkeypatched HERMES_AGENT_DIR
# ---------------------------------------------------------------------------

def _setup_real_patches(agent_dir):
    """Create stub files with the `before` content for all real _PATCHES."""
    from hermes_aegis.patches import _PATCHES
    for p in _PATCHES:
        fpath = agent_dir / p.file
        fpath.parent.mkdir(parents=True, exist_ok=True)
        # If file already exists (multiple patches target same file),
        # read existing content and append before text if not there.
        if fpath.exists():
            content = fpath.read_text()
            if p.before not in content:
                fpath.write_text(content + "\n" + p.before)
        else:
            fpath.write_text(p.before)


def test_apply_patches_all_succeed(fake_agent_dir):
    _setup_real_patches(fake_agent_dir)
    results = apply_patches()
    assert all(r.ok() for r in results), [r.summary() for r in results]
    assert any(r.status == "applied" for r in results)


def test_apply_patches_idempotent(fake_agent_dir):
    _setup_real_patches(fake_agent_dir)
    apply_patches()
    results = apply_patches()
    assert all(r.status == "already_applied" for r in results)


def test_revert_patches_after_apply(fake_agent_dir):
    _setup_real_patches(fake_agent_dir)
    apply_patches()
    results = revert_patches()
    assert all(r.ok() for r in results), [r.summary() for r in results]


def test_apply_patches_missing_dir(fake_agent_dir):
    """All patches should fail gracefully when no files exist."""
    results = apply_patches()
    assert len(results) > 0
    for r in results:
        assert r.status in ("error", "skipped")


def test_revert_patches_missing_dir(fake_agent_dir):
    """All reverts should skip gracefully when no files exist."""
    results = revert_patches()
    assert len(results) > 0
    for r in results:
        assert r.status == "skipped"


# ---------------------------------------------------------------------------
# patches_status()
# ---------------------------------------------------------------------------

def test_patches_status_no_files(fake_agent_dir):
    results = patches_status()
    assert len(results) > 0
    for r in results:
        assert r.status == "skipped"
        assert "file not found" in r.detail


def test_patches_status_unpatched(fake_agent_dir):
    _setup_real_patches(fake_agent_dir)
    results = patches_status()
    for r in results:
        assert r.status == "skipped"
        assert "not yet applied" in r.detail


def test_patches_status_after_apply(fake_agent_dir):
    _setup_real_patches(fake_agent_dir)
    apply_patches()
    results = patches_status()
    for r in results:
        assert r.status == "already_applied"


def test_patches_status_incompatible(fake_agent_dir):
    """When file exists but neither patched nor unpatched form is present."""
    from hermes_aegis.patches import _PATCHES
    for p in _PATCHES:
        fpath = fake_agent_dir / p.file
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text("completely unrelated content")

    results = patches_status()
    for r in results:
        assert r.status == "incompatible"
        assert "neither patched nor unpatched" in r.detail


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_apply_replaces_only_first_occurrence(fake_agent_dir):
    """Verify that apply replaces only the first occurrence of `before`."""
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("original_code()\noriginal_code()")

    patch = _make_patch()
    patch.apply()

    content = target.read_text()
    # Second occurrence should remain
    assert content.count("original_code()") == 1
    assert "patched_code()" in content


def test_path_method(fake_agent_dir):
    patch = _make_patch(file="tools/foo.py")
    assert patch.path() == fake_agent_dir / "tools/foo.py"
