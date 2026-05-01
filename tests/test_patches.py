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
    """Point patching code to a tmp directory and return it."""
    import hermes_aegis.patching.types as patch_types

    monkeypatch.setattr(patches_mod, "HERMES_AGENT_DIR", tmp_path)
    monkeypatch.setattr(patch_types, "HERMES_AGENT_DIR", tmp_path)
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

def _semantic_stub_source(patch):
    """Create minimal unpatched source matching a SemanticPatch anchor."""
    anchor = patch.anchor
    target = anchor.assign_target or "x"
    class_name = anchor.class_name or "ExampleClass"
    method_name = anchor.method_name or "start"

    if anchor.anchor_type == "assignment":
        return (
            f"class {class_name}:\n"
            f"    def {method_name}(self):\n"
            f"        {target} = value\n"
        )

    if anchor.anchor_type == "call":
        func = anchor.call_func or "func"
        arg = anchor.call_arg_contains or ""
        return (
            f"class {class_name}:\n"
            f"    def {method_name}(self):\n"
            f'        {func}("{arg}")\n'
        )

    if anchor.anchor_type == "line_pattern":
        pattern = anchor.line_pattern or "pass"
        return (
            f"class {class_name}:\n"
            f"    def {method_name}(self):\n"
            f"        {pattern}\n"
        )

    raise AssertionError(f"Unsupported semantic test stub for {patch.name}: {anchor.anchor_type}")


def _docker_py_stub_source():
    """Minimal parseable docker.py containing all current patch anchors."""
    return (
        "class DockerEnvironment:\n"
        "    def _build_init_env_args(self):\n"
        "        for key in self._forward_env:\n"
        "            value = self._env.get(key)\n"
        "            if value is not None:\n"
        "                exec_env[key] = value\n"
        "\n"
        "    def _execute_container(self):\n"
        "        all_run_args = list(_SECURITY_ARGS) + writable_args\n"
        "        logger.info(f\"Docker run_args: {all_run_args}\")\n"
        "\n"
        "    def start(self):\n"
        "        all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args + env_args\n"
        "        logger.info(f\"Docker run_args: {all_run_args}\")\n"
        "\n"
        "        # Resolve the docker executable once so it works even when\n"
        "        # /usr/local/bin is not in PATH (common on macOS gateway/service).\n"
        "        self._docker_exe = find_docker() or \"docker\"\n"
        "        self._container_id = result.stdout.strip()\n"
        "        logger.info(f\"Started container {container_name} ({self._container_id[:12]})\")\n"
        "\n"
        "        # Build the init-time env forwarding args\n"
    )


def _terminal_tool_py_stub_source():
    """Minimal parseable terminal_tool.py containing all current patch anchors."""
    return (
        'TERMINAL_TOOL_DESCRIPTION = """Execute shell commands on a Linux environment. Filesystem usually persists between calls."""\n'
        "import os\n"
        "import json\n"
        "\n"
        "def execute(command, force=False):\n"
        "    # Pre-exec security checks (tirith + dangerous command detection)\n"
        "    # Skip check if force=True (user has confirmed they want to run it)\n"
        "    approval_note = None\n"
        "    if not force:\n"
        "        pass\n"
        "\n"
        "    container_config = {\n"
        '                                "docker_mount_cwd_to_workspace": config.get("docker_mount_cwd_to_workspace", False),\n'
        '                                "docker_forward_env": config.get("docker_forward_env", []),\n'
        '                                "docker_env": config.get("docker_env", {}),\n'
        "                            }\n"
    )


def _setup_real_patches(agent_dir):
    """Create stub files with compatible unpatched content for all real _PATCHES."""
    from hermes_aegis.patches import _PATCHES

    # Files with dedicated, complete stubs — don't append raw before/snippet text
    _STUBBED_FILES = {
        "tools/environments/docker.py": _docker_py_stub_source,
        "tools/terminal_tool.py": _terminal_tool_py_stub_source,
    }

    # Pre-create all stubbed files first
    for file, stub_fn in _STUBBED_FILES.items():
        fpath = agent_dir / file
        fpath.parent.mkdir(parents=True, exist_ok=True)
        if not fpath.exists():
            fpath.write_text(stub_fn())

    for p in _PATCHES:
        fpath = agent_dir / p.file
        fpath.parent.mkdir(parents=True, exist_ok=True)

        # Files with dedicated stubs already have all necessary content
        if p.file in _STUBBED_FILES:
            continue

        sample = p.before if isinstance(p, FilePatch) else _semantic_stub_source(p)
        if fpath.exists():
            content = fpath.read_text()
            if sample not in content:
                fpath.write_text(content + "\n" + sample)
        else:
            fpath.write_text(sample)


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


def test_apply_patches_supports_mixed_file_and_semantic_patches(fake_agent_dir, monkeypatch):
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    regular = fake_agent_dir / "regular.py"
    regular.write_text("original_code()\n")

    semantic = fake_agent_dir / "docker.py"
    semantic.write_text(
        "class DockerEnvironment:\n"
        "    def start(self):\n"
        "        self._container_id = result.stdout.strip()\n"
    )

    mixed_patches = [
        FilePatch(
            name="file_patch",
            file="regular.py",
            sentinel="# PATCHED",
            before="original_code()",
            after="# PATCHED\npatched_code()",
            critical=True,
        ),
        SemanticPatch(
            name="semantic_patch",
            file="docker.py",
            sentinel="_aegis_cert_trust",
            anchor=AnchorSpec(
                class_name="DockerEnvironment",
                method_name="start",
                anchor_type="assignment",
                assign_target="self._container_id",
                position="after",
            ),
            transform=TransformSpec(code="# Aegis cert trust (_aegis_cert_trust)\ninstall_cert()"),
            critical=False,
        ),
    ]

    monkeypatch.setattr(patches_mod, "_PATCHES", mixed_patches)
    results = apply_patches()

    assert [r.status for r in results] == ["applied", "applied"]
    assert "# PATCHED" in regular.read_text()
    assert "_aegis_cert_trust" in semantic.read_text()


def test_docker_cert_system_trust_patch_is_semantic():
    from hermes_aegis.patching.semantic_patch import SemanticPatch
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == "docker_cert_system_trust")

    assert isinstance(patch, SemanticPatch)
    assert patch.anchor.class_name == "DockerEnvironment"
    assert patch.anchor.assign_target == "self._container_id"
    assert patch.anchor.position == "after"


@pytest.mark.parametrize(
    ("patch_name", "assign_target", "position", "method_name"),
    [
        ("docker_exec_proxy_translate", "exec_env[key]", "before", "_build_init_env_args"),
        ("docker_network_isolation", "all_run_args", "after", None),
    ],
)
def test_selected_docker_patches_are_semantic(patch_name, assign_target, position, method_name):
    from hermes_aegis.patching.semantic_patch import SemanticPatch
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == patch_name)

    assert isinstance(patch, SemanticPatch)
    assert patch.anchor.class_name == "DockerEnvironment"
    assert patch.anchor.assign_target == assign_target
    assert patch.anchor.position == position
    assert patch.anchor.method_name == method_name


def test_docker_cert_mount_is_semantic_call_anchor():
    """docker_cert_mount uses a call-anchor on logger.info."""
    from hermes_aegis.patching.semantic_patch import SemanticPatch
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == "docker_cert_mount")

    assert isinstance(patch, SemanticPatch)
    assert patch.anchor.anchor_type == "call"
    assert patch.anchor.call_func == "logger.info"
    assert patch.anchor.call_arg_contains == "all_run_args"
    assert patch.anchor.class_name == "DockerEnvironment"
    assert patch.anchor.method_name == "_execute_container"
    assert patch.anchor.position == "after"
    assert patch.critical is False


# ---------------------------------------------------------------------------
# Batch-migrated semantic patch verification tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "patch_name, anchor_type, target, position",
    [
        ("terminal_tool_container_handshake", "assignment", "approval_note", "before"),
        ("browser_tool_ignore_https_errors", "assignment", "cmd_prefix", "before"),
        ("browser_tool_strip_proxy_env", "assignment", "browser_env", "after"),
        ("local_sandbox_exec", "assignment", "run_env", "before"),
    ],
)
def test_assignment_semantic_migrations(patch_name, anchor_type, target, position):
    """Verify batch-migrated assignment-anchor patches are SemanticPatch."""
    from hermes_aegis.patching.semantic_patch import SemanticPatch
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == patch_name)
    assert isinstance(patch, SemanticPatch)
    assert patch.anchor.anchor_type == anchor_type
    assert patch.anchor.assign_target == target
    assert patch.anchor.position == position
    assert patch.critical is False


def test_hermes_update_repatch_is_semantic_call_anchor():
    """hermes_update_aegis_repatch uses a call-anchor on print()."""
    from hermes_aegis.patching.semantic_patch import SemanticPatch
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == "hermes_update_aegis_repatch")

    assert isinstance(patch, SemanticPatch)
    assert patch.anchor.anchor_type == "call"
    assert patch.anchor.call_func == "print"
    assert patch.anchor.call_arg_contains == "Code updated"
    assert patch.anchor.position == "after"
    assert patch.critical is False
