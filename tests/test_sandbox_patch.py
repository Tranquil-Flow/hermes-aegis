"""Tests for the local_sandbox_exec patch definition."""
from pathlib import Path

import pytest


def test_patch_exists_in_patches_list():
    """Sandbox patches are registered."""
    from hermes_aegis.patches import _PATCHES

    names = [p.name for p in _PATCHES]
    assert "terminal_description_neutral_env" in names
    assert "local_sandbox_exec" in names
    assert "local_sandbox_path_preference" in names
    assert "gateway_sandbox_startup_env" in names
    assert "cli_sandbox_terminal_override" in names


def test_patch_targets_local_py():
    """Patch targets tools/environments/local.py."""
    from hermes_aegis.patches import _PATCHES

    sb_patch = next(p for p in _PATCHES if p.name == "local_sandbox_exec")
    assert sb_patch.file == "tools/environments/local.py"


def test_gateway_patch_targets_gateway_run_py():
    """Gateway startup patch targets gateway/run.py."""
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == "gateway_sandbox_startup_env")
    assert patch.file == "gateway/run.py"


def test_patch_is_non_critical():
    """Sandbox patch is non-critical — failure is a warning, not an error."""
    from hermes_aegis.patches import _PATCHES

    sb_patch = next(p for p in _PATCHES if p.name == "local_sandbox_exec")
    path_patch = next(p for p in _PATCHES if p.name == "local_sandbox_path_preference")
    gateway_patch = next(p for p in _PATCHES if p.name == "gateway_sandbox_startup_env")
    cli_patch = next(p for p in _PATCHES if p.name == "cli_sandbox_terminal_override")
    desc_patch = next(p for p in _PATCHES if p.name == "terminal_description_neutral_env")
    assert desc_patch.critical is False
    assert sb_patch.critical is False
    assert path_patch.critical is False
    assert gateway_patch.critical is False
    assert cli_patch.critical is False


def test_patch_sentinel_is_unique():
    """Sentinel string is present in after but not in before."""
    from hermes_aegis.patches import _PATCHES

    sb_patch = next(p for p in _PATCHES if p.name == "local_sandbox_exec")
    # SemanticPatch: sentinel appears in transform.code
    if hasattr(sb_patch, "after"):
        assert sb_patch.sentinel in sb_patch.after
        assert sb_patch.sentinel not in sb_patch.before
    else:
        assert sb_patch.sentinel in sb_patch.transform.code


def test_terminal_description_patch_is_neutral():
    """Terminal schema should not always claim Linux when Aegis uses macOS."""
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == "terminal_description_neutral_env")
    assert "_aegis_terminal_description_neutral_env" in patch.after
    assert "configured terminal environment" in patch.after
    assert "Linux environment" in patch.before


def test_patch_before_matches_current_local_py():
    """The patch anchor matches the current hermes-agent local.py."""
    from hermes_aegis.patches import _PATCHES

    sb_patch = next(p for p in _PATCHES if p.name == "local_sandbox_exec")
    local_py = Path.home() / ".hermes" / "hermes-agent" / "tools" / "environments" / "local.py"
    if not local_py.exists():
        pytest.skip("hermes-agent not installed")

    content = local_py.read_text()
    if hasattr(sb_patch, "before"):
        assert sb_patch.before in content or sb_patch.sentinel in content
    else:
        assert sb_patch.is_compatible_content(content) or sb_patch.sentinel in content


def test_patched_code_wraps_args_with_sandbox_exec():
    """The patched code prepends sandbox-exec to args when AEGIS_SANDBOX=1."""
    from hermes_aegis.patches import _PATCHES

    sb_patch = next(p for p in _PATCHES if p.name == "local_sandbox_exec")
    # SemanticPatch: code is in transform.code
    if hasattr(sb_patch, "after"):
        after = sb_patch.after
    else:
        after = sb_patch.transform.code

    assert 'os.getenv("AEGIS_SANDBOX")' in after
    assert "AEGIS_SANDBOX_PROFILE" in after
    assert '"sandbox-exec"' in after


def test_sandbox_path_patch_keeps_homebrew_python_first():
    """Sandboxed local commands prefer Homebrew Python after shell snapshots."""
    from hermes_aegis.patches import _PATCHES

    path_patch = next(p for p in _PATCHES if p.name == "local_sandbox_path_preference")
    after = path_patch.after

    assert "_aegis_sandbox_path" in after
    assert "/opt/homebrew/bin" in after
    assert "cmd_string.startswith(\"source \")" in after
    assert "_aegis_path_export" in after


def test_gateway_patch_forces_local_backend_and_cwd():
    """Gateway startup patch switches Discord gateway sessions to local sandbox."""
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == "gateway_sandbox_startup_env")
    after = patch.after

    assert "_aegis_gateway_sandbox_startup" in after
    assert 'os.environ["TERMINAL_ENV"] = "local"' in after
    assert 'os.environ["TERMINAL_CWD"] = _work_dir' in after
    assert 'os.environ["AEGIS_SANDBOX"] = "1"' in after
    assert 'os.environ["PATH"] = ":".join(_merged_path)' in after
    assert "/opt/homebrew/bin" in after


def test_cli_patch_preserves_sandbox_terminal_override():
    """Lazy cli imports must not restore config.yaml's Docker backend."""
    from hermes_aegis.patches import _PATCHES

    patch = next(p for p in _PATCHES if p.name == "cli_sandbox_terminal_override")
    after = patch.after

    assert "_aegis_cli_sandbox_terminal_override" in after
    assert 'os.getenv("AEGIS_SANDBOX") == "1"' in after
    assert '"TERMINAL_ENV", "TERMINAL_CWD"' in after
