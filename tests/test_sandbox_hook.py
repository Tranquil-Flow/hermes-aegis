"""Tests for sandbox activation in the gateway:startup hook handler."""
import py_compile

import pytest

import hermes_aegis.hook as hook_module
from hermes_aegis.hook import install_hook


@pytest.fixture(autouse=True)
def isolated_hook_paths(tmp_path, monkeypatch):
    """Keep generated hook files in a temporary directory."""
    hermes_dir = tmp_path / ".hermes"
    hook_dir = hermes_dir / "hooks" / "aegis-security"
    monkeypatch.setattr(hook_module, "HERMES_DIR", hermes_dir)
    monkeypatch.setattr(hook_module, "HOOKS_DIR", hermes_dir / "hooks")
    monkeypatch.setattr(hook_module, "HOOK_DIR", hook_dir)
    monkeypatch.setattr(hook_module, "HERMES_AGENT_DIR", hermes_dir / "hermes-agent")


def test_handler_contains_sandbox_logic():
    """The generated handler.py includes sandbox activation code."""
    hook_dir = install_hook()
    handler = (hook_dir / "handler.py").read_text()

    assert "AEGIS_SANDBOX" in handler
    assert "TERMINAL_ENV" in handler
    assert "sandbox" in handler.lower()


def test_handler_checks_platform_is_darwin():
    """Sandbox mode is only activated on macOS (Darwin)."""
    hook_dir = install_hook()
    handler = (hook_dir / "handler.py").read_text()

    assert "Darwin" in handler or "darwin" in handler


def test_handler_sets_sandbox_env_vars():
    """Handler sets AEGIS_SANDBOX_PROFILE, CWD, WORK_DIR, CACHE_DIR, LOCAL_DIR."""
    hook_dir = install_hook()
    handler = (hook_dir / "handler.py").read_text()

    assert "AEGIS_SANDBOX_PROFILE" in handler
    assert "TERMINAL_CWD" in handler
    assert "AEGIS_SANDBOX_WORK_DIR" in handler
    assert "AEGIS_SANDBOX_CACHE_DIR" in handler
    assert "AEGIS_SANDBOX_LOCAL_DIR" in handler
    assert "PATH" in handler
    assert "/opt/homebrew/bin" in handler


def test_handler_reads_sandbox_config():
    """Handler reads gateway_sandbox setting from aegis config."""
    hook_dir = install_hook()
    handler = (hook_dir / "handler.py").read_text()

    assert "gateway_sandbox" in handler


def test_handler_overrides_terminal_env_to_local():
    """Handler sets TERMINAL_ENV=local for sandbox mode."""
    hook_dir = install_hook()
    handler = (hook_dir / "handler.py").read_text()

    assert '"TERMINAL_ENV"' in handler
    assert '"local"' in handler


def test_generated_handler_is_valid_python():
    """Generated handler.py compiles cleanly."""
    hook_dir = install_hook()

    py_compile.compile(str(hook_dir / "handler.py"), doraise=True)


def test_sandbox_activation_runs_before_proxy_startup():
    """Sandbox env vars are set before proxy startup can return early."""
    hook_dir = install_hook()
    handler = (hook_dir / "handler.py").read_text()

    sandbox_call = "if event_type == \"gateway:startup\":\n        _activate_sandbox_if_enabled()"
    assert sandbox_call in handler
    assert handler.index(sandbox_call) < handler.index("subprocess.Popen")
