"""Tests for Hermes hook management."""
import pytest
from pathlib import Path
from unittest.mock import patch

from hermes_aegis.hook import (
    HOOK_DIR,
    clean_old_setup,
    install_hook,
    is_hook_installed,
    uninstall_hook,
)


@pytest.fixture(autouse=True)
def cleanup_hook():
    """Remove hook after each test if it was installed."""
    yield
    if HOOK_DIR.exists():
        import shutil
        shutil.rmtree(HOOK_DIR)


class TestInstallHook:
    def test_creates_hook_directory(self):
        hook_dir = install_hook()
        assert hook_dir.exists()
        assert (hook_dir / "HOOK.yaml").exists()
        assert (hook_dir / "handler.py").exists()

    def test_hook_yaml_content(self):
        install_hook()
        content = (HOOK_DIR / "HOOK.yaml").read_text()
        assert "aegis-security" in content
        assert "gateway:startup" in content

    def test_handler_has_handle_function(self):
        install_hook()
        content = (HOOK_DIR / "handler.py").read_text()
        assert "async def handle" in content
        assert "hermes-aegis" in content
        assert "HTTP_PROXY" in content

    def test_idempotent(self):
        install_hook()
        install_hook()  # Should not raise
        assert is_hook_installed()


class TestUninstallHook:
    def test_removes_hook(self):
        install_hook()
        assert uninstall_hook() is True
        assert not HOOK_DIR.exists()

    def test_returns_false_if_not_installed(self):
        assert uninstall_hook() is False


class TestIsHookInstalled:
    def test_false_when_not_installed(self):
        assert is_hook_installed() is False

    def test_true_when_installed(self):
        install_hook()
        assert is_hook_installed() is True


class TestCleanOldSetup:
    def test_cleans_shell_rc(self, tmp_path):
        rc_file = tmp_path / ".zshrc"
        rc_file.write_text(
            "# existing stuff\n"
            "# Hermes-Aegis Security Layer\n"
            'export PYTHONPATH="$HOME/Projects/hermes-aegis/src:$PYTHONPATH"\n'
            "export TERMINAL_ENV=aegis  # Auto-activate Aegis protection\n"
            "# more stuff\n"
        )

        with patch("hermes_aegis.hook.Path.home", return_value=tmp_path):
            actions = clean_old_setup()

        content = rc_file.read_text()
        assert "hermes-aegis" not in content
        assert "TERMINAL_ENV" not in content
        assert "existing stuff" in content
        assert "more stuff" in content
        assert len(actions) >= 1

    def test_no_op_when_clean(self, tmp_path):
        rc_file = tmp_path / ".zshrc"
        rc_file.write_text("# normal config\nexport PATH=/usr/bin\n")

        with patch("hermes_aegis.hook.Path.home", return_value=tmp_path):
            actions = clean_old_setup()

        # No shell actions (sitecustomize might still produce actions)
        shell_actions = [a for a in actions if ".zshrc" in a or ".bashrc" in a]
        assert len(shell_actions) == 0

    def test_cleans_aegis_managed_env(self, tmp_path):
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        env_file = hermes_dir / ".env"
        env_file.write_text(
            "# Managed by hermes-aegis\n"
            "OPENROUTER_API_KEY=aegis-managed\n"
            "OPENAI_API_KEY=aegis-managed\n"
        )

        with patch("hermes_aegis.hook.HERMES_DIR", hermes_dir):
            with patch("hermes_aegis.hook.Path.home", return_value=tmp_path):
                actions = clean_old_setup()

        # File should be deleted (only had aegis-managed entries + comment)
        assert not env_file.exists()
        assert any("aegis-managed" in a for a in actions)

    def test_preserves_real_keys_in_env(self, tmp_path):
        hermes_dir = tmp_path / ".hermes"
        hermes_dir.mkdir()
        env_file = hermes_dir / ".env"
        env_file.write_text(
            "OPENROUTER_API_KEY=sk-real-key-123\n"
            "OPENAI_API_KEY=aegis-managed\n"
        )

        with patch("hermes_aegis.hook.HERMES_DIR", hermes_dir):
            with patch("hermes_aegis.hook.Path.home", return_value=tmp_path):
                actions = clean_old_setup()

        # File should still exist with real key preserved
        assert env_file.exists()
        content = env_file.read_text()
        assert "sk-real-key-123" in content
        assert "aegis-managed" not in content
