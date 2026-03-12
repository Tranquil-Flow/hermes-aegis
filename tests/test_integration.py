"""Tests for Hermes backend integration."""
from unittest.mock import MagicMock, patch
import sys
import types


def _make_fake_terminal_tool():
    """Create a fake tools.terminal_tool module for testing."""
    mod = types.ModuleType("tools.terminal_tool")
    mod._create_environment = MagicMock(side_effect=ValueError("unknown"))
    return mod


class TestRegisterAegisBackend:
    def test_patches_create_environment(self):
        """register_aegis_backend should add aegis to _create_environment."""
        import hermes_aegis.integration as integration
        integration._PATCHED = False

        fake_tt = _make_fake_terminal_tool()
        fake_tools = types.ModuleType("tools")

        with patch.dict(sys.modules, {
            "tools": fake_tools,
            "tools.terminal_tool": fake_tt,
        }):
            result = integration.register_aegis_backend()

        assert result is True
        assert integration._PATCHED is True
        integration._PATCHED = False

    def test_aegis_creates_aegis_environment(self):
        """Patched factory should create AegisEnvironment for env_type=aegis."""
        import hermes_aegis.integration as integration
        integration._PATCHED = False

        fake_tt = _make_fake_terminal_tool()
        fake_tools = types.ModuleType("tools")

        with patch.dict(sys.modules, {
            "tools": fake_tools,
            "tools.terminal_tool": fake_tt,
        }):
            integration.register_aegis_backend()
            patched_fn = fake_tt._create_environment

        with patch("hermes_aegis.environment.AegisEnvironment") as mock_aegis:
            mock_aegis.return_value = MagicMock()
            env = patched_fn("aegis", "python:3.11-slim", "/workspace", 180)
            mock_aegis.assert_called_once_with(
                image="python:3.11-slim",
                cwd="/workspace",
                timeout=180,
            )

        integration._PATCHED = False

    def test_non_aegis_delegates_to_original(self):
        """Non-aegis env_type should delegate to original factory."""
        import hermes_aegis.integration as integration
        integration._PATCHED = False

        fake_tt = _make_fake_terminal_tool()
        original_fn = fake_tt._create_environment
        original_fn.side_effect = None  # Remove error side_effect for delegation test
        original_fn.return_value = MagicMock()
        fake_tools = types.ModuleType("tools")

        with patch.dict(sys.modules, {
            "tools": fake_tools,
            "tools.terminal_tool": fake_tt,
        }):
            integration.register_aegis_backend()
            patched_fn = fake_tt._create_environment

        patched_fn("docker", "python:3.11-slim", "/workspace", 180)
        original_fn.assert_called_once_with(
            "docker", "python:3.11-slim", "/workspace", 180,
            ssh_config=None, container_config=None, task_id="default",
        )

        integration._PATCHED = False

    def test_idempotent(self):
        """Calling register twice should not double-patch."""
        import hermes_aegis.integration as integration
        integration._PATCHED = False

        fake_tt = _make_fake_terminal_tool()
        fake_tools = types.ModuleType("tools")

        with patch.dict(sys.modules, {
            "tools": fake_tools,
            "tools.terminal_tool": fake_tt,
        }):
            integration.register_aegis_backend()
            first_fn = fake_tt._create_environment
            integration.register_aegis_backend()
            second_fn = fake_tt._create_environment

        assert first_fn is second_fn
        integration._PATCHED = False

    def test_returns_false_when_hermes_missing(self):
        """Should return False when Hermes is not importable."""
        import builtins
        import hermes_aegis.integration as integration
        integration._PATCHED = False

        real_import = builtins.__import__

        def failing_import(name, *args, **kwargs):
            if name == "tools.terminal_tool":
                raise ImportError(f"No module named '{name}'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=failing_import):
            result = integration.register_aegis_backend()

        assert result is False
        integration._PATCHED = False
