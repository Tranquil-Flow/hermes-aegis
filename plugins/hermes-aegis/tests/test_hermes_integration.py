import pytest

try:
    from hermes_cli.plugins import PluginManager, VALID_HOOKS

    HERMES_AVAILABLE = True
except ImportError:
    HERMES_AVAILABLE = False

pytestmark = pytest.mark.skipif(not HERMES_AVAILABLE, reason="hermes-agent not importable")


def test_valid_hooks_includes_all_aegis_hooks():
    required = {
        "pre_tool_call",
        "post_tool_call",
        "transform_tool_result",
        "transform_terminal_output",
        "pre_llm_call",
        "post_api_request",
    }
    assert required.issubset(VALID_HOOKS)


def test_plugin_manager_can_scan_manifest():
    from hermes_constants import get_hermes_home

    manager = PluginManager()
    manifests = manager._scan_directory(get_hermes_home() / "plugins", source="user")
    assert any(manifest.name == "hermes-aegis" for manifest in manifests)
