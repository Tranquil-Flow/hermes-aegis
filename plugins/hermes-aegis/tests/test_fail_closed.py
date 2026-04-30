from unittest.mock import patch

from hooks.pre_tool_call import aegis_pre_tool_call


def test_internal_error_produces_block_signal():
    with patch("hooks.pre_tool_call._check_patterns", side_effect=RuntimeError("bug")):
        result = aegis_pre_tool_call(tool_name="terminal", args={"command": "ls"})
    assert result is not None
    assert result["action"] == "block"
    assert "internal error" in result["message"].lower()


def test_missing_args_does_not_crash():
    assert aegis_pre_tool_call(tool_name="terminal", args={}) is None
