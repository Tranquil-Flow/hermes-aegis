from hooks.pre_tool_call import aegis_pre_tool_call


def test_safe_read_file_allowed():
    assert aegis_pre_tool_call(tool_name="read_file", args={"path": "/tmp/test.txt"}) is None


def test_dangerous_recursive_delete_blocked():
    result = aegis_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /"})
    assert result is not None
    assert result["action"] == "block"


def test_safe_ls_command_allowed():
    assert aegis_pre_tool_call(tool_name="terminal", args={"command": "ls -la"}) is None


def test_non_terminal_tools_pass_through():
    assert aegis_pre_tool_call(tool_name="web_search", args={"query": "hello"}) is None


def test_raw_secret_in_args_blocked():
    result = aegis_pre_tool_call(
        tool_name="write_file",
        args={"path": "/tmp/env", "content": "OPENAI_API_KEY=sk-" + "a" * 24},
    )
    assert result is not None
    assert result["action"] == "block"
    assert "secret" in result["message"].lower()
