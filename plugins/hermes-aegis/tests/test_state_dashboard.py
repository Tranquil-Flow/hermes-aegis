import asyncio

from dashboard.api import get_audit, get_stats, get_violations
from hooks.post_api_request import aegis_post_api_request
from hooks.post_tool_call import aegis_post_tool_call
from hooks.pre_tool_call import aegis_pre_tool_call
import state
from state import reset_state_for_tests


def test_audit_and_stats_persist_for_dashboard(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "aegis_state_dir", lambda: tmp_path)
    reset_state_for_tests()
    aegis_post_tool_call(
        tool_name="read_file",
        args={"path": "/tmp/a"},
        result="ok",
        task_id="task-1",
        session_id="sess-1",
    )
    aegis_post_api_request(
        task_id="task-1",
        session_id="sess-1",
        model="claude-test",
        provider="anthropic",
        base_url="https://example.test",
    )

    audit = asyncio.run(get_audit(page=1, limit=50))
    stats = asyncio.run(get_stats())

    assert audit["total"] == 1
    assert audit["entries"][0]["tool_name"] == "read_file"
    assert stats["total_tool_calls"] == 1
    assert stats["sessions"]["sess-1"]["models"] == ["claude-test"]


def test_blocked_pre_tool_call_records_violation_for_dashboard(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "aegis_state_dir", lambda: tmp_path)
    reset_state_for_tests()
    result = aegis_pre_tool_call(
        tool_name="terminal",
        args={"command": "rm -rf /"},
        task_id="task-2",
        session_id="sess-2",
    )
    violations = asyncio.run(get_violations())

    assert result is not None
    assert violations["violations"][0]["decision"] == "BLOCKED"
    assert "delete" in violations["violations"][0]["reason"]
