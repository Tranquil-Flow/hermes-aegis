"""Tests for the audit-event CLI subcommand."""
import json
import pytest
from pathlib import Path
from click.testing import CliRunner
from hermes_aegis.cli import main
from hermes_aegis.audit.trail import AuditTrail


@pytest.fixture
def aegis_env(tmp_path, monkeypatch):
    """Set up a temporary aegis directory."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    return aegis_dir


def test_audit_event_command_exists():
    """Test that audit event command is registered."""
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "event", "--help"])
    assert result.exit_code == 0
    assert "event" in result.output.lower()
    assert "--type" in result.output
    assert "--tool" in result.output
    assert "--decision" in result.output
    assert "--data" in result.output


def test_audit_event_records_basic_event(aegis_env):
    """Test that audit event records an entry to audit.jsonl."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "audit", "event",
        "--type", "HERMES_APPROVAL",
        "--tool", "terminal",
        "--decision", "ALLOWED",
    ])

    assert result.exit_code == 0
    assert "Recorded HERMES_APPROVAL event (ALLOWED)" in result.output

    # Verify audit.jsonl was created and has the entry
    audit_path = aegis_env / "audit.jsonl"
    assert audit_path.exists()

    trail = AuditTrail(audit_path)
    entries = trail.read_all()
    assert len(entries) == 1

    entry = entries[0]
    assert entry.tool_name == "terminal"
    assert entry.decision == "ALLOWED"
    assert entry.middleware == "hermes_integration"


def test_audit_event_with_json_data(aegis_env):
    """Test audit event with --data containing valid JSON."""
    data = json.dumps({"command": "ls -la", "pattern": "safe_cmd"})
    runner = CliRunner()
    result = runner.invoke(main, [
        "audit", "event",
        "--type", "HERMES_APPROVAL",
        "--tool", "terminal",
        "--decision", "BLOCKED",
        "--data", data,
    ])

    assert result.exit_code == 0
    assert "BLOCKED" in result.output

    audit_path = aegis_env / "audit.jsonl"
    trail = AuditTrail(audit_path)
    entries = trail.read_all()
    assert len(entries) == 1

    # Check the args contain parsed JSON details
    entry_line = audit_path.read_text().strip()
    entry_data = json.loads(entry_line)
    args = entry_data["args_redacted"]
    assert args["event_type"] == "HERMES_APPROVAL"
    assert args["details"]["command"] == "ls -la"
    assert args["details"]["pattern"] == "safe_cmd"


def test_audit_event_with_invalid_json_data(aegis_env):
    """Test audit event with --data containing non-JSON string."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "audit", "event",
        "--type", "HERMES_GUARD",
        "--data", "not valid json",
    ])

    assert result.exit_code == 0
    assert "Recorded HERMES_GUARD event (ALLOWED)" in result.output

    audit_path = aegis_env / "audit.jsonl"
    entry_line = audit_path.read_text().strip()
    entry_data = json.loads(entry_line)
    args = entry_data["args_redacted"]
    assert args["details"] == "not valid json"


def test_audit_event_without_data(aegis_env):
    """Test audit event without --data has no details key."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "audit", "event",
        "--type", "HERMES_APPROVAL",
    ])

    assert result.exit_code == 0

    audit_path = aegis_env / "audit.jsonl"
    entry_line = audit_path.read_text().strip()
    entry_data = json.loads(entry_line)
    args = entry_data["args_redacted"]
    assert "details" not in args
    assert args["event_type"] == "HERMES_APPROVAL"


def test_audit_event_defaults(aegis_env):
    """Test default values for --tool and --decision."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "audit", "event",
        "--type", "CUSTOM_EVENT",
    ])

    assert result.exit_code == 0

    audit_path = aegis_env / "audit.jsonl"
    trail = AuditTrail(audit_path)
    entries = trail.read_all()
    assert len(entries) == 1

    entry = entries[0]
    assert entry.tool_name == "hermes"  # default --tool
    assert entry.decision == "ALLOWED"  # default --decision


def test_audit_event_requires_type():
    """Test that --type is required."""
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "event"])
    assert result.exit_code != 0
    assert "Missing" in result.output or "required" in result.output.lower()


def test_audit_event_chain_integrity(aegis_env):
    """Test that multiple audit events maintain hash chain integrity."""
    runner = CliRunner()

    for i in range(3):
        result = runner.invoke(main, [
            "audit", "event",
            "--type", f"EVENT_{i}",
            "--decision", "ALLOWED",
        ])
        assert result.exit_code == 0

    audit_path = aegis_env / "audit.jsonl"
    trail = AuditTrail(audit_path)
    assert trail.verify_chain()


def test_audit_event_visible_in_audit_show(aegis_env):
    """Test that events logged via audit-event show up in audit show."""
    runner = CliRunner()

    runner.invoke(main, [
        "audit", "event",
        "--type", "HERMES_APPROVAL",
        "--tool", "terminal",
        "--decision", "BLOCKED",
    ])

    result = runner.invoke(main, ["audit", "show"])
    assert result.exit_code == 0
    assert "terminal" in result.output
    assert "BLOCKED" in result.output
    assert "hermes_integration" in result.output
