"""Tests for CLI audit commands and audit middleware."""
import pytest
import json
from pathlib import Path
from click.testing import CliRunner
from cryptography.fernet import Fernet
from hermes_aegis.cli import main
from hermes_aegis.vault.store import VaultStore
from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.audit import _redact_args, _redact_value


@pytest.fixture
def master_key():
    """Provide a test master key."""
    return Fernet.generate_key()


def test_audit_show_command_exists():
    """Test that audit show command is registered."""
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show", "--help"])
    assert result.exit_code == 0
    assert "show" in result.output.lower()


def test_audit_verify_command_exists():
    """Test that audit verify command is registered."""
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify", "--help"])
    assert result.exit_code == 0
    assert "verify" in result.output.lower()


def test_audit_show_empty_trail(tmp_path, monkeypatch):
    """Test audit show with no entries."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show"])
    
    assert result.exit_code == 0
    assert "no audit trail" in result.output.lower() or "empty" in result.output.lower()


def test_audit_show_displays_entries(tmp_path, monkeypatch):
    """Test audit show displays trail entries."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    
    # Create audit trail with entries
    trail = AuditTrail(audit_path)
    trail.log(
        tool_name="test_tool_1",
        args_redacted={"arg": "value"},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    trail.log(
        tool_name="test_tool_2",
        args_redacted={},
        decision="DENY",
        middleware="BlockMiddleware"
    )
    
    # Patch AEGIS_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show"])
    
    assert result.exit_code == 0
    assert "test_tool_1" in result.output
    assert "test_tool_2" in result.output
    assert "ALLOW" in result.output
    assert "DENY" in result.output


def test_audit_show_limits_to_20_by_default(tmp_path, monkeypatch):
    """Test audit show limits to last 20 entries by default."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    
    # Create audit trail with 30 entries
    trail = AuditTrail(audit_path)
    for i in range(30):
        trail.log(
            tool_name=f"tool_{i:03d}",
            args_redacted={},
            decision="ALLOW",
            middleware="TestMiddleware"
        )
    
    # Patch AEGIS_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show"])
    
    assert result.exit_code == 0
    # Should show entries 10-29 (last 20)
    assert "tool_029" in result.output
    assert "tool_010" in result.output
    # Should NOT show first 10 entries
    assert "tool_009" not in result.output
    assert "tool_000" not in result.output


def test_audit_show_all_flag(tmp_path, monkeypatch):
    """Test audit show --all displays all entries."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    
    # Create audit trail with 30 entries
    trail = AuditTrail(audit_path)
    for i in range(30):
        trail.log(
            tool_name=f"tool_{i:03d}",
            args_redacted={},
            decision="ALLOW",
            middleware="TestMiddleware"
        )
    
    # Patch AEGIS_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show", "--all"])
    
    assert result.exit_code == 0
    # Should show all entries including first ones
    assert "tool_000" in result.output
    assert "tool_029" in result.output


def test_audit_verify_clean_trail(tmp_path, monkeypatch):
    """Test audit verify with untampered trail."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    
    # Create audit trail with entries
    trail = AuditTrail(audit_path)
    trail.log(
        tool_name="test_tool",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    trail.log(
        tool_name="test_tool_2",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    
    # Patch AEGIS_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify"])
    
    assert result.exit_code == 0
    assert "pass" in result.output.lower() or "verified" in result.output.lower()


def test_audit_verify_detects_tampering(tmp_path, monkeypatch):
    """Test audit verify detects tampered trail."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    
    # Create audit trail with entries
    trail = AuditTrail(audit_path)
    trail.log(
        tool_name="test_tool_1",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    trail.log(
        tool_name="test_tool_2",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    
    # Tamper with the audit file - modify a tool name
    lines = audit_path.read_text().splitlines()
    tampered_lines = []
    for line in lines:
        data = json.loads(line)
        if data["tool_name"] == "test_tool_1":
            data["tool_name"] = "tampered_tool"
        tampered_lines.append(json.dumps(data))
    
    audit_path.write_text("\n".join(tampered_lines) + "\n")
    
    # Patch AEGIS_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify"])
    
    assert result.exit_code == 1
    assert "failed" in result.output.lower() or "tampering" in result.output.lower()


def test_audit_verify_detects_deletion(tmp_path, monkeypatch):
    """Test audit verify detects deleted entries."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    
    # Create audit trail with entries
    trail = AuditTrail(audit_path)
    trail.log(
        tool_name="test_tool_1",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    trail.log(
        tool_name="test_tool_2",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    trail.log(
        tool_name="test_tool_3",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    
    # Delete middle entry
    lines = audit_path.read_text().splitlines()
    del lines[1]  # Remove second entry
    audit_path.write_text("\n".join(lines) + "\n")

    # Patch AEGIS_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify"])

    assert result.exit_code == 1
    assert "failed" in result.output.lower() or "tampering" in result.output.lower()


def test_audit_show_decision_filter(tmp_path, monkeypatch):
    """Test audit show --decision filters entries by decision type."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"

    trail = AuditTrail(audit_path)
    trail.log(tool_name="tool_a", args_redacted={}, decision="BLOCKED", middleware="ProxyScanner")
    trail.log(tool_name="tool_b", args_redacted={}, decision="COMPLETED", middleware="AuditMiddleware")
    trail.log(tool_name="tool_c", args_redacted={}, decision="BLOCKED", middleware="DomainAllowlist")

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show", "--decision", "BLOCKED"])

    assert result.exit_code == 0
    assert "tool_a" in result.output
    assert "tool_c" in result.output
    assert "tool_b" not in result.output


def test_audit_show_decision_filter_no_match(tmp_path, monkeypatch):
    """Test audit show --decision with no matching entries."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"

    trail = AuditTrail(audit_path)
    trail.log(tool_name="tool_a", args_redacted={}, decision="COMPLETED", middleware="AuditMiddleware")

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show", "--decision", "BLOCKED"])

    assert result.exit_code == 0
    assert "No entries" in result.output


def test_audit_show_decision_filter_case_insensitive(tmp_path, monkeypatch):
    """Test audit show --decision accepts lowercase input."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"

    trail = AuditTrail(audit_path)
    trail.log(tool_name="tool_a", args_redacted={}, decision="BLOCKED", middleware="ProxyScanner")

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show", "--decision", "blocked"])

    assert result.exit_code == 0
    assert "tool_a" in result.output


def test_audit_clear_command_exists():
    """Test that audit clear command is registered."""
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "clear", "--help"])
    assert result.exit_code == 0
    assert "clear" in result.output.lower()


def test_audit_clear_archives_and_removes(tmp_path, monkeypatch):
    """Test audit clear archives the trail and starts fresh."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"

    trail = AuditTrail(audit_path)
    trail.log(tool_name="tool_a", args_redacted={}, decision="BLOCKED", middleware="ProxyScanner")
    trail.log(tool_name="tool_b", args_redacted={}, decision="COMPLETED", middleware="AuditMiddleware")

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "clear", "--yes"])

    assert result.exit_code == 0
    assert "Archived" in result.output
    assert "cleared" in result.output.lower()
    # Original audit file is gone
    assert not audit_path.exists()
    # Archive file was created
    archives = list(aegis_dir.glob("audit.jsonl.*"))
    assert len(archives) == 1
    # Archive contains the original events
    assert "BLOCKED" in archives[0].read_text()


def test_audit_clear_shows_summary(tmp_path, monkeypatch):
    """Test audit clear displays event counts by decision type."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"

    trail = AuditTrail(audit_path)
    trail.log(tool_name="tool_a", args_redacted={}, decision="BLOCKED", middleware="ProxyScanner")
    trail.log(tool_name="tool_b", args_redacted={}, decision="BLOCKED", middleware="ProxyScanner")
    trail.log(tool_name="tool_c", args_redacted={}, decision="COMPLETED", middleware="AuditMiddleware")

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "clear", "--yes"])

    assert result.exit_code == 0
    assert "BLOCKED" in result.output
    assert "COMPLETED" in result.output
    # Counts should appear
    assert "2" in result.output  # 2 BLOCKED
    assert "1" in result.output  # 1 COMPLETED


def test_audit_clear_requires_confirmation(tmp_path, monkeypatch):
    """Test audit clear asks for confirmation without --yes."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"

    trail = AuditTrail(audit_path)
    trail.log(tool_name="tool_a", args_redacted={}, decision="BLOCKED", middleware="ProxyScanner")

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    # Answer 'n' to confirmation prompt
    result = runner.invoke(main, ["audit", "clear"], input="n\n")

    assert result.exit_code == 0
    assert "Aborted" in result.output
    # File should still exist
    assert audit_path.exists()


def test_audit_clear_empty_trail(tmp_path, monkeypatch):
    """Test audit clear with no audit trail."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "clear", "--yes"])

    assert result.exit_code == 0
    assert "no audit trail" in result.output.lower() or "empty" in result.output.lower()


class TestRedactArgs:
    """Tests for recursive _redact_args (fix #10)."""

    def test_flat_string_redaction(self):
        args = {"key": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"}
        result = _redact_args(args)
        assert result["key"] == "[REDACTED]"

    def test_flat_clean_string_passes(self):
        args = {"key": "hello world"}
        result = _redact_args(args)
        assert result["key"] == "hello world"

    def test_nested_dict_redaction(self):
        """Secrets nested in dicts should be redacted (was the bug)."""
        args = {"api": {"key": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"}}
        result = _redact_args(args)
        assert result["api"]["key"] == "[REDACTED]"

    def test_nested_list_redaction(self):
        """Secrets in lists should be redacted."""
        args = {"values": ["safe", "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"]}
        result = _redact_args(args)
        assert result["values"][0] == "safe"
        assert result["values"][1] == "[REDACTED]"

    def test_deeply_nested_redaction(self):
        args = {"outer": {"inner": {"deep": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"}}}
        result = _redact_args(args)
        assert result["outer"]["inner"]["deep"] == "[REDACTED]"

    def test_non_string_values_preserved(self):
        args = {"count": 42, "flag": True, "empty": None}
        result = _redact_args(args)
        assert result == {"count": 42, "flag": True, "empty": None}
