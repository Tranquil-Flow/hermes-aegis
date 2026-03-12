"""Tests for CLI audit commands."""
import pytest
import json
from pathlib import Path
from click.testing import CliRunner
from cryptography.fernet import Fernet
from hermes_aegis.cli import main
from hermes_aegis.vault.store import VaultStore
from hermes_aegis.audit.trail import AuditTrail


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
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    
    monkeypatch.setenv("HOME", str(tmp_path))
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show"])
    
    assert result.exit_code == 0
    assert "no audit trail" in result.output.lower() or "empty" in result.output.lower()


def test_audit_show_displays_entries(tmp_path, monkeypatch):
    """Test audit show displays trail entries."""
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    audit_path = armor_dir / "audit.jsonl"
    
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
    
    # Patch ARMOR_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.ARMOR_DIR", armor_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show"])
    
    assert result.exit_code == 0
    assert "test_tool_1" in result.output
    assert "test_tool_2" in result.output
    assert "ALLOW" in result.output
    assert "DENY" in result.output


def test_audit_show_limits_to_20_by_default(tmp_path, monkeypatch):
    """Test audit show limits to last 20 entries by default."""
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    audit_path = armor_dir / "audit.jsonl"
    
    # Create audit trail with 30 entries
    trail = AuditTrail(audit_path)
    for i in range(30):
        trail.log(
            tool_name=f"tool_{i:03d}",
            args_redacted={},
            decision="ALLOW",
            middleware="TestMiddleware"
        )
    
    # Patch ARMOR_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.ARMOR_DIR", armor_dir)
    
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
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    audit_path = armor_dir / "audit.jsonl"
    
    # Create audit trail with 30 entries
    trail = AuditTrail(audit_path)
    for i in range(30):
        trail.log(
            tool_name=f"tool_{i:03d}",
            args_redacted={},
            decision="ALLOW",
            middleware="TestMiddleware"
        )
    
    # Patch ARMOR_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.ARMOR_DIR", armor_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "show", "--all"])
    
    assert result.exit_code == 0
    # Should show all entries including first ones
    assert "tool_000" in result.output
    assert "tool_029" in result.output


def test_audit_verify_clean_trail(tmp_path, monkeypatch):
    """Test audit verify with untampered trail."""
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    audit_path = armor_dir / "audit.jsonl"
    
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
    
    # Patch ARMOR_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.ARMOR_DIR", armor_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify"])
    
    assert result.exit_code == 0
    assert "pass" in result.output.lower() or "verified" in result.output.lower()


def test_audit_verify_detects_tampering(tmp_path, monkeypatch):
    """Test audit verify detects tampered trail."""
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    audit_path = armor_dir / "audit.jsonl"
    
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
    
    # Patch ARMOR_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.ARMOR_DIR", armor_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify"])
    
    assert result.exit_code == 1
    assert "failed" in result.output.lower() or "tampering" in result.output.lower()


def test_audit_verify_detects_deletion(tmp_path, monkeypatch):
    """Test audit verify detects deleted entries."""
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    audit_path = armor_dir / "audit.jsonl"
    
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
    
    # Patch ARMOR_DIR to use tmp_path
    monkeypatch.setattr("hermes_aegis.cli.ARMOR_DIR", armor_dir)
    
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify"])
    
    assert result.exit_code == 1
    assert "failed" in result.output.lower() or "tampering" in result.output.lower()
