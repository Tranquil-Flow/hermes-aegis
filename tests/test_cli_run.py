"""Tests for CLI run command."""
import pytest
from pathlib import Path
from click.testing import CliRunner
from cryptography.fernet import Fernet
from hermes_aegis.cli import main
from hermes_aegis.vault.store import VaultStore
from hermes_aegis.audit.trail import AuditTrail


@pytest.fixture
def vault_path(tmp_path):
    """Provide a temporary vault path."""
    return tmp_path / "vault.enc"


@pytest.fixture
def audit_path(tmp_path):
    """Provide a temporary audit trail path."""
    return tmp_path / "audit.jsonl"


@pytest.fixture
def master_key():
    """Provide a test master key."""
    return Fernet.generate_key()


def test_run_command_exists():
    """Test that run command is registered."""
    runner = CliRunner()
    result = runner.invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output.lower()


def test_run_tier1_simple_command(tmp_path, monkeypatch):
    """Test run command with a simple echo in Tier 1 mode."""
    # Set up temporary directories
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    vault_path = armor_dir / "vault.enc"
    audit_path = armor_dir / "audit.jsonl"
    
    # Create vault
    master_key = Fernet.generate_key()
    vault = VaultStore(vault_path, master_key)
    
    # Mock the armor directory
    monkeypatch.setenv("HOME", str(tmp_path))
    
    # Mock keyring to return our test master key
    monkeypatch.setattr(
        "hermes_aegis.vault.keyring_store.get_or_create_master_key",
        lambda: master_key
    )
    
    runner = CliRunner()
    result = runner.invoke(main, ["--tier1", "run", "echo", "hello"])
    
    # Command should execute
    assert result.exit_code == 0
    # Should show summary
    assert "audit summary" in result.output.lower() or "summary" in result.output.lower()


def test_run_prints_audit_summary(tmp_path, monkeypatch):
    """Test that run command prints audit summary on exit."""
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    vault_path = armor_dir / "vault.enc"
    audit_path = armor_dir / "audit.jsonl"
    
    master_key = Fernet.generate_key()
    vault = VaultStore(vault_path, master_key)
    
    # Pre-populate audit trail with some entries
    trail = AuditTrail(audit_path)
    trail.log(
        tool_name="test_tool",
        args_redacted={},
        decision="ALLOW",
        middleware="TestMiddleware"
    )
    
    monkeypatch.setenv("HOME", str(tmp_path))
    
    # Mock keyring to return our test master key
    monkeypatch.setattr(
        "hermes_aegis.vault.keyring_store.get_or_create_master_key",
        lambda: master_key
    )
    
    runner = CliRunner()
    result = runner.invoke(main, ["--tier1", "run", "echo", "test"])
    
    # Should show audit summary
    assert "audit summary" in result.output.lower() or "summary" in result.output.lower()


def test_run_command_not_found(tmp_path, monkeypatch):
    """Test run command with non-existent command."""
    armor_dir = tmp_path / ".hermes-aegis"
    armor_dir.mkdir()
    vault_path = armor_dir / "vault.enc"
    
    master_key = Fernet.generate_key()
    vault = VaultStore(vault_path, master_key)
    
    monkeypatch.setenv("HOME", str(tmp_path))
    
    # Mock keyring to return our test master key
    monkeypatch.setattr(
        "hermes_aegis.vault.keyring_store.get_or_create_master_key",
        lambda: master_key
    )
    
    runner = CliRunner()
    result = runner.invoke(main, ["--tier1", "run", "nonexistent_command_xyz"])
    
    # Should fail with error
    assert result.exit_code != 0
