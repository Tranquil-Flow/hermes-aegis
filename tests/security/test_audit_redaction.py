"""Real security test for audit trail redaction.

Tests verify that secrets appearing in tool arguments are properly redacted
in the audit trail, and that the actual secret values never appear in the
audit log file.
"""
import pytest
import asyncio
from pathlib import Path
from cryptography.fernet import Fernet

from hermes_aegis.vault.store import VaultStore
from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.audit import AuditTrailMiddleware
from hermes_aegis.middleware.chain import MiddlewareChain, CallContext


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


@pytest.fixture
def vault_with_secret(vault_path, master_key):
    """Create a vault with secrets that match patterns."""
    vault = VaultStore(vault_path, master_key)
    # Use secrets that match known patterns
    vault.set("API_KEY", "sk-proj-testkey1234567890123456789012345678")
    vault.set("ANTHROPIC_KEY", "sk-ant-api01-abcdefghijklmnopqrstuvwxyz123456")
    return vault


# Task 3.4: Secret Leakage in Tool Arguments
def test_redacts_secrets_in_tool_args(audit_path, vault_with_secret):
    """Test that secrets in tool arguments are replaced with [REDACTED] in audit."""
    # Set up audit middleware
    trail = AuditTrail(audit_path)
    middleware = AuditTrailMiddleware(trail)
    chain = MiddlewareChain([middleware])
    
    # Simulate a tool call with a secret in the args
    api_key = vault_with_secret.get("API_KEY")
    
    async def dummy_tool(args):
        return "tool executed"
    
    ctx = CallContext()
    result = asyncio.run(chain.execute(
        "send_request",
        {"url": "https://api.example.com", "auth_token": api_key},
        dummy_tool,
        ctx
    ))
    
    # Verify tool executed
    assert result == "tool executed"
    
    # Read raw audit file content
    audit_content = audit_path.read_text()
    
    # The actual secret should NOT appear anywhere in the audit file
    assert api_key not in audit_content, "Secret leaked into audit trail!"
    
    # The redacted placeholder should appear
    assert "[REDACTED]" in audit_content
    
    # Verify via parsed entries
    entries = trail.read_all()
    assert len(entries) == 2  # pre and post dispatch
    
    initiated_entry = entries[0]
    assert initiated_entry.decision == "INITIATED"
    assert initiated_entry.args_redacted["url"] == "https://api.example.com"
    assert initiated_entry.args_redacted["auth_token"] == "[REDACTED]"


def test_allows_non_secret_args(audit_path, vault_with_secret):
    """Test that non-secret arguments are logged normally."""
    # Set up audit middleware
    trail = AuditTrail(audit_path)
    middleware = AuditTrailMiddleware(trail)
    chain = MiddlewareChain([middleware])
    
    async def dummy_tool(args):
        return "success"
    
    ctx = CallContext()
    result = asyncio.run(chain.execute(
        "fetch_data",
        {"endpoint": "/api/users", "method": "GET", "timeout": 30},
        dummy_tool,
        ctx
    ))
    
    # Read audit entries
    entries = trail.read_all()
    initiated_entry = entries[0]
    
    # All args should be present (not redacted)
    assert initiated_entry.args_redacted["endpoint"] == "/api/users"
    assert initiated_entry.args_redacted["method"] == "GET"
    assert initiated_entry.args_redacted["timeout"] == 30
    assert "[REDACTED]" not in str(initiated_entry.args_redacted)


def test_redacts_multiple_secrets(audit_path, vault_with_secret):
    """Test that multiple secrets in different args are all redacted."""
    trail = AuditTrail(audit_path)
    middleware = AuditTrailMiddleware(trail)
    chain = MiddlewareChain([middleware])
    
    api_key = vault_with_secret.get("API_KEY")
    anthropic_key = vault_with_secret.get("ANTHROPIC_KEY")
    
    async def dummy_tool(args):
        return "ok"
    
    ctx = CallContext()
    asyncio.run(chain.execute(
        "configure_system",
        {
            "openai_key": api_key,
            "anthropic_key": anthropic_key,
            "app_name": "test_app"
        },
        dummy_tool,
        ctx
    ))
    
    # Check audit file
    audit_content = audit_path.read_text()
    
    # Neither secret should appear
    assert api_key not in audit_content
    assert anthropic_key not in audit_content
    
    # Verify parsed entries
    entries = trail.read_all()
    initiated_entry = entries[0]
    
    assert initiated_entry.args_redacted["openai_key"] == "[REDACTED]"
    assert initiated_entry.args_redacted["anthropic_key"] == "[REDACTED]"
    assert initiated_entry.args_redacted["app_name"] == "test_app"


def test_redacts_pattern_matched_secrets(audit_path, vault_with_secret):
    """Test that secrets matching patterns (not just vault values) are redacted."""
    trail = AuditTrail(audit_path)
    middleware = AuditTrailMiddleware(trail)
    chain = MiddlewareChain([middleware])
    
    # Use a secret that matches a pattern but isn't in the vault
    fake_openai_key = "sk-proj-fakekey123456789012345678901234567890"
    
    async def dummy_tool(args):
        return "done"
    
    ctx = CallContext()
    asyncio.run(chain.execute(
        "call_openai",
        {"api_key": fake_openai_key, "model": "gpt-4"},
        dummy_tool,
        ctx
    ))
    
    # Check audit file
    audit_content = audit_path.read_text()
    
    # The fake key should be redacted (pattern match)
    assert fake_openai_key not in audit_content
    assert "[REDACTED]" in audit_content
    
    # Verify parsed
    entries = trail.read_all()
    initiated_entry = entries[0]
    
    assert initiated_entry.args_redacted["api_key"] == "[REDACTED]"
    assert initiated_entry.args_redacted["model"] == "gpt-4"
