"""Tests for the default middleware chain with output scanner."""
import asyncio
from pathlib import Path

import pytest

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.chain import CallContext, create_default_chain


@pytest.fixture
def audit_trail(tmp_path):
    """Create a temporary audit trail for testing."""
    return AuditTrail(tmp_path / "audit.jsonl")


class TestDefaultChain:
    """Test the default middleware chain creation."""

    def test_create_default_chain_instantiates(self):
        """Test that create_default_chain returns a valid middleware chain."""
        chain = create_default_chain()
        
        assert chain is not None
        assert len(chain.middlewares) >= 2  # At least dangerous blocker and output scanner

    def test_create_default_chain_with_audit_trail(self, audit_trail):
        """Test that create_default_chain accepts audit trail."""
        chain = create_default_chain(audit_trail=audit_trail)
        
        assert chain is not None
        assert len(chain.middlewares) > 0

    def test_create_default_chain_with_vault_values(self):
        """Test that create_default_chain accepts vault values."""
        vault_values = ["secret1", "secret2"]
        chain = create_default_chain(vault_values=vault_values)
        
        assert chain is not None
        assert len(chain.middlewares) > 0

    def test_default_chain_redacts_secrets(self, audit_trail):
        """Test that the default chain redacts secrets in output."""
        chain = create_default_chain(audit_trail=audit_trail)
        ctx = CallContext()
        
        async def mock_handler(args):
            return {"output": "API key: sk-proj-abc123def456ghi789jklmno"}
        
        result = asyncio.run(chain.execute("terminal", {}, mock_handler, ctx))
        
        assert "sk-proj-abc123def456ghi789jklmno" not in result["output"]
        assert "[REDACTED: openai_api_key]" in result["output"]

    def test_default_chain_logs_redactions(self, audit_trail):
        """Test that the default chain logs redactions to audit trail."""
        chain = create_default_chain(audit_trail=audit_trail)
        ctx = CallContext()
        
        async def mock_handler(args):
            return {"output": "Token: ghp_abc123def456ghi789jkl012mno345pqr678stuvwxyz"}
        
        asyncio.run(chain.execute("terminal", {}, mock_handler, ctx))
        
        entries = audit_trail.read_all()
        assert len(entries) == 1
        assert entries[0].decision == "OUTPUT_REDACTED"

    def test_default_chain_preserves_clean_output(self):
        """Test that the default chain preserves output without secrets."""
        chain = create_default_chain()
        ctx = CallContext()
        
        async def mock_handler(args):
            return {"output": "This is normal output"}
        
        result = asyncio.run(chain.execute("terminal", {}, mock_handler, ctx))
        
        assert result["output"] == "This is normal output"

    def test_default_chain_redacts_vault_values(self, audit_trail):
        """Test that the default chain redacts exact vault values."""
        vault_values = ["my-super-secret-value"]
        chain = create_default_chain(audit_trail=audit_trail, vault_values=vault_values)
        ctx = CallContext()
        
        async def mock_handler(args):
            return {"output": "Leaked: my-super-secret-value"}
        
        result = asyncio.run(chain.execute("terminal", {}, mock_handler, ctx))
        
        assert "my-super-secret-value" not in result["output"]
        assert "[REDACTED: exact_match]" in result["output"]

    def test_default_chain_includes_dangerous_blocker(self):
        """Test that the default chain includes dangerous command blocker."""
        from hermes_aegis.middleware.dangerous_blocker import DangerousBlockerMiddleware
        
        chain = create_default_chain()
        
        # Check that dangerous blocker is in the chain
        has_blocker = any(isinstance(m, DangerousBlockerMiddleware) for m in chain.middlewares)
        assert has_blocker, "Default chain should include DangerousBlockerMiddleware"

    def test_default_chain_dangerous_audit_mode(self, audit_trail):
        """Test that default chain uses audit mode for dangerous commands."""
        chain = create_default_chain(audit_trail=audit_trail, dangerous_mode="audit")
        ctx = CallContext()
        
        async def mock_handler(args):
            return {"output": "Command executed"}
        
        # Should allow dangerous command in audit mode
        result = asyncio.run(chain.execute("terminal", {"command": "rm -rf /"}, mock_handler, ctx))
        assert result["output"] == "Command executed"

    def test_default_chain_dangerous_block_mode(self, audit_trail):
        """Test that default chain can block dangerous commands when configured."""
        from hermes_aegis.middleware.dangerous_blocker import SecurityError
        
        chain = create_default_chain(audit_trail=audit_trail, dangerous_mode="block")
        ctx = CallContext()
        
        async def mock_handler(args):
            return {"output": "Command executed"}
        
        # Should raise SecurityError in block mode
        with pytest.raises(SecurityError):
            asyncio.run(chain.execute("terminal", {"command": "rm -rf /"}, mock_handler, ctx))
