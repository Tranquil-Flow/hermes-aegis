"""Tests for output secret scanner middleware."""
import asyncio
from pathlib import Path

import pytest

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.chain import CallContext
from hermes_aegis.middleware.output_scanner import OutputScannerMiddleware


@pytest.fixture
def audit_trail(tmp_path):
    """Create a temporary audit trail for testing."""
    return AuditTrail(tmp_path / "audit.jsonl")


@pytest.fixture
def vault_values():
    """Sample vault values for exact matching."""
    return ["my-secret-key-12345", "another-vault-secret"]


@pytest.fixture
def middleware(audit_trail, vault_values):
    """Create output scanner middleware with audit trail."""
    return OutputScannerMiddleware(trail=audit_trail, vault_values=vault_values)


@pytest.fixture
def middleware_no_audit(vault_values):
    """Create output scanner middleware without audit trail."""
    return OutputScannerMiddleware(vault_values=vault_values)


class TestOutputScannerBasic:
    """Test basic redaction functionality."""

    def test_redacts_openai_api_key_in_dict_output(self, middleware):
        """Test that OpenAI API keys are redacted from dict output."""
        result = {"output": "Config loaded with API key: sk-proj-abc123def456ghi789"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "sk-proj-abc123def456ghi789" not in redacted["output"]
        assert "[REDACTED: openai_api_key]" in redacted["output"]

    def test_redacts_anthropic_api_key_in_dict_output(self, middleware):
        """Test that Anthropic API keys are redacted from dict output."""
        result = {"output": "Using key sk-ant-api03-abc123def456ghi789jkl012"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "sk-ant-api03-abc123def456ghi789jkl012" not in redacted["output"]
        assert "[REDACTED: anthropic_api_key]" in redacted["output"]

    def test_redacts_github_token_in_dict_output(self, middleware):
        """Test that GitHub tokens are redacted from dict output."""
        result = {"output": "Clone with: ghp_abcd1234efgh5678ijkl9012mnop3456qrstuvwxyz"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "ghp_abcd1234efgh5678ijkl9012mnop3456qrstuvwxyz" not in redacted["output"]
        assert "[REDACTED: github_token]" in redacted["output"]

    def test_redacts_aws_secret_key_in_dict_output(self, middleware):
        """Test that AWS secret keys are redacted from dict output."""
        result = {"output": "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCD"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "abcdefghijklmnopqrstuvwxyz1234567890ABCD" not in redacted["output"]
        assert "[REDACTED: aws_secret_key]" in redacted["output"]

    def test_redacts_bearer_token_in_dict_output(self, middleware):
        """Test that Bearer tokens are redacted from dict output."""
        result = {"output": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted["output"]
        assert "[REDACTED: generic_bearer]" in redacted["output"]

    def test_redacts_generic_api_key_in_dict_output(self, middleware):
        """Test that generic API keys are redacted from dict output."""
        result = {"output": "api_key: abcdef1234567890ghijklmn"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "abcdef1234567890ghijklmn" not in redacted["output"]
        assert "[REDACTED: generic_api_key]" in redacted["output"]

    def test_redacts_rpc_url_with_embedded_key(self, middleware):
        """Test that RPC URLs with embedded API keys are redacted."""
        result = {"output": "RPC: https://eth-mainnet.g.alchemy.com/v2/abc123def456ghi789jkl"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "https://eth-mainnet.g.alchemy.com/v2/abc123def456ghi789jkl" not in redacted["output"]
        assert "[REDACTED: rpc_url_with_key]" in redacted["output"]

    def test_preserves_non_secret_output(self, middleware):
        """Test that normal output without secrets is preserved."""
        result = {"output": "Command completed successfully. No errors."}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert redacted["output"] == "Command completed successfully. No errors."

    def test_handles_dict_without_output_key(self, middleware):
        """Test that dict results without 'output' key are passed through."""
        result = {"data": "some data", "status": "ok"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert redacted == result

    def test_handles_non_string_output_value(self, middleware):
        """Test that non-string output values are passed through."""
        result = {"output": 12345}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert redacted == result


class TestOutputScannerStringResults:
    """Test scanning of plain string results."""

    def test_redacts_secrets_in_plain_string_result(self, middleware):
        """Test that secrets are redacted from plain string results."""
        result = "OpenAI key: sk-proj-xyz789abc123def456"
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "sk-proj-xyz789abc123def456" not in redacted
        assert "[REDACTED: openai_api_key]" in redacted

    def test_preserves_plain_string_without_secrets(self, middleware):
        """Test that plain strings without secrets are preserved."""
        result = "This is a safe output string."
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert redacted == result


class TestOutputScannerVaultValues:
    """Test exact vault value matching."""

    def test_redacts_exact_vault_value(self, middleware):
        """Test that exact vault values are redacted."""
        result = {"output": "Secret is: my-secret-key-12345 here"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "my-secret-key-12345" not in redacted["output"]
        assert "[REDACTED: exact_match]" in redacted["output"]

    def test_redacts_base64_encoded_vault_value(self, middleware):
        """Test that base64-encoded vault values are redacted."""
        # my-secret-key-12345 in base64
        result = {"output": "Encoded: bXktc2VjcmV0LWtleS0xMjM0NQ=="}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "bXktc2VjcmV0LWtleS0xMjM0NQ==" not in redacted["output"]
        assert "[REDACTED: exact_match_base64]" in redacted["output"]


class TestOutputScannerMultipleSecrets:
    """Test handling of multiple secrets in one output."""

    def test_redacts_multiple_different_secrets(self, middleware):
        """Test that multiple different secrets are all redacted."""
        result = {
            "output": "Keys: sk-proj-abc123def456ghi789jk and ghp_def456ghi789jkl012mno345pqr678stuvwx and api_key=secret123456789012345"
        }
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "sk-proj-abc123def456ghi789jk" not in redacted["output"]
        assert "ghp_def456ghi789jkl012mno345pqr678stuvwx" not in redacted["output"]
        assert "secret123456789012345" not in redacted["output"]
        assert redacted["output"].count("[REDACTED:") == 3

    def test_redacts_repeated_same_secret(self, middleware):
        """Test that repeated occurrences of same secret are all redacted."""
        result = {"output": "sk-proj-abc123def456ghi789jk first, sk-proj-abc123def456ghi789jk second, sk-proj-abc123def456ghi789jk third"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "sk-proj-abc123def456ghi789jk" not in redacted["output"]
        assert redacted["output"].count("[REDACTED: openai_api_key]") == 3


class TestOutputScannerAuditTrail:
    """Test audit trail logging."""

    def test_logs_redaction_to_audit_trail(self, middleware, audit_trail):
        """Test that redactions are logged to audit trail."""
        result = {"output": "Secret: sk-proj-abc123def456ghi789jk"}
        ctx = CallContext()

        asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        entries = audit_trail.read_all()
        assert len(entries) == 1
        assert entries[0].tool_name == "terminal"
        assert entries[0].decision == "OUTPUT_REDACTED"
        assert entries[0].middleware == "OutputScannerMiddleware"
        assert entries[0].args_redacted["redactions"] == 1

    def test_logs_multiple_redactions(self, middleware, audit_trail):
        """Test that multiple redactions are counted correctly in audit."""
        result = {"output": "Keys: sk-proj-abc123def456ghi789jk and ghp_def456ghi789jkl012mno345pqr678stuvwx"}
        ctx = CallContext()

        asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        entries = audit_trail.read_all()
        assert len(entries) == 1
        assert entries[0].args_redacted["redactions"] == 2

    def test_no_log_when_no_secrets_found(self, middleware, audit_trail):
        """Test that no audit entry is created when no secrets are found."""
        result = {"output": "Normal safe output"}
        ctx = CallContext()

        asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        entries = audit_trail.read_all()
        assert len(entries) == 0

    def test_works_without_audit_trail(self, middleware_no_audit):
        """Test that middleware works without audit trail configured."""
        result = {"output": "Secret: sk-proj-abc123def456ghi789jk"}
        ctx = CallContext()

        # Should not raise an exception
        redacted = asyncio.run(middleware_no_audit.post_dispatch("terminal", {}, result, ctx))

        assert "sk-proj-abc123def456ghi789jk" not in redacted["output"]
        assert "[REDACTED: openai_api_key]" in redacted["output"]


class TestOutputScannerEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_handles_empty_output(self, middleware):
        """Test handling of empty output string."""
        result = {"output": ""}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert redacted == result

    def test_handles_none_result(self, middleware):
        """Test handling of None result."""
        result = None
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert redacted is None

    def test_handles_list_result(self, middleware):
        """Test handling of list result."""
        result = ["item1", "item2"]
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert redacted == result

    def test_does_not_modify_original_dict(self, middleware):
        """Test that original result dict is not modified."""
        original = {"output": "Secret: sk-proj-abc123def456ghi789jk", "other": "data"}
        result = original.copy()
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        # Original should be unchanged
        assert "sk-proj-abc123def456ghi789jk" in original["output"]
        # Redacted should have secret removed
        assert "sk-proj-abc123def456ghi789jk" not in redacted["output"]
        # Other keys should be preserved
        assert redacted["other"] == "data"

    def test_overlapping_secrets_redacted_correctly(self, middleware):
        """Test that overlapping secret matches are handled correctly."""
        # This creates overlapping matches
        result = {"output": "api_key: sk-proj-abc123def456ghi789"}
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        # Both patterns should be redacted
        assert "sk-proj-abc123def456ghi789" not in redacted["output"]
        assert "[REDACTED:" in redacted["output"]


class TestOutputScannerTier1Tier2:
    """Test compatibility with Tier 1 and Tier 2 environments."""

    def test_tier1_subprocess_output_format(self, middleware):
        """Test handling of typical Tier 1 subprocess output format."""
        result = {
            "output": "stdout with secret: sk-proj-abc123def456ghi789jk",
            "exit_code": 0,
            "error": None
        }
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "sk-proj-abc123def456ghi789jk" not in redacted["output"]
        assert redacted["exit_code"] == 0
        assert redacted["error"] is None

    def test_tier2_container_output_format(self, middleware):
        """Test handling of typical Tier 2 container output format."""
        result = {
            "output": "container logs with token: ghp_abc123def456ghi789jkl012mno345pqr678stuvwx",
            "status": "completed"
        }
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("terminal", {}, result, ctx))

        assert "ghp_abc123def456ghi789jkl012mno345pqr678stuvwx" not in redacted["output"]
        assert redacted["status"] == "completed"
