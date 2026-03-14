"""Integration tests for allowlist feature."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, MagicMock

import pytest

from hermes_aegis.config.allowlist import DomainAllowlist
from hermes_aegis.proxy.addon import AegisAddon
from hermes_aegis.audit.trail import AuditTrail


@pytest.fixture
def allowlist_path(tmp_path):
    """Provide a temporary path for allowlist testing."""
    return tmp_path / "domain-allowlist.json"


@pytest.fixture
def audit_path(tmp_path):
    """Provide a temporary path for audit trail."""
    return tmp_path / "audit.jsonl"


class TestAllowlistProxyIntegration:
    """Test integration of allowlist with proxy addon."""

    def test_empty_allowlist_allows_all_domains(self, allowlist_path, audit_path):
        """Test that empty allowlist doesn't block any requests."""
        # Setup
        audit_trail = AuditTrail(audit_path)
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=audit_trail,
            allowlist_path=allowlist_path,
        )
        
        # Create mock flow for non-LLM request
        flow = Mock()
        flow.request.host = "random-site.com"
        flow.request.path = "/api/data"
        flow.request.url = "https://random-site.com/api/data"
        flow.request.headers = {}
        flow.request.get_content = Mock(return_value=b"")
        
        # Should not be killed (empty allowlist allows all)
        addon.request(flow)
        assert not flow.kill.called

    def test_allowlist_blocks_unlisted_domain(self, allowlist_path, audit_path):
        """Test that non-empty allowlist blocks unlisted domains."""
        # Setup allowlist with one domain
        allowlist = DomainAllowlist(allowlist_path)
        allowlist.add("trusted.com")
        
        audit_trail = AuditTrail(audit_path)
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=audit_trail,
            allowlist_path=allowlist_path,
        )
        
        # Create mock flow for blocked domain
        flow = Mock()
        flow.request.host = "evil.com"
        flow.request.path = "/api/exfiltrate"
        flow.request.url = "https://evil.com/api/exfiltrate"
        flow.request.headers = {}
        flow.request.get_content = Mock(return_value=b"")
        
        # Should be killed
        addon.request(flow)
        flow.kill.assert_called_once()

    def test_allowlist_allows_listed_domain(self, allowlist_path, audit_path):
        """Test that allowlist allows listed domains."""
        # Setup allowlist
        allowlist = DomainAllowlist(allowlist_path)
        allowlist.add("trusted.com")
        
        audit_trail = AuditTrail(audit_path)
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=audit_trail,
            allowlist_path=allowlist_path,
        )
        
        # Create mock flow for allowed domain
        flow = Mock()
        flow.request.host = "trusted.com"
        flow.request.path = "/api/safe"
        flow.request.url = "https://trusted.com/api/safe"
        flow.request.headers = {}
        flow.request.get_content = Mock(return_value=b"")
        
        # Should not be killed
        addon.request(flow)
        assert not flow.kill.called

    def test_allowlist_allows_subdomain(self, allowlist_path, audit_path):
        """Test that subdomains of allowed domains are allowed."""
        # Setup allowlist
        allowlist = DomainAllowlist(allowlist_path)
        allowlist.add("trusted.com")
        
        audit_trail = AuditTrail(audit_path)
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=audit_trail,
            allowlist_path=allowlist_path,
        )
        
        # Create mock flow for subdomain
        flow = Mock()
        flow.request.host = "api.trusted.com"
        flow.request.path = "/v1/data"
        flow.request.url = "https://api.trusted.com/v1/data"
        flow.request.headers = {}
        flow.request.get_content = Mock(return_value=b"")
        
        # Should not be killed
        addon.request(flow)
        assert not flow.kill.called

    def test_llm_requests_bypass_allowlist(self, allowlist_path, audit_path):
        """Test that LLM provider requests bypass allowlist check."""
        # Setup allowlist with only one domain (not OpenAI)
        allowlist = DomainAllowlist(allowlist_path)
        allowlist.add("trusted.com")
        
        audit_trail = AuditTrail(audit_path)
        addon = AegisAddon(
            vault_secrets={"OPENAI_API_KEY": "sk-test123"},
            vault_values=[],
            audit_trail=audit_trail,
            allowlist_path=allowlist_path,
        )
        
        # Create mock flow for OpenAI request (should bypass allowlist)
        flow = Mock()
        flow.request.host = "api.openai.com"
        flow.request.path = "/v1/chat/completions"
        flow.request.url = "https://api.openai.com/v1/chat/completions"
        flow.request.headers = {}
        
        # Should not be killed (LLM requests bypass allowlist)
        addon.request(flow)
        assert not flow.kill.called

    def test_blocked_request_logged_to_audit(self, allowlist_path, audit_path):
        """Test that blocked requests are logged to audit trail."""
        # Setup allowlist
        allowlist = DomainAllowlist(allowlist_path)
        allowlist.add("trusted.com")
        
        audit_trail = AuditTrail(audit_path)
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=audit_trail,
            allowlist_path=allowlist_path,
        )
        
        # Create mock flow for blocked domain
        flow = Mock()
        flow.request.host = "evil.com"
        flow.request.path = "/api/exfiltrate"
        flow.request.url = "https://evil.com/api/exfiltrate"
        flow.request.headers = {}
        flow.request.get_content = Mock(return_value=b"")
        
        # Execute request (should be blocked)
        addon.request(flow)
        flow.kill.assert_called_once()
        
        # Verify audit log
        entries = audit_trail.read_all()
        assert len(entries) == 1
        assert entries[0].decision == "BLOCKED"
        assert entries[0].middleware == "DomainAllowlist"
        assert "evil.com" in str(entries[0].args_redacted)

    def test_multiple_domains_in_allowlist(self, allowlist_path, audit_path):
        """Test allowlist with multiple domains."""
        # Setup allowlist with multiple domains
        allowlist = DomainAllowlist(allowlist_path)
        allowlist.add("trusted1.com")
        allowlist.add("trusted2.com")
        allowlist.add("api.github.com")
        
        audit_trail = AuditTrail(audit_path)
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=audit_trail,
            allowlist_path=allowlist_path,
        )
        
        # Test allowed domains
        for host in ["trusted1.com", "trusted2.com", "api.github.com", "sub.trusted1.com"]:
            flow = Mock()
            flow.request.host = host
            flow.request.path = "/"
            flow.request.url = f"https://{host}/"
            flow.request.headers = {}
            flow.request.get_content = Mock(return_value=b"")
            
            addon.request(flow)
            assert not flow.kill.called, f"{host} should be allowed"
        
        # Test blocked domain
        flow = Mock()
        flow.request.host = "evil.com"
        flow.request.path = "/"
        flow.request.url = "https://evil.com/"
        flow.request.headers = {}
        flow.request.get_content = Mock(return_value=b"")
        
        addon.request(flow)
        flow.kill.assert_called_once()


class TestAllowlistCLIIntegration:
    """Test CLI integration for allowlist management."""

    def test_cli_commands_functionality(self, allowlist_path):
        """Test that CLI functions work with the allowlist module."""
        from hermes_aegis.config.allowlist import DomainAllowlist
        
        # This tests the underlying functionality that CLI commands use
        allowlist = DomainAllowlist(allowlist_path)
        
        # Initial state should be empty
        assert allowlist.list() == []
        
        # Add domains (simulating 'add' command)
        allowlist.add("example.com")
        allowlist.add("github.com")
        
        # List domains (simulating 'list' command)
        domains = allowlist.list()
        assert "example.com" in domains
        assert "github.com" in domains
        assert len(domains) == 2
        
        # Remove domain (simulating 'remove' command)
        result = allowlist.remove("example.com")
        assert result is True
        
        # Verify removal
        domains = allowlist.list()
        assert "example.com" not in domains
        assert "github.com" in domains
        assert len(domains) == 1
        
        # Remove non-existent domain
        result = allowlist.remove("nonexistent.com")
        assert result is False
