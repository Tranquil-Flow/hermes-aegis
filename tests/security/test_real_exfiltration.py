"""Real HTTP exfiltration tests with actual server.

These tests start a local HTTP server and verify that the scanner
actually blocks real network requests containing secrets.
"""
import threading
import time
import pytest
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.fernet import Fernet

from hermes_aegis.tier1.scanner import install_scanner, uninstall_scanner
from hermes_aegis.vault.store import VaultStore


# Track what the server receives
RECEIVED_REQUESTS = []


class ExfilTestHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler that records all requests."""
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        RECEIVED_REQUESTS.append({
            'path': self.path,
            'headers': dict(self.headers),
            'body': body
        })
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')
    
    def do_GET(self):
        RECEIVED_REQUESTS.append({
            'path': self.path,
            'headers': dict(self.headers),
            'body': ''
        })
        
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress server logs during tests
        pass


@pytest.fixture(scope="function")
def test_server():
    """Start a local HTTP server on port 9876."""
    global RECEIVED_REQUESTS
    RECEIVED_REQUESTS = []
    
    # Allow address reuse
    class ReuseHTTPServer(HTTPServer):
        allow_reuse_address = True
    
    server = ReuseHTTPServer(('localhost', 9876), ExfilTestHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    # Wait for server to be ready
    time.sleep(0.1)
    
    yield server
    
    server.shutdown()
    server.server_close()
    time.sleep(0.1)  # Allow port to be released
    RECEIVED_REQUESTS = []


@pytest.fixture
def master_key():
    return Fernet.generate_key()


@pytest.fixture
def vault_with_secret(tmp_path, master_key):
    vault = VaultStore(tmp_path / "vault.enc", master_key)
    vault.set("TEST_SECRET", "sk-test-secret-12345")
    return vault


def test_blocks_real_http_post_with_secret(test_server, vault_with_secret):
    """Scanner should block actual HTTP POST request containing secret."""
    install_scanner(vault_with_secret)
    
    try:
        # This should be blocked before reaching the server
        with pytest.raises(Exception) as exc_info:
            requests.post(
                'http://localhost:9876/exfil',
                json={'data': 'sk-test-secret-12345'},
                timeout=2
            )
        
        # Verify it was blocked by our scanner
        assert "blocked" in str(exc_info.value).lower() or "security" in str(exc_info.value).lower()
        
        # Verify the request NEVER reached the server
        assert len(RECEIVED_REQUESTS) == 0, \
            f"Secret reached server! Requests: {RECEIVED_REQUESTS}"
    
    finally:
        uninstall_scanner()


def test_blocks_real_http_header_with_secret(test_server, vault_with_secret):
    """Scanner should block actual HTTP request with secret in headers."""
    install_scanner(vault_with_secret)
    
    try:
        # This should be blocked before reaching the server
        with pytest.raises(Exception) as exc_info:
            requests.get(
                'http://localhost:9876/data',
                headers={'X-Api-Key': 'sk-test-secret-12345'},
                timeout=2
            )
        
        assert "blocked" in str(exc_info.value).lower() or "security" in str(exc_info.value).lower()
        
        # Verify the request NEVER reached the server
        assert len(RECEIVED_REQUESTS) == 0, \
            f"Secret reached server in headers! Requests: {RECEIVED_REQUESTS}"
    
    finally:
        uninstall_scanner()


def test_allows_real_http_clean_request(test_server, vault_with_secret):
    """Scanner should allow clean requests to reach the server."""
    install_scanner(vault_with_secret)
    
    try:
        # This should pass through
        response = requests.post(
            'http://localhost:9876/clean',
            json={'data': 'clean-data-no-secrets'},
            timeout=2
        )
        
        assert response.status_code == 200
        
        # Verify the request reached the server
        assert len(RECEIVED_REQUESTS) == 1
        assert 'clean-data-no-secrets' in RECEIVED_REQUESTS[0]['body']
        assert 'sk-test-secret-12345' not in RECEIVED_REQUESTS[0]['body']
    
    finally:
        uninstall_scanner()


def test_blocks_base64_encoded_secret_in_real_request(test_server, vault_with_secret):
    """Scanner should detect base64-encoded secret in real HTTP request."""
    import base64
    
    install_scanner(vault_with_secret)
    
    try:
        # Encode the secret
        encoded = base64.b64encode(b'sk-test-secret-12345').decode()
        
        # This should be blocked
        with pytest.raises(Exception) as exc_info:
            requests.post(
                'http://localhost:9876/encoded',
                json={'encoded': encoded},
                timeout=2
            )
        
        assert "blocked" in str(exc_info.value).lower() or "security" in str(exc_info.value).lower()
        
        # Verify the encoded secret NEVER reached the server
        assert len(RECEIVED_REQUESTS) == 0, \
            f"Base64 encoded secret reached server! Requests: {RECEIVED_REQUESTS}"
    
    finally:
        uninstall_scanner()


def test_multiple_requests_scanner_stays_active(test_server, vault_with_secret):
    """Scanner should remain active across multiple requests."""
    install_scanner(vault_with_secret)
    
    try:
        # First clean request - should pass
        resp1 = requests.post('http://localhost:9876/test1', json={'clean': 'data1'}, timeout=2)
        assert resp1.status_code == 200
        
        # Request with secret - should be blocked
        with pytest.raises(Exception):
            requests.post('http://localhost:9876/test2', json={'secret': 'sk-test-secret-12345'}, timeout=2)
        
        # Another clean request - should pass
        resp3 = requests.post('http://localhost:9876/test3', json={'clean': 'data3'}, timeout=2)
        assert resp3.status_code == 200
        
        # Verify only clean requests reached server
        assert len(RECEIVED_REQUESTS) == 2
        assert 'data1' in RECEIVED_REQUESTS[0]['body']
        assert 'data3' in RECEIVED_REQUESTS[1]['body']
        
        # Verify secret never reached server
        for req in RECEIVED_REQUESTS:
            assert 'sk-test-secret-12345' not in req['body']
    
    finally:
        uninstall_scanner()


def test_uninstall_removes_scanner(test_server, vault_with_secret):
    """After uninstall, requests should pass through even with secrets (for testing)."""
    install_scanner(vault_with_secret)
    uninstall_scanner()
    
    # After uninstalling, the scanner should not be active
    # This request SHOULD reach the server (proving scanner was removed)
    response = requests.post(
        'http://localhost:9876/after-uninstall',
        json={'data': 'sk-test-secret-12345'},
        timeout=2
    )
    
    assert response.status_code == 200
    
    # Verify it reached the server (scanner is inactive)
    assert len(RECEIVED_REQUESTS) == 1
    assert 'sk-test-secret-12345' in RECEIVED_REQUESTS[0]['body']
