import os
import tempfile
from unittest.mock import MagicMock

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.proxy.addon import AegisAddon


class FakeFlow:
    """Minimal mock of mitmproxy.http.HTTPFlow."""

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


class TestAegisAddon:
    def test_injects_api_key_for_openai(self):
        addon = AegisAddon(
            vault_secrets={"OPENAI_API_KEY": "sk-test-123"},
            vault_values=["sk-test-123"],
        )
        flow = FakeFlow("api.openai.com", "/v1/chat/completions")

        addon.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer sk-test-123"
        assert not flow.killed

    def test_blocks_exfiltration_to_non_llm_host(self):
        addon = AegisAddon(
            vault_secrets={"OPENAI_API_KEY": "my-secret-value"},
            vault_values=["my-secret-value"],
        )
        flow = FakeFlow("evil.com", "/steal", body=b"data=my-secret-value")

        addon.request(flow)

        assert flow.killed

    def test_does_not_block_llm_provider_after_injection(self):
        addon = AegisAddon(
            vault_secrets={"OPENAI_API_KEY": "sk-test-456"},
            vault_values=["sk-test-456"],
        )
        flow = FakeFlow("api.openai.com", "/v1/chat/completions")

        addon.request(flow)

        assert not flow.killed
        assert flow.request.headers["Authorization"] == "Bearer sk-test-456"

    def test_allows_clean_browsing(self):
        addon = AegisAddon(
            vault_secrets={"OPENAI_API_KEY": "sk-secret"},
            vault_values=["sk-secret"],
        )
        flow = FakeFlow("google.com", "/search?q=python")

        addon.request(flow)

        assert not flow.killed

    def test_logs_to_audit(self):
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        addon = AegisAddon(
            vault_secrets={"OPENAI_API_KEY": "my-secret-value"},
            vault_values=["my-secret-value"],
            audit_trail=trail,
        )
        flow = FakeFlow("evil.com", "/exfil", body=b"my-secret-value")

        addon.request(flow)
        entries = trail.read_all()

        assert len(entries) > 0
        assert entries[0].decision == "BLOCKED"

    def test_large_body_scans_head_and_tail(self):
        """Bodies >1MB should still be scanned (first+last 64KB) instead of skipped."""
        secret = "my-secret-value"
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[secret],
        )
        # Secret at end of a >1MB body — should still be caught
        padding = b"A" * (1_048_576 + 100)
        body = padding + secret.encode()
        flow = FakeFlow("evil.com", "/exfil", body=body)

        addon.request(flow)
        assert flow.killed

    def test_large_body_scans_head(self):
        """Secret at the start of a large body should be caught."""
        secret = "my-secret-value"
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[secret],
        )
        body = secret.encode() + b"A" * (1_048_576 + 100)
        flow = FakeFlow("evil.com", "/exfil", body=body)

        addon.request(flow)
        assert flow.killed

    def test_large_clean_body_passes(self):
        """Large body with no secrets should pass through."""
        addon = AegisAddon(
            vault_secrets={},
            vault_values=["my-secret"],
        )
        body = b"A" * (1_048_576 + 100)
        flow = FakeFlow("example.com", "/upload", body=body)

        addon.request(flow)
        assert not flow.killed
