"""Tests for AegisAddon header injection — verifies headers are correctly
added, replaced, AND removed when the injector modifies them.

The critical case: OAuth tokens for Anthropic must replace x-api-key with
Authorization: Bearer, and the old x-api-key must be removed from the flow.
"""
from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from hermes_aegis.proxy.addon import AegisAddon


class FakeHeaders(dict):
    """Mimic mitmproxy's Headers (dict-like with case-insensitive get/set/del)."""
    pass


def _make_flow(host: str, path: str, headers: dict) -> MagicMock:
    """Create a minimal mitmproxy flow mock."""
    flow = MagicMock()
    flow.request.host = host
    flow.request.path = path
    flow.request.url = f"https://{host}{path}"
    flow.request.headers = FakeHeaders(headers)
    flow.request.get_content.return_value = b""
    return flow


class TestAddonOAuthInjection:
    """Verify that OAuth tokens are injected as Bearer and x-api-key is removed."""

    def test_anthropic_oauth_replaces_x_api_key(self):
        """When vault has ANTHROPIC_TOKEN (OAuth), addon must:
        1. Add Authorization: Bearer <token>
        2. Remove x-api-key placeholder from flow headers
        """
        vault_secrets = {"ANTHROPIC_TOKEN": "sk-ant-oat01-test-token-123"}
        addon = AegisAddon(vault_secrets=vault_secrets, vault_values=[])

        flow = _make_flow("api.anthropic.com", "/v1/messages", {
            "x-api-key": "placeholder-aegis-injects",
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        })

        addon._handle_request(flow)

        assert flow.request.headers.get("Authorization") == "Bearer sk-ant-oat01-test-token-123"
        assert "x-api-key" not in flow.request.headers, \
            "x-api-key placeholder must be removed when using OAuth Bearer auth"
        assert flow.request.headers["content-type"] == "application/json"

    def test_anthropic_api_key_uses_x_api_key(self):
        """Traditional sk-ant-api keys should use x-api-key header."""
        vault_secrets = {"ANTHROPIC_API_KEY": "sk-ant-api03-real-key"}
        addon = AegisAddon(vault_secrets=vault_secrets, vault_values=[])

        flow = _make_flow("api.anthropic.com", "/v1/messages", {
            "x-api-key": "placeholder",
        })

        addon._handle_request(flow)

        assert flow.request.headers["x-api-key"] == "sk-ant-api03-real-key"
        assert "Authorization" not in flow.request.headers

    def test_openai_bearer_injection(self):
        """OpenAI should get Bearer auth without removing anything."""
        vault_secrets = {"OPENAI_API_KEY": "sk-test-openai"}
        addon = AegisAddon(vault_secrets=vault_secrets, vault_values=[])

        flow = _make_flow("api.openai.com", "/v1/chat/completions", {
            "content-type": "application/json",
        })

        addon._handle_request(flow)

        assert flow.request.headers["Authorization"] == "Bearer sk-test-openai"

    def test_anthropic_token_alias_found(self):
        """ANTHROPIC_TOKEN (alias) should be found when ANTHROPIC_API_KEY is absent."""
        vault_secrets = {"ANTHROPIC_TOKEN": "sk-ant-oat01-my-oauth-token"}
        addon = AegisAddon(vault_secrets=vault_secrets, vault_values=[])

        flow = _make_flow("api.anthropic.com", "/v1/messages", {
            "x-api-key": "ignored-placeholder",
        })

        addon._handle_request(flow)

        assert flow.request.headers.get("Authorization") == "Bearer sk-ant-oat01-my-oauth-token"
        assert "x-api-key" not in flow.request.headers

    def test_no_vault_key_passes_through(self):
        """When no vault key exists, headers should pass through unchanged."""
        addon = AegisAddon(vault_secrets={}, vault_values=[])

        flow = _make_flow("api.anthropic.com", "/v1/messages", {
            "x-api-key": "placeholder",
            "content-type": "application/json",
        })

        addon._handle_request(flow)

        # No key to inject — headers unchanged
        assert flow.request.headers["x-api-key"] == "placeholder"
