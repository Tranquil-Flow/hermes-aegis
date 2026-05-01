"""Unit tests for hermes_aegis.proxy.injector module."""

from __future__ import annotations

import pytest

from hermes_aegis.proxy.injector import LLM_PROVIDERS, inject_api_key, is_llm_provider_request


# ---------------------------------------------------------------------------
# LLM_PROVIDERS structure
# ---------------------------------------------------------------------------

EXPECTED_PROVIDERS = {
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.together.xyz",
    "openrouter.ai",
    "api.minimax.io",
    "api.minimaxi.com",
    "chatgpt.com",
    "ai.vercel.com",
    "portal.nousresearch.com",
    "api.z.ai",
    "open.bigmodel.cn",
}


class TestLLMProviders:
    def test_all_expected_providers_present(self):
        assert set(LLM_PROVIDERS.keys()) == EXPECTED_PROVIDERS

    def test_provider_count(self):
        assert len(LLM_PROVIDERS) == 13

    def test_every_provider_key_env_is_in_auto_inject_keys(self):
        """Every provider that names a `key_env` must also appear in
        AUTO_INJECT_KEYS, otherwise hermes never receives the placeholder
        env var for that key and the provider 401s under aegis. The bug is
        silent (no error, just auth failures), so guard it at test time:
        a CI failure here means the next provider added needs a matching
        AUTO_INJECT_KEYS entry.

        Caught ZAI_API_KEY and VERCEL_API_TOKEN both missing pre-v0.3.0.
        """
        from hermes_aegis.cli import AUTO_INJECT_KEYS

        missing = sorted(
            entry["key_env"]
            for entry in LLM_PROVIDERS.values()
            if entry.get("key_env") and entry["key_env"] not in AUTO_INJECT_KEYS
        )
        assert not missing, (
            f"LLM_PROVIDERS reference key_env values that are not in "
            f"AUTO_INJECT_KEYS: {missing}. Add them to AUTO_INJECT_KEYS in "
            f"src/hermes_aegis/cli.py so hermes gets the placeholder env var."
        )

    @pytest.mark.parametrize("host", list(EXPECTED_PROVIDERS))
    def test_each_provider_has_required_keys(self, host):
        entry = LLM_PROVIDERS[host]
        assert "key_env" in entry
        assert "header" in entry
        assert "prefix" in entry

    def test_openai_uses_bearer_authorization(self):
        p = LLM_PROVIDERS["api.openai.com"]
        assert p["header"] == "Authorization"
        assert p["prefix"] == "Bearer "
        assert p["key_env"] == "OPENAI_API_KEY"

    def test_anthropic_uses_x_api_key(self):
        p = LLM_PROVIDERS["api.anthropic.com"]
        assert p["header"] == "x-api-key"
        assert p["prefix"] == ""
        assert p["key_env"] == "ANTHROPIC_API_KEY"

    def test_google_uses_x_goog_api_key(self):
        p = LLM_PROVIDERS["generativelanguage.googleapis.com"]
        assert p["header"] == "x-goog-api-key"
        assert p["prefix"] == ""
        assert p["key_env"] == "GOOGLE_API_KEY"


# ---------------------------------------------------------------------------
# is_llm_provider_request()
# ---------------------------------------------------------------------------

class TestIsLLMProviderRequest:
    @pytest.mark.parametrize("host", list(EXPECTED_PROVIDERS))
    def test_known_hosts_return_true(self, host):
        assert is_llm_provider_request(host, "/v1/chat/completions") is True

    @pytest.mark.parametrize("host", [
        "example.com",
        "google.com",
        "localhost",
        "some-random-host.io",
    ])
    def test_unknown_hosts_return_false(self, host):
        assert is_llm_provider_request(host, "/") is False

    def test_subdomain_not_matched(self):
        # "sub.api.openai.com" is not in the dict — should be False
        assert is_llm_provider_request("sub.api.openai.com", "/") is False

    def test_partial_hostname_not_matched(self):
        assert is_llm_provider_request("openai.com", "/") is False
        assert is_llm_provider_request("api.openai", "/") is False

    def test_empty_host(self):
        assert is_llm_provider_request("", "/") is False

    def test_path_does_not_affect_result(self):
        assert is_llm_provider_request("api.openai.com", "") is True
        assert is_llm_provider_request("api.openai.com", "/anything") is True


# ---------------------------------------------------------------------------
# inject_api_key()
# ---------------------------------------------------------------------------

class TestInjectApiKey:
    """Tests for inject_api_key(host, path, headers, vault_values)."""

    def test_openai_bearer_injection(self):
        headers = {"Content-Type": "application/json"}
        vault = {"OPENAI_API_KEY": "sk-test-123"}
        result = inject_api_key("api.openai.com", "/v1/chat/completions", headers, vault)
        assert result["Authorization"] == "Bearer sk-test-123"
        assert result["Content-Type"] == "application/json"

    def test_anthropic_x_api_key_injection(self):
        headers = {}
        vault = {"ANTHROPIC_API_KEY": "sk-ant-api03-test-key-456"}
        result = inject_api_key("api.anthropic.com", "/v1/messages", headers, vault)
        assert result["x-api-key"] == "sk-ant-api03-test-key-456"

    def test_anthropic_oauth_token_uses_bearer(self):
        headers = {}
        vault = {"ANTHROPIC_TOKEN": "sk-ant-oat01-oauth-token-789"}
        result = inject_api_key("api.anthropic.com", "/v1/messages", headers, vault)
        assert result["Authorization"] == "Bearer sk-ant-oat01-oauth-token-789"
        assert "x-api-key" not in result

    def test_anthropic_oauth_overrides_placeholder_bearer(self):
        """Vault token must override placeholder Bearer set by aegis env injection."""
        headers = {"Authorization": "Bearer aegis-managed"}
        vault = {"ANTHROPIC_TOKEN": "sk-ant-oat01-vault-token"}
        result = inject_api_key("api.anthropic.com", "/v1/messages", headers, vault)
        assert result["Authorization"] == "Bearer sk-ant-oat01-vault-token"
        assert "x-api-key" not in result

    def test_anthropic_oauth_overrides_any_existing_bearer(self):
        """Vault is authoritative — always inject, matching behavior of other providers."""
        headers = {"Authorization": "Bearer some-other-token"}
        vault = {"ANTHROPIC_TOKEN": "sk-ant-oat01-vault-token"}
        result = inject_api_key("api.anthropic.com", "/v1/messages", headers, vault)
        assert result["Authorization"] == "Bearer sk-ant-oat01-vault-token"

    def test_google_injection(self):
        headers = {}
        vault = {"GOOGLE_API_KEY": "goog-789"}
        result = inject_api_key(
            "generativelanguage.googleapis.com", "/v1/models", headers, vault
        )
        assert result["x-goog-api-key"] == "goog-789"

    def test_groq_injection(self):
        headers = {}
        vault = {"GROQ_API_KEY": "groq-abc"}
        result = inject_api_key("api.groq.com", "/", headers, vault)
        assert result["Authorization"] == "Bearer groq-abc"

    def test_together_injection(self):
        headers = {}
        vault = {"TOGETHER_API_KEY": "tog-def"}
        result = inject_api_key("api.together.xyz", "/", headers, vault)
        assert result["Authorization"] == "Bearer tog-def"

    def test_openrouter_injection(self):
        headers = {}
        vault = {"OPENROUTER_API_KEY": "or-ghi"}
        result = inject_api_key("openrouter.ai", "/", headers, vault)
        assert result["Authorization"] == "Bearer or-ghi"

    def test_minimax_injection(self):
        headers = {}
        vault = {"MINIMAX_API_KEY": "mm-ghi"}
        result = inject_api_key("api.minimax.io", "/anthropic/v1/messages", headers, vault)
        assert result["Authorization"] == "Bearer mm-ghi"

    def test_minimax_cn_injection(self):
        headers = {}
        vault = {"MINIMAX_CN_API_KEY": "mmcn-ghi"}
        result = inject_api_key("api.minimaxi.com", "/anthropic/v1/messages", headers, vault)
        assert result["Authorization"] == "Bearer mmcn-ghi"

    def test_zai_bigmodel_uses_zai_api_key(self):
        """open.bigmodel.cn (Z.AI's primary endpoint) shares ZAI_API_KEY
        with api.z.ai. Regression for the post-R7 outage where the host
        was allowlisted but missing from LLM_PROVIDERS, so the proxy
        treated outgoing requests as cross-provider exfiltration and
        blocked every LLM call."""
        headers = {}
        vault = {"ZAI_API_KEY": "zai-glm-secret"}
        result = inject_api_key(
            "open.bigmodel.cn", "/api/paas/v4/chat/completions", headers, vault,
        )
        assert result["Authorization"] == "Bearer zai-glm-secret"

    def test_zai_bigmodel_recognised_as_llm_provider(self):
        """is_llm_provider_request must early-return for open.bigmodel.cn
        so the addon skips body scanning."""
        from hermes_aegis.proxy.injector import is_llm_provider_request
        assert is_llm_provider_request("open.bigmodel.cn", "/api/x")

    @pytest.mark.parametrize("host", list(EXPECTED_PROVIDERS))
    def test_all_providers_inject_when_key_present(self, host):
        provider = LLM_PROVIDERS[host]
        # Use a realistic API key for Anthropic to test x-api-key path
        test_value = "sk-ant-api03-test-secret" if host == "api.anthropic.com" else "test-secret"
        vault = {provider["key_env"]: test_value}
        result = inject_api_key(host, "/", {}, vault)
        expected_value = provider["prefix"] + test_value
        assert result[provider["header"]] == expected_value

    # --- no injection cases ---

    def test_unknown_host_no_injection(self):
        headers = {"Foo": "bar"}
        vault = {"OPENAI_API_KEY": "sk-123"}
        result = inject_api_key("example.com", "/", headers, vault)
        assert result == {"Foo": "bar"}

    def test_key_missing_from_vault_no_injection(self):
        headers = {"Content-Type": "application/json"}
        vault = {}  # no keys at all
        result = inject_api_key("api.openai.com", "/v1/chat", headers, vault)
        assert "Authorization" not in result
        assert result["Content-Type"] == "application/json"

    def test_wrong_key_in_vault_no_injection(self):
        headers = {}
        vault = {"ANTHROPIC_API_KEY": "ant-key"}
        # Requesting openai but vault only has anthropic key
        result = inject_api_key("api.openai.com", "/", headers, vault)
        assert "Authorization" not in result

    def test_empty_vault_no_injection(self):
        result = inject_api_key("api.groq.com", "/", {}, {})
        assert "Authorization" not in result

    # --- does not mutate original headers ---

    def test_original_headers_not_mutated(self):
        original = {"Content-Type": "application/json"}
        vault = {"OPENAI_API_KEY": "sk-123"}
        result = inject_api_key("api.openai.com", "/", original, vault)
        assert "Authorization" in result
        assert "Authorization" not in original  # original unchanged

    # --- replaces existing header value ---

    def test_existing_auth_header_replaced(self):
        headers = {"Authorization": "Bearer old-placeholder"}
        vault = {"OPENAI_API_KEY": "sk-real"}
        result = inject_api_key("api.openai.com", "/", headers, vault)
        assert result["Authorization"] == "Bearer sk-real"

    # --- edge cases ---

    def test_empty_host_returns_headers_unchanged(self):
        headers = {"X-Custom": "val"}
        result = inject_api_key("", "/", headers, {})
        assert result == {"X-Custom": "val"}

    def test_none_key_value_not_injected(self):
        # If vault has key mapped to None, should not inject
        vault = {"OPENAI_API_KEY": None}
        result = inject_api_key("api.openai.com", "/", {}, vault)
        # None is falsy so no injection should happen
        assert "Authorization" not in result

    def test_empty_string_key_value_not_injected(self):
        vault = {"OPENAI_API_KEY": ""}
        result = inject_api_key("api.openai.com", "/", {}, vault)
        # Empty string is falsy so no injection should happen
        assert "Authorization" not in result
