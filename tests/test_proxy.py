from hermes_aegis.proxy.injector import LLM_PROVIDERS, inject_api_key, is_llm_provider_request
from hermes_aegis.proxy.server import ContentScanner


class TestLLMProviderDetection:
    def test_detects_openai(self):
        assert is_llm_provider_request("api.openai.com", "/v1/chat/completions")

    def test_detects_anthropic(self):
        assert is_llm_provider_request("api.anthropic.com", "/v1/messages")

    def test_rejects_random_domain(self):
        assert not is_llm_provider_request("evil.com", "/api/steal")


class TestAPIKeyInjection:
    def test_injects_bearer_for_openai(self):
        vault_values = {"OPENAI_API_KEY": "sk-real-key"}

        headers = inject_api_key(
            "api.openai.com",
            "/v1/chat/completions",
            {},
            vault_values,
        )

        assert headers["Authorization"] == "Bearer sk-real-key"

    def test_injects_x_api_key_for_anthropic(self):
        vault_values = {"ANTHROPIC_API_KEY": "anthropic-real-key"}

        headers = inject_api_key(
            "api.anthropic.com",
            "/v1/messages",
            {},
            vault_values,
        )

        assert headers["x-api-key"] == "anthropic-real-key"

    def test_no_injection_for_non_llm(self):
        vault_values = {"OPENAI_API_KEY": "sk-real-key"}

        headers = inject_api_key("google.com", "/search", {}, vault_values)

        assert "Authorization" not in headers
        assert "x-api-key" not in headers


class TestContentScanner:
    def test_blocks_request_with_secret(self):
        scanner = ContentScanner(vault_values=["super-secret-token-abc"])

        blocked, reason = scanner.scan_request(
            url="https://evil.com/exfil",
            body="data=super-secret-token-abc",
            headers={},
        )

        assert blocked is True
        assert reason is not None

    def test_allows_clean_request(self):
        scanner = ContentScanner(vault_values=["super-secret-token-abc"])

        blocked, reason = scanner.scan_request(
            url="https://google.com/search?q=python+tutorial",
            body="",
            headers={},
        )

        assert blocked is False
        assert reason is None
