import base64
from unittest.mock import MagicMock

from hermes_aegis.proxy.addon import AegisAddon
from hermes_aegis.proxy.injector import (
    LLM_PROVIDERS,
    inject_api_key,
    inject_git_credentials,
    is_git_host_request,
    is_llm_provider_request,
)
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


class TestGitHostDetection:
    def test_detects_github(self):
        assert is_git_host_request("github.com")

    def test_rejects_random_domain(self):
        assert not is_git_host_request("evil.com")

    def test_rejects_subdomain_of_github(self):
        assert not is_git_host_request("api.github.com")

    def test_rejects_github_lookalike(self):
        assert not is_git_host_request("github.com.evil.com")

    def test_rejects_github_with_port(self):
        # Exact match only — port suffix is a different string
        assert not is_git_host_request("github.com:443")


class TestGitCredentialInjection:
    def test_injects_basic_auth_for_github(self):
        vault = {"GITHUB_TOKEN": "ghp_testtoken1234567890"}
        headers = inject_git_credentials("github.com", {}, vault)

        expected = base64.b64encode(b"x-access-token:ghp_testtoken1234567890").decode()
        assert headers["Authorization"] == f"Basic {expected}"

    def test_no_injection_without_token(self):
        headers = inject_git_credentials("github.com", {}, {})
        assert "Authorization" not in headers

    def test_no_injection_for_non_git_host(self):
        vault = {"GITHUB_TOKEN": "ghp_testtoken1234567890"}
        headers = inject_git_credentials("evil.com", {}, vault)
        assert "Authorization" not in headers

    def test_preserves_existing_headers(self):
        vault = {"GITHUB_TOKEN": "ghp_testtoken1234567890"}
        headers = inject_git_credentials(
            "github.com", {"Accept": "application/json"}, vault
        )
        assert headers["Accept"] == "application/json"
        assert "Authorization" in headers

    def test_does_not_mutate_input_headers(self):
        vault = {"GITHUB_TOKEN": "ghp_testtoken1234567890"}
        original = {"Accept": "text/html"}
        inject_git_credentials("github.com", original, vault)
        assert "Authorization" not in original


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


class _FakeFlow:
    """Minimal mitmproxy HTTPFlow stand-in for addon tests."""
    def __init__(self, host: str, path: str = "/", body: bytes = b"", headers: dict | None = None):
        self.request = MagicMock()
        self.request.host = host
        self.request.path = path
        self.request.url = f"https://{host}{path}"
        self.request.get_content.return_value = body
        self.request.headers = dict(headers or {})
        self.killed = False

    def kill(self) -> None:
        self.killed = True


class TestOwnServicePassthrough:
    """API key sent to its own service should NOT be blocked."""

    def _make_addon(self, vault_secrets: dict) -> AegisAddon:
        return AegisAddon(
            vault_secrets=vault_secrets,
            vault_values=list(vault_secrets.values()),
        )

    def test_browserbase_key_allowed_to_browserbase(self):
        """BROWSERBASE_API_KEY sent to api.browserbase.com is legitimate auth, not exfiltration."""
        key = "bb_live_testtoken1234567890abcdef"
        addon = self._make_addon({"BROWSERBASE_API_KEY": key})
        flow = _FakeFlow(
            "api.browserbase.com",
            "/v1/sessions",
            body=b'{"projectId": "proj_abc"}',
            headers={"Authorization": f"Bearer {key}"},
        )
        addon.request(flow)
        assert not flow.killed

    def test_browserbase_key_blocked_when_sent_to_evil_host(self):
        """BROWSERBASE_API_KEY sent to a non-browserbase host IS exfiltration."""
        key = "bb_live_testtoken1234567890abcdef"
        addon = self._make_addon({"BROWSERBASE_API_KEY": key})
        flow = _FakeFlow(
            "evil.com",
            "/steal",
            body=key.encode(),
        )
        addon.request(flow)
        assert flow.killed

    def test_generic_service_key_allowed_to_own_service(self):
        """TAVILY_API_KEY sent to api.tavily.com is allowed."""
        key = "tvly-testtoken1234567890abcdef"
        addon = self._make_addon({"TAVILY_API_KEY": key})
        flow = _FakeFlow(
            "api.tavily.com",
            "/v1/search",
            headers={"Authorization": f"Bearer {key}"},
        )
        addon.request(flow)
        assert not flow.killed

    def test_non_api_key_vault_entry_still_scanned(self):
        """Vault entries without _API_KEY suffix are not exempt and still get scanned."""
        key = "mysecretvalue123"
        addon = self._make_addon({"SOME_RANDOM_SECRET": key})
        flow = _FakeFlow(
            "evil.com",
            "/steal",
            body=key.encode(),
        )
        addon.request(flow)
        assert flow.killed
