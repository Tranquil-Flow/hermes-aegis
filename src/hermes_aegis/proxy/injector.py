from __future__ import annotations

LLM_PROVIDERS = {
    "api.openai.com": {
        "key_env": "OPENAI_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
    "api.anthropic.com": {
        "key_env": "ANTHROPIC_API_KEY",
        "header": "x-api-key",
        "prefix": "",
    },
    "generativelanguage.googleapis.com": {
        "key_env": "GOOGLE_API_KEY",
        "header": "x-goog-api-key",
        "prefix": "",
    },
    "api.groq.com": {
        "key_env": "GROQ_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
    "api.together.xyz": {
        "key_env": "TOGETHER_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
    "openrouter.ai": {
        "key_env": "OPENROUTER_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
    # Codex endpoint — hermes-agent uses chatgpt.com/backend-api/codex for
    # the OpenAI Codex fallback model. Auth is via Codex OAuth tokens, not
    # a vault-managed key, so no injection is needed — just skip scanning.
    "chatgpt.com": {
        "key_env": "",
        "header": "",
        "prefix": "",
    },
    # Vercel AI Gateway — added in Hermes v0.3.0 (#1628). Routes to multiple
    # model providers. Uses Vercel API token as Bearer auth.
    "ai.vercel.com": {
        "key_env": "VERCEL_API_TOKEN",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
}


# Git hosts that receive credential injection. Each entry causes the plaintext
# token to be sent as HTTP Basic auth, so additions must be carefully reviewed.
GIT_HOSTS = {
    "github.com": "GITHUB_TOKEN",
}


def is_llm_provider_request(host: str, path: str) -> bool:
    """Check if a request is to a known LLM provider host.

    Determines whether an outbound HTTP request is destined for a configured
    LLM API provider (e.g., OpenAI, Anthropic, Google, Groq, Together, OpenRouter).
    Used to identify requests that require API key injection.

    Args:
        host: The HTTP request host header (e.g., 'api.openai.com').
        path: The HTTP request path (not currently used, reserved for future routing).

    Returns:
        True if the host is in the configured LLM_PROVIDERS mapping, False otherwise.
    """
    return host in LLM_PROVIDERS


def is_git_host_request(host: str) -> bool:
    """Check if a request is to a known Git hosting service.

    Determines whether an outbound HTTP request is destined for a Git service
    (currently GitHub) that requires credential injection via HTTP Basic auth.

    Args:
        host: The HTTP request host header (e.g., 'github.com').

    Returns:
        True if the host is in the configured GIT_HOSTS mapping, False otherwise.
    """
    return host in GIT_HOSTS


def inject_api_key(
    host: str,
    path: str,
    headers: dict,
    vault_values: dict[str, str],
) -> dict:
    """Inject API key into request headers for LLM provider requests.

    If the target host is a configured LLM provider (OpenAI, Anthropic, etc.),
    retrieves the corresponding API key from the vault and injects it into the
    request using the provider-specific header name and prefix format. This allows
    the agent to make authenticated LLM API calls without exposing secrets to
    memory.

    Args:
        host: The target HTTP host (e.g., 'api.openai.com').
        path: The HTTP request path (not currently used).
        headers: The incoming request headers dict. Not modified in-place.
        vault_values: A dict mapping environment variable names to secret values
            (e.g., {'OPENAI_API_KEY': 'sk-...'}).

    Returns:
        A new headers dict with the API key injected if applicable, or a copy of
        the input headers if the host is not a known provider or no key is found.
    """

    updated_headers = dict(headers)
    provider = LLM_PROVIDERS.get(host)
    if provider is None:
        return updated_headers

    key_value = vault_values.get(provider["key_env"])
    if key_value:
        updated_headers[provider["header"]] = provider["prefix"] + key_value

    return updated_headers


def inject_git_credentials(
    host: str,
    headers: dict,
    vault_values: dict[str, str],
) -> dict:
    """Inject git credentials as HTTP Basic auth for known git hosts.

    For requests to known Git hosting services (currently GitHub), retrieves the
    git credential token from the vault and injects it as HTTP Basic auth using
    the 'x-access-token:<token>' format. This allows the agent to make authenticated
    Git API calls (e.g., for repository operations) without exposing the token to
    memory.

    Args:
        host: The target HTTP host (e.g., 'github.com').
        headers: The incoming request headers dict. Not modified in-place.
        vault_values: A dict mapping environment variable names to secret values
            (e.g., {'GITHUB_TOKEN': 'ghp_...'}).

    Returns:
        A new headers dict with HTTP Basic Authorization injected if applicable,
        or a copy of the input headers if the host is not a known Git service or
        no credential is found.
    """
    import base64

    updated_headers = dict(headers)
    key_env = GIT_HOSTS.get(host)
    if key_env is None:
        return updated_headers

    token = vault_values.get(key_env)
    if token:
        credentials = base64.b64encode(
            f"x-access-token:{token}".encode()
        ).decode()
        updated_headers["Authorization"] = f"Basic {credentials}"

    return updated_headers
