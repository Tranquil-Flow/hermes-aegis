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
}


# Git hosts that receive credential injection. Each entry causes the plaintext
# token to be sent as HTTP Basic auth, so additions must be carefully reviewed.
GIT_HOSTS = {
    "github.com": "GITHUB_TOKEN",
}


def is_llm_provider_request(host: str, path: str) -> bool:
    return host in LLM_PROVIDERS


def is_git_host_request(host: str) -> bool:
    return host in GIT_HOSTS


def inject_api_key(
    host: str,
    path: str,
    headers: dict,
    vault_values: dict[str, str],
) -> dict:
    """Inject API key into request headers if this is an LLM provider call."""

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
    """Inject git credentials as HTTP Basic auth for known git hosts."""
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
