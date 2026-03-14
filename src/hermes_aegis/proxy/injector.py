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


def is_llm_provider_request(host: str, path: str) -> bool:
    return host in LLM_PROVIDERS


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
