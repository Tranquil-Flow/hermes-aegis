from __future__ import annotations

# Claude Code identity headers required for OAuth token auth with Anthropic.
# Without these, Anthropic rejects Bearer tokens with "OAuth not supported".
# The version should stay reasonably current — Anthropic may reject old versions.
_CLAUDE_CODE_VERSION = "2.1.74"
_OAUTH_BETAS = ["claude-code-20250219", "oauth-2025-04-20"]
_COMMON_BETAS = [
    "interleaved-thinking-2025-05-14",
    "fine-grained-tool-streaming-2025-05-14",
]

LLM_PROVIDERS = {
    "api.openai.com": {
        "key_env": "OPENAI_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
    "api.anthropic.com": {
        "key_env": "ANTHROPIC_API_KEY",
        "key_env_aliases": ["ANTHROPIC_TOKEN"],
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
    "api.minimax.io": {
        "key_env": "MINIMAX_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
    "api.minimaxi.com": {
        "key_env": "MINIMAX_CN_API_KEY",
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
    # Nous Research portal — OAuth token refresh for mimo-v2-pro. The OAuth flow
    # sends bearer tokens in the request body; skip content scanning so it isn't
    # incorrectly blocked as secret exfiltration. No key injection needed.
    "portal.nousresearch.com": {
        "key_env": "",
        "header": "",
        "prefix": "",
    },
    # Z.AI / GLM — fallback LLM provider. Auth via ZAI_API_KEY from vault.
    "api.z.ai": {
        "key_env": "ZAI_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
    # Z.AI / BigModel — Z.AI's primary endpoint for the GLM models. Same
    # ZAI_API_KEY as api.z.ai. Without this entry the host falls through
    # to body scanning, which sees the bearer token in the outgoing
    # request and blocks every call as cross-provider exfiltration.
    "open.bigmodel.cn": {
        "key_env": "ZAI_API_KEY",
        "header": "Authorization",
        "prefix": "Bearer ",
    },
}


# Git/GitHub API hosts that receive credential injection. Each entry causes the
# plaintext token to be sent as HTTP Basic auth, so additions must be carefully
# reviewed. Keep exact host matches only — no suffix or wildcard matching.
GIT_HOSTS = {
    # HTTPS git remotes: https://github.com/owner/repo.git
    "github.com": "GITHUB_TOKEN",
    # REST/GraphQL API calls: https://api.github.com/...
    "api.github.com": "GITHUB_TOKEN",
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
    """Check if a request is to a known Git hosting/API service.

    Determines whether an outbound HTTP request is destined for a Git service
    or GitHub API host that requires credential injection via HTTP Basic auth.

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
    if not key_value:
        for alias in provider.get("key_env_aliases", []):
            key_value = vault_values.get(alias)
            if key_value:
                break
    if key_value:
        # For Anthropic: only inject when the credential is recognizably
        # Anthropic-shaped. Other token shapes (e.g. sk-nous-* legacy bridge
        # values) would be wrongly Bearer-injected and cause 401s. When we
        # don't recognize the shape, pass through unchanged so hermes-agent's
        # own auth headers reach Anthropic untouched.
        if host == "api.anthropic.com":
            if not (
                key_value.startswith("sk-ant-api")
                or key_value.startswith("sk-ant-oat01-")
            ):
                return updated_headers
        if host == "api.anthropic.com" and not key_value.startswith("sk-ant-api"):
            # OAuth token — needs Bearer auth + Claude Code identity headers.
            # Without user-agent/x-app/beta headers, Anthropic rejects with
            # "OAuth authentication is currently not supported."
            updated_headers["Authorization"] = "Bearer " + key_value
            # Remove any placeholder x-api-key so Anthropic doesn't check it
            # (container code sends api_key="placeholder" → x-api-key header)
            for k in list(updated_headers):
                if k.lower() == "x-api-key":
                    del updated_headers[k]
            # Inject Claude Code identity headers for OAuth routing
            all_betas = _COMMON_BETAS + _OAUTH_BETAS
            existing_betas = updated_headers.get("anthropic-beta", "")
            if existing_betas:
                # Merge: keep existing betas, add missing OAuth ones
                existing_set = set(b.strip() for b in existing_betas.split(","))
                for beta in all_betas:
                    existing_set.add(beta)
                updated_headers["anthropic-beta"] = ",".join(sorted(existing_set))
            else:
                updated_headers["anthropic-beta"] = ",".join(all_betas)
            # Force-set user-agent. Must remove any existing casing variant
            # first — Python dicts are case-sensitive so "User-Agent" and
            # "user-agent" coexist, but Anthropic reads the wrong one.
            for k in list(updated_headers):
                if k.lower() == "user-agent":
                    del updated_headers[k]
            updated_headers["user-agent"] = f"claude-cli/{_CLAUDE_CODE_VERSION} (external, cli)"
            updated_headers["x-app"] = "cli"
        else:
            updated_headers[provider["header"]] = provider["prefix"] + key_value

    return updated_headers


def inject_git_credentials(
    host: str,
    headers: dict,
    vault_values: dict[str, str],
) -> dict:
    """Inject git/API credentials as HTTP Basic auth for known Git hosts.

    For requests to known Git hosting/API services (currently GitHub), retrieves
    the git credential token from the vault and injects it as HTTP Basic auth
    using the 'x-access-token:<token>' format. This allows the agent to make
    authenticated Git HTTPS and GitHub REST/GraphQL API calls without exposing
    the token to the Hermes process environment.

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
