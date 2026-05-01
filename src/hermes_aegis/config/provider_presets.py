"""Built-in mapping of provider names to the host(s) they reach.

Used by ``hermes-aegis allowlist add-provider <name>`` to bulk-add the
hosts a user needs when they enable a given LLM or tool provider, and
by ``hermes-aegis allowlist sync-from-hermes`` to bootstrap a fresh
aegis install from an existing hermes config.

Keep this list conservative — only include hosts that the provider's
official docs document, not third-party mirrors. Hostnames are exact
match against ``flow.request.host``; the allowlist matcher itself
already covers subdomains.
"""
from __future__ import annotations

import re

PROVIDER_PRESETS: dict[str, list[str]] = {
    # ---- LLM providers ----
    "openai":         ["api.openai.com"],
    "openai-codex":   ["api.openai.com", "chatgpt.com", "auth.openai.com"],
    "anthropic":      ["api.anthropic.com"],
    "google-gemini":  ["generativelanguage.googleapis.com"],
    "zai":            ["api.z.ai", "open.bigmodel.cn"],
    "deepseek":       ["api.deepseek.com"],
    "minimax":        ["api.minimax.chat", "api.minimaxi.com"],
    "openrouter":     ["openrouter.ai"],
    "mistral":        ["api.mistral.ai"],
    "groq":           ["api.groq.com"],
    "together":       ["api.together.xyz"],
    "fireworks":      ["api.fireworks.ai"],
    "perplexity":     ["api.perplexity.ai"],
    "huggingface":    ["huggingface.co", "api-inference.huggingface.co"],

    # ---- Tool providers ----
    "tavily":         ["api.tavily.com"],
    "firecrawl":      ["api.firecrawl.dev"],
    "firecrawl-nous": ["firecrawl-gateway.nousresearch.com"],
    "exa":            ["api.exa.ai"],
    "parallel":       ["api.parallel.ai"],
    "brave-search":   ["api.search.brave.com"],

    # ---- Nous Research stack ----
    "nous-portal":    ["portal.nousresearch.com",
                       "inference-api.nousresearch.com"],

    # ---- Catalogues / metadata ----
    "models-dev":     ["models.dev"],
}

# Conservative hostname check: lowercase, dot-separated labels of
# alphanumerics + hyphen, each label 1–63 chars, no scheme/path/port.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$"
)

# IPv4 literal — explicitly rejected so the allowlist doesn't end up with
# raw IPs (LAN/Tailscale endpoints in particular).
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def is_valid_hostname(host: str) -> bool:
    """Return True iff *host* looks like a bare DNS hostname.

    Rejects IPv4 literals, schemes, paths, ports, and uppercase. The
    public TLD requirement (at least one dot) means single-label names
    like ``localhost`` are rejected too — those should never be added
    to the allowlist.
    """
    if _IPV4_RE.match(host):
        return False
    return bool(_HOSTNAME_RE.match(host))


def list_providers() -> list[str]:
    """Return all preset names, sorted."""
    return sorted(PROVIDER_PRESETS.keys())


def get_provider_hosts(name: str) -> list[str] | None:
    """Return the hosts mapped to *name*, or None if unknown."""
    return PROVIDER_PRESETS.get(name)


def suggest_provider(name: str, *, max_suggestions: int = 3) -> list[str]:
    """Return up to *max_suggestions* preset names closest to *name*.

    Used to give a 'did you mean' hint when the user mistypes a preset.
    Pure stdlib — uses difflib so no extra dependency.
    """
    import difflib
    return difflib.get_close_matches(
        name, list_providers(), n=max_suggestions, cutoff=0.5,
    )


# Sentinel sources for sync_candidates entries.
SYNC_SOURCE_PRESET = "preset"
SYNC_SOURCE_API_URL = "api_url"


def compute_sync_candidates(
    providers_block: dict | None,
) -> dict[str, tuple[str, str]]:
    """Walk a hermes ``providers:`` mapping and return candidate hosts.

    Returns a dict of ``host -> (source_kind, provider_name)``. Source
    kinds are :data:`SYNC_SOURCE_PRESET` (added because the provider
    key matches a known preset name) or :data:`SYNC_SOURCE_API_URL`
    (extracted from the provider's ``api:`` / ``base_url:`` field).

    Public DNS hostnames only — IPv4 literals (LAN/Tailscale endpoints)
    and ``localhost`` are dropped. The first source seen for a given
    host wins, so preset matches take precedence over api: extraction
    when both produce the same host.
    """
    from urllib.parse import urlparse

    candidates: dict[str, tuple[str, str]] = {}
    if not isinstance(providers_block, dict) or not providers_block:
        return candidates

    for provider_name, conf in providers_block.items():
        # Preset-name match — exact, lowercase.
        preset_hosts = get_provider_hosts(provider_name)
        if preset_hosts:
            for h in preset_hosts:
                candidates.setdefault(h, (SYNC_SOURCE_PRESET, provider_name))

        # api: URL hostname — only public DNS names.
        if isinstance(conf, dict):
            api = conf.get("api") or conf.get("base_url")
            if isinstance(api, str):
                try:
                    parsed = urlparse(api if "://" in api else f"https://{api}")
                except Exception:
                    parsed = None
                if parsed and parsed.hostname:
                    host = parsed.hostname.lower()
                    if is_valid_hostname(host) and host != "localhost":
                        candidates.setdefault(
                            host, (SYNC_SOURCE_API_URL, provider_name),
                        )

    return candidates
