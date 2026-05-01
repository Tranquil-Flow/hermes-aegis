# Domain allowlist

Hermes-aegis filters outbound network requests against a per-user
allowlist stored at `~/.hermes-aegis/domain-allowlist.json`. When the
allowlist is empty (the install default), every host is permitted; once
you add a single entry, only listed hosts (and their subdomains) are
allowed through the proxy.

Aegis additionally **softens** the generic high-entropy secret detector
on allowlisted hosts. Tool providers like Tavily, Firecrawl, and Exa
embed a high-entropy API key in request bodies — without this gating,
the entropy detector self-blocks every legitimate call. Targeted
detectors (vault-value matches, known-pattern detectors like
`azure_sas_token`, etc.) keep firing on every request, so cross-provider
exfiltration is still caught.

## Adding a single host

```bash
hermes-aegis allowlist add api.example.com
hermes-aegis allowlist remove api.example.com
hermes-aegis allowlist list
```

## Adding a provider preset

Many LLM and tool providers reach more than one host. Aegis ships with
named presets — see them with:

```bash
hermes-aegis allowlist providers
```

Add every host for a preset in one command:

```bash
hermes-aegis allowlist add-provider zai
hermes-aegis allowlist add-provider tavily --dry-run
```

The command is idempotent — re-running it on an already-added preset is
a no-op.

A typo prints a "did you mean" hint:

```text
$ hermes-aegis allowlist add-provider opnai
Unknown provider preset: 'opnai'.
  Did you mean: openai, openai-codex, zai?
  See: hermes-aegis allowlist providers
```

## Bootstrapping from your hermes config

```bash
hermes-aegis allowlist sync-from-hermes [--dry-run] [--yes]
```

Walks `~/.hermes/config.yaml`, looks at the `providers:` block, and adds:

1. **Hosts from any matching preset.** If a provider key (e.g. `zai`)
   matches a preset name, every host in that preset is added.
2. **The hostname from the provider's `api:` URL.** Public DNS names
   only — IPv4 literals (LAN/Tailscale) and `localhost` are skipped.

Use `--dry-run` to preview, `--yes` to skip the confirmation prompt for
non-interactive runs.

## Provider presets reference

The full preset map lives in
[`src/hermes_aegis/config/provider_presets.py`](../src/hermes_aegis/config/provider_presets.py).
Run `hermes-aegis allowlist providers` to print the current list with
hostnames — that is always in sync with the code.

Categories covered:

- **LLM providers** — openai, openai-codex, anthropic, google-gemini,
  zai, deepseek, minimax, openrouter, mistral, groq, together,
  fireworks, perplexity, huggingface
- **Tool providers** — tavily, firecrawl, firecrawl-nous, exa, parallel,
  brave-search
- **Nous Research stack** — nous-portal
- **Catalogues / metadata** — models-dev

## How the matcher works

`is_allowed(host)` checks for an exact match first, then for suffix
matches against any allowlisted domain (so `foo.api.example.com` is
allowed when `api.example.com` is in the list). Port suffixes are
stripped. Comparisons are case-insensitive.

Empty allowlist == allow-all. This is the install default; it lets new
users get up and running without seeing blocked-domain errors. Adding
the first entry switches the proxy into deny-by-default mode.
