# Hermes-Aegis

**Security hardening layer for Hermes Agent** — Prevents secret leakage, dangerous command execution, and unauthorized data exfiltration through proxy-based monitoring.

[![Tests](https://img.shields.io/badge/tests-627%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## What It Does

Hermes-Aegis wraps Hermes Agent with a transparent MITM proxy that:

- **Blocks secret exfiltration** — scans all outbound HTTP for API keys, tokens, credentials
- **Injects API keys** — secrets stay in your encrypted vault, never in agent memory
- **Detects dangerous commands** — 27 risky patterns (shell injection, destructive ops, privesc)
- **Blocks dangerous commands in gateway mode** — Patch 5 enforces blocking when `AEGIS_ACTIVE=1`
- **Rate-limits bursts** — detects suspicious data tunneling patterns
- **Restricts domains** — optional allowlist for outbound connections
- **Audit trail** — tamper-proof hash-chained log of all security events

### What Hermes v0.2.0 Added Natively (and Why Aegis Still Matters)

Hermes Agent v0.2.0 added its own security features: `approval.py` (27 dangerous command
patterns with interactive prompting), `tirith_security.py` (content scanning for homograph
URLs, code injection), and `redact.py` (output masking for 40+ secret patterns).

**What Aegis uniquely provides that Hermes does not:**

| Feature | Hermes v0.2.0 | Aegis |
|---------|---------------|-------|
| Outbound HTTP secret blocking | No — redaction masks output only, doesn't block the request | **Yes** — MITM proxy blocks secrets in request bodies/headers/URLs |
| API key vault injection | No — keys in `.env` or env vars | **Yes** — keys never in process memory |
| Encrypted vault | No | **Yes** — keyring-backed AES encryption |
| Domain allowlisting | No | **Yes** — restrict outbound to approved domains |
| Rate anomaly detection | No | **Yes** — detects data tunneling bursts |
| Tamper-proof audit trail | No | **Yes** — SHA-256 hash chain |
| Gateway command blocking | Prompts user (can approve) | **Yes** — blocks outright via Patch 5 |
| Tirith content scanning (response bodies) | No | **Yes** — proxy-level homograph/injection/terminal scanning |
| Audit trail unification | No | **Yes** — hermes approval decisions forwarded to aegis audit |
| Approval backends (webhook, log_only) | No | **Yes** — pluggable strategies for gateway mode |
| Rate escalation (detection → blocking) | No | **Yes** — 4-level system with active blocking |
| Persistent approval cache | No | **Yes** — cross-session allow/deny with TTL + pattern matching |
| Container handshake protocol | No | **Yes** — ProtectionLevel detection + container awareness |

---

## Prerequisites

- **Python 3.10+**
- **Hermes Agent** installed at `~/.hermes/` (with `config.yaml`)
- **uv** package manager (recommended) or pip
- **Docker** (optional — for container isolation)

---

## Quick Start

```bash
# 1. Install hermes-aegis (global — available from any terminal)
uv tool install hermes-aegis
# Or from source:
uv tool install -e ~/Projects/hermes-aegis

# 2. Set up vault (one-time — auto-migrates keys from ~/.hermes/.env)
hermes-aegis setup

# 3. Install patches + Hermes hook + generate CA cert
hermes-aegis install

# 4. Verify it works
hermes-aegis test

# 5. Run Hermes with aegis protection
hermes-aegis run
```

> **Note:** `hermes-aegis setup` migrates API keys from `~/.hermes/.env` into the
> encrypted vault. If you don't have a `.env` file, use `hermes-aegis vault set KEY_NAME`.
> Security scanning works without any vault keys — only API key injection requires them.

> **Note:** Running standalone `hermes` (without `hermes-aegis run`) requires its own
> auth setup via `hermes setup`. Aegis vault keys are only available through the proxy.

### Auto-Injected API Keys (Optional)

If your vault has any of these keys, the proxy automatically injects them into LLM provider requests — they never touch Hermes's memory or `~/.hermes/.env`:

| Key | Provider | Injection Method |
|-----|----------|-----------------|
| `OPENAI_API_KEY` | OpenAI | Proxy replaces `Authorization` header |
| `ANTHROPIC_API_KEY` | Anthropic | Proxy replaces `x-api-key` header |
| `GOOGLE_API_KEY` | Google AI | Proxy replaces `x-goog-api-key` header |
| `GROQ_API_KEY` | Groq | Proxy replaces `Authorization` header |
| `TOGETHER_API_KEY` | Together AI | Proxy replaces `Authorization` header |
| `OPENROUTER_API_KEY` | OpenRouter | Proxy replaces `Authorization` header |
| `ANTHROPIC_TOKEN` | Anthropic OAuth | Injected directly into child env (Bearer auth) |

Add any key with `hermes-aegis vault set KEY_NAME` — you'll be prompted for the value.

> **ANTHROPIC_TOKEN** is special: OAuth setup-tokens use Bearer auth constructed before
> HTTP requests are made. The proxy cannot replace Bearer tokens at the header level,
> so `hermes-aegis run` injects the real value directly into the child process environment.

### How It Works

1. `hermes-aegis run` starts the mitmproxy-based security proxy (if not already running)
2. Sets `HTTP_PROXY`/`HTTPS_PROXY` env vars so all traffic routes through the proxy
3. Injects real `ANTHROPIC_TOKEN` from vault into child env (OAuth Bearer auth)
4. Runs `hermes` as a child process — all subprocess calls inherit the proxy env vars
5. Proxy scans for secrets, blocks exfiltration, injects real API keys from the vault
6. **The proxy keeps running after Hermes exits** — it's shared infrastructure. Multiple
   sessions share one proxy. Stop it explicitly with `hermes-aegis stop`.

### Patch System

`hermes-aegis install` applies 8 idempotent, reversible patches to hermes-agent source files:

| Patch | File | Purpose |
|-------|------|---------|
| 1–3 | `docker.py` | Add `forward_env` param, pass to `_Docker()`, translate localhost→`host.docker.internal` + remap cert paths |
| 4 | `terminal_tool.py` | Wire `_aegis_forward` env vars at DockerEnvironment instantiation |
| 5 | `terminal_tool.py` | Call `hermes-aegis scan-command` when `AEGIS_ACTIVE=1` for gateway blocking |
| 6 | `hermes (startup)` | Inject "🛡️ Aegis Protection Activated" into banner when `AEGIS_ACTIVE=1` |
| 7 | `terminal_tool.py` | Forward hermes approval decisions into aegis audit trail |
| 8 | `terminal_tool.py` | Inject container awareness (`AEGIS_CONTAINER_ISOLATED=1`) into approval flow |

Patches survive `hermes-aegis uninstall` (reverts cleanly) but are overwritten by
`hermes update` — re-run `hermes-aegis install` after each update.

---

## CLI Reference

```bash
# Lifecycle
hermes-aegis run                 # Run Hermes with aegis protection
hermes-aegis run -- gateway      # Run Hermes gateway with protection
hermes-aegis install             # Apply patches + install hook + generate CA cert
hermes-aegis uninstall           # Revert patches + remove hook
hermes-aegis start               # Start proxy manually
hermes-aegis stop                # Stop proxy
hermes-aegis status              # Show proxy, hook, vault, Docker, patch status
hermes-aegis test                # Verify proxy blocks secrets (canary test)

# Setup
hermes-aegis setup               # One-time vault init + optional Docker image build

# Vault (Encrypted Secrets)
hermes-aegis vault list          # List secret keys
hermes-aegis vault set KEY       # Store secret (prompted)
hermes-aegis vault remove KEY    # Delete secret

# Configuration
hermes-aegis config get [key]    # View settings
hermes-aegis config set KEY val  # Update setting
hermes-aegis config list         # List all settings with values
# Settings: dangerous_commands, rate_limit_requests, rate_limit_window,
#           approval_backend, approval_webhook_url, approval_webhook_timeout,
#           approval_webhook_secret, tirith_mode

# Domain Allowlist
hermes-aegis allowlist list      # Show allowed domains
hermes-aegis allowlist add DOM   # Add domain
hermes-aegis allowlist remove DOM # Remove domain

# Security
hermes-aegis scan-command CMD    # Check command against dangerous patterns (exit 0=safe, 1=blocked)

# Audit Trail
hermes-aegis audit show          # Recent events (last 20)
hermes-aegis audit show --all    # All events
hermes-aegis audit show --decision blocked  # Filter by decision type
hermes-aegis audit clear         # Archive and wipe audit trail
hermes-aegis audit verify        # Check integrity
hermes-aegis audit event         # Inject external event into audit trail

# Approval Cache
hermes-aegis approvals list      # Show cached approval decisions
hermes-aegis approvals add PAT   # Add allow/deny pattern (glob/substring)
hermes-aegis approvals remove PAT # Remove cached pattern
hermes-aegis approvals clear     # Clear all cached decisions
```

---

## Configuration Files

All stored in `~/.hermes-aegis/`:

```
~/.hermes-aegis/
├── vault.enc                 # Encrypted secrets (Fernet AES)
├── config.json               # Security settings
├── domain-allowlist.json     # Allowed domains
├── audit.jsonl               # Tamper-proof event log
├── approval-cache.json      # Persistent approval decisions (TTL + patterns)
├── proxy.pid                 # Running proxy PID + port
└── proxy-config.json         # Proxy startup config (secrets deleted after read)
```

---

## Development

```bash
uv run pytest tests/ -q          # Run all tests (627 passing)
uv run pytest tests/security/ -v # Security tests only
```

### Project Structure

```
src/hermes_aegis/
├── cli.py                 # CLI commands (including scan-command)
├── hook.py                # Hermes hook installer + old setup migration
├── patches.py             # 8 idempotent patches for hermes-agent source
├── utils.py               # Shared utilities (port finding, docker check, etc.)
├── proxy/
│   ├── addon.py           # AegisAddon (inject keys, scan, rate limit)
│   ├── entry.py           # mitmproxy entry script
│   ├── runner.py          # Proxy lifecycle (start/stop/is_running)
│   ├── server.py          # ContentScanner
│   └── injector.py        # API key injection logic
├── patterns/              # Detection patterns
│   ├── secrets.py         # API key / credential patterns
│   ├── dangerous.py       # 27 dangerous command patterns
│   ├── crypto.py          # Crypto wallet patterns
│   └── shared_registry.py # Merges hermes-agent redact.py patterns at runtime
├── middleware/             # Security middleware chain
│   ├── chain.py           # Middleware pipeline
│   ├── dangerous_blocker.py # Dangerous command blocking middleware
│   ├── rate_escalation.py # Rate limit escalation (4-level system)
│   └── tirith_scanner.py  # LLM response content scanning
├── approval/              # Approval backends + persistent cache
│   ├── backends.py        # Pluggable approval strategies (block, log_only, webhook)
│   └── cache.py           # Persistent approval decision cache
├── vault/                 # Encrypted secret storage
├── config/                # Settings + domain allowlist
├── audit/                 # Hash-chained audit trail
└── container/             # Docker builder/runner/handshake
    ├── builder.py         # Docker image builder
    └── handshake.py       # Container-Aegis handshake protocol
```

---

## For Hermes Agents

If you are a Hermes agent running under aegis protection, read [`docs/FOR_HERMES_AGENT.md`](docs/FOR_HERMES_AGENT.md) — it explains what aegis does to your environment, how to handle `aegis-managed` API keys, what blocked requests look like, and the diagnostic checklist.

---

## Troubleshooting

**"Hermes Agent not found"** when running `hermes-aegis install`
- Hermes must be installed at `~/.hermes/` with a `config.yaml`. Install Hermes first.

**"CA certificate not found"** or HTTPS errors
- Run `hermes-aegis install` again — it generates the mitmproxy CA cert automatically.
- If mitmproxy isn't installed: `uv pip install 'mitmproxy>=10.0'`

**Proxy not starting**
- Check status: `hermes-aegis status`
- Check if port is in use: `hermes-aegis start` will auto-find an available port (8443-8500)
- Check audit log: `hermes-aegis audit show`

**API calls failing through proxy**
- Verify vault has the right keys: `hermes-aegis vault list`
- Ensure CA cert env vars are set (the hook does this automatically)

**Docker patches missing after `hermes update`**
- Run `hermes-aegis install` to re-apply patches. The startup banner warns about this.

**Tirith/cosign errors**
- Aegis adds `--ignore-hosts` for sigstore/TUF domains so cosign can verify Tirith
  provenance. If you still see cert errors, check `~/.hermes-aegis/proxy.log`.

**Want to verify it works?**
- Run `hermes-aegis test` to send a canary secret through the proxy and confirm it gets blocked.

---

## License

MIT License — See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Tranquil-Flow

## Credits

**Author:** Tranquil-Flow (tranquil_flow@protonmail.com)
Built with Test-Driven Development by Hermes Agent
Inspired by the Moonsong vision of liberation through privacy
