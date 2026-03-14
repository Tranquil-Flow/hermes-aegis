# Hermes-Aegis

**Security hardening layer for Hermes Agent** — Prevents secret leakage, dangerous command execution, and unauthorized data exfiltration through proxy-based monitoring.

[![Tests](https://img.shields.io/badge/tests-338%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## What It Does

Hermes-Aegis wraps Hermes Agent with a transparent MITM proxy that:

- **Blocks secret exfiltration** — scans all outbound HTTP for API keys, tokens, credentials
- **Injects API keys** — secrets stay in your encrypted vault, never in agent memory
- **Detects dangerous commands** — 40+ risky patterns (shell injection, destructive ops, privesc)
- **Rate-limits bursts** — detects suspicious data tunneling patterns
- **Restricts domains** — optional allowlist for outbound connections
- **Audit trail** — tamper-proof hash-chained log of all security events

---

## Prerequisites

- **Python 3.11+**
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

# 3. Install Hermes hook (also configures Docker support)
hermes-aegis install

# 4. Verify it works
hermes-aegis test

# 5. Run Hermes with aegis protection
hermes-aegis run
```

> **Note:** `hermes-aegis setup` automatically migrates API keys from `~/.hermes/.env` into the encrypted vault. If you don't have a `.env` file (or want to add more keys later), use `hermes-aegis vault set KEY_NAME`. Security scanning works without any vault keys — only API key injection requires them.

### Auto-Injected API Keys (Optional)

If your vault has any of these keys, the proxy automatically injects them into LLM provider requests — they never touch Hermes's memory or `~/.hermes/.env`:

| Key | Provider |
|-----|----------|
| `OPENAI_API_KEY` | OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic |
| `GOOGLE_API_KEY` | Google AI |
| `GROQ_API_KEY` | Groq |
| `TOGETHER_API_KEY` | Together AI |
| `OPENROUTER_API_KEY` | OpenRouter |

Add any key with `hermes-aegis vault set KEY_NAME` — you'll be prompted for the value.

> **How Hermes sees your keys:** When you run `hermes-aegis run`, placeholder values (`aegis-managed`) are set as environment variables so Hermes passes its startup check. The proxy then injects real keys at the HTTP level. Your `~/.hermes/.env` file is never modified.

### How It Works

1. `hermes-aegis run` starts the mitmproxy-based security proxy (if not already running)
2. Sets `HTTP_PROXY`/`HTTPS_PROXY` env vars so all traffic routes through the proxy
3. Sets placeholder API keys (`aegis-managed`) that satisfy Hermes's startup check
4. Runs `hermes` as a child process — all subprocess calls inherit the proxy env vars
5. Proxy scans for secrets, blocks exfiltration, injects real API keys from the vault
6. **The proxy keeps running after Hermes exits** — it's shared infrastructure. Multiple
   sessions share one proxy. Stop it explicitly with `hermes-aegis stop`.

No monkey-patching. No shell modifications. No file modifications. Just a proxy.

---

## CLI Reference

```bash
# Lifecycle
hermes-aegis run                 # Run Hermes with aegis protection
hermes-aegis run -- gateway      # Run Hermes gateway with protection
hermes-aegis install             # Install Hermes hook + generate CA cert
hermes-aegis uninstall           # Remove Hermes hook
hermes-aegis start               # Start proxy manually
hermes-aegis stop                # Stop proxy
hermes-aegis status              # Show proxy, hook, vault, Docker status
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
# Settings: dangerous_commands (audit|block), rate_limit_requests, rate_limit_window

# Domain Allowlist
hermes-aegis allowlist list      # Show allowed domains
hermes-aegis allowlist add DOM   # Add domain
hermes-aegis allowlist remove DOM # Remove domain

# Audit Trail
hermes-aegis audit show          # Recent events (last 20)
hermes-aegis audit show --all    # All events
hermes-aegis audit verify        # Check integrity
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
├── proxy.pid                 # Running proxy PID + port
└── proxy-config.json         # Proxy startup config (secrets deleted after read)
```

---

## Development

```bash
uv run pytest tests/ -q          # Run all tests (314 passing)
uv run pytest tests/security/ -v # Security tests only
```

### Project Structure

```
src/hermes_aegis/
├── cli.py                 # CLI commands
├── hook.py                # Hermes hook installer + old setup migration
├── utils.py               # Shared utilities (port finding, docker check, etc.)
├── proxy/
│   ├── addon.py           # AegisAddon (inject keys, scan, rate limit)
│   ├── entry.py           # mitmproxy entry script
│   ├── runner.py          # Proxy lifecycle (start/stop/is_running)
│   ├── server.py          # ContentScanner
│   └── injector.py        # API key injection logic
├── patterns/              # Detection patterns
│   ├── secrets.py         # API key / credential patterns
│   ├── dangerous.py       # Dangerous command patterns
│   └── crypto.py          # Crypto wallet patterns
├── middleware/             # Security middleware chain
├── vault/                 # Encrypted secret storage
├── config/                # Settings + domain allowlist
├── audit/                 # Hash-chained audit trail
└── container/             # Docker builder/runner (optional)
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

**Want to verify it works?**
- Run `hermes-aegis test-canary` to send a canary secret through the proxy and confirm it gets blocked.

---

## License

MIT License — See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Tranquil-Flow

## Credits

**Author:** Tranquil-Flow (tranquil_flow@protonmail.com)  
Built with Test-Driven Development by Hermes Agent  
Inspired by the Moonsong vision of liberation through privacy
