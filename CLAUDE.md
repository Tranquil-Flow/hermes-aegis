# Hermes-Aegis

Security hardening layer for Hermes Agent. Stops secret exfiltration via MITM proxy.

## Stack
- Python 3.10+, managed with `uv`
- mitmproxy (required — proxy-based scanning)
- Docker (optional — container isolation)
- Fernet encryption (vault)

## Commands
```bash
uv run pytest tests/ -q              # Run all tests (353 passing)
uv run pytest tests/security/ -v     # Security tests only
uv run hermes-aegis run              # Run Hermes with aegis protection
uv run hermes-aegis setup            # One-time vault setup
uv run hermes-aegis install          # Apply patches + install hook
uv run hermes-aegis uninstall        # Revert patches + remove hook
uv run hermes-aegis start            # Start proxy manually
uv run hermes-aegis stop             # Stop proxy
uv run hermes-aegis status           # Check system status
uv run hermes-aegis test             # Canary test — verify proxy blocks secrets
uv run hermes-aegis scan-command CMD # Check command against dangerous patterns
```

## Architecture
- **`hermes-aegis run`** starts proxy, wraps `hermes` with proxy env vars + real ANTHROPIC_TOKEN from vault
- **`hermes-aegis install`** applies 5 idempotent patches to hermes-agent source (Docker proxy forwarding + gateway command scanning)
- **Hermes hook** at `~/.hermes/hooks/aegis-security/` available for gateway mode (optional)
- **MITM proxy** scans all outbound HTTP, blocks secret exfiltration, injects API keys for LLM providers
- **Patch system** (`patches.py`) modifies hermes-agent source files — re-run `install` after `hermes update`
- **No monkey-patching** — proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`) inherited by subprocesses
- **Decoupled** — hook shells out to `hermes-aegis start`, no Python imports from hermes-aegis

## Key Paths
| Component | Path |
|-----------|------|
| CLI | `src/hermes_aegis/cli.py` |
| Patch system | `src/hermes_aegis/patches.py` |
| Hook manager | `src/hermes_aegis/hook.py` |
| Utilities | `src/hermes_aegis/utils.py` |
| MITM proxy addon | `src/hermes_aegis/proxy/addon.py` |
| Proxy entry script | `src/hermes_aegis/proxy/entry.py` |
| Proxy lifecycle | `src/hermes_aegis/proxy/runner.py` |
| Secret scanner | `src/hermes_aegis/patterns/secrets.py` |
| Crypto patterns | `src/hermes_aegis/patterns/crypto.py` |
| Dangerous commands | `src/hermes_aegis/patterns/dangerous.py` |
| Container builder | `src/hermes_aegis/container/builder.py` |
| Audit trail | `src/hermes_aegis/audit/trail.py` |
| Middleware | `src/hermes_aegis/middleware/` |

## Rules
- Run `uv run pytest tests/ -q` after every change
- Never commit secrets or real API keys
- Keep TASKS.md items small and atomic
- Docker tests are skipped if Docker unavailable — that's fine
- Re-run `hermes-aegis install` after `hermes update` to re-apply patches
