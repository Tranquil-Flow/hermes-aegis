# Hermes-Aegis

Security hardening layer for Hermes Agent. Stops secret exfiltration via MITM proxy.

## Stack
- Python 3.10+, managed with `uv`
- mitmproxy (required — proxy-based scanning)
- Docker (optional — container isolation)
- Fernet encryption (vault)

## Commands
```bash
uv run pytest tests/ -q              # Run all tests (739 passing)
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
uv run hermes-aegis reactive init    # Create default reactive agent rules
uv run hermes-aegis reactive list    # Show loaded rules and status
uv run hermes-aegis reactive test    # Dry-run rules against recent audit
uv run hermes-aegis reactive enable/disable <name>  # Toggle rules
uv run hermes-aegis report schedule --every 24h     # Schedule periodic report
uv run hermes-aegis report list      # List scheduled reports
uv run hermes-aegis report run       # Generate report now
uv run hermes-aegis report cancel ID # Cancel scheduled report
uv run hermes-aegis vault unlock     # Unlock vault after circuit breaker lock
```

## Architecture
- **`hermes-aegis run`** starts proxy, wraps `hermes` with proxy env vars + real ANTHROPIC_TOKEN from vault
- **`hermes-aegis install`** applies 11 idempotent patches to hermes-agent source (Docker proxy forwarding, gateway command scanning, network isolation)
- **Hermes hook** at `~/.hermes/hooks/aegis-security/` available for gateway mode (optional)
- **MITM proxy** scans all outbound HTTP, blocks secret exfiltration, injects API keys for LLM providers
- **Reactive agents** watch the audit trail for patterns and can spawn investigation agents or send alerts
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
| Reactive rules | `src/hermes_aegis/reactive/rules.py` |
| Reactive watcher | `src/hermes_aegis/reactive/watcher.py` |
| Reactive manager | `src/hermes_aegis/reactive/manager.py` |
| Circuit breaker | `src/hermes_aegis/reactive/actions.py` |
| Agent runner | `src/hermes_aegis/reactive/agent_runner.py` |
| Report templates | `src/hermes_aegis/reactive/templates.py` |
| Report generator | `src/hermes_aegis/reports/generator.py` |
| Report scheduler | `src/hermes_aegis/reports/scheduler.py` |

## Rules
- Run `uv run pytest tests/ -q` after every change
- Never commit secrets or real API keys
- Keep TASKS.md items small and atomic
- Docker tests are skipped if Docker unavailable — that's fine
- Re-run `hermes-aegis install` after `hermes update` to re-apply patches
