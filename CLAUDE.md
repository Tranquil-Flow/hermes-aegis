# Hermes-Aegis

Security hardening layer for AI agents. Stops secret exfiltration.

## Stack
- Python 3.11+, managed with `uv`
- mitmproxy (Tier 2 proxy)
- Docker (Tier 2 container isolation)
- Fernet encryption (vault)

## Commands
```bash
uv run pytest tests/ -q          # Run all tests (186 passing)
uv run pytest tests/security/ -v  # Security tests only
uv run hermes-aegis setup         # One-time vault setup
uv run hermes-aegis status        # Check system status
```

## Architecture
- **Tier 1** (no Docker): urllib3 monkey-patch scans outbound HTTP for secrets
- **Tier 2** (Docker): Internal network + MITM proxy + hardened container. Secrets never enter container — proxy injects API keys into LLM requests.

## Key Paths
| Component | Path |
|-----------|------|
| Secret scanner | `src/hermes_aegis/patterns/secrets.py` |
| Crypto patterns | `src/hermes_aegis/patterns/crypto.py` |
| Dangerous commands | `src/hermes_aegis/patterns/dangerous.py` |
| Tier 1 scanner | `src/hermes_aegis/tier1/scanner.py` |
| MITM proxy | `src/hermes_aegis/proxy/` |
| Container builder | `src/hermes_aegis/container/builder.py` |
| Audit trail | `src/hermes_aegis/audit/trail.py` |
| Middleware | `src/hermes_aegis/middleware/` |
| CLI | `src/hermes_aegis/cli.py` |

## Rules
- Run `uv run pytest tests/ -q` after every change
- Never commit secrets or real API keys
- Keep TASKS.md items small and atomic
- Docker tests are skipped if Docker unavailable — that's fine
