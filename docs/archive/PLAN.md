# Hermes-Aegis Plan

## Current Status

Core MVP is built and working. 186 tests passing. All original phases (1-4) complete.

Hermes Agent was updated to v0.2.0 (2026.3.12) on 2026-03-13. The update added 143 commits with incremental security hardening (secret redaction patterns, dangerous command detection, file permissions) but nothing that overlaps with Aegis's core value: infrastructure-level isolation, MITM proxy, encrypted vault, and outbound content scanning.

The `_create_environment()` monkey-patch target is confirmed compatible — same function signature.

## What's Built

- Encrypted vault with OS keyring (Fernet/AES)
- Secret detection: API keys, crypto keys (BIP39/ETH/BTC/SOL), encoding-aware (base64/hex/URL/reversed)
- Tier 1: urllib3 monkey-patch scans all outbound HTTP
- Tier 2: Docker container (read-only root, all caps dropped, 512MB RAM, 50% CPU, non-root user) + internal network + MITM proxy
- Proxy API key injection (OpenAI, Anthropic, Google, Groq, Together)
- Hash-chained tamper-proof audit trail
- Middleware chain (audit, integrity, anomaly, content scan, redaction)
- 40+ dangerous command patterns (audit-only)
- CLI: setup, status, vault management, audit viewer, run command
- Integration: monkey-patches Hermes `_create_environment()` for `TERMINAL_ENV=aegis`
- 186 passing tests including 12 red team attack scenarios

## What's Next

See TASKS.md for the work plan. Three phases:

1. **Verify v0.2.0 compatibility** — run tests, confirm integration still works
2. **New features** — domain allowlist, output scanning, file write scanning, dangerous command blocking (off by default), network rate limiting
3. **Validation** — full red team + demo scripts

## Design Principle

Secure by default, tunable for more. Everything works out of the box. Users can tighten security (enable domain allowlists, enable dangerous command blocking) but never need to configure anything to get baseline protection.

## Architecture Reference

```
Tier 1 (no Docker):
  Agent → urllib3 monkey-patch → scan outbound HTTP → block if secret found
  Agent → middleware chain → audit + redact tool I/O

Tier 2 (Docker):
  Agent → hardened container (no secrets, no network) → MITM proxy on host
  Proxy → inject API keys for LLM providers
  Proxy → scan + block all other outbound traffic
  Proxy → audit trail
```

## Key Files

| File | What it does |
|------|-------------|
| `src/hermes_aegis/integration.py` | Monkey-patches Hermes `_create_environment()` |
| `src/hermes_aegis/environment.py` | `AegisEnvironment` — wraps Local/Docker with security |
| `src/hermes_aegis/tier1/scanner.py` | urllib3 outbound HTTP scanning |
| `src/hermes_aegis/proxy/addon.py` | MITM proxy ArmorAddon |
| `src/hermes_aegis/proxy/injector.py` | API key injection for LLM providers |
| `src/hermes_aegis/patterns/secrets.py` | Secret pattern detection |
| `src/hermes_aegis/patterns/crypto.py` | Crypto key detection |
| `src/hermes_aegis/patterns/dangerous.py` | Dangerous command patterns |
| `src/hermes_aegis/middleware/chain.py` | Middleware chain architecture |
| `src/hermes_aegis/vault/store.py` | Encrypted vault |
| `src/hermes_aegis/audit/trail.py` | Hash-chained audit log |
| `src/hermes_aegis/cli.py` | CLI entry point |
