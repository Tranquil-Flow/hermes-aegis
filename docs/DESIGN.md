# hermes-aegis: Security Hardening Layer for Hermes Agent

**Date**: 2026-03-11
**Status**: Approved
**Type**: Hackathon Project → Upstream PR Path

## Problem

Hermes Agent is a powerful 40+ tool AI agent with self-learning, cron automation, and multi-platform gateways. However, it has critical security gaps:

- Secrets stored as plaintext in `~/.hermes/.env`, accessible to all tools and leaked into LLM context
- Tool registry (`tools/registry.py`) dispatches with no middleware, pre/post hooks, or policy enforcement
- Approval system (`tools/approval.py`) only covers terminal tool, bypassed entirely in container backends
- Skills guard is pre-install static analysis only — no runtime sandboxing
- Redaction (`agent/redact.py`) only applies to log output, not tool results returned to the LLM
- No outbound traffic inspection — data exfiltration via HTTP, DNS, or markdown image rendering is trivial
- No integrity checking on instruction files, memory, or configuration

These gaps are exploitable by indirect prompt injection, malicious skills, data exfiltration, confused deputy attacks, and memory/context poisoning — all demonstrated attack vectors with real CVEs against similar agents.

## Goals

1. Make Hermes as secure as practically possible against known agent attack vectors
2. Zero user friction — `pip install hermes-aegis && hermes-aegis` replaces `hermes`
3. 100% functionality preserved — no allowlists, no blocked destinations, no restricted tools
4. Auto-detection of available security features (Docker present → Tier 2, otherwise → Tier 1)
5. Standalone wrapper for hackathon, with clear path to upstream PR

## Non-Goals

- Learning-based security policies (too fragile, approval drift between interactive/autonomous)
- Destination-based allowlists/blocklists (breaks research browsing, high friction)
- "Extra hard" restrictive modes (Tier 2 already handles autonomous safely)
- Replacing Hermes's existing security features (we layer on top)

## Architecture

### Two-Tier Auto-Detection

```
hermes-aegis CLI
    │
    ├── Docker available? ──yes──► Tier 2 (Container Isolation)
    │                                Hermes runs inside hardened Docker
    │                                Host-side proxy handles secrets + scanning
    │
    └── No Docker ──────────────► Tier 1 (In-Process Hardening)
                                   Middleware chain in same process
                                   Encrypted vault, content scanning, audit trail
```

Both tiers are fully autonomous-capable. No mode switching needed for cron jobs.

### Tier 1: In-Process Hardening (No Docker)

For users without Docker. Provides meaningful security improvements over bare Hermes, with the caveat that same-process middleware can theoretically be bypassed by malicious code executing raw subprocess calls or similar.

**Components:**

#### 1. Encrypted Secret Vault
- Secrets encrypted at rest with Fernet (handles AES-128-CBC + HMAC-SHA256 internally — no manual crypto needed)
- Master key stored in OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Locker)
- One-time migration: reads `~/.hermes/.env`, encrypts values, writes vault file, best-effort overwrites then deletes original (note: true secure deletion is not possible on modern journaled filesystems/SSDs — user should verify)
- Secrets injected into tool calls at dispatch time, never in environment variables
- Vault Python API: `vault.get(key)` — no bulk export, no enumeration (the CLI `vault list` command enumerates keys for user convenience but requires host-side access, not exposed to tools)

#### 2. Tool Dispatch Middleware Chain
Hooks into `tools/registry.py` `dispatch()` method:

```python
class ToolMiddleware(ABC):
    async def pre_dispatch(self, name: str, args: dict, ctx: CallContext) -> DispatchDecision:
        return DispatchDecision.ALLOW

    async def post_dispatch(self, name: str, args: dict, result: str, ctx: CallContext) -> str:
        return result

class MiddlewareChain:
    async def execute(self, name, args, handler, context):
        for mw in self.middlewares:
            decision = await mw.pre_dispatch(name, args, context)
            if decision == DispatchDecision.DENY:
                return {"error": f"Blocked by {mw.__class__.__name__}"}
            if decision == DispatchDecision.NEEDS_APPROVAL:
                if not await request_approval(name, args, context):
                    return {"error": "User denied"}
        result = await handler(args)
        for mw in reversed(self.middlewares):
            result = await mw.post_dispatch(name, args, result, context)
        return result
```

Default middleware stack (order matters — `pre_dispatch` runs top-down, `post_dispatch` runs bottom-up):
1. **AuditTrailMiddleware** — pre: logs tool call initiation; post: logs raw result before redaction
2. **IntegrityCheckMiddleware** — pre: verifies file hashes when file-reading tools are called; post: no-op
3. **AnomalyMonitorMiddleware** — pre: tracks call frequency, flags anomalies; post: no-op (observational only, never blocks)
4. **OutboundContentScanner** — pre: monkey-patches HTTP libraries (once at startup); post: no-op (scanning happens at HTTP layer)
5. **SecretRedactionMiddleware** — pre: no-op; post: scans tool results for secret patterns + exact vault matches (runs last in post_dispatch = final filter before LLM sees results)

#### 3. Outbound Content Scanning (Tier 1)
- Monkey-patches `urllib3` at import time (covers `requests` and `httpx` which use it internally). Additional libraries (`aiohttp`, etc.) are post-hackathon scope.
- Scans outgoing request bodies, URLs, query parameters, and headers
- Detection: regex patterns for known secret formats + exact-match against all vault values
- Encoding-aware: checks base64, URL-encoding, hex, and reversed variants of vault values
- On match: blocks request, logs to audit trail, returns sanitized error to tool
- Cryptocurrency key patterns: Ethereum/EVM (`0x` + 64 hex), Bitcoin WIF (`5`/`K`/`L` + base58), BIP32 extended keys (`xprv`), Solana (base58 ed25519), BIP39 seed phrases (12/24 known-wordlist sequences), Substrate (`0x` + 64 hex SR25519), Cosmos (`cosmos1` bech32)

#### 4. Audit Trail
- Append-only JSONL file at `~/.hermes-aegis/audit.jsonl`
- Each entry: timestamp, tool name, args (redacted), result hash, decision, middleware that acted
- Hash chain: each entry includes SHA-256 of previous entry → tamper detection
- Rotation: new file daily, old files compressed

#### 5. Integrity Checking
- On first run, computes SHA-256 of all instruction/config files and stores manifest
- On each read of these files, verifies hash against manifest
- Detects: modified CLAUDE.md equivalents, poisoned memory files, tampered skills
- On mismatch: logs warning to audit trail + alerts user (does not block — the file may have been legitimately edited)

#### 6. Anomaly Monitor
- Tracks per-session baselines: tool call frequency, unique tools used, data volume out
- Static thresholds (not learned): >50 tool calls/minute, >10 unique external HTTP requests/minute, any tool called >100 times in a session
- Observational only: writes alerts to audit trail and stderr, never blocks execution
- Provides `hermes-aegis audit` CLI command to review alerts

### Tier 2: Container Isolation (Docker Available)

True process-level isolation. This is the recommended mode and activates automatically when Docker is detected.

**Important: In Tier 2, the middleware chain does NOT run inside the container.** All security enforcement runs on the host side: the MITM proxy handles content scanning and secret injection, the audit trail logs proxy events, and the anomaly monitor reads proxy logs. The container runs vanilla Hermes with no armor code — this means a compromised container process cannot bypass security controls. The Tier 1 middleware chain is only used when Docker is unavailable.

**Architecture:**

```
┌─────────────────────────────────────┐
│            HOST (trusted)           │
│                                     │
│  hermes-aegis CLI                   │
│    ├── Secret Vault (encrypted)     │
│    ├── MITM Proxy (:8443)           │
│    │    ├── Injects API keys into   │
│    │    │   LLM provider requests   │
│    │    ├── Scans ALL outbound for  │
│    │    │   secret material         │
│    │    └── Logs to audit trail     │
│    ├── Audit Trail (append-only)    │
│    ├── Anomaly Monitor (reads logs) │
│    └── Integrity Checker            │
│                                     │
│  Docker socket                      │
└────────────┬────────────────────────┘
             │ volume: workspace only
             │ network: proxy only
┌────────────▼────────────────────────┐
│         CONTAINER (untrusted)       │
│                                     │
│  Hermes Agent (full functionality)  │
│    ├── All 40+ tools                │
│    ├── Skills system                │
│    ├── Self-learning loop           │
│    └── HTTP_PROXY=host:8443         │
│                                     │
│  Hardening:                         │
│    ├── --cap-drop=ALL               │
│    ├── --security-opt=no-new-privs  │
│    ├── --read-only (root FS)        │
│    ├── --pids-limit=256             │
│    ├── --user=nonroot               │
│    └── tmpfs for /tmp, /var/tmp     │
│                                     │
│  NO secrets in env vars             │
│  NO direct internet access          │
│  ALL traffic through host proxy     │
└─────────────────────────────────────┘
```

#### Key Tier 2 Properties

**Secret Isolation**: No secrets exist inside the container. The host-side MITM proxy recognizes LLM API calls (OpenAI, Anthropic, etc.) and injects the appropriate API key into the Authorization header. The container's Hermes instance is configured with `HTTP_PROXY`/`HTTPS_PROXY` pointing to the host proxy. All other outbound traffic passes through the proxy for content scanning but receives no secret injection.

**Content-Aware Scanning (not destination filtering)**: The proxy does NOT maintain allowlists or blocklists of domains. Instead it scans the CONTENT of every outbound request for:
- Regex patterns matching known secret formats (API keys, tokens, private keys)
- Exact-match against every value in the vault (in plain, base64, URL-encoded, hex, and reversed forms)
- Cryptocurrency private key patterns (see Tier 1 list)

This means the agent can freely browse the internet for research — only requests containing actual secret material are blocked.

**Config Immutability**: Inside the container, security-relevant files are read-only:
- MCP server configs, tool registry configs, approval policies → mounted read-only
- Existing skills directory → mounted read-only (prevents malicious skill from modifying other skills)
- Separate writable directory for newly installed skills (integrity-checked before promotion to read-only on next container restart)
- Memory files, user preferences → writable (learning state preserved)
- This separation allows Hermes's self-learning loop to function normally while preventing malicious skills from weakening security policy

**Volume Mounting**: Only the user's workspace directory is mounted into the container. No access to `~/.ssh`, `~/.aws`, `~/.config`, browser profiles, or other sensitive host directories.

#### Malicious Skill Protection (Tier 2)
A malicious skill that attempts to exfiltrate secrets via subprocess or raw HTTP is contained because:
1. No secrets exist in the container's environment — environment variables are empty
2. All HTTP requests route through the host proxy — if the skill somehow obtained a secret and embedded it in a request body, the proxy catches it via exact-match scanning
3. The container has no access to host filesystem paths where secrets might be stored
4. `--cap-drop=ALL` and `--no-new-privileges` prevent privilege escalation
5. Read-only root filesystem prevents writing persistent backdoors

### CLI Interface

```bash
# Install
pip install hermes-aegis

# Run (replaces `hermes` command)
hermes-aegis                    # Auto-detects tier, launches Hermes securely
hermes-aegis --tier1            # Force Tier 1 (skip Docker even if available)
hermes-aegis setup              # One-time: migrate secrets, build container image
hermes-aegis audit              # Review audit trail and anomaly alerts
hermes-aegis audit --tail       # Live-follow audit trail
hermes-aegis vault list         # List secret keys (not values)
hermes-aegis vault set KEY      # Add/update a secret (prompts for value)
hermes-aegis vault remove KEY   # Remove a secret
hermes-aegis integrity check    # Verify all instruction file hashes
hermes-aegis status             # Show current tier, vault status, container health
```

**First-run experience:**
1. User runs `hermes-aegis setup`
2. Detects existing `~/.hermes/.env`, offers to migrate secrets to encrypted vault
3. If Docker available: pulls/builds hardened container image
4. Generates integrity manifest for current instruction files
5. Done. User runs `hermes-aegis` instead of `hermes` from now on.

### Upstream PR Path

**Phase 1 (Hackathon)**: Standalone `hermes-aegis` package that wraps Hermes. No changes to Hermes source. Works with any Hermes version.

**Phase 2 (Post-hackathon)**: PR to Hermes adding the middleware hook system to `tools/registry.py` (aligns with Issue #626 — Agent loop middleware architecture). This makes hermes-aegis's middleware chain native rather than monkey-patched.

**Phase 3 (Long-term)**: hermes-aegis becomes a Hermes plugin/extension, installable via `hermes install armor` or similar. Security features become first-class Hermes capabilities.

## Threat Coverage Matrix

| Attack Vector | Tier 1 | Tier 2 |
|---|---|---|
| Plaintext secret exposure | Encrypted vault | Encrypted vault + no secrets in container |
| Secret leakage to LLM context | Post-dispatch redaction middleware | Same + proxy blocks outbound exfil |
| Data exfiltration (HTTP) | Monkey-patched content scanning | MITM proxy content scanning (stronger) |
| Data exfiltration (DNS) | Not covered | Container network only allows proxy — direct DNS (UDP 53) is blocked at network level |
| Malicious skill (subprocess) | Limited — same process | Contained — no secrets, no host access |
| Confused deputy (self-config) | Integrity checking detects | Config mounted read-only |
| Memory/context poisoning | Integrity checking on read | Same + read-only security config |
| Prompt injection in files | Integrity checking detects modification | Same |
| Privilege escalation | Not covered | cap-drop=ALL, no-new-privileges |
| Persistent backdoors | Limited | Read-only root filesystem |
| Unattended autonomous abuse | Audit trail + anomaly alerts | Same + full container isolation |

## Known Limitations

1. **Tier 1 same-process bypass**: Malicious code running in the same Python process can theoretically bypass monkey-patched HTTP libraries by using raw sockets or ctypes. Tier 2 is recommended for high-security use.
2. **DNS exfiltration in Tier 1**: Not covered. Monkey-patching DNS resolution is fragile. Tier 2 handles this via container networking.
3. **Anomaly detection is observational**: Will not prevent a fast-moving attack, only alert after the fact. This is intentional — false positives that block execution would break the zero-friction guarantee.
4. **Container rebuild needed for Hermes updates**: When Hermes updates, the container image needs rebuilding. `hermes-aegis setup --rebuild` handles this.
5. **Docker Desktop licensing**: Docker Desktop requires a paid license for large organizations. Users can use Docker Engine (free) or Podman as alternatives.
6. **Vault key rotation**: No master key rotation mechanism. If the OS keyring is compromised, re-run `hermes-aegis setup` to generate a new master key and re-encrypt all secrets.
7. **File-based exfiltration in Tier 1**: A malicious skill could write secrets to a workspace file (later pushed to a repo). Tier 2 mitigates this since no secrets exist in the container. Tier 1 users should be aware of this gap.
8. **Gateway input injection**: Inbound messages from Telegram/Discord/Slack gateways are a prompt injection surface not addressed by hermes-aegis. This is a Hermes-core concern (see Issue #496).
9. **Container escape**: Kernel-level container escapes are out of scope. The Docker hardening flags reduce attack surface but do not prevent zero-day kernel exploits.
10. **Secure deletion**: True secure deletion of the original `.env` file is not possible on modern journaled filesystems and SSDs. Best-effort overwrite-then-delete is performed.

## Tech Stack

- **Language**: Python (matches Hermes, enables deep integration)
- **Encryption**: `cryptography` library (Fernet)
- **Keyring**: `keyring` library (cross-platform OS keyring access)
- **Proxy (Tier 2)**: `mitmproxy` library (programmatic MITM proxy)
- **Container**: Docker SDK for Python (`docker` library)
- **CLI**: `click` or `typer` (matches Hermes patterns)
- **Audit**: Standard library JSONL + `hashlib`

## File Structure (Proposed)

```
hermes-aegis/
├── pyproject.toml
├── README.md
├── src/
│   └── hermes_aegis/
│       ├── __init__.py
│       ├── cli.py                  # Click/Typer CLI entry point
│       ├── detect.py               # Tier auto-detection
│       ├── vault/
│       │   ├── __init__.py
│       │   ├── store.py            # Fernet-encrypted secret storage
│       │   ├── keyring.py          # OS keyring integration
│       │   └── migrate.py          # .env → vault migration
│       ├── middleware/
│       │   ├── __init__.py
│       │   ├── chain.py            # MiddlewareChain + DispatchDecision
│       │   ├── redaction.py        # SecretRedactionMiddleware
│       │   ├── scanner.py          # OutboundContentScanner
│       │   ├── audit.py            # AuditTrailMiddleware
│       │   ├── integrity.py        # IntegrityCheckMiddleware
│       │   └── anomaly.py          # AnomalyMonitorMiddleware
│       ├── container/
│       │   ├── __init__.py
│       │   ├── builder.py          # Docker image build/management
│       │   ├── runner.py           # Container lifecycle
│       │   └── Dockerfile          # Hardened Hermes container
│       ├── proxy/
│       │   ├── __init__.py
│       │   ├── server.py           # MITM proxy with content scanning
│       │   └── injector.py         # API key injection for LLM calls
│       ├── patterns/
│       │   ├── __init__.py
│       │   ├── secrets.py          # Secret detection regex patterns
│       │   └── crypto.py           # Cryptocurrency key patterns
│       └── audit/
│           ├── __init__.py
│           ├── trail.py            # Append-only JSONL hash chain
│           └── viewer.py           # CLI audit viewer
├── tests/
│   ├── test_vault.py
│   ├── test_middleware.py
│   ├── test_scanner.py
│   ├── test_container.py
│   ├── test_proxy.py
│   ├── test_patterns.py
│   └── test_audit.py
└── docs/
    └── threat-model.md
```

## Hackathon MVP Prioritization

If time is tight, build in this order (items 1-4 = compelling demo):

1. **Encrypted vault + migration** — highest unique value, foundational for everything else
2. **Tier 2 container isolation + host-side proxy** — the strongest security guarantee, the "wow" factor
3. **Audit trail with hash chain** — simple to build, great for demo, useful for debugging
4. **Secret redaction middleware (Tier 1)** — core Tier 1 value for users without Docker
5. **Integrity checking** — medium effort, good demo
6. **Outbound content scanner (Tier 1 monkey-patching)** — high effort, fragile — defer if needed (Tier 2 proxy handles this better)
7. **Anomaly monitor** — observational only, lowest urgency, nice-to-have

## Success Criteria

1. `hermes-aegis setup && hermes-aegis` works in under 2 minutes on a fresh machine with Docker (assumes pre-built image; first build may take longer)
2. All 40+ Hermes tools function identically through hermes-aegis
3. No secrets appear in audit trail, LLM context, or outbound HTTP (verified by test suite)
4. Malicious skill test: a skill that attempts to exfiltrate secrets via HTTP is blocked in Tier 2
5. Self-learning loop continues to function (skills installed, memory updated, preferences saved)
6. Anomaly monitor correctly flags >50 tool calls/minute in test scenarios
7. Audit trail hash chain validates end-to-end (no gaps, no tampering)
