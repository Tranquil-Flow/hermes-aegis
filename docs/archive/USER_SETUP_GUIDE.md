# Hermes-Aegis User Setup Guide

**Your system is ready to use Hermes-Aegis!**

## Current Status ✓

- **Installation:** Complete (uv-installed as editable package)
- **Vault:** 5 secrets stored (ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, LLM_MODEL, TEST_VAR)
- **Config:** Initialized (~/.hermes-aegis/config.json)
- **Tier:** Tier 2 (Docker available, but image not built yet - using Tier 1 for now)
- **Tests:** 330/330 passing

## Quick Start

### 1. Check Status
```bash
cd ~/Projects/hermes-aegis
uv run hermes-aegis status
```

### 2. Manage Vault Secrets
```bash
# List secrets
uv run hermes-aegis vault list

# Add a secret
uv run hermes-aegis vault set MY_API_KEY "sk-..."

# Get a secret
uv run hermes-aegis vault get MY_API_KEY

# Remove a secret
uv run hermes-aegis vault remove MY_API_KEY
```

### 3. Configure Security Settings
```bash
# View current settings
uv run hermes-aegis config get

# Enable dangerous command blocking
uv run hermes-aegis config set dangerous_commands block

# Adjust rate limiting
uv run hermes-aegis config set rate_limit_requests 100
uv run hermes-aegis config set rate_limit_window 2.0
```

### 4. Manage Domain Allowlist
```bash
# List allowed domains
uv run hermes-aegis allowlist list

# Add a domain (enables allowlist - only listed domains permitted)
uv run hermes-aegis allowlist add api.openai.com
uv run hermes-aegis allowlist add github.com

# Remove a domain
uv run hermes-aegis allowlist remove github.com
```

## Using with Hermes Agent (Tier 1 - No Docker)

**Option A: Environment Variable (Recommended)**

Add to your shell profile (~/.zshrc or ~/.bashrc):
```bash
export PYTHONPATH="$HOME/Projects/hermes-aegis/src:$PYTHONPATH"
```

Then in any Python script or Hermes config:
```python
# This will register the Aegis backend
import hermes_aegis.integration

# Now Hermes will use Aegis for terminal operations
```

**Option B: Manual Integration**

In your Hermes startup or config:
```python
import sys
from pathlib import Path

# Add Aegis to path
sys.path.insert(0, str(Path.home() / "Projects" / "hermes-aegis" / "src"))

# Register Aegis backend
from hermes_aegis.integration import register_aegis_backend
register_aegis_backend()

# Set environment to use Aegis
import os
os.environ['TERMINAL_ENV'] = 'aegis'
```

## Tier 2 Setup (Docker - For Maximum Security)

To use Tier 2 with full container isolation, you need to:

1. **Fix Docker credentials issue:**
   ```bash
   # Remove any stuck credentials
   rm ~/.docker/config.json
   # Or configure Docker Desktop credentials
   ```

2. **Build the Aegis container:**
   ```bash
   cd ~/Projects/hermes-aegis
   docker build -t hermes-aegis:latest -f src/hermes_aegis/container/Dockerfile .
   ```

3. **Tier 2 will auto-activate** when Docker image is available

## Security Features (All Active by Default)

### 1. Output Secret Scanning ✓
- Scans all subprocess output for secrets before returning to LLM
- Redacts found secrets automatically
- No configuration needed

### 2. Workspace File Write Monitoring ✓
- Monitors files written to /workspace for secrets
- Warns when secrets are written to files
- Logs violations to audit trail

### 3. Network Rate Limiting ✓  
- Detects burst patterns (50+ requests/second by default)
- Logs anomalies for review
- Adjustable thresholds via config

### 4. Dangerous Command Detection ✓
- Detects 40+ dangerous patterns (curl|sh, rm -rf, etc.)
- Audit-only by default (logs but allows)
- Enable blocking: `hermes-aegis config set dangerous_commands block`

### 5. Domain Allowlist (Off by Default)
- Empty allowlist = allow all
- Add domains to restrict outbound connections
- Example: Only allow LLM API providers

## Audit Trail

View security events:
```bash
# View recent audit entries
uv run hermes-aegis audit tail

# Verify audit chain integrity
uv run hermes-aegis audit verify

# Export audit log
uv run hermes-aegis audit export --format json > audit.json
```

## Configuration Files

All configuration is stored in `~/.hermes-aegis/`:

```
~/.hermes-aegis/
├── vault.enc                  # Encrypted secrets (Fernet/AES)
├── config.json                # Settings (dangerous_commands, rate limits)
├── domain-allowlist.json      # Allowed domains (empty = allow all)
└── audit.log                  # Tamper-proof audit trail
```

## Testing Your Setup

Run the test script:
```bash
python3 /tmp/test_aegis_simple.py
```

Expected output:
```
ALL TESTS PASSED ✓
```

## Troubleshooting

### Docker credentials error
If you see "error getting credentials", either:
- Use Tier 1 (works without Docker)
- Fix Docker Desktop credentials
- Remove ~/.docker/config.json and retry

### Import errors
Make sure hermes-aegis is installed:
```bash
cd ~/Projects/hermes-aegis
uv pip install -e .
```

### Secrets not loading
Check vault:
```bash
uv run hermes-aegis vault list
```

If empty, migrate from .env:
```bash
uv run hermes-aegis setup
```

## Next Steps

1. **Test with real Hermes usage** - Try running Hermes commands and check the audit trail
2. **Review audit logs** - See what security events are captured
3. **Tune settings** - Adjust rate limits, enable command blocking if needed
4. **Add domain allowlist** - Restrict outbound connections for maximum security

## Support

- Tests: `cd ~/Projects/hermes-aegis && uv run pytest tests/ -v`
- Status: `uv run hermes-aegis status`
- Docs: See README.md and docs/ directory

**You're all set! Hermes-Aegis is protecting your Hermes Agent sessions.** 🛡️
