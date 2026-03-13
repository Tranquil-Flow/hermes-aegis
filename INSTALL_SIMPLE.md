# Install Hermes-Aegis (Simple Guide)

**Protects your AI agent from leaking secrets and running dangerous commands.**

---

## For Non-Technical Users

### One-Command Installation

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/hermes-aegis/main/install.sh | bash
```

Or if you have the code locally:

```bash
cd ~/Projects/hermes-aegis
./install.sh
```

**That's it!** The installer does everything automatically.

---

## What It Does

The installer:
1. ✅ Installs hermes-aegis package
2. ✅ Configures your shell (.zshrc or .bashrc)
3. ✅ Sets up encrypted vault for secrets
4. ✅ Initializes configuration files

---

## Using It

After installation, Aegis is automatically active!

### Start Hermes with protection:
```bash
hermes
# You'll see: 🛡️ Aegis Activated (Tier 1 or 2)
```

**No setup needed** - protection is automatic!

### Check status:
```bash
hermes-aegis status
```

### Manage your secrets:
```bash
hermes-aegis vault list
hermes-aegis vault set OPENAI_API_KEY "sk-..."
```

### Configure security:
```bash
hermes-aegis config get
hermes-aegis config set dangerous_commands block
```

---

## What It Protects Against

✅ **Secret Leakage** - Blocks API keys in outbound HTTP requests  
✅ **Command Injection** - Detects dangerous commands like `curl | sh`  
✅ **File Exfiltration** - Warns when secrets written to files  
✅ **Data Tunneling** - Detects suspicious network burst patterns  
✅ **Output Leaks** - Removes secrets from subprocess output  

All protection is **on by default** - zero configuration needed!

---

## Tier Selection (Security Levels)

Aegis automatically picks the best tier:

**Tier 1 (Default)** - Works everywhere, no Docker needed
- HTTP scanning, output redaction, file monitoring
- Perfect for most users

**Tier 2 (Maximum Security)** - Requires Docker
- Everything in Tier 1 + container isolation
- Auto-activates when Docker image is built

**To check your tier:**
```bash
hermes-aegis status
# Shows: Tier: 1 or Tier: 2
```

**To force Tier 1 (if you prefer):**
```bash
export AEGIS_FORCE_TIER1=1
hermes
```

**Both tiers are secure** - Tier 2 just adds extra isolation!

---

## Uninstall

```bash
pip3 uninstall hermes-aegis
# Remove the lines from ~/.zshrc or ~/.bashrc
```

---

## For Developers

See **INSTALLATION.md** for manual installation and **USER_SETUP_GUIDE.md** for advanced usage.

---

## Help

- Check status: `hermes-aegis status`
- View help: `hermes-aegis --help`
- Run tests: `cd ~/Projects/hermes-aegis && uv run pytest tests/ -q`

**Questions?** Open an issue on GitHub.
