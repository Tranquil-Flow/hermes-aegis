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

**Restart your terminal**, then:

### Start Hermes with protection:
```bash
export TERMINAL_ENV=aegis
hermes
```

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
