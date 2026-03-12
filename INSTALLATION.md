# Hermes-Aegis Installation Guide

## Understanding the Setup

Hermes-Aegis works by **extending Hermes Agent** with a security layer. There are two ways to install it:

### Method 1: PYTHONPATH (Recommended - Easiest)

This makes hermes-aegis importable without modifying Hermes's environment.

**Step 1: Add to your shell profile**

Add these lines to `~/.zshrc` or `~/.bashrc`:

```bash
# Hermes-Aegis integration
export PYTHONPATH="$HOME/Projects/hermes-aegis/src:$PYTHONPATH"
```

**Step 2: Reload your shell**

```bash
source ~/.zshrc  # or source ~/.bashrc
```

**Step 3: Test the installation**

```bash
python3 -c "import hermes_aegis; print('✓ Aegis installed')"
```

**Step 4: Configure Hermes to use Aegis**

Create or edit `~/.hermes/config.yaml` and add:

```yaml
# Security: Use Hermes-Aegis for terminal isolation
terminal:
  backend: aegis  # or set TERMINAL_ENV=aegis
```

Or set the environment variable:
```bash
export TERMINAL_ENV=aegis
```

**That's it!** Hermes will now use Aegis for all terminal operations.

---

### Method 2: System-wide pip install

Install hermes-aegis into your system Python (useful if you use multiple Python tools).

**Step 1: Install the package**

```bash
cd ~/Projects/hermes-aegis
pip3 install -e .
```

**Step 2: Configure Hermes** (same as Method 1 Step 4)

Set `TERMINAL_ENV=aegis` or configure in Hermes config.

---

## What Those Environment Variables Mean

### `PYTHONPATH`
Tells Python where to find the `hermes_aegis` module. Without this (or pip install), Python won't be able to import hermes-aegis.

### `TERMINAL_ENV=aegis`
Tells Hermes Agent to use the "aegis" backend when creating terminal environments. This activates the security layer.

---

## Verification

**1. Check that Aegis is importable:**
```bash
python3 -c "import hermes_aegis; print('✓ Aegis found')"
```

**2. Check that Hermes can use Aegis:**
```bash
python3 << 'EOF'
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / ".hermes" / "hermes-agent"))
sys.path.insert(0, str(Path.home() / "Projects" / "hermes-aegis" / "src"))

from hermes_aegis.integration import register_aegis_backend
result = register_aegis_backend()
print(f"Aegis backend registration: {'✓ SUCCESS' if result else '✗ FAILED'}")
EOF
```

**3. Test Aegis functionality:**
```bash
python3 /tmp/test_aegis_simple.py
# Should show: ALL TESTS PASSED ✓
```

---

## Current Installation Status

✓ **hermes-aegis is installed** in system Python (via `pip3 install -e`)
✓ **CLI commands work:** `hermes-aegis status`, `hermes-aegis vault list`, etc.
✓ **Vault has 5 secrets** stored
✓ **Config is initialized** with default settings
✓ **All 330 tests passing**

**To use with Hermes:** Just add PYTHONPATH to your shell profile (Method 1).

---

## How It Works

When you run Hermes with Aegis enabled:

1. Hermes Agent starts up
2. `hermes_aegis.integration` registers the "aegis" backend
3. When `TERMINAL_ENV=aegis`, Hermes creates `AegisEnvironment` instead of default
4. `AegisEnvironment` wraps all terminal operations with security:
   - Tier 1: HTTP scanning, file monitoring, middleware
   - Tier 2: + Docker isolation, MITM proxy, full containment

---

## Uninstallation

**If you used PYTHONPATH:**
Remove the export lines from your shell profile.

**If you used pip install:**
```bash
pip3 uninstall hermes-aegis
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'hermes_aegis'"

**Solution:** Add PYTHONPATH to your shell profile (Method 1) or install via pip (Method 2).

### "Aegis backend registration: FAILED"

**Solution:** Hermes Agent is not on Python path. Add:
```bash
export PYTHONPATH="$HOME/.hermes/hermes-agent:$PYTHONPATH"
```

### Hermes not using Aegis

**Solution:** Ensure `TERMINAL_ENV=aegis` is set **before** running Hermes:
```bash
export TERMINAL_ENV=aegis
hermes
```

---

## Next Steps

After installation:

1. **Test it:** Run `hermes-aegis status`
2. **Configure secrets:** Run `hermes-aegis vault list`
3. **Use with Hermes:** Set `TERMINAL_ENV=aegis` and run Hermes
4. **Review audit logs:** After some usage, check `hermes-aegis audit tail`

See **USER_SETUP_GUIDE.md** for detailed usage instructions.
