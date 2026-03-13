# Finish Installation - Simple Steps

## What's Done ✅

- ✅ Aegis installed
- ✅ ~/.zshrc configured with TERMINAL_ENV=aegis
- ✅ PYTHONPATH configured
- ✅ Auto-loader installed to sitecustomize.py

## What You Need To Do

### Step 1: Open a NEW terminal window

The settings are in ~/.zshrc but your current terminal doesn't have them loaded.

**Just open a fresh terminal!**

### Step 2: Verify settings loaded

```bash
echo $TERMINAL_ENV
# Should show: aegis

echo $PYTHONPATH
# Should include: /Users/evinova/Projects/hermes-aegis/src
```

### Step 3: Launch Hermes

```bash
hermes
```

**You should see:**
```
🛡️ Aegis Activated (Tier 1)
```

In the startup display!

---

## If You Don't See "Aegis Activated"

###Troubleshoot:

**1. Check TERMINAL_ENV:**
```bash
echo $TERMINAL_ENV
# Must show: aegis
```

If not, run:
```bash
source ~/.zshrc
```

**2. Check auto-loader exists:**
```bash
ls -la ~/Library/Python/3.13/lib/python/site-packages/sitecustomize.py
# Should exist
```

**3. Manually load for testing:**
```bash
export TERMINAL_ENV=aegis
python3 << 'EOF'
import sys
sys.path.insert(0, '/Users/evinova/Projects/hermes-aegis/src')
from hermes_aegis.display import print_aegis_status
print_aegis_status()
EOF
```

Should show: `🛡️ Aegis Activated (Tier 1)`

---

## Alternative: Manual Method

If auto-loading doesn't work, add this to `~/.hermes/config.yaml`:

```yaml
# Add at the top
python_path:
  - /Users/evinova/Projects/hermes-aegis/src
  
terminal:
  backend: local  # or docker for Tier 2
  env:
    TERMINAL_ENV: aegis
```

---

## Quick Summary

**The absolute simplest way:**

1. Open a brand new terminal
2. Run: `hermes`
3. Look for: `🛡️ Aegis Activated`

That's it!

---

## Configuration

Want Tier 2 (Docker isolation)?

Edit `~/.hermes/config.yaml`:
```yaml
terminal:
  backend: docker
```

Then run:
```bash
hermes-aegis setup
```

Next time you launch Hermes → Tier 2!

---

## Still Having Issues?

The core issue is that Hermes needs to import `hermes_aegis.integration` at startup.

The sitecustomize.py we installed should do this automatically when TERMINAL_ENV=aegis.

If it's not working, we may need to patch Hermes's cli.py directly. Let me know and I'll create that patch!
