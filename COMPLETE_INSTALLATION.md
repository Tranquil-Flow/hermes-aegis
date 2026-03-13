# Complete Installation Steps

You're almost there! Just need to connect the pieces.

## Current Status

✅ Aegis installed: `pip3 show hermes-aegis` shows it's installed
✅ PYTHONPATH configured in ~/.zshrc
✅ TERMINAL_ENV=aegis configured in ~/.zshrc
❌ Hermes doesn't auto-load Aegis (missing step!)

## The Missing Piece

Hermes needs to **import** hermes_aegis.integration at startup to register the backend.

## Solution: Add to Hermes Config

**Option 1: Via Hermes config.yaml (Recommended)**

Edit `~/.hermes/config.yaml` and add:

```yaml
# At the top of the file
startup_script: |
  import hermes_aegis.integration
  hermes_aegis.integration.register_aegis_backend()
```

**Option 2: Via sitecustomize.py (Auto-loads on Python startup)**

Create `~/.local/lib/python3.13/site-packages/sitecustomize.py`:

```python
import os
if os.getenv('TERMINAL_ENV') == 'aegis':
    try:
        import hermes_aegis.integration
        hermes_aegis.integration.register_aegis_backend()
    except ImportError:
        pass
```

**Option 3: Patch Hermes CLI directly**

Add this to `~/.hermes/hermes-agent/cli.py` near the top (after imports):

```python
# Load Aegis if configured
import os
if os.getenv('TERMINAL_ENV') == 'aegis':
    try:
        import hermes_aegis.integration
        hermes_aegis.integration.register_aegis_backend()
    except ImportError:
        pass
```

## Quick Test (Manual)

For now, to test it works:

```bash
# In a new terminal
export TERMINAL_ENV=aegis
python3 << 'PYTHON_EOF'
import sys
sys.path.insert(0, '/Users/evinova/Projects/hermes-aegis/src')
sys.path.insert(0, '/Users/evinova/.hermes/hermes-agent')

from hermes_aegis.integration import register_aegis_backend
success = register_aegis_backend()
print(f"Registration: {success}")

# Now check tier
from hermes_aegis.detect import detect_tier
print(f"Tier: {detect_tier()}")
PYTHON_EOF
```

## Let Me Create an Auto-Loader

I'll create a better solution that automatically loads...
