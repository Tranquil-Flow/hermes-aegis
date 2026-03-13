# Answer: Backend and Tier Detection

## Your Question

> "So if a user is running backend:docker it will be tier 2 by default? 
> Will aegis pick up on changes here?"

---

## Short Answer

**No - these are separate systems!** ✅

- `backend: docker` = Hermes's Docker backend
- `TERMINAL_ENV=aegis` = Aegis backend **(replaces all Hermes backends)**
- Aegis Tier 1/2 = Internal to Aegis

**When using Aegis, Hermes's backend setting is ignored.**

---

## How It Actually Works

### User Sets TERMINAL_ENV=aegis

```
TERMINAL_ENV=aegis
         ↓
Hermes uses: Aegis backend (NOT docker backend)
         ↓
Aegis decides internally: Tier 1 or Tier 2
         ↓
├─ Tier 1: No Docker image needed
└─ Tier 2: Docker image must be built
```

### Tier Detection Logic (Fixed!)

**OLD (Wrong):**
- Tier 2 if Docker daemon running ❌
- Would fail because image not built

**NEW (Correct):**
- Tier 2 ONLY if Docker daemon running **AND** image built ✅
- Tier 1 by default (always works)
- Tier 2 auto-activates after building image

---

## Does Aegis Pick Up Changes?

**YES!** ✅

Aegis checks tier **dynamically** when:
1. Creating new Aegis environment
2. Running `hermes-aegis status`  
3. Displaying startup message

**Example:**
```bash
# 1. Start with Tier 1 (no image)
hermes
# Shows: 🛡️ Aegis Activated (Tier 1)

# 2. Build Docker image
docker build -t hermes-aegis:latest -f src/hermes_aegis/container/Dockerfile .

# 3. Restart Hermes
hermes
# Shows: 🛡️ Aegis Activated (Tier 2)
```

**Automatic upgrade - no config changes!**

---

## What I Fixed

**Added `docker_image_available()` check:**

```python
def docker_image_available():
    """Check if hermes-aegis Docker image is built."""
    result = subprocess.run(
        ["docker", "images", "-q", "hermes-aegis:latest"],
        capture_output=True, text=True
    )
    return bool(result.stdout.strip())

def detect_tier():
    # ... priority checks ...
    
    # Was: return 2 if docker_available() else 1
    # Now:
    return 2 if docker_image_available() else 1
```

**Now checks BOTH:**
- ✅ Docker daemon running
- ✅ Image `hermes-aegis:latest` exists

---

## For Users

**Simple message:**

> "Aegis starts in Tier 1 (works immediately). If you build the Docker 
> image later, Aegis automatically upgrades to Tier 2 next time you 
> start Hermes. No configuration needed!"

**Most users will stay on Tier 1** because:
- No Docker image setup required
- Still provides excellent protection
- Lower barrier to entry

---

## Summary

✅ Fixed tier detection to require image, not just daemon
✅ Tier 1 is default (works everywhere)
✅ Tier 2 auto-activates when image is built
✅ Dynamic detection - picks up changes automatically
✅ Hermes backend setting is separate/ignored

**Bottom line:** Users get Tier 1 immediately, Tier 2 is optional bonus!
