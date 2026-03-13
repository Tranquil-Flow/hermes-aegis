# Backend vs Tier Clarification

## Important Distinction

There are **two separate concepts** that users might confuse:

### 1. Hermes Backend (Terminal Environment)

Hermes Agent supports multiple terminal backends:
- `local` - Run commands on your local machine
- `docker` - Run commands in a Docker container (Hermes's container)
- `ssh` - Run commands on a remote SSH server
- `modal` - Run commands on Modal.com
- `aegis` - Run commands with Aegis security layer

**Set via:** `TERMINAL_ENV` environment variable or Hermes config

### 2. Aegis Tier (Internal to Aegis)

When using `TERMINAL_ENV=aegis`, Aegis has TWO internal tiers:
- **Tier 1** - In-process protection (no Docker)
- **Tier 2** - Container isolation (requires Docker + image)

---

## How They Relate

```
User sets: TERMINAL_ENV=aegis
           ↓
Hermes uses: Aegis backend
           ↓
Aegis internally: Detects Tier 1 or Tier 2
           ↓
           ├─ Tier 1: HTTP scanning, file monitoring, middleware
           └─ Tier 2: Tier 1 + Docker container isolation
```

---

## Common Confusions

### "I have backend: docker in my config"

**That's Hermes's Docker backend, NOT Aegis!**

When you set `TERMINAL_ENV=aegis`:
- Hermes uses **Aegis backend** (ignores `backend: docker`)
- Aegis decides Tier 1 or 2 internally
- Your `backend: docker` setting is **not used**

### "Will Aegis pick up on backend changes?"

**Aegis doesn't look at Hermes's backend setting.**

Aegis only checks:
1. Is Docker daemon running?
2. Is `hermes-aegis:latest` image built?
3. Is `AEGIS_FORCE_TIER1` set?
4. Is `force_tier1` in config?

Then decides: Tier 1 or Tier 2

---

## Tier Selection Logic (Corrected)

```python
def detect_tier():
    if force_tier1:
        return 1  # Explicit override
    
    if AEGIS_FORCE_TIER1 env var:
        return 1  # Environment override
    
    if force_tier1 in config:
        return 1  # Config override
    
    if docker_daemon_running() AND image_built():
        return 2  # Auto-upgrade to Tier 2
    
    return 1  # Default
```

**Key point:** Checks **both** Docker AND image availability

---

## Dynamic Detection

**Yes, Aegis detects changes dynamically!**

The tier is checked when:
- Aegis environment is created
- User runs `hermes-aegis status`
- Display hook runs (on Hermes startup)

**Scenario:**
1. User starts with Tier 1 (no image)
2. User builds image: `docker build -t hermes-aegis:latest ...`
3. User restarts Hermes
4. Aegis automatically switches to Tier 2

**No config changes needed!**

---

## For Users

**Simple explanation:**

> When you use Aegis with Hermes, it automatically picks the best
> security level:
>
> - **Tier 1** (default) - Works everywhere, no setup
> - **Tier 2** (automatic) - Activates when you build the Docker image
>
> You don't pick - Aegis detects what's available and upgrades
> automatically!

---

## For Developers

**Integration check:**

```python
from hermes_aegis.detect import detect_tier, docker_image_available

print(f"Current tier: {detect_tier()}")
print(f"Image built: {docker_image_available()}")
```

**Force Tier 1:**

```python
import os
os.environ['AEGIS_FORCE_TIER1'] = '1'

# or
from hermes_aegis.detect import detect_tier
tier = detect_tier(force_tier1=True)
```

---

## Summary

| Setting | What It Does |
|---------|-------------|
| `TERMINAL_ENV=aegis` | Use Aegis backend (replaces local/docker/ssh) |
| `backend: docker` in Hermes | Ignored when using Aegis |
| Aegis Tier 1 | In-process protection (default) |
| Aegis Tier 2 | Container isolation (auto-activates with image) |
| `AEGIS_FORCE_TIER1=1` | Force Tier 1 even if Tier 2 available |

**Most important:** Users just set `TERMINAL_ENV=aegis` and Aegis handles the rest!
