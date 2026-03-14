# New Behavior: Aegis Respects Hermes Backend Setting

## The Change

**OLD Behavior:**
- Aegis ignored Hermes's backend setting
- TERMINAL_ENV=aegis completely overrode backend: docker
- Confusing for users!

**NEW Behavior:**
- Aegis respects Hermes's backend setting
- `backend: local` → Aegis Tier 1
- `backend: docker` → Aegis Tier 2 (if image available)
- Intuitive and predictable!

---

## How It Works Now

### Priority System

1. **Explicit overrides** (highest priority)
   - `AEGIS_FORCE_TIER1=1` environment variable
   - `force_tier1: true` in Aegis config
   
2. **Hermes backend setting** (respects user choice)
   - `backend: docker` → Tries Tier 2 (warns if image missing)
   - `backend: local` → Uses Tier 1
   - `backend: ssh/modal/etc` → Uses Tier 1

3. **Auto-detect** (fallback)
   - Docker + image available → Tier 2
   - Otherwise → Tier 1

---

## User Experience

### Scenario 1: Fresh Install

```yaml
# User's Hermes config (default)
backend: local
```

**Result:** Aegis Tier 1 ✅

---

### Scenario 2: User Wants Docker Isolation

```yaml
# User changes Hermes config
backend: docker
```

**Result:** Aegis Tier 2 ✅ (if image built)

**If image not built:**
```
⚠️  Hermes backend set to 'docker' but Aegis Tier 2 image not built.
   Run: hermes-aegis setup
   Falling back to Aegis Tier 1.
```

---

### Scenario 3: Remote SSH Backend

```yaml
# User's Hermes config
backend: ssh
```

**Result:** Aegis Tier 1 ✅
(Can't use Docker containers on remote machines)

---

## Benefits

### 1. Intuitive User Control

Users already understand Hermes backends:
- `backend: local` = run locally
- `backend: docker` = run in container

Now it just works naturally with Aegis!

### 2. No Surprise Behavior

**Before:**
- User sets `backend: docker`
- Confused when it's ignored
- Has to learn about TERMINAL_ENV override

**After:**
- User sets `backend: docker`
- Gets Aegis Tier 2 (Docker isolation)
- Behavior matches expectations!

### 3. Graceful Degradation

If image isn't built:
- Shows helpful message
- Suggests fix: `hermes-aegis setup`
- Falls back to Tier 1 (still protected!)

---

## Configuration Guide

### For Most Users (Tier 1)

**Do nothing!** Default is `backend: local` → Tier 1

```yaml
# ~/.hermes/config.yaml
backend: local  # or omit for default
```

### For Maximum Security (Tier 2)

**Change to Docker backend:**

```yaml
# ~/.hermes/config.yaml
backend: docker
```

**Build the image:**
```bash
hermes-aegis setup
# or
docker build -t hermes-aegis:latest -f src/hermes_aegis/container/Dockerfile .
```

**That's it!** Next time you run Hermes → Tier 2

### To Force Tier 1 (Even with Docker backend)

**Option 1: Environment variable (temporary)**
```bash
export AEGIS_FORCE_TIER1=1
hermes
```

**Option 2: Aegis config (permanent)**
```bash
hermes-aegis config set force_tier1 true
```

---

## Implementation Details

### Reading Hermes Config

```python
def get_hermes_backend() -> str:
    # 1. Check TERMINAL_BACKEND env var
    if os.getenv("TERMINAL_BACKEND"):
        return os.getenv("TERMINAL_BACKEND")
    
    # 2. Parse ~/.hermes/config.yaml
    config = yaml.safe_load(open(config_path))
    backend = config.get("terminal", {}).get("backend") or config.get("backend")
    
    # 3. Default to local
    return backend or "local"
```

### Tier Selection Logic

```python
def detect_tier():
    # Explicit overrides
    if AEGIS_FORCE_TIER1:
        return 1
    
    # Read Hermes backend
    backend = get_hermes_backend()
    
    if backend == "docker":
        # User wants Docker → try Tier 2
        if image_available():
            return 2
        else:
            warn("Image not built, falling back to Tier 1")
            return 1
    
    elif backend in ["local", "ssh", "modal", ...]:
        # These backends use Tier 1
        return 1
    
    # Auto-detect (legacy)
    return 2 if image_available() else 1
```

---

## Migration from Old Behavior

**No breaking changes!**

Users who were on Tier 1 stay on Tier 1 (backend defaults to local).

Users who want Tier 2 now just change `backend: docker` - simpler than before!

---

## Documentation Updates Needed

- [x] Update README.md - Change warning to explanation
- [x] Update INSTALL_SIMPLE.md - Mention backend setting
- [x] Update TIER_SELECTION.md - New priority order
- [x] Remove warnings about Aegis "overriding" backends
- [x] Add positive messaging: "Aegis works WITH your backend choice"

---

## Summary

**Key message for users:**

> "Aegis respects your Hermes backend setting!
> 
> - Want local execution? → Keep `backend: local`
> - Want Docker isolation? → Change to `backend: docker`
> 
> Aegis automatically provides the right security tier for your choice."

**Much more intuitive!** ✅
