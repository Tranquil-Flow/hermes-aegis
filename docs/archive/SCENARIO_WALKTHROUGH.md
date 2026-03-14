# User Journey: From Default to Aegis to Docker Backend

## Scenario: What happens when users change backend settings?

Let's trace a typical user's journey:

---

## Step 1: Fresh Hermes Install (At Risk)

**User installs Hermes Agent**

```bash
# Default config
backend: local
TERMINAL_ENV: (not set)
```

**Status:**
- ❌ No protection
- ❌ Secrets could leak via HTTP
- ❌ No dangerous command detection
- ❌ No output scanning

**User is at risk!**

---

## Step 2: Install Aegis (Protected - Tier 1)

**User runs installer:**

```bash
./install.sh
# Adds to ~/.zshrc:
# export TERMINAL_ENV=aegis
```

**New config:**
```bash
backend: local        # Still in Hermes config
TERMINAL_ENV=aegis    # Added to shell profile
```

**Status:**
- ✅ Protected by Aegis Tier 1
- ✅ HTTP scanning active
- ✅ Output redaction active
- ✅ Dangerous command detection active

**Hermes's `backend: local` is IGNORED** - Aegis takes over!

---

## Step 3: User Changes to backend: docker (Confusing!)

**User edits their Hermes config:**

```yaml
# ~/.hermes/config.yaml
backend: docker  # User thinks this will use Docker
```

**Actual config:**
```bash
backend: docker       # In Hermes config (IGNORED!)
TERMINAL_ENV=aegis    # Still set in shell profile (ACTIVE!)
```

**What actually happens:**
- ✅ Still using Aegis Tier 1 (NOT Hermes's Docker backend)
- ✅ Still protected
- ❌ User's `backend: docker` setting is IGNORED
- ❌ User might be confused why Docker isn't being used

**TERMINAL_ENV takes precedence!**

---

## The Key Issue

**Priority order:**
```
TERMINAL_ENV=aegis  >  backend: docker  >  backend: local
     (wins)              (ignored)         (ignored)
```

When `TERMINAL_ENV=aegis` is set, **ALL other backend settings are ignored**.

---

## What If User Wants Hermes's Docker Backend?

**Option 1: Remove Aegis (Not Recommended)**

```bash
# Edit ~/.zshrc, remove:
export TERMINAL_ENV=aegis

# Restart terminal
hermes
# Now uses backend: docker (but NO Aegis protection!)
```

**Option 2: Build Aegis Docker Image (Recommended)**

```bash
# Keep TERMINAL_ENV=aegis
# Build Aegis Tier 2 image
docker build -t hermes-aegis:latest -f src/hermes_aegis/container/Dockerfile .

# Restart Hermes
hermes
# Now uses Aegis Tier 2 (Aegis's OWN Docker container)
```

---

## Confusion: Users Might Think

❌ "I set `backend: docker` so I'm using Docker"
- **Wrong!** TERMINAL_ENV=aegis overrides this

❌ "Aegis Tier 2 uses my `backend: docker` setting"  
- **Wrong!** Aegis Tier 2 uses its OWN container

❌ "I need to change my backend to get Tier 2"
- **Wrong!** Just build the image, Tier auto-upgrades

---

## The Right Way To Think About It

**Two completely separate systems:**

### Hermes's Backends (When NOT using Aegis)
```
backend: local   → Run on local machine
backend: docker  → Run in Hermes's Docker container
backend: ssh     → Run on SSH server
```

### Aegis System (When using Aegis)
```
TERMINAL_ENV=aegis → Aegis takes over completely
                   ↓
              Aegis decides:
              - Tier 1 (no Docker needed)
              - Tier 2 (Aegis's own container)
```

**They don't mix!**

---

## Recommendations for Docs

**Add WARNING in documentation:**

> ⚠️ When using Aegis (TERMINAL_ENV=aegis), your Hermes backend 
> setting (local/docker/ssh) is ignored. Aegis replaces all backends 
> with its own security layer.
>
> - Want NO isolation? → Aegis Tier 1 (automatic)
> - Want Docker isolation? → Build Aegis image for Tier 2
> 
> Don't change your Hermes backend - it won't do anything!

---

## FAQ

**Q: I have `backend: docker` and AEGIS_FORCE_TIER1=1, what happens?**

A: Aegis Tier 1 is used. Both Docker backends (Hermes's and Aegis's) are skipped.

**Q: Can I use Hermes's docker backend AND Aegis?**

A: No. When TERMINAL_ENV=aegis, Aegis replaces ALL backends. Use Aegis Tier 2 instead.

**Q: I want to temporarily disable Aegis**

A: `unset TERMINAL_ENV` in your current shell, then run Hermes.

**Q: How do I know which backend I'm ACTUALLY using?**

A: Look for the startup message:
- `🛡️ Aegis Activated (Tier N)` → Using Aegis
- No Aegis message → Using Hermes's configured backend

---

## Summary

**Key takeaway for users:**

> Aegis is an "all or nothing" system. When you install it, it 
> completely takes over terminal execution. Your Hermes backend 
> settings are ignored. This is by design for security!
>
> - Tier 1 = Aegis without Docker
> - Tier 2 = Aegis with its own Docker container
>
> Don't try to mix Aegis with Hermes's backends - they're separate!
