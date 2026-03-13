# Your Questions - Final Answers ✅

## Question 1: Do users have to run TERMINAL_ENV command?

**Answer: NO!** ✅

The installer now:
1. Adds `export TERMINAL_ENV=aegis` to shell profile
2. **Activates it immediately** in the current terminal

**User experience:**
```bash
./install.sh
# Installer shows: "Aegis is now active in this terminal!"

hermes
# Works immediately! Shows: 🛡️ Aegis Activated
```

**No manual exports, no restarts needed!**

---

## Question 2: How do users pick between Tier 1/Tier 2?

**Answer: Automatic!** (but controllable if desired) ✅

### Default Behavior (Recommended)

**Users don't pick** - Aegis auto-selects:

- **Has Docker + image built?** → Tier 2 (maximum security)
- **No Docker or no image?** → Tier 1 (still excellent protection)

### What Users See

```bash
hermes-aegis status
```

Shows:
```
Tier: 1
Docker: not available
Vault: 5 secrets
```

Or when starting Hermes:
```
🛡️ Aegis Activated (Tier 1)
```

### If Users Want Control

**Force Tier 1 (skip Docker even if available):**

```bash
# Temporary (this session)
export AEGIS_FORCE_TIER1=1
hermes

# Permanent (config file)
hermes-aegis config set force_tier1 true
```

---

## Tier Comparison: Which to Recommend?

**For Most Users:** Let it auto-select (Tier 1 by default)

**Tier 1 is great because:**
- ✅ No Docker setup needed
- ✅ Works everywhere
- ✅ Lighter resource usage
- ✅ Still provides excellent protection:
  - Blocks secret exfiltration
  - Monitors dangerous commands
  - Scans output for secrets
  - Rate limiting
  - File write monitoring

**Tier 2 adds:**
- Container isolation
- Network sandboxing
- Filesystem isolation
- Process isolation

**Recommendation:** Tell users:
> "Aegis starts in Tier 1 (works everywhere). If you want maximum 
> isolation, build the Docker image and it automatically upgrades to 
> Tier 2. Both tiers are secure!"

---

## Simple User Instructions

**For hackathon demo:**

1. Run installer: `./install.sh`
2. Run Hermes: `hermes`
3. See activation: `🛡️ Aegis Activated`

**That's it!**

---

## Technical Details (for docs)

**Tier Selection Priority:**
1. `force_tier1` parameter = True → Tier 1
2. `AEGIS_FORCE_TIER1` env var → Tier 1
3. `force_tier1` in config → Tier 1
4. Docker available + image built → Tier 2
5. Default → Tier 1

**Most users will be on Tier 1** because:
- Docker setup is optional
- Tier 1 already provides strong protection
- Lower barrier to entry

**See:** `docs/TIER_SELECTION.md` for full guide

---

## What Changed

✅ **install.sh** - Activates Aegis immediately (no restart)
✅ **detect.py** - Added AEGIS_FORCE_TIER1 support
✅ **All docs** - Clarified automatic activation and tier selection
✅ **TIER_SELECTION.md** - Complete tier guide created

---

## Summary

**Users experience:**
1. Install with one command
2. Hermes works immediately with protection
3. Tier auto-selects (Tier 1 by default)
4. Zero manual configuration

**This is as simple as it gets!** 🎉
