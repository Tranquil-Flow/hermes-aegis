# Tier Selection Guide

Hermes-Aegis has two security tiers:

## Tier 1: In-Process Protection
**What it does:**
- HTTP scanning (urllib3 monkey-patch)
- File write monitoring
- Output secret scanning
- Dangerous command detection
- Middleware chain protection

**Requirements:**
- Python 3.11+
- No Docker needed

**When to use:**
- Docker not available
- Quick setup
- Development environments
- Lighter resource footprint

---

## Tier 2: Container Isolation
**What it does:**
- Everything in Tier 1, PLUS:
- Hardened Docker container
- Internal network isolation
- MITM proxy for LLM API access
- Read-only filesystem
- No Linux capabilities
- Resource limits (512MB RAM, 50% CPU)

**Requirements:**
- Docker installed and running
- Docker image built: `hermes-aegis:latest`

**When to use:**
- Maximum security needed
- Production environments
- Untrusted code execution
- Complete isolation required

---

## How Tier Selection Works

### Automatic Detection (Default)

Aegis automatically selects the highest tier available:

1. **Check for Docker:** Is Docker installed and running?
2. **Check for image:** Does `hermes-aegis:latest` exist?
3. **If both yes:** Use Tier 2
4. **Otherwise:** Use Tier 1

**No configuration needed!**

---

## Forcing Tier 1

If you have Docker but prefer Tier 1:

**Method 1: Environment Variable**
```bash
export AEGIS_FORCE_TIER1=1
hermes
```

**Method 2: Persistent Config**
```bash
hermes-aegis config set force_tier1 true
```

**Method 3: CLI Flag**
```bash
hermes-aegis --tier1 status
```

---

## Building Tier 2

To enable Tier 2, build the Docker image:

```bash
cd ~/Projects/hermes-aegis
docker build -t hermes-aegis:latest -f src/hermes_aegis/container/Dockerfile .
```

**Or use the setup command:**
```bash
hermes-aegis setup
# This builds the image if Docker is available
```

After building, Tier 2 auto-activates!

---

## Checking Your Current Tier

```bash
hermes-aegis status
```

Output shows:
```
Tier: 2
Docker: available
Vault: 5 secrets
```

Or when you start Hermes:
```
🛡️ Aegis Activated (Tier 2)
```

---

## Tier Comparison Table

| Feature | Tier 1 | Tier 2 |
|---------|--------|--------|
| HTTP scanning | ✅ urllib3 patch | ✅ MITM proxy |
| Output scanning | ✅ | ✅ |
| File monitoring | ✅ | ✅ |
| Dangerous commands | ✅ | ✅ |
| Network isolation | ❌ | ✅ Container network |
| Filesystem isolation | ❌ | ✅ Read-only root |
| Process isolation | ❌ | ✅ Container PID namespace |
| Resource limits | ❌ | ✅ 512MB RAM, 50% CPU |
| API key injection | ❌ | ✅ Proxy-based |
| Setup complexity | Low | Medium |
| Resource usage | Low | Medium |

---

## Recommendations

**Use Tier 1 if:**
- You're developing/testing Aegis
- Docker isn't available
- You want minimal overhead
- You trust the code being executed

**Use Tier 2 if:**
- Running in production
- Executing untrusted code
- Maximum security needed
- You have Docker available

---

## Troubleshooting

### "Tier: 1" but I have Docker

**Possible causes:**
1. Docker image not built → Run `hermes-aegis setup`
2. Docker not running → Start Docker Desktop
3. Force tier1 enabled → Check `hermes-aegis config get force_tier1`

### "Tier: 2" but I want Tier 1

**Solution:**
```bash
export AEGIS_FORCE_TIER1=1
hermes
```

### Docker build fails

**Solution:** Use Tier 1 (still provides excellent protection!)

---

## Summary

- **Tier selection is automatic** by default
- **Tier 1 is the default** (no Docker setup needed)
- **Tier 2 activates** when Docker image is built
- **Both tiers are secure** - choose based on your needs
- **Force Tier 1** with `AEGIS_FORCE_TIER1=1` if needed
