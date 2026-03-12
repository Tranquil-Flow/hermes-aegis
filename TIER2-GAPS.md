# Tier 2 Implementation Gaps & Clarifications

**Purpose**: Identify every ambiguity, missing detail, and potential blocker before starting Tier 2 build.

---

## CRITICAL GAPS

### 1. Container Needs Hermes Agent Itself

**Problem**: Container must run `hermes` command, but how does it get there?

**Options**:
A. **Install hermes in container image** (cleanest)
   - Dockerfile: `RUN pip install hermes-agent`
   - Pro: Self-contained
   - Con: Couples aegis to specific hermes version
   
B. **Mount hermes from host** (flexible)
   - Volume: `~/.hermes/hermes-agent:/hermes:ro`
   - Pro: Uses host's hermes version
   - Con: Complex path management

C. **Don't run hermes in container** (simplest)
   - Just run arbitrary Python scripts for testing
   - Pro: Simpler for MVP, proves isolation
   - Con: Doesn't test real agent use case

**Recommendation**: **Option C for MVP testing**, document that full agent-in-container is v1.1

**Why**: Running full hermes in container requires:
- Config file access (~/.hermes/config.yaml)
- Memory/session storage
- Skills directory
- Gateway connectivity
This is a MUCH bigger integration project than Tier 2 isolation alone.

**MVP scope**: Prove container ISOLATION works (secrets protected, exfil blocked)  
**v1.1 scope**: Run actual hermes agent inside container

---

### 2. HTTPS/TLS Certificate Chain

**Problem**: Container requests to api.openai.com use HTTPS, proxy has self-signed cert.

**Current solution in code**: `ssl_insecure=True` in proxy Options
**Issue**: This only affects mitmproxy's server mode, NOT container's requests library

**What actually happens**:
```
Container: requests.get('https://api.openai.com')
    ↓ (via HTTP_PROXY=http://host:8443)
Proxy intercepts HTTPS CONNECT
    ↓
Proxy presents self-signed cert for api.openai.com
    ↓
Container's requests library: SSLError - certificate verify failed
    ↓
Request FAILS
```

**Solutions**:

A. **Disable SSL verification in container** (insecure but functional)
```python
# In container:
import requests
requests.get('https://api.openai.com', verify=False)
```
- Pro: Works immediately
- Con: Defeats purpose of HTTPS, bad practice

B. **Install mitmproxy CA cert in container** (secure and proper)
```dockerfile
# Copy mitmproxy CA cert into container
COPY mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/
RUN update-ca-certificates
```
- Pro: Proper solution
- Con: Need to export proxy's CA cert first

C. **Use HTTP_PROXY for http:// only** (limited)
```python
# Only proxy HTTP, let HTTPS go direct
# But then we can't inject keys into HTTPS LLM calls
```
- Pro: No cert issues
- Con: Defeats the whole purpose (LLM APIs are HTTPS)

**Recommendation**: **Option B - Install CA cert**

**Implementation steps**:
1. Start proxy once to generate CA cert (~/.mitmproxy/mitmproxy-ca-cert.pem)
2. Copy into container during build
3. Update Dockerfile to trust it
4. Test: curl https://api.openai.com from container should work

---

### 3. Workspace Security Confusion

**Problem in TIER2-PLAN.md line 84**:
```python
workspace = Path.cwd()  # Use current directory as workspace
```

**Issue**: If user runs `hermes-aegis run` from their home directory, it mounts EVERYTHING:
- ~/.ssh/
- ~/Documents/
- ~/.hermes/ (including non-encrypted config!)

**This defeats the isolation!**

**Solutions**:

A. **Require explicit workspace argument**
```python
@main.command()
@click.option('--workspace', type=click.Path(), default='/tmp/aegis-workspace')
def run(ctx, workspace, command):
    # Use specified workspace, not cwd
```
- Pro: Safe by default
- Con: Extra argument friction

B. **Create isolated workspace automatically**
```python
workspace = ARMOR_DIR / "workspace"
workspace.mkdir(exist_ok=True)
# Copy command or script into workspace first
```
- Pro: Zero friction
- Con: User's files not accessible by default

C. **Warn if running from sensitive directory**
```python
if Path.cwd() == Path.home():
    click.echo("WARNING: Running from home directory will mount everything!")
    if not click.confirm("Continue?"):
        sys.exit(1)
```
- Pro: User controls trade-off
- Con: Easy to click through

**Recommendation**: **Option A + B hybrid**
- Default: `~/.hermes-aegis/workspace` (isolated)
- Optional: `--workspace /path/to/project` for specific projects
- Warning if workspace contains ~/.ssh or ~/.hermes

---

### 4. Container Image Dependencies

**From TIER2-PLAN.md Task 6.1 Dockerfile**:
```dockerfile
RUN pip install --no-cache-dir requests urllib3
```

**Gap**: What else does a typical agent workflow need?

**Minimal viable container must have**:
- Python 3.11+ ✅
- requests/urllib3 ✅
- NO curl/wget/netcat ✅
- Standard library ✅

**But for real workflows might need**:
- git (for repository tools)
- common packages (pandas, numpy, etc.)
- SDK clients (boto3 for AWS, etc.)

**Dilemma**: 
- Minimal = secure but limited functionality
- Full deps = useful but larger attack surface

**Recommendation for MVP**:
- Ship minimal image (python + requests only)
- Document that users can build custom images: `FROM hermes-aegis:latest`
- Test with ONLY simple HTTP requests (proves isolation)

---

### 5. Network Policy Contradiction

**From TIER2-PLAN.md Task 6.2**:
```python
# Option 1: Restrict DNS
"dns": [config.proxy_host],

# OR: Option 2: No network
"network_mode": "none",
```

**Issue**: These are mutually exclusive, plan doesn't choose one.

**Analysis**:

**Option 1: DNS through proxy**
- Pro: Container can make network calls (through proxy)
- Con: DNS queries might not route through proxy (depends on implementation)
- Con: Container can still make direct connections

**Option 2: No network + selective access**
- Use: `network_mode: "none"` + attach to specific network later
- Pro: Complete isolation by default
- Con: Complex, might break things

**Option 3: Network with egress filtering** (Docker doesn't support this easily)

**Recommendation**: **Option 1 with documentation**
- Use normal network + proxy
- Document that container CAN make direct connections (bypass proxy)
- This is acceptable for MVP (proves key injection works)
- v1.1 can add strict network policies (iptables, Calico, etc.)

---

### 6. Proxy Startup Race Condition

**Problem**: 
```python
proxy_thread = start_proxy(...)
time.sleep(1)  # Give proxy time to bind
```

**Issue**: Race condition - proxy might take >1s or fail silently

**Better approach**:
```python
proxy_thread = start_proxy(...)
if not wait_for_proxy_ready(port=8443, timeout=5):
    raise RuntimeError("Proxy failed to start - check if port is in use")
```

**But wait_for_proxy_ready() checks localhost** - container connects to host.docker.internal

**Need TWO checks**:
1. Host check: Is proxy listening on localhost:8443?
2. Container check: Can container reach host.docker.internal:8443?

**Implementation**:
```python
# After proxy starts:
assert_proxy_listening_on_host(8443)

# After container starts:
exit_code = runner.exec(['python', '-c', 
    'import socket; s=socket.socket(); s.connect(("host.docker.internal", 8443))'])
assert exit_code == 0, "Container cannot reach proxy"
```

---

### 7. Error Handling & Cleanup

**Current plan has no error handling**:
```python
proxy_thread = start_proxy(...)
runner = ContainerRunner(...)
runner.start()
exit_code = runner.exec(command)  # What if this throws?
runner.stop()  # Never reached!
```

**Should be**:
```python
proxy_thread = None
runner = None

try:
    proxy_thread = start_proxy(...)
    runner = ContainerRunner(...)
    runner.start()
    exit_code = runner.exec(command)
finally:
    if runner is not None:
        try:
            runner.stop()
        except Exception as e:
            click.echo(f"Warning: Container cleanup failed: {e}")
    
    # Proxy thread is daemon, will die with process
    # But could add explicit shutdown if needed
```

---

### 8. Integration Test Complexity

**Task 7.1 says**:
```python
# 3. Run: hermes chat -q "What's 2+2?" 
```

**Problems with this**:
1. Hermes agent not in container (see Gap #1)
2. Hermes needs config file (~/.hermes/config.yaml)
3. Hermes needs model access (Ollama server at 192.168.1.112:11434)
4. Container would need network to reach Ollama server
5. This is testing HERMES functionality, not AEGIS isolation

**Better integration test** (simpler, proves isolation):
```python
def test_tier2_proves_isolation_end_to_end():
    """
    Container tries to exfiltrate secret via HTTP.
    Proxy blocks it. Secret never reaches test server.
    
    This proves the architecture works WITHOUT needing full hermes agent.
    """
    # 1. Python script in workspace tries to exfil
    # 2. Run via hermes-aegis run python exfil.py
    # 3. Verify script ran but request blocked
    # 4. Verify test server never received secret
```

**This is sufficient for MVP** - proves isolation works. Full hermes-in-container is v1.1.

---

## REVISED TIER 2 PLAN (Executable)

### Phase 5: Orchestration (4-6 hours)

**Task 5.1**: Complete CLI run command
- Add try/finally error handling
- Use wait_for_proxy_ready() with proper checks
- Default workspace to ~/.hermes-aegis/workspace (isolated)
- Add --workspace argument for custom paths
- Warn if mounting sensitive directories

**Task 5.2**: Add container exec method
- Implement exec() in ContainerRunner
- Handle streaming output
- Return exit code
- Add test (mocked docker client)

**Task 5.3**: Proxy health checks
- Implement wait_for_proxy_ready()
- Check from host perspective (localhost:8443)
- Check from container perspective (host.docker.internal:8443)

### Phase 6: Container Image (2-3 hours)

**Task 6.1**: Build minimal Python image
- Base: python:3.11-alpine
- Install: requests, urllib3 only (minimal)
- Add: non-root user `hermes`
- Add: mitmproxy CA certificate for HTTPS
- Test: Build succeeds, no exfil tools present

**Task 6.2**: Export and install mitmproxy CA cert
- Start proxy once to generate cert (~/.mitmproxy/mitmproxy-ca-cert.pem)
- Copy into Dockerfile
- Update CA trust store in container
- Test: curl https://example.com works from container

### Phase 7: Integration Testing (3-4 hours)

**Task 7.1**: Simple isolation test (NOT full hermes)
- Python script tries HTTP exfil
- Run via hermes-aegis run
- Verify blocked by proxy
- Verify secret never reaches test server

**Task 7.2**: Key injection test
- Python script calls mock OpenAI API
- No key in script or env
- Verify proxy injects key
- Verify request succeeds

**Task 7.3**: Bypass prevention tests
- Test DNS (should fail or be restricted)
- Test raw socket (should fail - no CAP_NET_RAW)
- Test curl subprocess (should fail - not in image)
- Test file write (should fail outside workspace)

### Phase 8: Red Team (2-3 hours)

**Task 8.1**: Create malicious script
- Tries all bypass techniques
- Runs inside container
- Documents what works/doesn't

**Task 8.2**: Document results
- Update WHY-WE-DONT-BLOCK.md with Tier 2 results
- Update README with Tier 2 protection matrix

---

## WHAT'S MISSING FROM CURRENT PLAN

### Must Fix Before Building:

1. ✅ **Workspace isolation** - Default to safe directory, warn about home
2. ✅ **CA certificate setup** - Document how to install mitmproxy cert
3. ✅ **Error handling** - try/finally cleanup blocks
4. ✅ **Proxy health checks** - Host + container perspective
5. ✅ **Integration test scope** - Don't require full hermes agent

### Can Be Simplified:

6. ✅ **Network policy** - Use normal network + proxy (not "none" mode)
7. ✅ **Container dependencies** - Minimal image sufficient for MVP
8. ✅ **Test complexity** - Prove isolation, not full agent functionality

### Optional Enhancements (v1.1+):

9. ⏸️ Full hermes agent in container (complex, defer to v1.1)
10. ⏸️ DNS monitoring (requires custom resolver)
11. ⏸️ Performance benchmarks (nice to have)

---

## BLOCKING ISSUES IDENTIFIED

### 🔴 CRITICAL: CA Certificate Problem

**Impact**: Without mitmproxy CA cert, HTTPS requests from container WILL FAIL

**Solution Required**:
1. Setup phase: Start proxy once, export CA cert
2. Container build: COPY cert, update-ca-certificates  
3. Test: Verify HTTPS works from container

**This is NON-OPTIONAL** - without it, Tier 2 is broken.

**Implementation complexity**: Medium (need to generate cert, copy to image, trust it)

### 🟡 MEDIUM: Workspace Mounting Risk

**Impact**: Mounting home directory exposes secrets, defeats isolation

**Solution Required**:
- Default to isolated workspace
- Validate workspace path (reject ~/.ssh, ~/.hermes, ~/)
- Add explicit --workspace flag

**Implementation complexity**: Low (validation logic)

### 🟢 LOW: Error Handling

**Impact**: Container/proxy might leak if cleanup fails

**Solution Required**:
- try/finally blocks in CLI run
- Graceful degradation

**Implementation complexity**: Low (standard Python patterns)

---

## DEPENDENCIES & PREREQUISITES

### External Dependencies (Already Met)
- ✅ Docker Desktop running
- ✅ mitmproxy installed (in deps)
- ✅ python-docker library installed

### Code Dependencies (Already Built)
- ✅ Proxy addon working (tested)
- ✅ Container runner working (tested)
- ✅ Vault with secrets (tested)

### Missing Prerequisites
- ❌ mitmproxy CA certificate exported
- ❌ Container image with CA cert  
- ❌ Workspace isolation validation
- ❌ Error handling in CLI

---

## CONTEXT REQUIRED FOR IMPLEMENTATION

### Files to read before starting:
1. `src/hermes_aegis/proxy/runner.py` - Proxy startup
2. `src/hermes_aegis/container/runner.py` - Container lifecycle
3. `src/hermes_aegis/cli.py` lines 210-214 - Current placeholder
4. `tests/test_proxy_addon.py` - How proxy works
5. `tests/test_container.py` - How container config works

### Key decisions documented:
1. Workspace defaults to ~/.hermes-aegis/workspace (isolated)
2. Container image is minimal (python + requests only)
3. Integration tests use simple scripts, NOT full hermes agent
4. CA certificate must be handled (non-optional)
5. Error handling with try/finally (non-optional)

### External references needed:
1. mitmproxy CA cert export: `~/.mitmproxy/mitmproxy-ca-cert.pem`
2. Docker exec_run API: https://docker-py.readthedocs.io/en/stable/containers.html#docker.models.containers.Container.exec_run
3. Alpine ca-certificates: `apk add ca-certificates`

---

## RISK ASSESSMENT

### Low Risk (Can likely solve during build)
- Container exec method (straightforward Docker API)
- Health check polling (standard pattern)
- Error handling (standard Python)
- Workspace validation (string operations)

### Medium Risk (Might require debugging)
- CA certificate chain (TLS configuration tricky)
- Proxy-container connectivity (networking config)
- Docker build process (credentials, cache)

### High Risk (Might block Tier 2)
- mitmproxy certificate trust in Alpine Linux (might need specific packages)
- Container reaching host.docker.internal (Mac/Windows/Linux differ)
- Proxy SSL handling with Docker (certificates are always painful)

### Mitigation for High Risks
1. **CA cert**: Test manually first (`docker run -it alpine ...`)
2. **host.docker.internal**: Already tested in config, should work
3. **SSL**: Can fall back to HTTP-only for MVP testing (document limitation)

---

## ESTIMATED TIMELINE

**Optimistic** (everything works first try): 8-10 hours
**Realistic** (some debugging needed): 11-16 hours  
**Pessimistic** (SSL/network issues): 20+ hours

**Most likely blocker**: CA certificate setup in container

**Fallback plan**: If CA cert is too painful, test with HTTP-only mock servers for MVP

---

## READINESS ASSESSMENT

**Can we start building Tier 2 now?**

### ✅ Ready to Build (Low Risk)
- Task 5.2: Container exec method
- Task 5.3: Health checks  
- Workspace isolation fixes
- Error handling

### ⚠️ Need Specification Refinement (Medium Risk)
- Task 5.1: CLI orchestration (needs Gap #3 fixed)
- Task 6.1: Container image (needs Gap #1 decided)
- Task 6.2: CA certificate (needs investigation)

### ❌ Need Research First (High Risk)
- SSL/TLS certificate chain (might be painful)
- Integration test scope (simplified to exclude full hermes)

---

## RECOMMENDATION

**Two-phase approach**:

### Phase A: Build Infrastructure (Low Risk - 4-6 hours)
1. Fix workspace isolation (Gap #3)
2. Add container exec method (Task 5.2)
3. Add health checks (Task 5.3)
4. Error handling in CLI
5. Document CA cert limitation for now

**Deliverable**: Code exists, but untested due to CA cert blocker

### Phase B: Solve CA Cert + Integration (Medium Risk - 4-6 hours)
6. Research mitmproxy CA cert export
7. Add to container image
8. Test HTTPS from container
9. Write integration tests
10. Red team validation

**Deliverable**: Fully working Tier 2

**Total: 8-12 hours split into manageable phases**

---

## FINAL VERDICT

**Is TIER2-PLAN.md ready to execute?**

**Answer: 80% ready, needs refinements:**

### Must fix before building:
1. ✅ Documen workspace isolation strategy (Gap #3)
2. ✅ Remove hermes-in-container requirement (Gap #1) 
3. ✅ Specify CA certificate approach (Gap #2)
4. ✅ Choose network policy (Gap #5)
5. ✅ Add error handling specs (Gap #7)

### Can build with current knowledge:
- Container exec method (clear spec)
- Health checks (clear spec)
- CLI orchestration (once Gap #3 fixed)
- Simple integration tests (once Gap #1 scoped)

**Recommendation**: Let me create a REFINED Tier 2 plan that addresses all gaps before we start building.

Should I create TIER2-PLAN-REFINED.md with all gaps addressed and ready-to-execute specs?