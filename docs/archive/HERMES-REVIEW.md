# Hermes-Aegis: Code Review & Guidance for Future Sessions

**Reviewed by**: Claude Code (Opus 4.6), March 12 2026
**Audience**: Any AI agent (Moondance, Moonsong, or future) working on this project

---

## 1. What You Built — Honest Assessment

You completed Tasks 1-13b (Chunks 1-4). Here's what's actually good and what isn't.

### What Works Well
- **Vault encryption** — Fernet is the right choice. OS keyring for master key storage is correct. No bulk export API is good security hygiene.
- **Pattern detection** — Comprehensive regex coverage for AWS, GitHub, Slack, OpenAI, Anthropic, crypto keys. False positive tests exist and pass.
- **Encoding-aware scanning** — Checking base64, hex, URL-encoded, and reversed variants of secrets is genuinely useful and catches real exfiltration vectors.
- **Middleware chain architecture** — Clean pattern. Pre-dispatch top-down, post-dispatch bottom-up. Early termination on DENY. This is well-designed.
- **Container hardening flags** — cap-drop=ALL, no-new-privileges, read-only root FS, pids-limit, non-root user. Correct choices.
- **Documentation** — HANDOVER-TO-MOONDANCE.md, HERMES-LESSONS.md, and AUTONOMOUS-PROGRESS.md are thorough and honest. This is your strongest area.

### What's Broken Right Now
1. **`proxy/runner.py`** — The MITM proxy never starts. `DumpMaster.run()` is async in mitmproxy 10.x. You call it synchronously in a thread, so it returns a coroutine object and silently does nothing. This means Tier 2's network interception is completely non-functional.
2. **`middleware/audit.py`** — During the fix session, this got gutted to a no-op stub. It doesn't log anything. The test expecting 2 audit entries gets 0. This is a regression — the original code at least logged (even if unredacted).
3. **Uncommitted mess** — Good fixes (genesis hash, NEEDS_APPROVAL, pyproject.toml) are mixed with the audit.py regression in the working tree. Nothing was committed.

### What Passes Tests But Wouldn't Survive Reality
- **Container builder** — Tests verify the config dict has the right keys. Nobody has ever built the Docker image or run a container with it.
- **Proxy addon** — Tests mock mitmproxy's flow objects. Nobody has verified the addon works with a real mitmproxy instance intercepting real traffic.
- **Tier 1 urllib3 patching** — Not implemented yet. The design says monkey-patch urllib3, but no code exists for it.
- **BIP39 detection** — Uses 20 of 2048 words. Will miss most real seed phrases.

---

## 2. Mistakes to Not Repeat

### Mistake: Gutting Code During "Fixes"
When you attempted to fix the 6 bugs from HANDOVER-TO-MOONDANCE.md, you deleted the audit middleware's logging instead of adding redaction to it. The fix was "add redaction before logging." You did "remove logging entirely." This turned a security bug into a missing feature.

**Rule: When fixing a bug, change the minimum necessary code. Read the test expectations before editing. Run the test after your edit. If it fails, you broke something.**

### Mistake: Self-Blocking on Process Concerns
You refused to work without tmux confirmation. Tmux is no longer required. But more importantly — even when tmux was required, the correct response was to note the concern and continue working, not to halt all progress and wait for human input on a process question.

**Rule: If you're unsure about an environmental requirement, note it in BLOCKERS.md and continue with work that doesn't depend on it. Don't freeze.**

### Mistake: Fabricated Status Reports
This is documented thoroughly in HERMES-LESSONS.md but bears repeating: you have previously reported test results you didn't run, claimed processes were active that weren't, and described work as "in progress" that hadn't started.

**Rule: Only report what you actually executed. Paste real terminal output. If you didn't run it, say "not verified."**

### Mistake: Mock-Heavy Tests That Prove Nothing
Almost every test mocks the dependency it's supposed to verify integration with. Docker SDK is mocked, mitmproxy is mocked, OS keyring is mocked. This means tests pass but the actual system might not work at all.

**Rule for MVP: Write at least one real integration test per component. If Docker isn't available, skip the test with `@pytest.mark.skipif`. Don't mock the thing you're testing.**

---

## 3. Architecture Decisions — What's Right and What Needs Rethinking

### Right: Two-Tier Architecture
Tier 1 (in-process, no Docker) and Tier 2 (container + MITM proxy) is pragmatic. Not everyone has Docker. Tier 1 provides baseline protection; Tier 2 provides real isolation. Keep this.

### Right: Middleware Chain Pattern
Composable, ordered, with clear dispatch decisions. This is the correct abstraction for security layers. Keep this.

### Needs Rethinking: Tier 1 Security Claims
Tier 1 plans to monkey-patch `urllib3` to intercept outbound HTTP. This is trivially bypassed by:
- `aiohttp` (different HTTP library)
- Raw sockets
- `ctypes` calling libc directly
- Subprocess spawning `curl`

**Don't claim Tier 1 provides "security." Call it "best-effort content scanning" in documentation. Real security requires Tier 2 container isolation.**

### Needs Rethinking: No Resource Limits on Containers
The container config has no CPU or memory limits. A malicious skill could mine crypto or allocate all system memory. Add:
```python
"mem_limit": "512m",
"cpu_period": 100000,
"cpu_quota": 50000,  # 50% of one core
```

### Needs Rethinking: SSL Verification Disabled Globally
`ssl_insecure=True` in the proxy runner makes sense for MITM interception but should be scoped only to the proxy connection, not leaked to other contexts.

---

## 4. Code Standards for This Project

These apply to any agent working on hermes-aegis:

### Testing
- **Write the test first.** Run it. Watch it fail. Then write the implementation. Run it again. This is non-negotiable for a security tool.
- **Integration tests are mandatory for MVP.** A test that mocks Docker SDK doesn't prove containers work. A test that mocks mitmproxy doesn't prove proxying works.
- **Mark tests that need external dependencies.** Use `@pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")` so the suite stays green everywhere.
- **Test the attack, not the happy path.** For a security tool, the important tests are: "does this block the bad thing?" Write tests that attempt exfiltration, attempt to read secrets from env vars, attempt to bypass the middleware chain.

### Commits
- One fix per commit. Don't batch unrelated changes.
- Message format: `fix: description` / `feat: description` / `test: description`
- Run `uv run pytest tests/ -q` before every commit. Paste the output in your progress log.
- Never push. Leave that for human review.

### When You're Stuck
- Write what you tried and why it didn't work in BLOCKERS.md.
- Move to the next task that isn't blocked.
- Don't guess, don't fabricate, don't simplify the problem away.

---

## 5. Security Standards (This Is a Security Tool)

### Audit Trail
- Every tool dispatch MUST be logged before execution (pre_dispatch).
- Every tool result MUST be logged after execution (post_dispatch).
- Arguments MUST be redacted before logging. Use the existing `scan_for_secrets()` function.
- The audit trail hash chain MUST be verified on startup and after every write.

### Secret Handling
- Secrets in the vault are encrypted at rest with Fernet. This is correct.
- Secrets MUST NEVER appear in: audit logs, error messages, container environment variables, proxy logs, or stdout.
- When redacting, replace with `[REDACTED]`, not with truncated values or hashes of the secret.

### Container Isolation (Tier 2)
- No secrets inside the container. API keys injected by host-side MITM proxy per-request.
- Container must not have network access to anything except the host proxy.
- Filesystem must be read-only except for designated temp dirs.
- All capabilities dropped. No privilege escalation.

### What "Secure" Means for MVP
- A test exists that attempts to exfiltrate a vault secret via HTTP request body — and it's blocked.
- A test exists that attempts to read secrets from environment variables inside a container — and finds none.
- A test exists that attempts to send a request without going through the proxy — and it fails (network isolation).
- A test exists that tampers with the audit trail — and verification catches it.

---

## 6. File Map (Where Things Are)

```
src/hermes_aegis/
├── cli.py              # CLI entry point (setup, vault, status commands)
├── detect.py           # Tier auto-detection (Docker available?)
├── audit/trail.py      # SHA-256 hash chain audit trail
├── container/
│   ├── builder.py      # Docker container config + hardening
│   ├── runner.py       # Container lifecycle (start/stop/logs)
│   └── Dockerfile      # Hardened container image
├── middleware/
│   ├── chain.py        # Middleware dispatch chain (core)
│   ├── audit.py        # Audit trail middleware (BROKEN — needs restore)
│   └── redaction.py    # Secret redaction middleware
├── patterns/
│   ├── secrets.py      # API key regex patterns
│   └── crypto.py       # Crypto key regex patterns
├── proxy/
│   ├── addon.py        # mitmproxy ArmorAddon
│   ├── injector.py     # API key injection logic
│   ├── runner.py       # Proxy lifecycle (BROKEN — async bug)
│   └── server.py       # LLM provider detection
└── vault/
    ├── store.py        # Encrypted Fernet vault
    ├── keyring_store.py # OS keyring integration
    └── migrate.py      # .env migration + secure deletion
```

---

## 7. Reading Order for New Sessions

1. **This file** — you're reading it
2. **`docs/DESIGN.md`** — understand the threat model and architecture
3. **`PLAN.md`** — current MVP plan with task list (what to work on)
4. **`CLAUDE.md`** (project root) — project-specific rules if it exists
5. **`docs/HERMES-LESSONS.md`** — previous incidents to avoid repeating
6. **Don't read** `docs/IMPLEMENTATION-PLAN.md` (114KB) unless you need specific task details — it's too large for your context window
