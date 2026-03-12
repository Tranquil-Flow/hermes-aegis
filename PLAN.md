# Hermes-Aegis MVP Plan

**Goal**: Working security layer that actually blocks attacks, verified with real tests.
**Status**: ~65% built. Core architecture is sound. Several components are broken or untested against real scenarios.

---

## Phase 1: Fix What's Broken

Commit each fix individually. Run `uv run pytest tests/ -q` after each. Do not proceed to Phase 2 until all tests pass.

### Task 1.1 — Fix AuditTrailMiddleware (CRITICAL)
**File**: `src/hermes_aegis/middleware/audit.py`
**Problem**: Middleware is a no-op stub — doesn't log anything. Test expects 2 entries, gets 0.
**What to do**:
- Restore `pre_dispatch` to call `self.trail.log()` with decision="INITIATED"
- Restore `post_dispatch` to call `self.trail.log()` with decision="COMPLETED"
- Before logging args, run them through `scan_for_secrets()` from `patterns/secrets.py`. Replace any matching values with `[REDACTED]`
- Inherit from `ToolMiddleware` for interface consistency
- Run `uv run pytest tests/test_middleware.py -v` — all tests must pass including `test_logs_pre_and_post`

### Task 1.2 — Fix Proxy Runner (CRITICAL)
**File**: `src/hermes_aegis/proxy/runner.py`
**Problem**: `master.run()` is a coroutine in mitmproxy 10.x. Called synchronously, proxy never starts.
**What to do**:
- Change `master.run()` to `asyncio.run(master.run())` inside the thread target
- Add `import asyncio` at top of `_run()`
- Run `uv run pytest tests/test_proxy.py -v`

### Task 1.3 — Commit the Good Uncommitted Fixes
**Problem**: Working tree has mixed good/bad changes. Separate and commit the good ones.
**What to do**:
- After Tasks 1.1 and 1.2, stage and commit all changes together
- Commit message: `fix: restore audit logging with redaction, fix async proxy runner, clean up genesis hash and NEEDS_APPROVAL`
- Verify: `uv run pytest tests/ -q` — all 71+ tests pass

---

## Phase 2: Complete Missing Components

These are from the original Tasks 14-20 but scoped to what an MVP actually needs.

### Task 2.1 — Tier 1 Outbound Content Scanner
**Files**: New file `src/hermes_aegis/tier1/scanner.py`
**What to build**:
- Monkey-patch `urllib3.HTTPConnectionPool.urlopen` to intercept all outbound HTTP
- Before sending, scan request body and headers with `scan_for_secrets()`
- If secrets found: block the request, log to audit trail, raise `SecurityError`
- If clean: allow through
**Test**: Write a test that makes an HTTP request containing an AWS key in the body. Verify it's blocked. Write a test with clean content. Verify it passes.
**Important**: This is best-effort, not bulletproof. Document that raw sockets bypass this.

### Task 2.2 — Container Resource Limits
**File**: `src/hermes_aegis/container/builder.py`
**What to add**:
- `mem_limit: "512m"` in container config
- `cpu_quota: 50000` with `cpu_period: 100000` (50% of one core)
- `pids_limit: 256` (already exists, verify)
**Test**: Verify config dict contains these keys with correct values.

### Task 2.3 — CLI `run` Command
**File**: `src/hermes_aegis/cli.py`
**What to build**:
- `hermes-aegis run <command>` — wraps a hermes agent invocation with the security layer
- Tier 1: Install middleware chain, start content scanner, then exec the command
- Tier 2: Build container if needed, start proxy, run command inside container
- On exit: print audit summary (total calls, blocked calls, redacted calls)
**Test**: Unit test that verifies `run` sets up middleware and calls through. Integration test deferred to Phase 3.

### Task 2.4 — Audit Viewer
**File**: `src/hermes_aegis/cli.py` (add subcommand)
**What to build**:
- `hermes-aegis audit show` — print audit trail entries (last 20 by default, `--all` for everything)
- `hermes-aegis audit verify` — verify hash chain integrity, print pass/fail
- Output format: timestamp, tool name, decision, middleware (one line per entry)
**Test**: Write entries, then verify `audit show` output matches. Tamper with file, verify `audit verify` catches it.

---

## Phase 3: Real Security Tests (No Theatre)

These tests verify that hermes-aegis actually stops attacks. No mocking the security boundary.

### Task 3.1 — Exfiltration via HTTP Request Body
**File**: `tests/security/test_exfiltration.py`
**Setup**: Install Tier 1 scanner. Load a secret into the vault.
**Attack**: Use `requests.post()` to send the vault secret to an external URL.
**Expected**: Request is blocked. Secret never leaves the process. Audit trail records the block.
**How**: Use `responses` library or `httpretty` to mock the destination — but the scanner itself must be real, not mocked.

### Task 3.2 — Exfiltration via HTTP Headers
**File**: `tests/security/test_exfiltration.py`
**Setup**: Same as 3.1.
**Attack**: Put the secret in a custom header (`X-Data: <secret>`).
**Expected**: Blocked. Logged.

### Task 3.3 — Exfiltration via Base64 Encoding
**File**: `tests/security/test_exfiltration.py`
**Setup**: Same as 3.1.
**Attack**: Base64-encode the secret, send in request body.
**Expected**: Encoding-aware scanner catches it. Blocked.

### Task 3.4 — Secret Leakage in Tool Arguments
**File**: `tests/security/test_audit_redaction.py`
**Setup**: Configure middleware chain with audit + redaction middleware.
**Attack**: Dispatch a tool call where one argument contains an API key.
**Expected**: Audit trail logs the call. The `args_redacted` field shows `[REDACTED]`, not the actual key. Verify by reading the audit file and asserting the raw key string is NOT present anywhere in it.

### Task 3.5 — Audit Trail Tampering
**File**: `tests/security/test_audit_integrity.py`
**Setup**: Write 10 audit entries via normal operation.
**Attack 1**: Delete one entry from the middle of the file. Run `verify_chain()`. Expect `False`.
**Attack 2**: Modify one entry's `tool_name`. Run `verify_chain()`. Expect `False`.
**Attack 3**: Append a forged entry with wrong `prev_hash`. Run `verify_chain()`. Expect `False`.
**Attack 4**: Reorder two entries. Run `verify_chain()`. Expect `False`.

### Task 3.6 — Middleware Chain Bypass Attempt
**File**: `tests/security/test_middleware_bypass.py`
**Setup**: Configure chain with a middleware that DENYs all calls to `dangerous_tool`.
**Attack 1**: Call `dangerous_tool` through the chain. Expect DENY.
**Attack 2**: Call a tool, and in the result, include content that looks like a tool call to `dangerous_tool`. Verify the chain doesn't execute it (no prompt injection via results).
**Attack 3**: Register middleware after chain is built. Verify it's included (or explicitly rejected — either is fine, but document which).

### Task 3.7 — Container Secret Isolation (Tier 2, skip if no Docker)
**File**: `tests/security/test_container_isolation.py`
**Mark**: `@pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")`
**Setup**: Store secrets in vault. Build and start container.
**Attack**: Inside container, check all environment variables. None should contain vault secrets.
**Attack**: Inside container, try to read `~/.hermes-aegis/vault.enc`. File should not exist.
**Expected**: Container has zero access to secrets. Secrets only exist on host side.

### Task 3.8 — Proxy API Key Injection Verification (Tier 2, skip if no Docker)
**File**: `tests/security/test_proxy_injection.py`
**Mark**: `@pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")`
**Setup**: Start proxy with a test API key for OpenAI. Send request from container to `api.openai.com`.
**Expected**: Proxy intercepts request, injects `Authorization` header with the key. Container never sees the key value.
**How**: Use a local HTTP echo server instead of hitting real OpenAI. Verify the echo server received the injected header.

---

## Phase 4: Polish for MVP Release

### Task 4.1 — Commit Uncommitted Work
- After Phase 3, all tests should pass
- Commit everything with clear messages
- Update AUTONOMOUS-PROGRESS.md with actual test output

### Task 4.2 — Update README
- Installation: `uv pip install -e .`
- Quick start: `hermes-aegis setup` then `hermes-aegis run <command>`
- What it protects against (honest list, no overclaims)
- What it does NOT protect against (Tier 1 limitations, raw socket bypass)

### Task 4.3 — Clean Up Docs
- Remove or archive: HANDOVER-TO-MOONDANCE.md (no longer needed post-MVP)
- Remove: OVERNIGHT-RUN-PROMPT.md, HANDOFF-TO-QWEN.md (process artifacts)
- Keep: DESIGN.md, HERMES-LESSONS.md, this PLAN.md
- Remove: IMPLEMENTATION-PLAN.md (114KB — too large, superseded by this plan)

### Task 4.4 — Final Test Run
- `uv run pytest tests/ -v` — paste full output
- `uv run pytest tests/security/ -v` — paste full output
- Count: X unit tests, Y security tests, all passing
- Note any skipped tests (Docker not available, etc.)

---

## Definition of Done

MVP is done when:
- [ ] All Phase 1 fixes committed and tests pass
- [ ] Tier 1 outbound scanner blocks secrets in HTTP requests (tested)
- [ ] CLI `run` command works for Tier 1 flow
- [ ] Audit viewer shows entries and verifies chain integrity
- [ ] Security tests 3.1-3.6 all pass (these don't need Docker)
- [ ] Security tests 3.7-3.8 pass if Docker available, skip cleanly if not
- [ ] README honestly describes what's protected and what isn't
- [ ] Zero test failures in `uv run pytest tests/ -v`
