# Tier 2 Build Readiness Assessment

**Date**: March 12, 2026 05:45 PM
**Status**: READY TO BUILD

After reading HANDOVER.md, TIER2-PLAN.md, and HERMES-REVIEW.md, here's my assessment:

---

## CONTEXT GAPS: NONE ✅

All critical information is present:

### ✅ Interface Requirements
- BaseEnvironment.execute() signature clear
- BaseEnvironment.cleanup() requirements clear
- DockerEnvironment already exists to wrap
- How Hermes selects backends (TERMINAL_ENV) clear

### ✅ Technical Gotchas Documented
- Hermes uses subprocess, not docker-py (HANDOVER.md #1)
- DockerEnvironment adds caps back (HANDOVER.md #4)
- File operations route through backend (HANDOVER.md #5)
- host.docker.internal may need --add-host on Linux (HANDOVER.md #3)
- 11 failing tests are expected (HANDOVER.md #6)

### ✅ Design Decisions Made
- internal: true network (blocks direct TCP/DNS)
- CA cert mounted as volume (no Dockerfile rebuild)
- Lazy proxy start (first execute, not __init__)
- Strip secrets from env before passing to DockerEnvironment
- Auto port selection (8443-8500)
- Graceful fallback to Tier 1 if no Docker

### ✅ Implementation Code Provided
- AegisEnvironment skeleton (TIER2-PLAN.md Phase 1)
- find_available_port() implementation
- wait_for_proxy_ready() implementation
- ensure_mitmproxy_ca_cert() implementation
- All test fixtures defined

---

## CONCERNS: 3 MEDIUM, 0 BLOCKING

### Concern #1: CA Certificate Workflow (Medium)

**Issue**: Generating mitmproxy CA cert requires starting mitmdump once

**From TIER2-PLAN.md Task 3.1**:
```python
subprocess.Popen(["mitmdump", "--set", "listen_port=0"])
time.sleep(2)
proc.terminate()
```

**Concern**: What if mitmdump isn't in PATH? What if it hangs?

**Mitigation**: 
- Check `shutil.which("mitmdump")` first
- Add timeout to Popen.wait()
- If fails, fallback to Tier 1 with warning

**Verdict**: Can handle during build, not blocking

### Concern #2: DockerEnvironment Wrapping (Medium)

**Issue**: Need to wrap mini-swe-agent's DockerEnvironment (line 84 of docker.py):
```python
from minisweagent.environments.docker import DockerEnvironment as _Docker
```

**Concern**: mini-swe-agent might not be importable from our code

**From TIER2-PLAN.md Phase 1**:
```python
from tools.environments.docker import DockerEnvironment
# Use Hermes's DockerEnvironment, not mini-swe-agent directly
```

**Mitigation**: Import from tools.environments.docker (Hermes's wrapper), not minisweagent directly

**Verdict**: Already addressed in plan, not blocking

### Concern #3: Integration Test Fixtures (Medium)

**Issue**: Tests need `aegis_container` fixture that provides AegisEnvironment instance

**From TIER2-PLAN.md lines 729-737**:
```python
@pytest.fixture
def aegis_container(tmp_path):
    env = AegisEnvironment(image="python:3.11-slim", cwd=str(tmp_path / "workspace"), timeout=30)
    yield env
    env.cleanup()
```

**Concern**: This fixture needs to:
- Create vault with test secrets
- Ensure workspace exists
- Handle Docker not available (skip test)
- Clean up proxy thread

**Mitigation**: Write comprehensive fixture in tests/integration/conftest.py first

**Verdict**: Clear requirement, code examples provided, not blocking

---

## PLAN QUALITY ASSESSMENT

### ✅ Strengths

1. **Phased approach**: 7 distinct phases, clear dependencies
2. **Code examples**: Every phase has concrete implementation code
3. **Test-first**: Integration tests specified before building
4. **Honest scope**: Doesn't try to run full hermes in container (simplified for MVP)
5. **Error handling**: try/finally, health checks, fallbacks
6. **Attack coverage**: 9 specific attack scenarios in red team test

### ✅ Completeness

- ✅ Task ordering clear (dependency graph in TIER2-PLAN.md line 702)
- ✅ File locations specified for every change
- ✅ Test expectations defined
- ✅ Success criteria explicit (Definition of Done)
- ✅ What NOT to do documented (HANDOVER.md line 139)

### ✅ Testability

Every phase has concrete verification:
- Phase 1: Test execute() returns output ✅
- Phase 2: Test direct TCP fails ✅
- Phase 3: Test HTTPS through proxy works ✅
- Phase 4: Test patterns match RPC URLs ✅
- Phase 5: 6 integration tests specified ✅
- Phase 6: Test graceful fallback ✅
- Phase 7: Red team script with 9 attacks ✅

---

## POTENTIAL BLOCKERS & MITIGATIONS

### 1. mitmproxy Not in Environment

**Risk**: mitmdump command not available
**Check**: `shutil.which("mitmdump")`
**Mitigation**: Install via `pip install mitmproxy` or fail gracefully to Tier 1
**Likelihood**: LOW (already in dependencies)

### 2. Docker Permissions

**Risk**: Docker socket not accessible (Linux non-root user)
**Check**: `docker ps` in pre-flight
**Mitigation**: Clear error message, fallback to Tier 1
**Likelihood**: LOW (Docker Desktop on Mac)

### 3. host.docker.internal on Linux

**Risk**: Doesn't resolve on native Linux Docker
**Check**: Platform detection
**Mitigation**: Use `--add-host host.docker.internal:hostgateway` 
**Likelihood**: LOW (Mac environment per git log paths)

### 4. CA Cert Trust Chain

**Risk**: Mounting cert might not be sufficient, might need update-ca-certificates
**Check**: Test HTTPS request from container in Phase 3
**Mitigation**: If mounting fails, add update-ca-certificates to Dockerfile
**Likelihood**: MEDIUM (TLS is always finicky)

**Fallback**: Use HTTP for MVP testing, document HTTPS as v1.1

---

## ESTIMATED BUILD TIME

**Optimistic** (everything works first try): 6-8 hours
**Realistic** (some debugging): 9-12 hours
**Pessimistic** (SSL issues, network issues): 15-18 hours

**Most likely timeline**: 10-12 hours with normal debugging

**Critical path**: Phase 1 → Phase 2 → Phase 3 → Phase 5
**Can parallelize**: Phase 4 (patterns) and Phase 6 (vault import) any time

---

## MISSING INFORMATION: NONE

All questions from TIER2-GAPS.md are answered in TIER2-PLAN.md:

- ✅ Gap #1 (hermes in container): Simplified - just prove isolation
- ✅ Gap #2 (CA cert): Mount as volume + env vars
- ✅ Gap #3 (workspace): Isolated default workspace
- ✅ Gap #5 (network policy): internal: true network
- ✅ Gap #7 (error handling): try/finally specified

---

## COMMIT STRATEGY

Per HANDOVER.md line 129:

**✅ Clear**:
- One commit per phase (or per task if large)
- Run `uv run pytest tests/ -q` before every commit
- Format: `feat:` / `fix:` / `test:`
- Never push
- 11 Docker failures expected until complete

**No ambiguity**. Can execute.

---

## COMPARISON TO TIER 1 BUILD

**Tier 1 build** (just completed):
- Had gaps (approval.py relationship unclear, testing scope undefined)
- Discovered issues during build (vault API, master_key requirement)
- Required mid-flight decisions (simplify Docker tests, add real HTTP server)
- **Result**: Success, but iterative discovery

**Tier 2 build** (about to start):
- No gaps (all design decisions made)
- Gotchas pre-documented (subprocess vs docker-py, caps added back)
- Test fixtures specified upfront
- Fallback plan clear (HTTP if HTTPS fails)
- **Expected**: Smoother build, less discovery

---

## HERMES-REVIEW.md LESSONS APPLIED

### ✅ Will Follow

1. **Test first** - Write failing test, implement, verify (REVIEW.md #4)
2. **Real integration tests** - Don't mock the security boundary (REVIEW.md #7)
3. **Honest reporting** - Paste actual test output (REVIEW.md #2, HERMES-LESSONS.md)
4. **No batch commits** - One feature per commit (REVIEW.md #4)
5. **Skip gracefully** - `@pytest.mark.skipif` for Docker tests (REVIEW.md #4)

### ✅ Will NOT Do

1. **Mock Docker/proxy** - Integration tests use real containers (REVIEW.md #7)
2. **Guess when stuck** - Document blockers, move to parallel task (REVIEW.md #5)
3. **Gut code during fixes** - Minimal changes only (REVIEW.md #2)
4. **Fabricate status** - Run commands, report actual output (HERMES-LESSONS.md)

---

## PRE-FLIGHT CHECKS

```bash
# Will run these before starting:
shutil.which("docker")          # Docker available?
shutil.which("mitmdump")        # mitmproxy available?
docker ps                       # Docker daemon running?
docker network ls               # Can create networks?
git status                      # Clean working tree?
uv run pytest tests/ -q         # Baseline test count?
```

---

## FINAL VERDICT

**Ready to build: YES** ✅

**Why**:
1. All context gaps filled
2. Interface requirements clear
3. Design decisions made
4. Code examples provided
5. Test expectations defined
6. Gotchas documented
7. Fallback plans specified
8. No blocking unknowns

**Confidence level**: 85%

**Expected issues**: CA certificate trust (medium complexity), but fallback plan exists

**Estimated duration**: 10-12 hours

**Recommended approach**:
1. Start with Phase 1 (AegisEnvironment) - 2 hours
2. Test Phase 1 in isolation - 30 min
3. Add Phase 2 (network) + Phase 3 (cert) - 2 hours
4. Test Phases 1-3 together - 1 hour
5. If working: Continue to Phase 5 (integration tests)
6. If blocked: Document blocker, complete Phase 4+6 (patterns/vault)

---

## PROCEED?

**Ready when you are.** I have:
- ✅ Read all three files
- ✅ Understood Hermes interface
- ✅ Identified no blocking gaps
- ✅ Internalized lessons from HERMES-REVIEW.md
- ✅ Committed to honest reporting
- ✅ Clear on what not to do

**Command to start**: "Proceed with Tier 2 build"

**I will**:
- Follow TIER2-PLAN.md phases exactly
- Write tests before code (TDD)
- Run actual commands and paste actual output
- Commit per phase with clean messages
- Document blockers if stuck
- Not modify Hermes source files

**Ready to build Tier 2.**
