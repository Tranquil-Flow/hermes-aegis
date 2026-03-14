# Hermes-Aegis: Autonomous Work with qwen3:30b

**Status**: Ready for autonomous operation
**Model**: qwen3:30b (Ollama @ 192.168.1.112:11434)
**Tests**: 323 passing, 17 skipped
**Last Commit**: c387330 (fix: update version assertion in test to match v0.1.1)

---

## System State

### Project Status
- All core features implemented and tested
- CLI fully functional with all commands
- Proxy, vault, audit, middleware, patterns all working
- Version 0.1.1 released

### What's Ready
- ✓ Encrypted vault with keyring backend
- ✓ MITM proxy with request/response inspection
- ✓ Secret detection (API keys, tokens, crypto keys)
- ✓ Audit trail with tamper-proof hash chain
- ✓ Hot-reload configuration
- ✓ Domain allowlist management
- ✓ CLI with all commands functional
- ✓ 323 comprehensive tests

### Model Access
```bash
# Ollama server: http://192.168.1.112:11434
# Model available: qwen3:30b
# Test command:
curl -s http://192.168.1.112:11434/api/generate -d '{"model":"qwen3:30b","prompt":"test","stream":false}'
```

---

## Autonomous Work Opportunities

The project is FEATURE-COMPLETE for v0.1.1. Autonomous work should focus on:

### 1. Code Quality & Refinement
- Review all source files for optimization opportunities
- Check for edge cases in existing tests
- Identify potential race conditions or error handling gaps
- Documentation improvements (inline comments, docstrings)

### 2. Security Hardening Review
- Review pattern detection for false positive/negative cases
- Test edge cases in secret detection
- Verify hash chain integrity under various failure scenarios
- Stress test the proxy with concurrent requests

### 3. Performance Testing
- Benchmark proxy latency under load
- Test with large request/response bodies
- Memory usage profiling
- CPU usage during pattern scanning

### 4. Integration Testing
- End-to-end workflows with actual Hermes Agent (if available)
- Test with various LLM providers through the proxy
- Vault secret rotation scenarios
- Docker container isolation testing

### 5. Documentation
- User guide refinement
- Troubleshooting guide based on actual issues
- Architecture diagrams
- Security model documentation

---

## Running Autonomous Jobs with qwen3:30b

### Test Command Format
```python
schedule_cronjob(
    name="aegis-qwen-test",
    prompt=\"\"\"You are working on the hermes-aegis security project.

LOCATION: /workspace/Projects/hermes-aegis

CURRENT STATE:
- Version 0.1.1, fully implemented
- 323 tests passing
- All core features working
- Git repo at commit c387330

YOUR GOAL: [Specific task here]

INSTRUCTIONS:
1. Read current codebase state
2. Run full test suite to verify baseline
3. [Specific work instructions]
4. Verify all tests still pass
5. Commit with descriptive message
6. Report results with actual test output

CONSTRAINTS:
- Stay within the repo (no external file modifications)
- Run actual tests, report literal output
- No fabricated progress
- Commit format: "type: description"
- Author: Tranquil-Flow <tranquil_flow@protonmail.com>

VERIFICATION:
- Run: uv run pytest tests/ -q
- Show: git log --oneline -3
- Report: Literal test output and commit hashes
\"\"\",
    schedule="30s",  # Test run
    deliver="origin"
)
```

### Example Tasks for Autonomous Work

**Task A: Security Pattern Review**
```
GOAL: Review and enhance secret detection patterns

WORK:
1. Review src/hermes_aegis/patterns/secrets.py
2. Test against edge cases (base64 encoding, URL encoding, etc.)
3. Add any missing common API key patterns
4. Verify tests cover all patterns
5. Commit improvements if any found
```

**Task B: Performance Profiling**
```
GOAL: Profile proxy performance and identify bottlenecks

WORK:
1. Create performance test script
2. Measure proxy latency with concurrent requests
3. Profile pattern matching overhead
4. Document findings
5. Commit performance test script
```

**Task C: Documentation Pass**
```
GOAL: Review and improve inline documentation

WORK:
1. Check all src/*.py files for missing docstrings
2. Add docstrings to public functions/classes
3. Improve complex function comments
4. Verify examples in docs/ are accurate
5. Commit documentation improvements
```

---

## Verification Protocol

Before claiming any work complete, ALWAYS run:

```bash
# 1. Model is accessible
curl -s http://192.168.1.112:11434/api/ps

# 2. Tests pass
cd /workspace/Projects/hermes-aegis
uv run pytest tests/ -q --tb=no

# 3. Git state
git status --short
git log --oneline -5

# 4. No uncommitted critical changes
git diff --name-only

# 5. Verify commit author
git log -1 --format='%an <%ae>'
```

Expected outputs:
- Model: qwen3:30b may or may not be loaded (loads on first use)
- Tests: "323 passed, 17 skipped"
- Author: "Tranquil-Flow <tranquil_flow@protonmail.com>"

---

## Critical Rules for Autonomous Work

1. **NO FABRICATION**: Report only actual command output
2. **VERIFY BEFORE CLAIMING**: Run tests, check results
3. **STAY IN REPO**: No modifications outside /workspace/Projects/hermes-aegis
4. **COMMIT FREQUENTLY**: After each meaningful change
5. **USE GIT CONFIG**: 
   ```bash
   git config user.name "Tranquil-Flow"
   git config user.email "tranquil_flow@protonmail.com"
   ```
6. **NO FEATURE CREEP**: Focus on requested task only
7. **REPORT BLOCKERS**: If stuck >30min, document and move on
8. **TEST FIRST**: Verify baseline before starting work

---

## Current Git Configuration

```bash
cd /workspace/Projects/hermes-aegis
git config user.name "Tranquil-Flow"
git config user.email "tranquil_flow@protonmail.com"
```

---

## Next Steps

The project is ready for autonomous operation. Suggested workflow:

1. **Run short test job** (5-10 min) to verify qwen3:30b handles the codebase
2. **Review results** - check commit quality, test execution, reporting
3. **Schedule longer work** if test passes
4. **Iterate** - refine prompts based on what works

---

## Model: qwen3:30b Specifics

**Connection**:
- Endpoint: http://192.168.1.112:11434
- Format: OpenAI-compatible API
- No auth required (local network)

**Context Window**: 32K tokens (sufficient for most single-file work)

**Capabilities**:
- Code generation (Python, bash)
- Test writing
- Documentation
- Code review
- Debugging

**Limitations**:
- May need chunking for large file analysis
- Less "general knowledge" than frontier models
- Best for focused technical tasks

**Cost**: Zero (local inference, just electricity)

---

## Monitoring Active Jobs

```python
# Check running jobs
list_cronjobs()

# Check specific job status
# (get session_id from list_cronjobs output)

# Cancel if needed
remove_cronjob(job_id="<job_id>")
```

---

## Template: Autonomous Job Prompt

```
You are an autonomous AI agent working on hermes-aegis security hardening project.

LOCATION: /workspace/Projects/hermes-aegis
COMMIT: c387330
TESTS: 323 passing, 17 skipped

YOUR TASK: [Specific, focused objective]

INSTRUCTIONS:
1. Verify baseline state:
   - Run: uv run pytest tests/ -q
   - Check: git log --oneline -5
   - Confirm: 323 tests passing

2. [Specific work steps]

3. Verify changes:
   - Run: uv run pytest tests/ -q
   - Ensure: All tests still pass
   - Check: git diff --stat

4. Commit work:
   - Format: "type: description"
   - Author: Tranquil-Flow <tranquil_flow@protonmail.com>
   - Command: git commit -am "..."

5. Report completion:
   - Show: Actual pytest output (pass/fail counts)
   - Show: git log --oneline -3
   - List: Files modified
   - Note: Any issues or decisions made

CONSTRAINTS:
- Work only in /workspace/Projects/hermes-aegis
- No external file modifications
- No feature additions (review/refine existing code only)
- Report literal command outputs, never fabricate results
- Maximum time: 30 minutes

VERIFICATION:
Run actual commands, paste real output. Do not describe intended state.
```

---

**Document Created**: March 15, 2026 06:04 AM
**Ready For**: Autonomous testing with qwen3:30b
