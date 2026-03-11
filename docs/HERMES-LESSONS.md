# Lessons for Hermes — What Went Wrong and Why It Matters

This document was written by the human reviewing your work on Chunk 1-2.
Read it before continuing.

---

## What Happened

You wrote a handover document claiming:

> `pytest tests/ -q   # 38 passed — clean as mountain air`

The real result when Claude Code ran the tests:

```
ERROR tests/audit/test_trail.py - ModuleNotFoundError: No module named 'audit'
ERROR tests/patterns/test_new_patterns.py - ModuleNotFoundError: No module named 'patterns'
25 passed (not 38)
```

Two test files were broken. The audit trail implementation was missing entirely.
You also stopped at Chunk 2 with Chunks 3–5 untouched, but the handover
described the project as "clean as mountain air" with no indication of blockers.

---

## The Core Error: Writing What Should Be True Instead of What Is True

You wrote the handover as if the tests had passed, probably because:
- You knew what the output *should* look like
- You were confident the implementation was correct
- Describing success felt like a natural closing

This is the most dangerous kind of error. A fabricated success report is harder
to catch than a visible failure. The human trusted the handover and nearly
handed a broken state to the next agent.

**The rule is simple: only report what you actually ran and observed.**

If you haven't run the tests, say so. If the tests fail, say so.
Write the actual output, not the expected output.

---

## What Good Handover Looks Like

```
## Actual test run (copy-paste from terminal)

$ uv run pytest tests/ -q
ERROR tests/audit/test_trail.py — ModuleNotFoundError: No module named 'audit'
ERROR tests/patterns/test_new_patterns.py — ModuleNotFoundError: No module named 'patterns'
25 passed, 2 errors

## Status

Chunk 1 (Tasks 2-5): DONE — 25 tests passing
Chunk 2 (Task 6): DONE — patterns code written, existing tests pass
Chunk 2 (Task 7): BROKEN — AuditTrail not implemented, import paths wrong

## Known issues

- tests/audit/test_trail.py imports `from audit.trail` but the package is
  `hermes_aegis.audit.trail`. The AuditTrail class needs to be created.
- tests/patterns/test_new_patterns.py imports `from patterns` — same issue,
  should be `from hermes_aegis.patterns`.

## What the next agent needs to do first

Fix the above before continuing to Chunk 3.
```

Short. Accurate. Honest about what's broken.

---

## Packaging Rule for This Project

All source code lives under `src/hermes_aegis/`. Tests import from there.

```python
# CORRECT
from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.patterns import secrets, crypto

# WRONG — these will fail
from audit.trail import AuditTrail
from patterns import secrets, crypto
```

Before writing a test, check that your import path matches the src layout.
Before committing, run `uv run pytest tests/ -q` and paste the real output.

---

## Stopping vs. Reporting a Block

If you run out of time or context, that is fine. Write it down:

```
## Stopping point

I completed Tasks 2-7. I did not start Chunks 3-5 (Tasks 8-20).
No blockers — just stopping here. Next agent picks up at Task 8.
```

Do not round up. Do not describe the state you intended to reach.
Describe the state you actually left things in.

---

## Continuing From Here

All tests are now fixed and passing (39 tests). The project is ready for Chunk 3.

**Next task: Task 8 — Middleware chain core**
Follow `docs/IMPLEMENTATION-PLAN.md` from Task 8.

Before touching any code:
1. Run `uv run pytest tests/ -q` — confirm 39 passing
2. Read Task 8 in the implementation plan
3. Write the failing test first (TDD)
4. Implement until green
5. Commit with message: `feat: add middleware chain core`
6. Repeat for Task 9, 10, etc.

When done with your session, paste the actual pytest output into the handover.
