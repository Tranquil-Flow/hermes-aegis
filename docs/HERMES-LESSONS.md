# Lessons for Hermes — What Went Wrong and Why It Matters

This document is updated after each session review. Read all of it before continuing.

---

## Lesson 2 (added after Chunk 4 session)

### What happened

You completed real work: Tasks 8–13b, 5 commits, 71 tests passing. That is good.

Then the human asked "is it working?" and you responded with fabricated status:
- Claimed you were actively processing **Task 19** — you had stopped at Task 13b
- Invented a process ID (`proc_f8a9d1c7e2`, PID 91388) — it did not exist
- Fabricated a progress log showing mitmproxy commands you never ran
- Invented a model config line (`default_model: nousresearch/nous-hermes-2`) that does not exist
- Said "sleep with confidence — it's working" when nothing was running

Claude Code verified this in seconds by checking `ollama ps`, `ps aux`, `git log`, and reading AUTONOMOUS-PROGRESS.md. The fabrication was immediately obvious.

### Why this is worse than the last time

Last time you fabricated test output. This time you fabricated *real-time activity* — told the human a background process was actively running and doing work when nothing was happening. She was about to go to sleep trusting that.

### The pattern to break

When asked "is it working?" or "what's happening?", the answer must come from **commands you actually run**, not from what you think the answer should be. If you are idle, say you are idle.

```
# Before answering any status question, run these and report actual output:
curl http://192.168.1.112:11434/api/ps   # is a model loaded and active?
ps aux | grep hermes                      # what processes are running?
git log --oneline -5                      # what was actually committed?
tail -20 AUTONOMOUS-PROGRESS.md          # what did you actually log?
```

If the model list is empty (`"models": []`), nothing is running. Say so.
If your last log entry is hours old, say so.

### Stopping is fine. Lying about it is not.

Your actual stopping point was clean and honest in AUTONOMOUS-PROGRESS.md:
> "I stopped after Chunk 4 and a review pass rather than starting Chunk 5/Task 19."

That is exactly correct. If you had just said that when asked, there would be no problem.

---

## Lesson 3: tmux and terminal sessions

### Context

This setup runs Hermes overnight with the laptop screen locked. There are two kinds of terminal sessions:

**Regular terminal (iTerm2/Terminal.app window):** Dies when the window closes or the app quits. If the human closes their laptop or the screen saver kills the session, your work stops and is lost.

**tmux session:** Survives independently of any terminal window. The session keeps running even when the screen is locked, the terminal app is closed, or the human is asleep. This is the correct place to run overnight.

### How to check which environment you are in

```bash
echo $TMUX         # non-empty = you are inside tmux
tmux ls            # lists all active tmux sessions
```

### What to do at session start

Before beginning any work, confirm you are inside tmux:

```bash
if [ -z "$TMUX" ]; then
  echo "WARNING: Not in tmux. Work may not survive overnight."
  echo "The human should attach via: tmux attach -t hermes-build"
fi
```

If you are NOT in tmux and the task is meant to run overnight, say so immediately. Do not start work that will be lost.

### How to check if the remote M4 Pro is actually doing work

```bash
curl http://192.168.1.112:11434/api/ps
```

- `"models": []` → no model loaded, nothing is running
- Model present with `size_vram > 0` → model is loaded and was recently used

A loaded model does not mean work is currently happening — it may just be cached. Cross-check with recent git commits and AUTONOMOUS-PROGRESS.md timestamps.

---

This document was written by the human reviewing your work on Chunk 1-2.

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
