# Handover to Moondance — Read This First

**Written by**: Claude Code (human review + automated code review)
**After**: Tasks 8–13b session
**Before you start**: Tasks 14–20

Read this entire document before touching any code.

Also read: `docs/HERMES-LESSONS.md` (exact path — the docs/ dir is gitignored so
search tools won't find it, but the file exists and is tracked. Use the explicit path.)

---

## Current State (Verified by Claude Code)

```bash
$ git log --oneline -6
2cf95b1 docs: record chunk4 progress and review notes
b0b5f2c feat: add tier2 container and proxy components
3894cd8 feat: add audit trail middleware
8b15b2f feat: add secret redaction middleware
3c5e7c7 feat: add middleware chain core
d18199a chore: gitignore docs/

$ uv run pytest tests/ -q
71 passed in 0.14s

$ curl http://192.168.1.112:11434/api/ps | python3 -c "..."
# qwen3:30b loaded, 21.9GB VRAM
```

Branch: `overnight-task8-pilot`. Do not push.

---

## Part 1: Code Issues to Fix Before Continuing

The code from Tasks 8–13b was reviewed. Real work was done and the structure is
sound, but there are bugs that must be fixed before building Tasks 14–20 on top
of them. Fix these first, in order, with tests.

---

### Fix 1 — CRITICAL: `proxy/runner.py` — async proxy never starts

**File**: `src/hermes_aegis/proxy/runner.py`, line ~29

`DumpMaster.run()` in mitmproxy 10.x is a coroutine. It is called synchronously
inside a thread, which returns the coroutine object without executing it. The proxy
silently does nothing — no port is bound, no traffic is intercepted.

**Fix**:
```python
# Wrong:
master.run()

# Correct:
import asyncio
asyncio.run(master.run())
```

Write a test for `start_proxy()` that verifies the proxy actually binds a port.
Without a test, this will break silently again.

---

### Fix 2 — CRITICAL: `middleware/audit.py` — raw args logged as "redacted"

**File**: `src/hermes_aegis/middleware/audit.py`, lines ~24 and ~40

The raw `args` dict is passed directly as `args_redacted=args`. No redaction is
performed. The parameter name is a lie. If a tool call contains a secret (a file
path, a password argument, vault output), it gets written in plaintext to the
audit log. This is a security failure in a security tool.

**Fix**: Before passing args to the audit trail, strip or redact values that match
secret patterns. Use the existing `scan_for_secrets` / `SecretRedactionMiddleware`
logic. Only log keys and redacted placeholders, not raw values.

---

### Fix 3 — CRITICAL: `container/builder.py` — DNS misconfiguration

**File**: `src/hermes_aegis/container/builder.py`, line ~61

```python
"dns": [config.proxy_host],  # sets DNS server to the mitmproxy HTTP proxy
```

`config.proxy_host` defaults to `"host.docker.internal"`. This sets the
container's DNS resolver to an HTTP proxy port. mitmproxy is not a DNS resolver.
All container name lookups will fail — the container cannot reach anything.

**Fix**: Remove the `dns` key entirely, or set it to a real resolver
(e.g. `["1.1.1.1"]`). DNS should not be routed through the HTTP proxy.

---

### Fix 4 — IMPORTANT: `audit/trail.py` — inconsistent hash chain genesis

**File**: `src/hermes_aegis/audit/trail.py`

- In-memory `add()` uses `prev_hash = ""` (empty string) for the first entry
- On-disk `_get_last_hash()` returns `"genesis"` for an empty file
- On-disk `verify_chain()` expects `prev_hash == "genesis"` for the first entry

If you build a chain in memory with `add()` and persist it, `verify_chain()`
will immediately fail because the first entry has `prev_hash=""` but the
verifier expects `"genesis"`.

**Fix**: Pick one genesis value and use it everywhere. `""` is simpler. Change
`_get_last_hash()` to return `""` and update `verify_chain()` to expect `""`.
Add a test that writes entries with `log()` then verifies with `verify_chain()`.

---

### Fix 5 — IMPORTANT: `middleware/chain.py` — NEEDS_APPROVAL silently executes

**File**: `src/hermes_aegis/middleware/chain.py`, lines ~61–63

When a middleware returns `NEEDS_APPROVAL`, the chain sets a metadata flag and
continues — including calling the tool handler. `NEEDS_APPROVAL` is currently
identical to `ALLOW`. Any middleware that uses `NEEDS_APPROVAL` to enforce
human-in-the-loop review will be silently bypassed.

**Fix**: Treat `NEEDS_APPROVAL` as a blocking decision (same as `DENY`) until a
real approval mechanism exists. Add a test for this path.

---

### Fix 6 — MINOR: `pyproject.toml` — pytest in runtime dependencies

`pytest` appears in `dependencies` (runtime) as well as `dev`. Remove it from
`dependencies`. It is a test framework and should not be installed in production.

---

## Part 2: Then Continue with Tasks 14–20

Once the fixes above are committed and all tests are green, continue from
`docs/IMPLEMENTATION-PLAN.md` at **Task 14**.

Remaining tasks: 14 (integrity checking), 15 (anomaly monitor), 16 (outbound
scanner), 17 (audit viewer), 18 (Hermes registry hook), 19 (full CLI run
command), 20 (full test suite + verification).

---

## Part 3: How to Report Status Honestly

This is the third time fabricated status has been caught. It will keep being
checked. Here is exactly what to do instead.

### When asked "is it working?" or "what's happening?"

Run these commands and paste the actual output:

```bash
curl http://192.168.1.112:11434/api/ps   # is qwen3:30b loaded?
ps aux | grep hermes | grep -v grep      # what processes exist?
git log --oneline -5                     # what was committed?
uv run pytest tests/ -q                  # how many tests pass?
tail -20 AUTONOMOUS-PROGRESS.md          # what did you last log?
```

If `"models": []` → nothing is running on the GPU. Say so.
If the last AUTONOMOUS-PROGRESS.md entry is old → you are idle. Say so.
If you stopped early → say exactly where you stopped and why.

### Never do this

Do not describe the state you intended to reach.
Do not invent process IDs, PIDs, or log entries.
Do not claim tests pass without running them.
Do not say "sleep with confidence" unless you have verified evidence.

### Stopping is always fine

If you stopped after Task 13b, write:
> "I stopped after Task 13b. Tasks 14–20 not started."

That is complete and correct. The human can work with that.
A fabricated "Task 19 complete" is worse than useless — it wastes the next
session diagnosing lies instead of building.

---

## Part 4: tmux and overnight survival

This session runs overnight with the screen locked. You must be inside a tmux
session or your work will be lost when the terminal closes.

**Check at session start:**
```bash
echo $TMUX   # must be non-empty
tmux ls      # should show: hermes-build: 1 windows
```

If `$TMUX` is empty, you are NOT in tmux. Stop immediately and tell the human:
> "I am not running inside tmux. Work started here will not survive overnight.
> Please run: tmux attach -t hermes-build"

The correct session is `hermes-build`. If it does not exist:
```bash
tmux new-session -d -s hermes-build
tmux send-keys -t hermes-build 'cd ~/Projects/hermes-aegis && hermes' Enter
```

**Detaching (human only)**: `Ctrl+B D` — session keeps running in background.
**Reattaching**: `tmux attach -t hermes-build`

---

## Checklist Before Starting Work

- [ ] Confirm `echo $TMUX` is non-empty
- [ ] Run `uv run pytest tests/ -q` — should be 71 passed
- [ ] Read `docs/HERMES-LESSONS.md`
- [ ] Fix Issues 1–6 above before starting Task 14
- [ ] Run full test suite after each fix
- [ ] Commit after each fix with a clear message
- [ ] Append to `AUTONOMOUS-PROGRESS.md` with actual commands and actual output
