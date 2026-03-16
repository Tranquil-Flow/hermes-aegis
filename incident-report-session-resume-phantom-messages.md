# Incident Report: CLI Session Resume Fails — "No Messages" Despite Complete Conversation Data

**Date**: 2026-03-16
**Severity**: Medium (data integrity — no data loss, but resume UX broken)
**Affected components**:
- `hermes-agent` CLI session persistence (`cli.py`, `run_agent.py`, `hermes_state.py`)
- `hermes-aegis` session ID discovery (`cli.py:_discover_hermes_session`)

---

## 1. Symptom

```
Session 20260316_111235_325fc0 found but has no messages. Starting fresh.
```

User had a long interactive session (62 messages across user/assistant/tool roles). When attempting to resume via the session link, the CLI reported the session had no messages and started a fresh conversation, discarding all prior context.

A second reproduction attempt revealed an additional bug: hermes-aegis displayed a **different session ID** than hermes itself:

```
# Hermes inner session (the real conversation):
Resume this session with:
  hermes --resume 20260316_134310_45365a
Session:        20260316_134310_45365a
Messages:       99 (6 user, 87 tool calls)

# Hermes-aegis outer session (wrong ID):
Resume this session with:
    hermes-aegis run -- --resume 20260316_133913_9f248b
Session:        20260316_133913_9f248b
Messages:       0
```

## 2. Scope

### hermes-agent: Phantom sessions

Cross-referencing `~/.hermes/state.db` (SQLite) against `~/.hermes/sessions/` (JSON logs):

| Metric | Value |
|--------|-------|
| Total sessions in SQLite | 294 |
| Sessions with `message_count = 0` | 25 (8.5%) |
| **Phantom sessions** (0 in SQLite, >0 in JSON) | **12** |
| Truly empty (no data anywhere) | 13 |

**12 sessions have complete conversation data on disk that the resume system cannot see.** These span CLI and cron sources, from 2026-03-14 through 2026-03-16, containing between 3 and 62 messages each.

### hermes-aegis: Session ID mismatch

The `_discover_hermes_session()` function queries SQLite for the most recent active session 2 seconds after spawning hermes. It has no filters for session source or creation time, so it frequently picks up **stale cron or gateway sessions** instead of the CLI session that hermes-aegis just spawned.

Evidence from SQLite:
```sql
-- Sessions around the reproduction timestamp:
20260316_133913_9f248b | cron | started_at=1773632353  ← aegis picked this one (wrong)
20260316_134310_45365a | cli  | started_at=1773632645  ← actual hermes session (created ~5min later)
```

The cron session existed before aegis started. The hermes CLI session was created after the 2-second discovery window.

## 3. Root Cause Analysis

### Bug 1: hermes-aegis discovers the wrong session ID

**Location**: `hermes-aegis/src/hermes_aegis/cli.py:_discover_hermes_session()` (line 932)

**Before** (broken):
```python
def _discover_hermes_session(timeout: float = 2.0) -> dict | None:
    # ...
    row = db.execute(
        "SELECT id, started_at, message_count FROM sessions "
        "WHERE ended_at IS NULL ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
```

**Problem**: No filtering by `source` or `started_at`. Any active session (cron, gateway, previous CLI) can be returned. The 2-second sleep after `sp.Popen` is a race condition — hermes may not have created its session record yet.

**Impact**: The resume link printed by hermes-aegis points to the wrong session. Users who follow the `hermes-aegis run -- --resume <id>` link resume into an empty/unrelated session.

### Bug 2: hermes-agent SQLite flush silently fails (hermes-agent upstream)

**Location**: `hermes-agent/run_agent.py:_flush_messages_to_session_db()` (line 1035)

```python
def _flush_messages_to_session_db(self, messages, conversation_history=None):
    if not self._session_db:
        return
    try:
        start_idx = len(conversation_history) if conversation_history else 0
        flush_from = max(start_idx, self._last_flushed_db_idx)
        for msg in messages[flush_from:]:          # ← may iterate over nothing
            # ... append_message() calls ...
        self._last_flushed_db_idx = len(messages)  # ← only set if loop completes
    except Exception as e:
        logger.debug("Session DB append_message failed: %s", e)  # ← swallowed at DEBUG
```

**Three plausible failure modes:**

#### Mode A: `conversation_history` aliased to `messages` (most likely)

The agent loop calls `_persist_session(messages, conversation_history)` from 20+ call sites. If `conversation_history` and `messages` are the **same list reference** (or equal in length due to in-place mutation):

```python
start_idx = len(conversation_history)  # == len(messages)
flush_from = max(start_idx, 0)         # == len(messages)
messages[flush_from:]                  # == [] — empty, loop never executes
```

The JSON writer (`_save_session_log`) doesn't use offset logic — it dumps the entire array unconditionally. This explains why JSON always has data but SQLite never does.

#### Mode B: Exception swallowed by `logger.debug`

If `append_message()` raises (FTS trigger failure, SQLite `BUSY`, malformed `tool_calls`), the `except Exception` catches it at DEBUG level (invisible in normal operation). `_last_flushed_db_idx` is never updated, so every subsequent call retries the same failing message.

#### Mode C: `_session_db` is None in AIAgent

If `SessionDB()` import/instantiation fails inside `AIAgent.__init__`, `self._session_db` is `None` and all flushes return immediately. The session **row** exists (created by CLI before agent init), hence `get_session()` finds it — just with `message_count=0`.

### Bug 3: CLI resume has no JSON fallback (hermes-agent upstream)

**Location**: `hermes-agent/cli.py:_preload_resumed_session()` (line 1682)

The gateway code (`gateway/session.py:783-807`) has a JSONL fallback when SQLite returns empty. The CLI's `_preload_resumed_session()` does not — it queries only SQLite and gives up.

Note: the CLI's JSON format is a single JSON object with a `messages` array (not JSONL like the gateway). A correct fallback must handle both formats.

## 4. Fixes Applied

### Fix 1: hermes-aegis session discovery (hermes-aegis — committed)

**File**: `src/hermes_aegis/cli.py`

Changed `_discover_hermes_session()` to:
- Accept an `after_ts` parameter — only consider sessions created after aegis started
- Filter by `source = 'cli'` — exclude cron/gateway sessions
- Re-discover at exit (both normal and KeyboardInterrupt paths) to get the correct session ID and final message count

```python
def _discover_hermes_session(after_ts: float = 0, timeout: float = 2.0) -> dict | None:
    row = db.execute(
        "SELECT id, started_at, message_count FROM sessions "
        "WHERE source = 'cli' AND started_at > ? "
        "ORDER BY started_at DESC LIMIT 1",
        (after_ts,),
    ).fetchone()
```

Call sites updated:
```python
session_info = _discover_hermes_session(after_ts=start_time)  # initial (may miss)
# ... hermes_proc.wait() or KeyboardInterrupt ...
session_info = _discover_hermes_session(after_ts=start_time) or session_info  # re-discover
```

### Fix 2: JSON fallback in CLI resume (hermes-agent — local patch)

**File**: `~/.hermes/hermes-agent/cli.py`

Added fallback to both resume paths (`_preload_resumed_session` and `_init_agent`):
When `get_messages_as_conversation()` returns empty, reads `~/.hermes/sessions/session_{id}.json` and extracts the `messages` array.

This is safe because:
- Read-only on an existing file
- Falls through to "no messages" if file missing or malformed
- JSON format is well-defined (`atomic_json_write` with `default=str`)
- No behavioral change when SQLite has messages

## 5. Suggested Upstream Fixes (for hermes-agent PRs)

### 5.1 Fix the flush offset calculation (root cause)

Remove `conversation_history` from the offset calculation in `_flush_messages_to_session_db`. Rely solely on `_last_flushed_db_idx`:

```python
flush_from = self._last_flushed_db_idx  # not max(len(conversation_history), ...)
```

Promote exception logging from DEBUG to WARNING:
```python
logger.warning("Session DB flush failed at idx %d: %s", self._last_flushed_db_idx, e)
```

### 5.2 Add JSON fallback to CLI resume

Port the gateway's `load_transcript()` fallback pattern to `_preload_resumed_session()`, adapted for the CLI's single-object JSON format.

### 5.3 Add a backfill migration

One-time script to read JSON logs for the 12 phantom sessions and populate the SQLite messages table.

## 6. Verification

### Test suite
- **51 tests pass** across `test_run_command.py`, `test_cli_commands.py`, `test_cli_audit.py` (the test files covering session and CLI functionality)
- 719 total tests pass; pre-existing failures in `test_tirith_scanner.py` (unrelated) excluded

### Manual verification (2026-03-16, 14:23)

Test session `20260316_142347_5c2944`:
1. Started `hermes-aegis run`, sent 2 user messages ("tirith download" question + "remember to pat the cat"), exited with Ctrl+C
2. Aegis printed session ID `20260316_142347_5c2944` — **matches** hermes's own session ID
3. Aegis showed `Messages: 8` — **matches** hermes's count of `8 (2 user, 4 tool calls)`
4. Ran `hermes-aegis run -- --resume 20260316_142347_5c2944`
5. Output: `↻ Resumed session 20260316_142347_5c2944 (2 user messages, 8 total messages)`
6. Full conversation history displayed in "Previous Conversation" panel
7. Sent "we should pat the ___?" — Moonsong responded "cat!" confirming context was restored

- [x] hermes-aegis prints the correct hermes CLI session ID (not a stale cron/gateway session)
- [x] Resume using the aegis-provided link restores full conversation history
- [x] Session ID matches between aegis and hermes
- [x] Conversation context is preserved across resume (memory + message history)

## 7. Files Modified

| File | Change | Scope |
|------|--------|-------|
| `hermes-aegis/src/hermes_aegis/cli.py` | `_discover_hermes_session()` filters by `source='cli'` and `started_at > after_ts`; re-discovers at exit | hermes-aegis |
| `~/.hermes/hermes-agent/cli.py` | JSON fallback in `_preload_resumed_session()` and `_init_agent()` resume paths | hermes-agent (local) |

## 8. Evidence

```
SQLite:  SELECT message_count FROM sessions WHERE id = '20260316_111235_325fc0';  → 0
SQLite:  SELECT COUNT(*) FROM messages WHERE session_id = '20260316_111235_325fc0';  → 0
JSON:    session_20260316_111235_325fc0.json → 62 messages (1 user, 31 assistant, 30 tool)
Pattern: 12 of 25 zero-message sessions have complete JSON data (48% phantom rate)

Session ID mismatch:
  Aegis discovered: 20260316_133913_9f248b (cron, started_at=1773632353)
  Hermes actual:    20260316_134310_45365a (cli, started_at=1773632645, 99 messages)
  Delta: ~292 seconds — hermes CLI session created well after aegis's 2-second discovery window
```
