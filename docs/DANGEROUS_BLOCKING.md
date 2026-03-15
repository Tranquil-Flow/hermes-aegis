# Dangerous Command Blocking

This feature provides dangerous command detection with two enforcement paths:

1. **Audit mode** (default) — logs dangerous commands to the audit trail
2. **Gateway blocking** (via Patch 5) — blocks dangerous commands outright when `AEGIS_ACTIVE=1` in non-interactive mode

## Overview

The dangerous command system checks terminal commands for 27 dangerous patterns (like `rm -rf /`, `curl | sh`, `DROP TABLE`, etc.).

**Note:** Hermes Agent v0.2.0 added its own approval system (`approval.py` with 27 overlapping patterns + `tirith_security.py` for content scanning). Aegis's dangerous command detection is complementary — it provides **silent blocking** in gateway/non-interactive mode where Hermes would otherwise auto-allow or prompt a user who isn't present.

### How Patch 5 Works (Gateway Blocking)

When `hermes-aegis install` applies Patch 5 to `terminal_tool.py`:
1. After Hermes's own `_check_all_guards()` approves a command
2. If `AEGIS_ACTIVE=1` is set (indicating hermes-aegis run context)
3. Runs `hermes-aegis scan-command -- <command>` as a subprocess
4. If exit code is 1 (blocked), the command is denied without user prompting
5. Fails open — if hermes-aegis is unavailable or times out, the command proceeds

## Configuration

The blocker has two modes:

- **audit** (default): Log dangerous commands but allow execution (backward compatible)
- **block**: Prevent execution of dangerous commands by raising SecurityError

### Setting the Mode

```bash
# Enable blocking mode
hermes-aegis config set dangerous_commands block

# Return to audit-only mode (default)
hermes-aegis config set dangerous_commands audit

# View current setting
hermes-aegis config get dangerous_commands

# View all settings
hermes-aegis config get
```

Configuration is stored in `~/.hermes-aegis/config.json` and persists across sessions.

## Dangerous Patterns Detected

The blocker checks for 27 dangerous patterns including:

- **Recursive deletion**: `rm -rf /`, `rm --recursive`, `find -delete`
- **Dangerous permissions**: `chmod 777`, `chmod -R 777`
- **Ownership changes**: `chown -R root`
- **Filesystem operations**: `mkfs`, `dd if=`, write to `/dev/sd*`
- **SQL operations**: `DROP TABLE`, `DELETE FROM` (without WHERE), `TRUNCATE`
- **System config**: Overwrites to `/etc/`, `/dev/`, etc.
- **Service control**: `systemctl stop/disable/mask`
- **Process killing**: `kill -9 -1`, `pkill -9`
- **Remote execution**: `curl | bash`, `wget | sh`, `bash -c`, `python -c`
- **Dangerous piping**: `xargs rm`, `find -exec rm`, `tee` to sensitive paths

See `src/hermes_aegis/patterns/dangerous.py` for the complete list.

## Architecture

### Components

1. **Settings Manager** (`config/settings.py`)
   - Persistent JSON configuration in `~/.hermes-aegis/config.json`
   - Default: `dangerous_commands = "audit"`
   - Graceful recovery from corrupted config files

2. **Dangerous Blocker Middleware** (`middleware/dangerous_blocker.py`)
   - Pre-dispatch middleware (runs before tool execution)
   - Uses patterns from `patterns/dangerous.py`
   - Logs to audit trail with danger metadata
   - Raises `SecurityError` in block mode

3. **Middleware Chain Integration** (`middleware/chain.py`)
   - `create_default_chain()` now accepts `dangerous_mode` parameter
   - Dangerous blocker runs first (before output scanner)
   - Integrates with audit trail for logging

4. **CLI Commands** (`cli.py`)
   - `hermes-aegis config get [key]`
   - `hermes-aegis config set <key> <value>`
   - Validates dangerous_commands values (audit/block)

## Usage Examples

### Audit Mode (Default)

```python
from hermes_aegis.middleware.chain import create_default_chain

# Default: audit mode (logs but allows)
chain = create_default_chain(
    audit_trail=trail,
    dangerous_mode="audit"  # or omit for default
)

# Dangerous commands are logged but allowed
result = await chain.execute(
    "terminal",
    {"command": "rm -rf /tmp/test"},
    handler,
    context
)
```

### Block Mode

```python
from hermes_aegis.middleware.chain import create_default_chain
from hermes_aegis.middleware.dangerous_blocker import SecurityError

# Enable blocking
chain = create_default_chain(
    audit_trail=trail,
    dangerous_mode="block"
)

# Dangerous commands raise SecurityError
try:
    result = await chain.execute(
        "terminal",
        {"command": "rm -rf /"},
        handler,
        context
    )
except SecurityError as e:
    print(f"Blocked: {e}")
    # Check context for details
    print(f"Reason: {context.metadata['blocked_reason']}")
    print(f"Pattern: {context.metadata['pattern']}")
```

## Audit Trail Integration

When dangerous commands are detected, they're logged to the audit trail with metadata:

```json
{
  "timestamp": 1710331200.0,
  "tool_name": "terminal",
  "args_redacted": {
    "command": "rm -rf /",
    "_danger_pattern": "rm\\s+(-[^\\s]*\\s+)*/",
    "_danger_type": "delete in root path"
  },
  "decision": "BLOCKED",  // or "AUDIT"
  "middleware": "DangerousBlockerMiddleware"
}
```

## Testing

Comprehensive test suite in `tests/test_dangerous_blocking.py`:

- 36 tests covering both modes
- Configuration persistence tests
- Edge cases and error handling
- Integration with audit trail
- Command extraction from various formats
- All dangerous patterns validated

Run tests:
```bash
pytest tests/test_dangerous_blocking.py -v
```

## Backward Compatibility

- **Default mode is "audit"** - existing behavior unchanged
- Blocking must be explicitly enabled via config
- No breaking changes to existing APIs
- Middleware is opt-in via `create_default_chain()`

## Security Considerations

1. **Defense in Depth**: This is one layer - not a replacement for proper sandboxing
2. **Pattern Based**: Sophisticated attackers may find bypasses
3. **Terminal Only**: Only checks terminal/shell commands, not API calls
4. **Audit Trail**: All dangerous commands are logged, even in audit mode
5. **User Control**: Users can disable blocking if needed for legitimate use cases

## Integration with Hermes Agent v0.2.0

Hermes v0.2.0 added its own security features that overlap with Aegis dangerous command detection:

| Feature | Hermes v0.2.0 | Aegis |
|---------|---------------|-------|
| Dangerous patterns | 27 in `approval.py` | 27 in `patterns/dangerous.py` (same patterns) |
| Tirith content scanning | Homograph URLs, code injection, terminal injection | Not duplicated — Aegis defers to Tirith |
| Action on detection | **Prompts user** (once/session/always/deny) | **Blocks silently** (gateway) or **audits** (CLI) |
| Gateway mode | Prompts user (may not be present) | Blocks outright via Patch 5 |
| Container mode | Auto-approves (container is the boundary) | Patch 5 still checks if `AEGIS_ACTIVE=1` |

**Key insight:** The unique value of Aegis's dangerous command blocking is in
**gateway/non-interactive mode** where Hermes would auto-approve or prompt a user
who isn't present. In interactive CLI mode, Hermes's own approval system handles it.
