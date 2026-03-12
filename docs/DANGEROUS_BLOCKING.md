# Dangerous Command Blocking

This feature upgrades dangerous command detection from audit-only logging to configurable blocking, providing defense-in-depth against risky terminal operations.

## Overview

The dangerous command blocker middleware checks terminal commands for dangerous patterns (like `rm -rf /`, `curl | sh`, `DROP TABLE`, etc.) and either logs them or blocks execution based on configuration.

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

The blocker checks for 40+ dangerous patterns including:

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

## Future Enhancements

- Pattern customization via config
- Allowlist for specific dangerous commands
- Integration with approval workflows
- Real-time alerts for blocked commands
- Telemetry for pattern effectiveness
