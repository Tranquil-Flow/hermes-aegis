# Aegis Banner Integration

## What It Does

When you start Hermes with TERMINAL_ENV=aegis, the welcome banner now displays:

```
Security: Aegis Tier 1 🛡️
```

This appears in the left panel below the session ID, confirming that Aegis security protection is active.

## How It Works

1. **Sitecustomize Auto-Loader**
   - File: `~/.hermes/hermes-agent/venv/lib/python3.11/site-packages/sitecustomize.py`
   - Installed to the **venv** site-packages (user site-packages is disabled in venvs)
   - Runs automatically when Hermes Python starts
   - Checks if `TERMINAL_ENV=aegis`
   - If yes, loads `hermes_aegis.integration.register_aegis_backend()`

2. **Backend Registration**
   - File: `src/hermes_aegis/integration.py`
   - Patches `_create_environment()` in terminal_tool module to support `env_type="aegis"`
   - Calls `inject_aegis_status_hook()` to patch the banner

3. **Banner Display Injection**
   - File: `src/hermes_aegis/display.py`
   - Monkey-patches `hermes_cli.banner.build_welcome_banner()`
   - Adds a cyan-colored "Security: Aegis Tier X 🛡️" line to the left panel
   - The tier (1 or 2) is auto-detected based on Docker availability

## Testing

To see the banner with Aegis status:

```bash
# Make sure TERMINAL_ENV is set in your shell config
echo $TERMINAL_ENV  # Should show "aegis"

# Start a new Hermes session
hermes

# You should see:
#   Session: <session_id>
#   Security: Aegis Tier 1 🛡️  <-- THIS LINE
```

## Technical Details

### Challenge: Module Import
The main challenge was that `tools.terminal_tool` resolves to a *function*, not the module, because `tools/__init__.py` exports the function directly. 

Solution: Use `importlib.util.spec_from_file_location()` to load the actual terminal_tool.py module file directly.

### Challenge: Venv Site-Packages
Python virtual environments disable user site-packages by default (`site.ENABLE_USER_SITE = False`). This means `~/.local/lib/pythonX.X/site-packages/` is NOT used. 

Solution: Detect if running in venv and install sitecustomize.py to the venv's own site-packages directory instead:
- Venv: `~/.hermes/hermes-agent/venv/lib/python3.11/site-packages/`
- System: `~/.local/lib/python3.13/site-packages/`

### Implementation Notes
- The banner patch is NON-INVASIVE - if patching fails, Hermes still works normally
- The Aegis status line uses Rich markup: `[bold #00D9FF]...[/]` for cyan text
- Tier detection is automatic - no configuration needed
- The whole patch replicates the original banner building logic to insert one line
