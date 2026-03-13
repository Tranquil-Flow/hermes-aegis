# Banner Integration Troubleshooting Log

## Goal
Display "Security: Aegis Tier X 🛡️" in the Hermes welcome banner when TERMINAL_ENV=aegis

## Attempts Made

### Attempt 1: Monkey-patch build_welcome_banner
- **Approach**: Patched `hermes_cli.banner.build_welcome_banner()` via sitecustomize.py
- **Location**: `src/hermes_aegis/display.py` - `inject_aegis_status_hook()`
- **Result**: ❌ Failed - function not found or path issues
- **Why it failed**: Complex import issues, sitecustomize timing

### Attempt 2: Direct patch of hermes_cli/banner.py
- **Approach**: Directly edited `~/.hermes/hermes-agent/hermes_cli/banner.py` line 256
- **Code added**: 
  ```python
  if os.getenv("TERMINAL_ENV") == "aegis":
      from hermes_aegis.detect import detect_tier
      tier = detect_tier()
      left_lines.append(f"[bold cyan]Security: Aegis Tier {tier} 🛡️[/]")
  ```
- **Result**: ❌ Not showing in banner
- **Why it failed**: Unknown - maybe not the right file or cache issues

### Attempt 3: Patch cli.py instead of banner.py
- **Approach**: Discovered cli.py has its OWN `build_welcome_banner()` at line 829
- **Location**: Patched `~/.hermes/hermes-agent/cli.py` line 890
- **Code added**: Same Aegis check
- **Result**: ❌ Still not showing
- **Why it failed**: Possibly cache, or still not the right code path

## Investigation Needed

### Files with build_welcome_banner function:
1. `~/.hermes/hermes-agent/hermes_cli/banner.py` - Line 208
2. `~/.hermes/hermes-agent/cli.py` - Line 829 (overrides import)

### Cache files that might interfere:
- `~/.hermes/hermes-agent/hermes_cli/__pycache__/banner.cpython-311.pyc`
- `~/.hermes/hermes-agent/__pycache__/cli.cpython-311.pyc`

### Environment verification:
- ✅ TERMINAL_ENV is set to "aegis" in ~/.zshrc
- ✅ sitecustomize.py is installed in venv
- ✅ Can import hermes_aegis.detect.detect_tier() manually
- ❌ Banner is NOT showing the line

## Next Steps

1. **Trace exact execution path**: 
   - Where does `hermes` command start?
   - Which build_welcome_banner is actually called?
   - Add print() statements to verify code execution

2. **Test with simple print statements**:
   - Add `print("AEGIS TEST")` to both banner functions
   - See which one actually runs

3. **Check if there's a third location**:
   - Maybe hermes_cli/main.py has its own banner?
   - Search for all banner display code

### Attempt 4: Debug with print() to trace execution
- **Approach**: Added print() statements to cli.py to see what TERMINAL_ENV actually is
- **Discovery**: ✅ **FOUND THE BUG!**
  - TERMINAL_ENV was being set to "local" by Hermes config
  - Line in ~/.hermes/config.yaml: `backend: local`
  - This overrides the .zshrc setting
- **Solution**: Change config.yaml to `backend: aegis`

## Root Cause

The Hermes config file (`~/.hermes/config.yaml`) has a `terminal.backend` setting that **overrides** the TERMINAL_ENV environment variable. It was set to "local".

## Solution

Changed `~/.hermes/config.yaml`:
```yaml
terminal:
  backend: aegis  # was: local
```

## Final Solution

1. **Patch both banner files**:
   - `~/.hermes/hermes-agent/cli.py` (line 890) - main CLI banner
   - `~/.hermes/hermes-agent/hermes_cli/banner.py` (line 256) - alternate banner
   - Script: `patch-hermes-banner.sh`

2. **Fix Hermes config**:
   - Change `~/.hermes/config.yaml`: `terminal.backend: aegis`
   - This was overriding TERMINAL_ENV

3. **Clear Python cache**:
   - Remove `.pyc` files so Python reloads the patched code

## Current Status
✅ **WORKING** - Banner displays "Security: Aegis Tier X 🛡️" in cyan
