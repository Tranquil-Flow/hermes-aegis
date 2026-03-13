# Hermes-Aegis MVP Setup Guide

## Current Status
✅ **READY FOR TESTING** - All features installed and working

## What's Installed

### Core Features
- ✅ **Tier 1 Security**: Dangerous command审批, audit logging, rate limiting
- ✅ **Vault**: 5 secrets stored securely
- ✅ **CLI Tools**: `hermes-aegis` command working
- ✅ **Banner Integration**: Shows "Security: Aegis Tier 1 🛡️" in Hermes startup

### Files Patched
- `~/.hermes/config.yaml` - Set `terminal.backend: aegis`
- `~/.hermes/hermes-agent/cli.py` - Banner displays Aegis status
- `~/.hermes/hermes-agent/hermes_cli/banner.py` - Alternate banner path
- `~/.hermes/hermes-agent/venv/lib/python3.11/site-packages/sitecustomize.py` - Auto-load

## Using Aegis

### See Status
```bash
cd ~/Projects/hermes-aegis
uv run hermes-aegis status
```

Output:
```
Tier: 1
Docker: not found
Vault: 5 secrets
```

### View Audit Logs
```bash
uv run hermes-aegis audit list
uv run hermes-aegis audit show <request_id>
```

### Manage Vault
```bash
uv run hermes-aegis vault list
uv run hermes-aegis vault set KEY value
uv run hermes-aegis vault get KEY
uv run hermes-aegis vault delete KEY
```

### Run Demos
```bash
# Basic security demo
./demo.sh

# Red team attack scenarios
./demo_redteam.sh
```

## Testing Checklist

- [ ] Banner shows Aegis status on Hermes startup
- [ ] Dangerous commands require approval
- [ ] Audit logs are created in ~/.hermes-aegis/logs/
- [ ] Vault encrypts/decrypts secrets correctly
- [ ] Rate limiting blocks rapid-fire commands
- [ ] Secret redaction works in logs
- [ ] CLI commands all work

## Known Limitations

1. **Tier 2 (Docker) not available**: Docker not installed on this Mac
2. **Patches need reapplication**: After `hermes update`, run `./patch-hermes-banner.sh`
3. **Python cache**: If banner doesn't show, clear cache with:
   ```bash
   rm -f ~/.hermes/hermes-agent/__pycache__/cli.cpython-*.pyc
   ```

## Quick Verification

```bash
cd ~/Projects/hermes-aegis

# Check installation
./verify-banner.sh

# Test CLI
uv run hermes-aegis status
uv run hermes-aegis vault list
uv run hermes-aegis audit list

# Run tests
uv run pytest tests/ -v
```

## Troubleshooting

### Banner not showing
1. Check config: `grep backend ~/.hermes/config.yaml` should show "aegis"
2. Clear cache: `rm -f ~/.hermes/hermes-agent/__pycache__/cli.cpython-*.pyc`
3. Verify patch: `grep "Aegis security status" ~/.hermes/hermes-agent/cli.py`
4. Check env: Open new terminal, run `source ~/.zshrc && echo $TERMINAL_ENV`

### Commands blocked unexpectedly
- Check allowlist: `uv run hermes-aegis allowlist show`
- View pattern: `uv run hermes-aegis patterns list`
- Temporarily disable: Set `AEGIS_APPROVAL=auto` in environment

### Audit logs not created
- Check permissions: `ls -la ~/.hermes-aegis/logs/`
- Verify middleware: `uv run pytest tests/test_middleware.py -v`

## Next Steps for Production

1. **Enable Tier 2**: Install Docker and test container isolation
2. **Custom patterns**: Add project-specific dangerous patterns
3. **Allowlist tuning**: Add known-safe commands to allowlist
4. **Integration testing**: Test with real Hermes workflows
5. **Performance testing**: Verify middleware overhead is acceptable

## Files to Version Control

Committed to git:
- All source code in `src/hermes_aegis/`
- Tests in `tests/`
- Documentation
- Installation scripts

NOT committed (user-specific):
- `~/.hermes-aegis/vault.enc` - encrypted secrets
- `~/.hermes-aegis/config.json` - local config
- `~/.hermes-aegis/logs/` - audit logs
- Hermes patches (applied per-machine)
