# Hermes-Aegis Quick Start

## Is It Working?

Open a new terminal and run:
```bash
hermes
```

You should see in the banner (left side):
```
Session: <timestamp>
Security: Aegis Tier 1 🛡️
```

If you see the shield, **Aegis is active!** 🎉

## What Does It Do?

Aegis is a security layer that protects you when Hermes executes commands:

1. **Blocks dangerous commands** - rm -rf, sudo, curl|bash, etc require your approval
2. **Logs everything** - Full audit trail of all commands
3. **Hides secrets** - Redacts API keys and passwords from logs
4. **Rate limits** - Prevents command spam attacks
5. **Shows status** - Banner confirms protection is active

## Quick Test

In Hermes, try:
```
delete all my files
```

You should get an approval prompt instead of instant execution!

## Common Commands

```bash
cd ~/Projects/hermes-aegis

# Check status
uv run hermes-aegis status

# View recent commands
uv run hermes-aegis audit list

# Manage secrets
uv run hermes-aegis vault list
uv run hermes-aegis vault set KEY value

# View dangerous patterns
uv run hermes-aegis patterns list

# Run tests
uv run pytest tests/ -q
```

## Configuration

### Hermes Must Use Aegis Backend
File: `~/.hermes/config.yaml`
```yaml
terminal:
  backend: aegis  # CRITICAL - must be "aegis"
```

### Aegis Settings
File: `~/.hermes-aegis/config.json`
```json
{
  "tier": 1,
  "log_all_commands": true
}
```

## Troubleshooting

### Banner not showing?
```bash
# 1. Check config
grep backend ~/.hermes/config.yaml
# Should show: backend: aegis

# 2. Reapply patches
cd ~/Projects/hermes-aegis
./patch-hermes-banner.sh

# 3. Clear cache
rm -f ~/.hermes/hermes-agent/__pycache__/cli.cpython-*.pyc

# 4. Restart terminal completely
```

### Commands not being blocked?
```bash
# Check Aegis is active
uv run hermes-aegis status

# View audit log to see if commands are being logged
uv run hermes-aegis audit list
```

## Documentation

- **MVP_SETUP.md** - Full testing guide with scenarios
- **BANNER_TROUBLESHOOTING.md** - How we fixed the banner integration
- **README.md** - Complete technical documentation

## Ready to Use!

Start using Hermes normally. Aegis runs invisibly in the background, only stepping in when dangerous commands are detected.

The banner confirms your safety! 🛡️
