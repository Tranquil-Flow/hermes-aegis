# Reactive Audit Agents — Configuration Guide

Reactive agents watch the hermes-aegis audit trail in real time and take automated action when security events match configurable rules. This is the v0.1.5 automated response system.

---

## Quick Start

```bash
# 1. Create default rules
hermes-aegis reactive init

# 2. View the rules
hermes-aegis reactive list

# 3. Test rules against recent audit history
hermes-aegis reactive test

# 4. Run hermes with reactive agents active
hermes-aegis run
```

The watcher starts automatically when `hermes-aegis run` detects `~/.hermes-aegis/reactive-agents.json`.

---

## How It Works

1. A **file watcher thread** tails `~/.hermes-aegis/audit.jsonl` for new entries (1s poll)
2. Each entry is evaluated against **rules** in `~/.hermes-aegis/reactive-agents.json`
3. When a rule fires:
   - **`notify`** rules format a message and deliver it (e.g. Telegram)
   - **`investigate`** rules spawn a hermes-agent session to analyze the event, produce a report, and optionally take defensive action

---

## Rule Types

### Notify Rules

Lightweight alerts — no agent spawned. Uses `message_template` with placeholders.

```json
{
  "name": "block-alert",
  "type": "notify",
  "trigger": { "decision": "BLOCKED" },
  "cooldown": "2m",
  "deliver": "telegram",
  "message_template": "Aegis blocked {count} request(s) to {host}: {reason}"
}
```

**Template placeholders:** `{count}`, `{host}`, `{reason}`, `{decision}`

### Investigate Rules

Spawns a restricted hermes-agent session to analyze the security event and write a report.

```json
{
  "name": "exfiltration-response",
  "type": "investigate",
  "severity": "critical",
  "trigger": {
    "decision_in": ["BLOCKED"],
    "middleware_in": ["ProxyContentScanner"],
    "count": 5,
    "window": "120s"
  },
  "cooldown": "15m",
  "model": "anthropic/claude-sonnet-4-6",
  "prompt": "Investigate this exfiltration attempt...",
  "context": "recent",
  "report_path": "~/.hermes-aegis/reports/",
  "deliver": "telegram",
  "allowed_actions": ["kill_proxy", "lock_vault", "block_domain"],
  "require_justification": true
}
```

---

## Trigger Configuration

All trigger fields are optional. Omitted fields match everything.

| Field | Type | Description |
|-------|------|-------------|
| `decision` | string | Exact match on decision type |
| `decision_in` | list | Match any of these decision types |
| `middleware` | string | Exact match on middleware source |
| `middleware_in` | list | Match any of these middleware sources |
| `count` | int | Threshold: N matching events required |
| `window` | string | Time window for threshold (e.g. "60s", "5m") |

**Per-event triggers** (no `count`/`window`): fire on every matching event.
**Threshold triggers** (`count` + `window`): fire when N events match within the time window.

### Available Decision Types

`BLOCKED`, `ANOMALY`, `DANGEROUS_COMMAND`, `OUTPUT_REDACTED`, `INITIATED`, `COMPLETED`, `CHAIN_TAMPERED`, `CIRCUIT_BREAKER`

### Available Middleware Sources

`ProxyContentScanner`, `DomainAllowlist`, `RateLimiter`, `AuditTrailMiddleware`, `DangerousBlockerMiddleware`, `OutputScannerMiddleware`

---

## Circuit Breaker Actions

Only available to `investigate` rules with `severity: "critical"`. Actions **reduce capability only** — never expand. Worst case is DoS, which is preferable to data exfiltration.

| Action | Effect | How to Reverse |
|--------|--------|----------------|
| `kill_proxy` | Stops all outbound HTTP | `hermes-aegis start` |
| `kill_hermes` | Terminates running Hermes session | User restarts |
| `lock_vault` | Blocks secret reads via sentinel file | `hermes-aegis vault unlock` |
| `block_domain` | Adds domain to blocklist | Edit `~/.hermes-aegis/domain-blocklist.json` |
| `shrink_allowlist` | Removes domain from allowlist | `hermes-aegis allowlist add <domain>` |
| `tighten_rate_limit` | Lowers rate threshold by factor | `hermes-aegis config set rate_limit_requests <n>` |

### Safety Design

- Actions are a **hardcoded whitelist** — no arbitrary command execution
- Agent runs with restricted toolset (no terminal, browser, code execution, or cron)
- Agent has no access to vault secrets, no file writes except reports
- Every action logged to audit trail as `CIRCUIT_BREAKER` with justification
- Only `severity: "critical"` rules can have `allowed_actions`
- **Cooldown** prevents rapid repeated triggers
- **Global spawn rate limit**: max 5 agent spawns per hour across all rules

---

## Cooldown & Rate Limits

- **Per-rule cooldown**: After a rule fires, it won't fire again until `cooldown` expires (e.g. "5m" = 5 minutes)
- **Global spawn limit**: Max 5 investigation agents per hour across all rules. If exceeded, the rule fires but the agent spawn is skipped with a log warning.
- **Thread pool**: Max 2 concurrent investigation agents. Additional spawns queue or are skipped.

---

## Default Rules

`hermes-aegis reactive init` creates three starter rules:

1. **`block-alert`** — `notify`, fires on any `BLOCKED` event, 2m cooldown, delivers formatted alert
2. **`anomaly-reporter`** — `investigate`, fires on 3+ `ANOMALY` events in 60s, 10m cooldown, report-only
3. **`exfiltration-response`** — `investigate`, `severity: critical`, fires on 5+ `BLOCKED` from `ProxyContentScanner` in 120s, 15m cooldown, can take circuit breaker actions

---

## CLI Commands

```bash
hermes-aegis reactive init              # Create default rules
hermes-aegis reactive list              # Show rules and status
hermes-aegis reactive test              # Dry-run against recent audit entries
hermes-aegis reactive enable <name>     # Enable a rule
hermes-aegis reactive disable <name>    # Disable a rule
```

---

## Reports

Reports are saved to `~/.hermes-aegis/reports/` as timestamped markdown files:

```
~/.hermes-aegis/reports/
├── exfiltration-response_20260315_210530.md
├── anomaly-reporter_20260315_220100.md
└── digest_20260316_090000.md
```

---

## Hash Chain Integrity

Before spawning an investigation agent, the watcher verifies `audit_trail.verify_chain()`. If the chain is tampered:

1. A `CHAIN_TAMPERED` decision is logged to the audit trail
2. This itself can trigger rules (e.g. a critical rule matching `decision: "CHAIN_TAMPERED"`)
3. The investigation agent is told the chain is compromised so it factors this into its analysis

---

## Scheduled Reports

Separate from reactive agents, you can schedule periodic audit digest reports via the hermes cron system:

```bash
hermes-aegis report schedule --every 24h --deliver telegram
hermes-aegis report schedule --cron "0 9 * * 1" --name weekly-digest
hermes-aegis report list
hermes-aegis report run           # Generate immediately
hermes-aegis report cancel <id>
```

Reports read the audit trail, compute statistics (events by type, top blocked domains, anomaly timeline), and generate a markdown digest.

---

## Files

| File | Purpose |
|------|---------|
| `~/.hermes-aegis/reactive-agents.json` | Rule configuration |
| `~/.hermes-aegis/reports/` | Investigation and digest reports |
| `~/.hermes-aegis/.watcher-offset` | Watcher position persistence |
| `~/.hermes-aegis/vault.lock` | Circuit breaker vault lock sentinel |
| `~/.hermes-aegis/domain-blocklist.json` | Circuit breaker domain blocks |
| `~/.hermes-aegis/.last-report-timestamp` | Last scheduled report time |
