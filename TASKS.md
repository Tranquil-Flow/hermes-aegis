# Hermes-Aegis Tasks

## Phase 1: Verify v0.2.0 Compatibility

Hermes Agent was updated to v0.2.0 (2026.3.12). Verify Aegis still works.

- [ ] Run full test suite: `uv run pytest tests/ -q` — fix any failures
- [ ] Verify integration.py monkey-patch works with v0.2.0's `_create_environment()` at `tools/terminal_tool.py:506`. Signature: `(env_type, image, cwd, timeout, ssh_config=None, container_config=None, task_id="default")`. Our patch already matches this — just confirm tests pass.
- [ ] Verify `AegisEnvironment` still correctly wraps `_LocalEnvironment` (Tier 1) and `_DockerEnvironment` (Tier 2) from `tools/environments/`
- [ ] Run red team tests if Docker available: `uv run pytest tests/red_team/ -v`

## Phase 2: New Security Features

Design principle: everything works secure by default, user can fine-tune for more security. Follow Hermes-Agent's pattern.

- [ ] **Domain allowlist** — Add user-configurable domain allowlist to proxy. Default: allow all (no breakage). User can tighten by adding allowed domains. Store in `~/.hermes-aegis/domain-allowlist.json`. Add CLI commands: `hermes-aegis allowlist add/remove/list`. When allowlist is non-empty, only those domains are permitted. Update proxy to check allowlist before forwarding. Write tests.

- [ ] **Output secret scanning** — Scan stdout/stderr from subprocess execution for secret patterns before returning to LLM. On by default. Wire into middleware chain post-dispatch. Use existing `scan_for_secrets()`. Redact matches in output. Write tests.

- [ ] **Workspace file write scanning** — Monitor file writes in `/workspace` for secret patterns. On by default. Hook into Tier 1 via `os.open` monkey-patch or filesystem watcher. Log violations to audit trail. Write tests.

- [ ] **Dangerous command blocking** — Upgrade dangerous command detection from audit-only to configurable blocking. Off by default (audit-only, current behavior). User enables blocking via config or `hermes-aegis config set dangerous_commands block`. When enabled, raise `SecurityError` for curl/wget/nc/ncat/ssh/scp and other dangerous patterns. Wire into middleware chain. Write tests.

- [ ] **Network rate limiting** — Detect burst patterns as likely tunneling. On by default with sensible thresholds (e.g. 50+ requests in 1 second). Implement as sliding-window counter in proxy ArmorAddon (Tier 2 — proxy already sees all requests). Log anomalies to audit trail. User can adjust thresholds via config. Write tests.

## Phase 3: Validation

- [ ] Run full test suite — all tests pass
- [ ] Run all 12 red team attacks against updated setup
- [ ] Update demo scripts if needed for new features
