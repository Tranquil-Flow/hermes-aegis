# Changelog

All notable changes to Hermes Aegis will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-03-17

### Added
- **Vercel AI Gateway provider** — `ai.vercel.com` added to `LLM_PROVIDERS` for API key injection.
  Hermes v0.3.0 added Vercel AI Gateway support (#1628); aegis now intercepts and injects
  `VERCEL_API_TOKEN` as a Bearer header for those requests.

### Changed
- **Hermes v0.3.0 compatibility** — Updated `patches.py` patch targets for the new
  `DockerEnvironment.__init__` signature. Hermes v0.3.0 added `host_cwd` and
  `auto_mount_cwd` parameters (persistent shell mode, PR #1067); the `docker_env_init_param`
  and `terminal_tool_docker_forward` patches are updated to match the new upstream code.
- **`cli_banner_aegis_status` patch** — Marked obsolete for v0.3.0+. Hermes v0.3.0 removed
  the duplicate `build_welcome_banner` from `cli.py`; the banner is now exclusively in
  `hermes_cli/banner.py`. The `hermes_banner_aegis_status` patch (6a) covers v0.3.0.
  The cli.py patch will show `incompatible` on v0.3.0+ installs — this is expected and safe.

---

## [0.1.5] - 2026-03-15

### Added
- **Proxy process group isolation** — `os.setsid()` moves the mitmdump process into its
  own process group so terminal signals (SIGHUP, SIGINT from Ctrl+C) do not kill the
  proxy when Hermes exits or the user interrupts the terminal session. The proxy is now
  truly persistent background infrastructure.
- **Dual stdout+stderr logging** — Both stdout and stderr from the mitmdump subprocess
  are captured to `~/.hermes-aegis/proxy.log`. Previously only stderr was logged; mitmdump
  prints addon errors and crash tracebacks to stdout, so this was causing silent failures.

### Changed
- `hermes-aegis status` now shows container isolation state (`AEGIS_CONTAINER_ISOLATED`)
  even when the proxy is not running, so container detection works independently.

### Documentation
- README updated for v0.1.5 feature set
- FOR_HERMES_AGENT.md updated with v0.1.5 feature notes
- CHANGELOG updated to reflect all features since v0.1.0

---

## [0.1.4] - 2026-03-15

### Added
- **Hermes banner integration** — Patch 6 injects "🛡️ Aegis Protection Activated" into hermes startup banner below session ID when AEGIS_ACTIVE=1
- **Audit trail unification** — `hermes-aegis audit event` CLI command for external event injection; Patch 7 forwards hermes approval decisions into aegis audit trail for unified security timeline
- **Tirith proxy-level content scanner** — New middleware scans LLM responses for:
  - Homograph/confusable URLs (punycode, Cyrillic/Greek lookalikes, mixed-script domains)
  - Code injection patterns (eval, exec, subprocess, obfuscated variants)
  - Terminal injection (ANSI escapes, control characters, OSC sequences)
  - Two modes: "detect" (log only, default) and "block" (redact findings)
- **Shared pattern registry** — `patterns/shared_registry.py` discovers and imports hermes-agent's redact.py patterns at runtime, merges with aegis patterns, deduplicates
- **HermesConfig auto-discovery** — Reads ~/.hermes/config.yaml to auto-detect terminal backend, model, volumes; exposed via Settings.hermes_config
- **Container-Aegis handshake protocol** — ProtectionLevel enum (NONE/PROXY_ONLY/CONTAINER_ONLY/FULL), detect_protection() for runtime security state; Patch 8 injects container awareness into hermes approval flow
- **Pluggable approval backends** — Gateway mode now supports configurable strategies:
  - `block` (default): hard block, most secure
  - `log_only`: log + allow for supervised autonomous operation
  - `webhook`: POST to URL with HMAC signing, configurable timeout
- **Rate limiting escalation** — Anomaly detection now escalates: 4-level system (normal→warning→elevated→blocked); repeated anomalies on same host trigger active blocking
- **Persistent approval cache** — Stores allow/deny decisions across sessions with TTL support, glob/substring pattern matching; CLI: `hermes-aegis approvals list/add/remove/clear`
- **CLI config commands** — `hermes-aegis config get/set/list` for managing all aegis settings
- **Container isolation env vars** — Docker containers now get AEGIS_ACTIVE=1 and AEGIS_CONTAINER_ISOLATED=1

### Fixed
- **Version string inconsistency** — CLI banner and main command now read from __version__ (was hardcoded v0.1.2)
- **Async test failures** — Tirith scanner tests properly use pytest-asyncio
- **Dynamic version assertion** — test_cli_commands.py imports __version__ instead of hardcoding

### Test Coverage
- 627 tests passing, 0 failures
- New test files: test_patches.py (33), test_settings.py (15), test_injector.py (46), test_shared_registry.py (18), test_hermes_config.py (23), test_tirith_scanner.py (41), test_container_handshake.py (20), test_approval_backends.py (33), test_rate_escalation.py (25), test_approval_cache.py (28), test_audit_event.py (9)

---

## [0.1.3] — 2026-03-15

### Added
- **Patch system** (`patches.py`) — 5 idempotent, reversible patches applied to
  hermes-agent source at install time:
  - Patches 1–4: Docker proxy forwarding — adds `forward_env` param to
    `DockerEnvironment.__init__`, passes it to `_Docker()` constructor, translates
    `127.0.0.1`/`localhost` → `host.docker.internal` in exec loop, remaps mitmproxy
    cert path to `/certs/mitmproxy-ca-cert.pem`, wires `_aegis_forward` at the
    `terminal_tool.py` DockerEnvironment instantiation site
  - Patch 5: `terminal_tool_command_scan` — when `AEGIS_ACTIVE=1`, calls
    `hermes-aegis scan-command` as a secondary check after hermes-agent's own guards,
    enforcing `DangerousBlockerMiddleware` pattern blocking in gateway/non-interactive
    mode where hermes would otherwise auto-allow without prompting
- `patches_status()` — dry-run inspection of which patches are applied, missing,
  or incompatible without modifying any files
- `aegis scan-command <cmd>` — CLI command that runs a shell command string through
  Aegis dangerous-pattern detection; exit 0 = safe, exit 1 = blocked with reason.
  Used by Patch 5 and useful as a standalone pre-flight check.
- `install` now calls `apply_patches()` and reports applied/skipped/incompatible
  per patch with actionable guidance on incompatible hermes-agent versions
- `uninstall` now calls `revert_patches()` to restore upstream hermes-agent files

### Fixed
- **Tirith cosign failure** — mitmproxy no longer intercepts sigstore/TUF TLS:
  `--ignore-hosts` added for `sigstore.dev`, `tuf.dev`, `rekor`, `fulcio`, and
  `tuf-repo-cdn` domains; cosign uses its own cert bundle and rejects the mitmproxy
  CA, breaking Tirith's auto-install and provenance verification
- **ANTHROPIC_TOKEN 401 error** — OAuth setup-tokens use Bearer auth constructed
  before any HTTP request; the proxy cannot replace them at the header level the way
  it replaces `x-api-key`. `hermes-aegis run` now reads `ANTHROPIC_TOKEN` directly
  from the vault and injects it into the child process environment
- **`.env` placeholder after vault migration** — `hermes setup` no longer loops with
  "no API keys found" when run directly (without `hermes-aegis run`): after deleting
  the original `.env`, a placeholder `.env` is written with vault-managed keys set
  to `aegis-managed` so Hermes's startup credential check passes
- **Duplicate key list** — `_HERMES_PROVIDER_KEYS` set was an exact duplicate of
  `AUTO_INJECT_KEYS`; removed, `_get_vault_provider_keys()` now uses
  `set(AUTO_INJECT_KEYS)` directly

### Known limitations
- `hermes update` (git pull) overwrites patched hermes-agent files; re-run
  `hermes-aegis install` after every `hermes update` to re-apply patches
- Patches target specific upstream strings; incompatible hermes-agent versions
  produce a warning and continue rather than hard-failing
- Patch 5 (`terminal_tool_command_scan`) is `critical=False` — gateway mode
  blocking requires `AEGIS_ACTIVE=1` set in the environment and `hermes-aegis`
  on PATH; fails open (does not block) if hermes-aegis is unavailable

---

## [0.1.2] - 2026-03-15

### Added
- `audit clear` command — shows summary by decision type, prompts for confirmation,
  archives existing log to `audit.jsonl.YYYYMMDD-HHMMSS` before wiping
- `--decision` filter on `audit show` (case-insensitive: `blocked`, `allowed`, etc.)
- Banner event breakdown: "74 events (3 blocked, 2 dangerous command)" instead of
  raw count

### Fixed
- Multi-session proxy bug 1: `_start_proxy_for_run` now stops stale proxy before
  starting new one, preventing orphan processes; preserves existing port so running
  sessions' `HTTPS_PROXY` stays valid
- Multi-session proxy bug 2: `_restart_proxy_if_running` passes
  `listen_port=existing_port` on vault-triggered restarts so running sessions don't
  lose proxy connectivity
- Multi-session proxy bug 3: `_proxy_watchdog` adds 12s grace period + re-probe
  before killing Hermes, allowing transparent proxy restarts without disrupting
  active sessions
- Test suite: add `docker>=7.0` to dev deps; fix `pytest.importorskip` usage in
  integration/security tests; 353 passing, 0 failures

### Not included (added in v0.1.3)
- Docker proxy forwarding into containers (patches.py)
- `.env` placeholder fix after vault migration

---

## [0.1.1] - 2026-03-15

### Changed
- Bumped version to 0.1.1; fixed version assertion in test suite to match

---

## [0.1.0] - 2026-03-14

### Added
- **Transparent MITM Proxy** - Zero-modification interception of all API calls
- **Secret Vault System** - Secure storage with keyring integration
- **Real-time Request Scanning** - Pattern matching for secrets, PII, dangerous patterns
- **Audit Trail** - Comprehensive JSONL logging of all intercepted requests
- **Rate Limiting** - Protection against token floods and enumeration attacks
- **Allowlist System** - Domain and pattern-based request filtering
- **CLI Interface** - Complete command-line tooling for proxy management
- **Hook Integration** - Automatic injection into Hermes Agent workflow
- **Container Support** - Optional Docker isolation for untrusted commands (Level 3)
- **Run Command** - Sandboxed command execution with network isolation

### Security Features
- Recursive secret redaction at any nesting depth
- Request/response body scanning
- URL parameter scanning
- Header scanning with common secret patterns
- Automatic secret detection (API keys, tokens, passwords)
- Cryptographic audit trail with chain verification

### Technical Details
- Port binding retry logic (handles TOCTOU races)
- Enhanced error handling and logging throughout
- Lifecycle management for proxy processes
- Graceful shutdown with cleanup
- Comprehensive test coverage (60+ tests)

### CLI Commands
- `aegis install` - One-command setup with auto-configuration
- `aegis start` - Launch proxy with hot-reload
- `aegis stop` - Graceful shutdown
- `aegis status` - Connection and health check
- `aegis vault add/list/remove` - Secret management
- `aegis audit show/stats` - Audit trail analysis
- `aegis test-canary` - Verify secret detection works
- `aegis run` - Execute commands in sandboxed environment

### Documentation
- Comprehensive README with quickstart
- Attack scenario demonstrations
- Architecture documentation
- Test coverage reports
- Installation guides

## [0.0.1] - 2026-03-13

### Added
- Initial prototype
- Basic proxy interception
- Simple secret scanning
- Proof of concept

[0.1.5]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.5
[0.1.4]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.4
[0.1.3]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.3
[0.1.2]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.2
[0.1.1]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.1
[0.1.0]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.0
[0.0.1]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.0.1
