# Changelog

All notable changes to Hermes Aegis will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v0.1.3

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

[0.1.2]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.2
[0.1.1]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.1
[0.1.0]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.0
[0.0.1]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.0.1
