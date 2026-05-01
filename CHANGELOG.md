# Changelog

All notable changes to Hermes Aegis will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-05-01

### Added
- **Phase 1 — Policy engine core** — Normalized `SecurityEvent` / `PolicyDecision` /
  `PolicyEngine` layer. Single writer to the audit trail with hash-chain integrity,
  legacy-compatible `log()` plus typed `emit()`. All security components now route
  through the engine instead of writing to the audit trail directly.
- **Phase 2 — Engine wiring + audit noise reduction** — Rate-limit anomaly events
  are coalesced per-host-per-window (60s default), reducing audit noise. CLI status
  banner shows 24h counts grouped by middleware category.
- **Phase 3 — LibCST semantic patching** — Patches that modify hermes-agent source
  are now anchored to code structure (class, method, assignment) via LibCST instead
  of exact text strings, making them resilient to whitespace, comment, and refactor
  drift in upstream hermes-agent. Adds `SemanticPatch`, `AnchorSpec`, `TransformSpec`,
  and a fast pre-AST sentinel check.
- **Phase 4 — Modular detector framework** — Pluggable secret detectors (api_keys,
  crypto, entropy, structural). Detectors are registered, ordered, and runnable
  individually for unit testing. Replaces the monolithic regex sweep in the proxy
  content scanner.
- **Phase 5 — Seccomp profile + reactive sequence triggers** — macOS sandbox profile
  generation, reactive-rule sequence triggers (multi-event patterns over time), and
  `test-sandbox` command for verifying syscall isolation.
- **Audit summary command** — `hermes-aegis audit summarize` with `--since`,
  `--group-by`, and JSON/text output for audit-noise triage.
- **Provider presets + allowlist sync** — `hermes-aegis allowlist add-provider`,
  `sync-from-hermes`, and a curated preset library so onboarding allowlist for a
  multi-provider setup is one command instead of one-host-at-a-time.
- **Auto-bootstrap allowlist on install** — First-time `hermes-aegis install` now
  reads `~/.hermes/config.yaml` and seeds the allowlist with all configured
  providers, so the proxy works out of the box for existing hermes users.
- **`open.bigmodel.cn` registered as Z.AI provider** — Z.AI's primary endpoint
  (used by hermes update 2026-05-01 onward) now skips body scanning and shares
  `ZAI_API_KEY` injection with `api.z.ai`.

### Changed
- **Release version** — Bumped package and plugin metadata to `0.3.0`.
- **Auto-injection list expanded** — `AUTO_INJECT_KEYS` now includes `ZAI_API_KEY`
  and `VERCEL_API_TOKEN`, with a consistency test asserting every non-empty
  `key_env` in `LLM_PROVIDERS` is present so future provider additions can't
  silently 401.

### Fixed
- **AuditTrail.log is now O(1)** — Replaced linear file scan on every append with
  a stat-validated tail cache; multi-writer audit chain corruption (361 hash-chain
  breaks observed over 46 days pre-fix) resolved.
- **Generic entropy detector no longer blocks allowlisted hosts** — Tavily,
  Firecrawl, Exa, and similar tool providers carry their per-user API key in the
  request body. Phase 4 entropy detection was flagging these as `BLOCKED_SECRET`
  even when the host was explicitly allowlisted. Generic entropy + bearer + api_key
  patterns now skip on allowlisted hosts, while structural detectors still apply.
- **Coalescing / rate-limit / escalation host dicts are bounded** — Unbounded
  per-host dicts could grow indefinitely under sustained load. All three are now
  capped with LRU eviction.
- **azure_sas_token regex is reachable** — Pattern was previously masked by an
  earlier alternation; tests added to lock the fix.
- **Z.AI / GLM provider works under aegis** — `ZAI_API_KEY` was registered in
  `LLM_PROVIDERS` but missing from `AUTO_INJECT_KEYS`, so hermes never received
  the placeholder env var and Z.AI calls 401'd silently. `VERCEL_API_TOKEN` had
  the same shape and is fixed in the same commit.

### Removed
- **Three obsolete patches** dropped — absorbed natively by hermes-agent v0.7 so
  the aegis-side patches are no longer needed. Patch count: 17 → 14.

---

## [0.2.0] - 2026-04-29

### Added
- **Hermes v0.11 hybrid plugin direction** — Added `plugins/hermes-aegis/` with plugin
  metadata, hook entrypoints, state helpers, dashboard API scaffolding, and plugin-focused tests
  so Aegis can be discovered through the current Hermes plugin architecture.
- **macOS gateway sandbox support** — Added sandbox profile generation, a `test-sandbox`
  command, and patches that activate `sandbox-exec` for gateway sessions while preserving the
  local gateway backend through agent initialization.
- **One-command self-update integration** — The Aegis patch for `hermes update` now calls
  `hermes-aegis update`, so Hermes and Hermes-Aegis update together and patches are re-applied
  automatically.
- **Default protected launch** — Running `hermes-aegis` with no subcommand now starts Hermes
  under Aegis protection, equivalent to `hermes-aegis run`.
- **Hybrid migration helpers** — Added `src/hermes_aegis/migration.py` and regression coverage
  for migrating existing installs toward the hybrid plugin layout.

### Changed
- **Release target** — Bumped core package, `__version__`, and plugin metadata to `0.2.0` to
  match the larger plugin/sandbox architecture shift.
- **Dangerous command visibility for Docker** — Docker operations are now logged as dangerous
  patterns in the audit trail so reports and reactive rules can see container-risk activity
  with the same classification used for other risky commands.
- **README compatibility guidance** — Updated stale v0.1.6 / Hermes v0.3.0 text for the v0.2.0
  Hermes v0.11 compatibility release.

### Fixed
- **Hermes compatibility drift** — Updated patch targets and runtime glue for current Hermes
  provider/proxy routing, command approval, Docker, and sandbox behavior.
- **Proxy auth refresh propagation** — Restored `refresh_hermes_auth` propagation when starting
  the proxy from `hermes-aegis run`, so OAuth-derived provider credentials can refresh from
  Hermes auth state.
- **Provider allowlist coverage** — Refreshed provider/proxy allowlists for current Hermes
  provider endpoints.

---

## [0.1.9] - 2026-04-07

### Fixed
- **Hermes Agent v0.7.0 patch drift** — Updated all 6 broken install-time patches to match
  upstream `docker.py` and `terminal_tool.py` refactors, restoring Docker env forwarding,
  command scanning, approval handshake wiring, and cert/proxy propagation.
- **Banner rendering** — Removed the obsolete `cli_banner_aegis_status` patch and fixed the
  shield emoji glyph so Rich no longer miscalculates column widths in the Hermes banner.

---

## [0.1.8] - 2026-04-07

### Added
- **MiniMax provider support** — Added `MINIMAX_API_KEY` and `MINIMAX_CN_API_KEY` vault/env
  injection support plus `api.minimax.io` and `api.minimaxi.com` provider routing.
- **Self-update command** — `hermes-aegis update` now pulls the latest checkout, reinstalls the
  package, and re-applies Aegis patches after an upstream Hermes update.
- **Version flag** — `hermes-aegis --version` now reports the package version together with the
  current git SHA and clean/dirty working-tree status when run from a checkout.

### Fixed
- **Vault env sync** — `_sync_vault_to_env()` now merges vault-managed keys into `~/.hermes/.env`
  instead of overwriting unrelated user-managed entries.
- **Post-merge patch sentinels** — Updated patch anchor strings after upstream Hermes changes so
  install/reinstall keeps working on newer agent checkouts.

## [0.1.7] - 2026-03-26

### Added
- **macOS Keychain trust on install** — `hermes-aegis install` now adds the mitmproxy CA cert
  to the user's macOS Keychain so Chromium, Safari, and other browsers trust HTTPS through
  the aegis proxy without any manual steps
- **Docker cert mount patch** (`docker_cert_mount`) — new aegis patch that automatically
  bind-mounts the mitmproxy CA cert into Docker containers at `/certs/mitmproxy-ca-cert.pem`
  when `AEGIS_ACTIVE=1`, making the cert available to all in-container tools
- **Docker cert system trust patch** (`docker_cert_system_trust`) — new aegis patch that
  installs the CA into the container OS trust store via `update-ca-certificates` at container
  startup, enabling Playwright/Chromium HTTPS inside Docker containers
- **Honcho self-hosted sidecar** — optional Honcho memory server with graceful degradation,
  pre-flight health checks, and Gemini key support
- **OAuth → proxy bridging** — hermes `auth.json` Bearer tokens injected into proxy headers;
  case-insensitive header removal prevents duplicate auth entries
- **SSH/exfiltration patterns** — additional blocking patterns in security test suite

### Fixed
- **Browser HTTPS** — `AGENT_BROWSER_IGNORE_HTTPS_ERRORS=1` set in run environment so MCP
  browser servers inherit it. Chromium (BoringSSL) ignores system CA stores; this lets the
  browser accept mitmproxy-signed certs while mitmproxy validates upstream certs. Also added
  `browser_tool_strip_proxy_env` and `browser_tool_ignore_https_errors` patches for non-MCP
  browser paths
- **Docker proxy env forwarding** — `hermes-aegis run` hook now sets `TERMINAL_DOCKER_FORWARD_ENV`
  so proxy URL and cert path env vars reach Docker `exec` calls (was silently empty before)
- **Docker container internet access** — removed `--internal` network flag that was blocking
  containers from reaching the proxy; security enforced at proxy layer instead
- **Proxy binding** — mitmproxy now binds to `0.0.0.0` so Docker containers can reach it
  via `host.docker.internal`
- **Ctrl+C during flush_memories** — `KeyboardInterrupt` from SSL socket reads on exit
  no longer produces a traceback; caught as `BaseException` in both exit paths
- **Honcho port/install** — fixed `localhost:8000` endpoint, venv-first install check,
  and misleading error messages during Honcho setup

---

## [0.1.6] - 2026-03-17

### Added
- **Vercel AI Gateway provider** — `ai.vercel.com` added to `LLM_PROVIDERS` for API key injection
- **Native forward_env via TERMINAL_DOCKER_FORWARD_ENV** — Aegis now sets
  `TERMINAL_DOCKER_FORWARD_ENV` at launch, leveraging v0.3.0's native `docker_forward_env`
  config support instead of patching `DockerEnvironment.__init__` and `terminal_tool.py`
- **Comprehensive docstrings** across audit, middleware, patterns, proxy, and vault modules
- **Security benchmark harness** — Red-team test suite (10 scenarios, 100% block rate)
- **Session resume fix** — Correct session ID discovery after hermes spawn
- **Vault-to-env sync** — Vault keys written to `~/.hermes/.env` for provider startup check
- **LAN/localhost proxy bypass** — `NO_PROXY` set for Ollama and local LAN services
- **Docker mount improvements** — Host file mounts at original paths, sanitized config

### Changed
- **Hermes v0.3.0 compatibility** — Removed 3 obsolete patches (`docker_env_init_param`,
  `docker_env_constructor`, `terminal_tool_docker_forward`) since v0.3.0 added native
  `forward_env` support to `DockerEnvironment`. Updated `docker_exec_proxy_translate`
  patch to target the new `self._forward_env` loop pattern with `hermes_env` fallback.
- **`cli_banner_aegis_status` patch** — Marked obsolete for v0.3.0+. Hermes v0.3.0 removed
  the duplicate `build_welcome_banner` from `cli.py`; the `hermes_banner_aegis_status`
  patch covers v0.3.0. Shows `incompatible` on v0.3.0+ installs — expected and safe.

### Fixed
- **OAuth token handling** — Don't inject stale OAuth tokens; let hermes manage its own auth
- **chatgpt.com endpoint** — Added to LLM providers for Codex API key injection

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
