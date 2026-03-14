# Handover: Building Aegis Tier 2

Read this FIRST. Then read `TIER2-PLAN.md`. Then read `HERMES-REVIEW.md`.

---

## Current State (March 12, 2026)

**Branch**: `overnight-task8-pilot`
**Tests**: 131 passing, 11 failing (Docker-dependent tests that skip when Docker isn't available — these are expected failures when running without Docker)
**Uncommitted**: Only `TIER2-PLAN.md` (the revised plan)

Everything else is committed and clean.

---

## What You're Building

An `AegisEnvironment` class that plugs into Hermes's existing backend system. When a user sets `TERMINAL_ENV=aegis`, all terminal commands and file operations run inside a Docker container with a MITM proxy on the host. The proxy:
- Injects API keys into LLM provider requests (container never sees the keys)
- Scans all outbound traffic for secret exfiltration
- Logs everything to a tamper-proof audit trail

---

## Critical File Locations

### Hermes Agent (read-only, do not modify)
| File | What It Is |
|------|-----------|
| `~/.hermes/hermes-agent/tools/environments/base.py` | `BaseEnvironment` — the interface you must implement |
| `~/.hermes/hermes-agent/tools/environments/docker.py` | `DockerEnvironment` — wraps this for the inner container |
| `~/.hermes/hermes-agent/tools/terminal_tool.py` | Lines 437-486: `_get_env_config()` — how backends are selected |
| `~/.hermes/config.yaml` | User config — `terminal.backend` sets the backend |

### Hermes-Aegis (your workspace)
| File | What It Is |
|------|-----------|
| `src/hermes_aegis/proxy/addon.py` | ArmorAddon — already works, tested |
| `src/hermes_aegis/proxy/injector.py` | LLM provider matrix — already works |
| `src/hermes_aegis/proxy/runner.py` | Proxy startup — already fixed (asyncio.run) |
| `src/hermes_aegis/proxy/server.py` | ContentScanner — already works |
| `src/hermes_aegis/container/builder.py` | Container config — needs `internal: true` network and cert volume |
| `src/hermes_aegis/container/runner.py` | Container lifecycle — exists but may be replaced by wrapping Hermes's DockerEnvironment |
| `src/hermes_aegis/audit/trail.py` | Audit trail — works, tested |
| `src/hermes_aegis/vault/store.py` | Encrypted vault — works, tested |
| `src/hermes_aegis/patterns/secrets.py` | Secret patterns — works, needs RPC URL patterns added |
| `src/hermes_aegis/patterns/crypto.py` | Crypto patterns — works, needs full BIP39 wordlist |

---

## The BaseEnvironment Interface You Must Implement

```python
class BaseEnvironment(ABC):
    def __init__(self, cwd: str, timeout: int, env: dict = None):
        ...

    @abstractmethod
    def execute(self, command: str, cwd: str = "", *,
                timeout: int | None = None,
                stdin_data: str | None = None) -> dict:
        """Return {"output": str, "returncode": int}"""
        ...

    @abstractmethod
    def cleanup(self):
        """Release resources."""
        ...
```

Your `AegisEnvironment` must match this interface exactly. Hermes will call `execute()` for every terminal command and file operation.

---

## How Hermes Selects Backends

In `terminal_tool.py` line 441:
```python
env_type = os.getenv("TERMINAL_ENV", "local")
```

Then a factory function creates the environment. You need to either:
1. Add `aegis` to that factory (requires modifying Hermes — less ideal)
2. Create a wrapper/installer that monkey-patches the factory at import time
3. Create a small shim that sets up the environment and delegates

**Recommended**: Option 2 or 3 — don't modify Hermes source. Create an entry point that patches the registration.

---

## Things That Will Trip You Up

### 1. DockerEnvironment uses subprocess, not docker-py
Hermes's `DockerEnvironment` runs `docker` CLI commands via `subprocess.Popen`, NOT the Python `docker` SDK. The existing Aegis `ContainerRunner` uses `docker` SDK (`docker.from_env()`). These are incompatible approaches. You need to decide:
- **Wrap Hermes's DockerEnvironment** (uses subprocess, battle-tested) — recommended
- **Replace with your own** (uses docker SDK) — more control but more work

### 2. CA cert must exist before first proxy run
mitmproxy generates `~/.mitmproxy/mitmproxy-ca-cert.pem` on first run. If this file doesn't exist, the container won't trust HTTPS through the proxy. Run `ensure_mitmproxy_ca_cert()` during setup, not during first execute.

### 3. The `internal: true` network blocks ALL outbound
When you set `internal: true` on the Docker network, the container cannot reach the internet at all — not even through the proxy, unless the proxy is on the host side and the container reaches it via `host.docker.internal`. Verify that `host.docker.internal` resolves inside the container on your platform (it works on Docker Desktop for Mac/Windows, but on Linux you may need `--add-host`).

### 4. Hermes's DockerEnvironment adds capabilities back
Look at `docker.py` line 30-34:
```python
"--cap-drop", "ALL",
"--cap-add", "DAC_OVERRIDE",
"--cap-add", "CHOWN",
"--cap-add", "FOWNER",
```
It adds DAC_OVERRIDE, CHOWN, and FOWNER back so pip/npm can install packages. Your Aegis builder drops ALL with nothing added back (`builder.py` line 39). If you wrap Hermes's DockerEnvironment, those caps come back. If you use your own, you need to decide: do you want users to be able to `pip install` inside the container? If yes, add them back. If no (more secure), leave them dropped but document the limitation.

### 5. File operations go through the same backend
When `TERMINAL_ENV=docker` (or `aegis`), Hermes routes `read_file`, `write_file`, `search` through the same environment. This means file operations also run inside the container. The container only sees `/workspace`. This is a feature (isolation), but it means the agent can't read host files. Make sure the workspace has everything the agent needs before starting.

### 6. The 11 failing tests are expected
They fail because they require Docker at runtime. When Docker is available and Tier 2 is built, they should pass. Don't "fix" them by removing them.

### 7. Don't use `time.sleep()` for proxy startup
Use `wait_for_proxy_ready()` with socket polling. The plan has the implementation.

### 8. Proxy port conflicts
If another process is on 8443, the proxy silently fails. Use `find_available_port()` from the plan.

---

## Commit Strategy

- One commit per phase (or per task if a phase is large)
- Run `uv run pytest tests/ -q` before every commit
- Message format: `feat: description` / `fix: description` / `test: description`
- Never push — leave for human review
- The 11 Docker-dependent failures are expected until Tier 2 is complete

---

## What NOT to Do

- Don't modify Hermes source files (`~/.hermes/hermes-agent/`)
- Don't rebuild the existing Aegis Tier 1 code — it works
- Don't delete existing tests — add new ones
- Don't mock the security boundary in integration tests (mock the destination server, not the scanner/proxy)
- Don't use `network_mode: "none"` — use `internal: true` instead (allows host.docker.internal)
- Don't hardcode port 8443 — use auto-selection
- Don't store secrets in container env vars — that's the entire point of Tier 2
- Don't fabricate test output — run tests and paste actual results

---

## Reading Order

1. **This file** (you're reading it)
2. **`TIER2-PLAN.md`** — the full implementation plan with code examples
3. **`HERMES-REVIEW.md`** — code review, lessons from previous mistakes
4. **`~/.hermes/hermes-agent/tools/environments/base.py`** — the interface to implement
5. **`~/.hermes/hermes-agent/tools/environments/docker.py`** (first 100 lines) — understand what you're wrapping
6. **`src/hermes_aegis/proxy/addon.py`** — the proxy logic you're integrating

Do NOT read `docs/IMPLEMENTATION-PLAN.md` (114KB, outdated, superseded by TIER2-PLAN.md).

---

## Definition of Done

When all of these are true, Tier 2 is complete:
1. `TERMINAL_ENV=aegis` causes Hermes to run commands in a container with proxy
2. Container env has zero API keys
3. Proxy injects keys for LLM providers
4. HTTP exfiltration from container is blocked
5. Direct TCP from container is blocked (internal network)
6. Red team script: all 9 attacks fail
7. All existing tests still pass
8. New integration tests pass with Docker
9. `uv run pytest tests/ -v` — zero failures
