## Phase — Auto-Update Integration

- [x] Add 'update' CLI command to hermes-aegis that runs: git pull + pip install -e . + re-apply patches
- [x] Add version check: hermes-aegis --version shows version + git SHA + clean/dirty status
- [x] Patch 12 (`hermes_update_aegis_repatch`) verified applied and working after hermes 0.3→0.7 update
- [x] Test full flow on host: hermes update → aegis patches auto-reapplied → verified (2026-04-06)

## Phase — Patch Drift Fix (hermes-agent v0.7.0)

After updating hermes-agent from v0.3.0 → v0.7.0 (1,100+ commits), 6 patches broke.
Non-Docker gateway sessions are still protected. Docker isolation is degraded until fixed.

### docker.py patches — `tools/environments/docker.py`

- [ ] **`docker_network_isolation`** — `before` pattern missing `+ env_args`: upstream added explicit
  env var forwarding (`env_args = []; for key in sorted(self._env)`) before `all_run_args`.
  Fix: update `before` to `"all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args + env_args\n"`

- [ ] **`docker_cert_mount`** — same `before` pattern as `docker_network_isolation`, same fix needed.

- [ ] **`docker_cert_system_trust`** — `before` was `self._container_id = self._inner.container_id`.
  The `_inner` indirection is gone; now `self._container_id = result.stdout.strip()` (after `docker run`).
  Fix: update `before` to match new assignment site.

- [ ] **`docker_exec_proxy_translate`** — `host.docker.internal` and `self._forward_env` loop removed.
  Env forwarding is now via `self._env` dict passed at construction. Patch needs full redesign
  to intercept the new env_args construction (`for key in sorted(self._env)`).

### terminal_tool.py patches — `tools/terminal_tool.py`

- [ ] **`terminal_tool_command_scan`** — sentinel `"hermes-aegis", "scan-command"` not found.
  Investigate whether `terminal_tool_audit_forward` (which applied successfully) shifted the
  surrounding code enough to break the `before` match, or if the target section moved.

- [ ] **`terminal_tool_container_handshake`** — same `before` as command_scan, likely same root cause.

- [ ] **`terminal_tool_docker_forward_env`** — `before` targets `"container_cpu": config.get(...)` which
  exists at terminal_tool.py:1092. Check if surrounding context changed.

### After fixing patches

- [ ] Run `hermes-aegis install` and confirm all patches apply cleanly
- [ ] Run `uv run pytest tests/ -q` — ensure test suite still passes
- [ ] Verify Docker container sessions route traffic through aegis proxy
