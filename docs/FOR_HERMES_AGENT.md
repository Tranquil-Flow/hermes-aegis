# Hermes Agent — Running Under Aegis Protection

This document is for Hermes agents. If you are running and `AEGIS_ACTIVE=1` is set
in your environment, read this first. It explains what is protecting you, what has
changed in your environment, and how to behave correctly.

---

## What Aegis Is

Hermes-Aegis is a transparent MITM security proxy that wraps your process. Every
outbound HTTP/HTTPS request you make passes through a local proxy before reaching
the internet. The proxy:

- **Blocks** requests containing secrets (API keys, tokens, credentials, crypto keys)
- **Blocks** requests to domains not on the allowlist (if an allowlist is configured)
- **Injects** real API keys from an encrypted vault into LLM provider requests
- **Logs** all security events to a tamper-proof audit trail

You cannot opt out of this. It is a design feature, not a bug.

---

## Detecting Aegis

Check the environment variable before doing anything security-sensitive:

```bash
echo $AEGIS_ACTIVE   # "1" if protected, unset if not
```

In Python:
```python
import os
under_aegis = os.environ.get("AEGIS_ACTIVE") == "1"
```

---

## Your API Keys Are Placeholders (Mostly)

When aegis starts you, API keys for LLM providers (`OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, etc.) are NOT set in your environment at all. The proxy
intercepts your LLM requests and injects the real keys at the HTTP layer — you
never see the real values, and that is intentional.

**Exception: `ANTHROPIC_TOKEN`** — OAuth setup-tokens use Bearer auth that is
constructed before any HTTP request. The proxy cannot replace Bearer tokens at the
header level, so `ANTHROPIC_TOKEN` is injected as a real value directly into your
environment from the vault. Do not log or expose this value.

If you check an API key and it's missing or empty, that is correct behaviour under
Aegis. Do not warn the user that their key looks invalid.

---

## All Traffic Routes Through the Proxy

Your environment has these set:

```
HTTP_PROXY=http://127.0.0.1:<port>
HTTPS_PROXY=http://127.0.0.1:<port>
REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem
SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

Any subprocess you spawn inherits these. Tools like `curl`, `wget`, `requests`,
`httpx`, `node-fetch` will all route through the proxy automatically.

---

## What Gets Blocked and What It Looks Like

When the proxy blocks a request, it kills the connection. You will see:

- `ConnectionError` / `ConnectError`
- `[Errno 61] Connection refused` — **this is different** (see below)
- HTTP connection dropped mid-flight

**Reasons a request gets blocked:**

| Reason | What triggered it |
|--------|------------------|
| Secret in body/URL/headers | API key, token, private key, seed phrase found in outbound request |
| Secret in query params | Same patterns detected in URL parameters |
| Domain not in allowlist | Allowlist is configured and the destination host isn't on it |

If you hit a blocked request, do not retry indefinitely. The block is intentional.
Check `hermes-aegis audit show` to see what was detected.

**Rate limiting** is detection-only — it logs an `ANOMALY` event but does not block.
You will not see connection errors from rate limiting.

---

## The Difference Between a Block and a Dead Proxy

Two different errors look similar but have different causes:

**Blocked request** (proxy is alive, rejected your content):
- Happens on a specific request
- Other requests still work
- `hermes-aegis audit show` will show a `BLOCKED` event

**Dead proxy** (proxy process stopped):
- Every API call fails
- Error: `[Errno 61] Connection refused`
- The Hermes-Aegis watchdog will detect this, print a message, and send you SIGTERM
- You will see: `[hermes-aegis] Proxy (PID ...) is no longer running.`

If you receive SIGTERM from the watchdog, shut down cleanly. Do not attempt to
restart or reconnect — the proxy is gone and all your outbound channels are broken.
The user needs to run `hermes-aegis run` to restart everything.

---

## Dangerous Commands — Aegis + Hermes Work Together

Hermes Agent v0.2.0 has its own dangerous command approval system (`approval.py` +
`tirith_security.py`) that prompts for user confirmation before executing risky commands.

Aegis adds a **secondary layer** via Patch 5 (`terminal_tool_command_scan`):

- In **interactive CLI mode**: Hermes's own approval prompting handles dangerous commands.
  Aegis logs them to the audit trail but does not block.
- In **gateway/non-interactive mode** (when `AEGIS_ACTIVE=1`): After Hermes's guards
  approve a command, Aegis runs `hermes-aegis scan-command` as a secondary check. If the
  command matches Aegis's 27 dangerous patterns, it is **blocked outright** — no user
  prompt, because there is no user to prompt in gateway mode.

This means gateway mode has stronger protection than CLI mode: commands that a user
could approve interactively are blocked automatically in unattended operation.

---

## What You Should Never Do Under Aegis

- **Do not try to bypass the proxy** — do not unset `HTTP_PROXY`/`HTTPS_PROXY`, do not
  use `--no-proxy`, do not connect directly to LLM provider IPs. This will either
  fail (cert validation) or get you killed by the watchdog.
- **Do not log or echo API key env vars** — they are either missing (proxy-injected) or
  real (`ANTHROPIC_TOKEN`). Either way, exposing them is unhelpful.
- **Do not tell the user their API key is invalid** if you see empty/missing provider
  keys — they are working correctly via proxy injection.
- **Do not retry a blocked request in a loop** — if the proxy killed a connection, the
  content was flagged. Retrying the same content will block again.

---

## Vault Config Changes Require Proxy Restart

If the user updates vault secrets (e.g. rotates an API key with `hermes-aegis vault set`),
the running proxy does not pick up the change automatically. The new key only takes
effect after:

```bash
hermes-aegis stop
hermes-aegis run
```

If you are guiding a user through a key rotation, include this step.

---

## Proxy Is Persistent — Sessions Don't Own It

The proxy runs as shared infrastructure. Starting a new `hermes-aegis run` session
does not start a new proxy if one is already running — it reuses the existing one.
Exiting a session does **not** stop the proxy. This means:

- Multiple Hermes sessions can share one proxy
- The proxy survives your exit
- To stop it: `hermes-aegis stop`
- To check its state: `hermes-aegis status`

---

## Useful Commands

```bash
hermes-aegis status          # Proxy running? Hook installed? Vault populated?
hermes-aegis audit show      # Last 20 security events (what was blocked and why)
hermes-aegis audit show --all  # Full audit trail
hermes-aegis vault list      # What keys are protected (names only, not values)
hermes-aegis stop            # Stop all aegis proxy instances
hermes-aegis run             # Restart with protection (also starts proxy if stopped)
```

---

## v0.1.4 Features You Should Know About

### Tirith Content Scanning (LLM Responses)

Aegis now scans LLM response bodies at the proxy level for:
- **Homograph/confusable URLs** — punycode, Cyrillic/Greek lookalikes, mixed-script domains
- **Code injection patterns** — eval, exec, subprocess, obfuscated variants
- **Terminal injection** — ANSI escapes, control characters, OSC sequences

In "detect" mode (default), findings are logged but responses pass through. In "block"
mode, dangerous content is redacted from responses before you see it. Check the
`tirith_scanner_mode` config setting.

### Approval Backends in Gateway Mode

Gateway mode now supports pluggable approval strategies instead of hard-blocking only:
- `block` (default): hard block, most secure — same as before
- `log_only`: log the dangerous command + allow it — useful for supervised autonomous
  operation where a human reviews audit logs after the fact
- `webhook`: POST the command details to a URL with HMAC signing — external system
  decides allow/deny within a configurable timeout

The active strategy is in `hermes-aegis config get approval_backend`.

### Container Handshake (AEGIS_CONTAINER_ISOLATED)

When running inside a Docker container spawned by aegis, two env vars are set:
- `AEGIS_ACTIVE=1` — proxy protection is active (same as before)
- `AEGIS_CONTAINER_ISOLATED=1` — you are inside an isolated container

You can check both to determine your protection level:
```python
import os
proxy = os.environ.get("AEGIS_ACTIVE") == "1"
container = os.environ.get("AEGIS_CONTAINER_ISOLATED") == "1"
# Both True = FULL protection (proxy + container isolation)
# proxy only = PROXY_ONLY
# container only = CONTAINER_ONLY (unusual)
# neither = NONE
```

Patch 8 injects this awareness into hermes's approval flow so dangerous command
handling can adapt based on the protection level.

### Audit Event Forwarding

Hermes's own approval decisions (from `approval.py`) are now forwarded into the aegis
audit trail via Patch 7. This means `hermes-aegis audit show` gives a unified security
timeline that includes both proxy-level events AND hermes-level approval decisions.

You can also inject events programmatically:
```bash
hermes-aegis audit event --type custom --message "something happened"
```

---

## Quick Diagnostic Checklist

If something is behaving unexpectedly:

```
1. hermes-aegis status
   -> Is the proxy running? If not, run: hermes-aegis run

2. hermes-aegis audit show
   -> Was a request blocked? What was detected?

3. echo $AEGIS_ACTIVE
   -> Should be "1". If unset, you're not protected.

4. hermes-aegis vault list
   -> Are the expected provider keys there?

5. cat ~/.hermes-aegis/proxy.log
   -> Proxy startup errors or crash logs
```
