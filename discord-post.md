**🛡️ Hermes Aegis — Security Hardening Layer for Hermes Agent**

Aegis is a MITM proxy that sits between the agent and the outside world. Every outbound HTTP/S request from the container gets intercepted, scanned, and logged before it leaves.

**What it does:**
- Scans all outbound traffic for API keys, bearer tokens, crypto private keys — blocks exfiltration before it hits the wire
- Rate limiting (50 req/s burst, anomaly flagging beyond that)
- Encrypted secret vault — credentials injected at the proxy layer, never in the process environment or config
- Approval/HITL system — webhook-based interactive approval with per-pattern caching (e.g. allow `git push*` for 60min after one approval)
- Tamper-evident hash-chained audit log
- Reactive agents — auto-fire on blocked/anomaly/exfiltration thresholds: Telegram alerts, AI investigation subagents, circuit breakers (kill proxy, lock vault, block domain)
- Config sanitizer — containers get a redacted copy of config, secrets never land in the container environment

**Issues & PRs this directly addresses:**

**#1444 — Agent executes actions without user approval in Telegram gateway** (https://github.com/NousResearch/hermes-agent/issues/1444)
This is the strongest overlap. Aegis implements a full approval backend as an out-of-band layer — the agent doesn't need to behave correctly for approval to be enforced, because it happens at the network level before the request leaves.

**#7 — MCP server integration** (https://github.com/NousResearch/hermes-agent/pull/7)
Every MCP connection (especially SSE/HTTP transport) routes through the proxy. All outbound calls to MCP servers get audited, rate-limited, and secret-scanned. If a misconfigured MCP tool tries to exfiltrate a key in a request body, Aegis catches it.

**#1463 — Execution Integrity Layer for post-tool verification** (https://github.com/NousResearch/hermes-agent/pull/1463)
Complementary, not redundant. #1463 checks whether local filesystem state matches what the tool reported. Aegis covers the network side — did the tool make an unexpected outbound call? Did it try to send a secret? Together they cover both surfaces.

**#6 — Dynamic tool loading** (https://github.com/NousResearch/hermes-agent/pull/6)
Dynamically loaded tools still make outbound calls through the proxy. Aegis logs `tool_name` in every audit entry, so even runtime-registered tools leave a traceable trail.

**#9 — Streaming tool execution** (https://github.com/NousResearch/hermes-agent/pull/9)
Rate limiting and secret scanning apply to streaming response bodies too. Streaming creates sustained high-frequency traffic patterns — exactly what the anomaly detection is built for.

**Honest caveats:**
- Aegis operates at the network layer. It doesn't cover agent-local state integrity (that's what #1463 does).
- The vault model means secrets must be vaulted to work — if a custom endpoint key (#1460) is only in config, the sanitizer will redact it and the agent won't see it. That's a UX tension we're aware of.
- Dangerous command scanning is currently in audit mode, not block mode.

**Repo:** https://github.com/evinova/hermes-aegis
