# Hermes-Aegis Tasks

## New Security Features

- [ ] Add user-configurable domain allowlist to proxy — only allow traffic to known LLM provider domains + user-configured list. Store in `~/.hermes-aegis/domain-allowlist.json`. Add CLI commands: `hermes-aegis allowlist add/remove/list`. Update `proxy/injector.py` to check allowlist before forwarding. Write tests.

- [ ] Add output secret scanning — scan stdout/stderr from subprocess execution for secret patterns before displaying to user. Wire into the middleware chain. Use existing `scan_for_secrets()`. Redact matches in output. Write tests.

- [ ] Add workspace file write scanning — monitor file writes in `/workspace` for secret patterns using existing scanner. Hook into Tier 1 via `os.open` monkey-patch or filesystem watcher. Log violations to audit trail. Write tests.

- [ ] Upgrade dangerous command detection from audit-only to configurable blocking — add `block=True` mode to `patterns/dangerous.py` detection. Default to audit-only for backward compat. When blocking enabled, raise `SecurityError` for curl/wget/nc/ncat/ssh/scp. Wire into middleware chain. Write tests.

- [ ] Add network rate limiting — detect burst patterns (e.g. 50+ DNS lookups or connections in 1 second) as likely tunneling. Implement in middleware or proxy layer. Log anomalies to audit trail. Write tests.
