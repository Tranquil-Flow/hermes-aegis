from __future__ import annotations

import json as _json
import logging
import os
import time
from collections import deque
from pathlib import Path

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.config.allowlist import DomainAllowlist
from hermes_aegis.middleware.rate_escalation import RateEscalationTracker
from hermes_aegis.proxy.injector import (
    inject_api_key,
    inject_git_credentials,
    is_git_host_request,
    is_llm_provider_request,
)
from hermes_aegis.proxy.server import ContentScanner

logger = logging.getLogger("hermes_aegis.proxy")

# Path to hermes-agent's auth store (contains minted agent keys)
_HERMES_AUTH_FILE = Path.home() / ".hermes" / "auth.json"
# Don't re-read auth.json more often than this (seconds)
_AUTH_REFRESH_MIN_INTERVAL = 30


class AegisAddon:
    """Inject API keys for trusted LLM hosts and block secret exfiltration elsewhere."""

    def __init__(
        self,
        vault_secrets: dict[str, str],
        vault_values: list[str],
        audit_trail: AuditTrail | None = None,
        allowlist_path: Path | None = None,
        rate_limit_requests: int = 50,
        rate_limit_window: float = 1.0,
        refresh_hermes_auth: bool = False,
        escalation: RateEscalationTracker | None = None,
    ) -> None:
        self._vault_secrets = vault_secrets
        self._scanner = ContentScanner(vault_values=vault_values)
        self._audit = audit_trail
        # Pre-compute service→host mapping so own-service requests are not
        # blocked. e.g. BROWSERBASE_API_KEY → "browserbase" must be allowed
        # to reach api.browserbase.com without triggering the secret scanner.
        #
        # Sources: vault keys (always) + environment _API_KEY vars (covers
        # web-tool backends like TAVILY_API_KEY, FIRECRAWL_API_KEY, etc.
        # that may live in hermes .env rather than the aegis vault).
        self._own_service_hosts: set[str] = set()
        for key_name in vault_secrets:
            if key_name.endswith("_API_KEY"):
                service = key_name[:-8].lower().replace("_", "")
                self._own_service_hosts.add(service)
        for key_name in os.environ:
            if key_name.endswith("_API_KEY") and os.environ[key_name].strip():
                service = key_name[:-8].lower().replace("_", "")
                self._own_service_hosts.add(service)
        
        # Direct construction is hermetic by default. The mitmproxy entrypoint
        # wires the user-level allowlist path explicitly for production runs.
        self._allowlist = DomainAllowlist(allowlist_path)
        self._refresh_hermes_auth_enabled = refresh_hermes_auth
        
        self._escalation = escalation
        self._vault_values_list = vault_values  # keep ref for scanner updates

        # Track when we last refreshed from hermes auth.json
        self._auth_last_refreshed: float = 0.0

        # Rate limiting: track per-host request timestamps using sliding window
        self._rate_limit_requests = rate_limit_requests
        self._rate_limit_window = rate_limit_window
        self._request_timestamps: dict[str, deque[float]] = {}
        self._rate_anomaly_logged_until: dict[str, float] = {}
    
    def _check_rate_limit(self, host: str) -> bool:
        """Check if request rate exceeds threshold for given host.
        
        Uses sliding window algorithm with O(1) operations via deque.
        
        Args:
            host: The host being accessed
            
        Returns:
            True if rate limit exceeded, False otherwise
        """
        current_time = time.time()
        
        # Initialize deque for this host if first request
        if host not in self._request_timestamps:
            self._request_timestamps[host] = deque()
        
        timestamps = self._request_timestamps[host]
        
        # Remove timestamps outside the sliding window (older than window)
        cutoff_time = current_time - self._rate_limit_window
        while timestamps and timestamps[0] < cutoff_time:
            timestamps.popleft()
        
        # Check if adding this request would exceed the limit
        if len(timestamps) >= self._rate_limit_requests:
            # Rate limit exceeded
            return True
        
        # Add current request timestamp
        timestamps.append(current_time)
        return False

    def _should_log_rate_anomaly(self, host: str) -> bool:
        """Log at most one rate anomaly per host per rate-limit window."""
        current_time = time.time()
        logged_until = self._rate_anomaly_logged_until.get(host, 0.0)
        if current_time < logged_until:
            return False
        self._rate_anomaly_logged_until[host] = current_time + self._rate_limit_window
        return True

    def _refresh_hermes_auth(self, force: bool = False) -> bool:
        """Re-read hermes auth.json and update vault_secrets if the key changed.

        Called periodically before Anthropic requests and on 401 responses.
        Returns True if the key was updated.
        """
        now = time.time()
        if not force and (now - self._auth_last_refreshed) < _AUTH_REFRESH_MIN_INTERVAL:
            return False
        self._auth_last_refreshed = now

        if not _HERMES_AUTH_FILE.exists():
            return False

        try:
            auth_store = _json.loads(_HERMES_AUTH_FILE.read_text())
        except Exception:
            return False

        nous = auth_store.get("providers", {}).get("nous", {})
        agent_key = nous.get("agent_key")
        if not isinstance(agent_key, str) or not agent_key.strip():
            return False

        agent_key = agent_key.strip()
        old_key = self._vault_secrets.get("ANTHROPIC_API_KEY")
        if old_key == agent_key:
            return False  # unchanged

        # Update in-place so all subsequent requests use the new key
        self._vault_secrets["ANTHROPIC_API_KEY"] = agent_key

        # Also add to vault_values for scanner (don't leak our own key)
        if agent_key not in self._vault_values_list:
            self._vault_values_list.append(agent_key)

        logger.info("Refreshed ANTHROPIC_API_KEY from hermes auth.json")
        return True

    def request(self, flow) -> None:
        try:
            self._handle_request(flow)
        except Exception:
            # Never let an exception crash the proxy — log and pass through
            logger.exception("Unhandled error processing request to %s", flow.request.host)

    def response(self, flow) -> None:
        """Handle responses — refresh auth on 401 from Anthropic."""
        try:
            if (flow.request.host == "api.anthropic.com"
                    and flow.response
                    and flow.response.status_code == 401):
                # The minted agent key may have expired. Try refreshing from
                # auth.json — hermes-agent's auth loop mints a new key when
                # the old one is close to expiry.
                if self._refresh_hermes_auth_enabled and self._refresh_hermes_auth(force=True):
                    logger.info(
                        "Got 401 from Anthropic — refreshed key from auth.json. "
                        "Next request will use the new key."
                    )
        except Exception:
            pass  # never crash the proxy

    def _handle_request(self, flow) -> None:
        host = flow.request.host
        path = flow.request.path

        # Check rate limiting for ALL requests (detection-only, don't block)
        if self._check_rate_limit(host):
            # Log anomaly but don't block
            if self._audit is not None and self._should_log_rate_anomaly(host):
                timestamps = self._request_timestamps[host]
                window_size = len(timestamps)
                self._audit.log(
                    tool_name="outbound_http",
                    args_redacted={
                        "host": host,
                        "path": path,
                        "reason": f"burst pattern detected: {window_size} requests in {self._rate_limit_window}s (threshold: {self._rate_limit_requests})",
                        "requests_in_window": window_size,
                        "window_seconds": self._rate_limit_window,
                    },
                    decision="ANOMALY",
                    middleware="RateLimiter",
                )

            # Escalation: track repeated anomalies
            if self._escalation is not None:
                escalation = self._escalation.record_anomaly(host)
                if escalation.is_blocked:
                    if self._audit is not None:
                        self._audit.log(
                            tool_name="outbound_http",
                            args_redacted={
                                "host": host, "path": path,
                                "reason": f"rate escalation level {escalation.escalation_level}: host blocked after {escalation.anomaly_count} anomalies",
                            },
                            decision="BLOCKED",
                            middleware="RateEscalation",
                        )
                    flow.kill()
                    return

        if is_llm_provider_request(host, path):
            # Proactively refresh from auth.json before Anthropic requests
            # so we pick up newly minted keys without waiting for a 401.
            if host == "api.anthropic.com" and self._refresh_hermes_auth_enabled:
                self._refresh_hermes_auth()
            original_headers = dict(flow.request.headers)
            new_headers = inject_api_key(host, path, original_headers, self._vault_secrets)
            # Replace all headers atomically. The injector returns a complete
            # dict (copy of originals + modifications), so clearing and
            # rebuilding avoids case-sensitivity bugs between Python dicts
            # (case-sensitive) and mitmproxy Headers (case-insensitive).
            # The old diff-based approach broke OAuth because deleting
            # "User-Agent" from case-insensitive Headers also killed
            # "user-agent" before it could be re-added.
            flow.request.headers.clear()
            for key, value in new_headers.items():
                flow.request.headers[key] = value
            return

        # Inject git credentials for known git hosts (e.g. github.com).
        # Early-return like LLM providers: the proxy injects the credential,
        # so scanning our own injected Authorization header would self-block.
        if is_git_host_request(host):
            new_headers = inject_git_credentials(host, dict(flow.request.headers), self._vault_secrets)
            for key, value in new_headers.items():
                flow.request.headers[key] = value
            return

        # Allow a service's own API key to reach its own endpoint.
        # BROWSERBASE_API_KEY sent to api.browserbase.com is legitimate auth,
        # not exfiltration — same logic as LLM providers, just not pre-enumerated.
        # Match: service name extracted from key (e.g. "browserbase") ⊂ host.
        host_lower = host.lower()
        if any(svc in host_lower for svc in self._own_service_hosts):
            return

        # Check domain allowlist for non-LLM requests
        if not self._allowlist.is_allowed(host):
            if self._audit is not None:
                self._audit.log(
                    tool_name="outbound_http",
                    args_redacted={"host": host, "path": path, "reason": "domain not in allowlist"},
                    decision="BLOCKED",
                    middleware="DomainAllowlist",
                )
            flow.kill()
            return

        # For large bodies (>1MB), scan only the first and last 64KB
        # where secrets are most likely to appear, instead of skipping entirely.
        # This prevents bypass by padding requests with junk data.
        body = flow.request.get_content() or b""
        _LARGE_BODY = 1_048_576  # 1MB
        _SCAN_CHUNK = 65_536     # 64KB
        if len(body) > _LARGE_BODY:
            head = body[:_SCAN_CHUNK]
            tail = body[-_SCAN_CHUNK:]
            body_text = (head + tail).decode("utf-8", errors="replace")
        else:
            body_text = body.decode("utf-8", errors="replace")
        blocked, reason = self._scanner.scan_request(
            url=flow.request.url,
            body=body_text,
            headers=dict(flow.request.headers),
        )
        if not blocked:
            return

        if self._audit is not None:
            self._audit.log(
                tool_name="outbound_http",
                args_redacted={"host": host, "path": path, "reason": reason},
                decision="BLOCKED",
                middleware="ProxyContentScanner",
            )
        flow.kill()
