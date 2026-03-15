from __future__ import annotations

import logging
import time
from collections import deque
from pathlib import Path

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.config.allowlist import DomainAllowlist
from hermes_aegis.middleware.rate_escalation import RateEscalationTracker
from hermes_aegis.proxy.injector import inject_api_key, is_llm_provider_request
from hermes_aegis.proxy.server import ContentScanner

logger = logging.getLogger("hermes_aegis.proxy")


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
        escalation: RateEscalationTracker | None = None,
    ) -> None:
        self._vault_secrets = vault_secrets
        self._scanner = ContentScanner(vault_values=vault_values)
        self._audit = audit_trail
        
        # Load domain allowlist
        if allowlist_path is None:
            aegis_dir = Path.home() / ".hermes-aegis"
            allowlist_path = aegis_dir / "domain-allowlist.json"
        self._allowlist = DomainAllowlist(allowlist_path)
        
        self._escalation = escalation
        
        # Rate limiting: track per-host request timestamps using sliding window
        self._rate_limit_requests = rate_limit_requests
        self._rate_limit_window = rate_limit_window
        self._request_timestamps: dict[str, deque[float]] = {}
    
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

    def request(self, flow) -> None:
        try:
            self._handle_request(flow)
        except Exception:
            # Never let an exception crash the proxy — log and pass through
            logger.exception("Unhandled error processing request to %s", flow.request.host)

    def _handle_request(self, flow) -> None:
        host = flow.request.host
        path = flow.request.path

        # Check rate limiting for ALL requests (detection-only, don't block)
        if self._check_rate_limit(host):
            # Log anomaly but don't block
            if self._audit is not None:
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
            new_headers = inject_api_key(host, path, dict(flow.request.headers), self._vault_secrets)
            for key, value in new_headers.items():
                flow.request.headers[key] = value
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
