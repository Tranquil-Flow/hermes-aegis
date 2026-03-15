"""Approval backends for gateway/non-interactive mode.

When hermes runs in gateway mode (no interactive user), dangerous commands
need an approval strategy. This module provides pluggable backends:

- 'block': Hard block, no approval possible (current default, most secure)
- 'webhook': POST to configured URL, wait for approve/deny response
- 'log_only': Log the event but allow execution (supervised autonomous)
"""
from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ApprovalDecision(Enum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ApprovalRequest:
    command: str
    pattern_key: str
    description: str
    timestamp: float
    session_id: str = ""


@dataclass 
class ApprovalResponse:
    decision: ApprovalDecision
    reason: str = ""
    responder: str = ""
    response_time: float = 0.0


class ApprovalBackend(ABC):
    @abstractmethod
    def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        ...
    
    @property
    @abstractmethod
    def name(self) -> str:
        ...


class BlockBackend(ApprovalBackend):
    """Always blocks. Most secure, default for gateway mode."""
    
    @property
    def name(self) -> str:
        return "block"
    
    def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            decision=ApprovalDecision.DENIED,
            reason=f"Blocked by policy: {request.description}",
            responder="block_backend",
        )


class LogOnlyBackend(ApprovalBackend):
    """Logs but allows. For supervised autonomous operation."""
    
    @property
    def name(self) -> str:
        return "log_only"
    
    def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        logger.warning(
            "Dangerous command allowed (log_only mode): %s [%s]",
            request.command[:200], request.pattern_key,
        )
        return ApprovalResponse(
            decision=ApprovalDecision.APPROVED,
            reason="Allowed by log_only policy",
            responder="log_only_backend",
        )


class WebhookBackend(ApprovalBackend):
    """POST to webhook URL and wait for response."""
    
    def __init__(self, url: str, timeout: float = 30.0, secret: str = ""):
        self._url = url
        self._timeout = timeout
        self._secret = secret
    
    @property
    def name(self) -> str:
        return "webhook"
    
    def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        import requests
        
        payload = {
            "command": request.command[:500],
            "pattern_key": request.pattern_key,
            "description": request.description,
            "timestamp": request.timestamp,
            "session_id": request.session_id,
        }
        
        headers = {"Content-Type": "application/json"}
        if self._secret:
            import hashlib, hmac
            sig = hmac.new(
                self._secret.encode(), 
                json.dumps(payload, sort_keys=True).encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Aegis-Signature"] = sig
        
        start = time.monotonic()
        try:
            resp = requests.post(
                self._url, json=payload, headers=headers,
                timeout=self._timeout,
            )
            elapsed = time.monotonic() - start
            
            if resp.status_code == 200:
                data = resp.json()
                approved = data.get("approved", False)
                return ApprovalResponse(
                    decision=ApprovalDecision.APPROVED if approved else ApprovalDecision.DENIED,
                    reason=data.get("reason", ""),
                    responder=data.get("responder", "webhook"),
                    response_time=elapsed,
                )
            else:
                return ApprovalResponse(
                    decision=ApprovalDecision.DENIED,
                    reason=f"Webhook returned {resp.status_code}",
                    responder="webhook",
                    response_time=elapsed,
                )
        except requests.Timeout:
            return ApprovalResponse(
                decision=ApprovalDecision.TIMEOUT,
                reason=f"Webhook timeout after {self._timeout}s",
                responder="webhook",
            )
        except Exception as e:
            return ApprovalResponse(
                decision=ApprovalDecision.ERROR,
                reason=str(e),
                responder="webhook",
            )


class CachedBackend(ApprovalBackend):
    """Wraps another backend with a persistent approval cache.

    Cache behavior:
    - Only 'allow' decisions are cached (denials always re-checked)
    - Default TTL: 3600 seconds (1 hour)
    - Cache key is the command pattern, not exact command
    - Disabled by default — must be explicitly enabled via config
    """

    def __init__(self, inner: ApprovalBackend, cache: "ApprovalCache", default_ttl: float = 3600.0):
        self._inner = inner
        self._cache = cache
        self._default_ttl = default_ttl

    @property
    def name(self) -> str:
        return f"cached_{self._inner.name}"

    def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        # Check cache first
        cached = self._cache.check(request.command)
        if cached is not None and cached.decision == "allow":
            return ApprovalResponse(
                decision=ApprovalDecision.APPROVED,
                reason=f"Cached approval: {cached.reason}",
                responder=f"cache (original: {cached.created_by})",
            )

        # Cache miss or cached denial — ask the real backend
        response = self._inner.request_approval(request)

        # Only cache approvals, never denials
        if response.decision == ApprovalDecision.APPROVED:
            self._cache.add(
                pattern=request.command,
                decision="allow",
                reason=response.reason,
                ttl_seconds=self._default_ttl,
                created_by=response.responder,
            )

        return response


def get_backend(config: dict) -> ApprovalBackend:
    """Factory: create approval backend from config dict.
    
    Config keys:
        approval_backend: 'block' | 'log_only' | 'webhook' (default: 'block')
        approval_webhook_url: URL for webhook backend
        approval_webhook_timeout: seconds (default: 30)
        approval_webhook_secret: HMAC secret for webhook signing
    """
    backend_type = config.get("approval_backend", "block")
    
    if backend_type == "log_only":
        backend = LogOnlyBackend()
    elif backend_type == "webhook":
        url = config.get("approval_webhook_url", "")
        if not url:
            logger.error("Webhook backend requires approval_webhook_url")
            backend = BlockBackend()  # Fall back to block
        else:
            backend = WebhookBackend(
                url=url,
                timeout=float(config.get("approval_webhook_timeout", 30)),
                secret=config.get("approval_webhook_secret", ""),
            )
    else:
        backend = BlockBackend()

    # Wrap with cache if enabled
    if config.get("approval_cache_enabled", False):
        from hermes_aegis.approval.cache import ApprovalCache
        cache_path = None  # uses default ~/.hermes-aegis/approval-cache.json
        cache = ApprovalCache(cache_path)
        ttl = float(config.get("approval_cache_ttl", 3600))
        backend = CachedBackend(backend, cache, default_ttl=ttl)

    return backend
