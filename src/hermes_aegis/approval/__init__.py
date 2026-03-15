"""Approval system — pluggable backends and persistent cache for command approval decisions."""
from .backends import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    BlockBackend,
    LogOnlyBackend,
    WebhookBackend,
    get_backend,
)
from .cache import ApprovalCache, CachedApproval

__all__ = [
    "ApprovalBackend",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalCache",
    "BlockBackend",
    "CachedApproval",
    "LogOnlyBackend",
    "WebhookBackend",
    "get_backend",
]
