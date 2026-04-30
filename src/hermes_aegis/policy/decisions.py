"""Policy enforcement decisions.

The PolicyDecision enum represents the outcome of policy evaluation.
Every SecurityEvent that passes through the PolicyEngine results in a
decision that determines both the audit trail entry and any active
enforcement action (block, redact, etc.).
"""
from __future__ import annotations

from enum import Enum


class PolicyDecision(str, Enum):
    """Enforcement decision returned by the policy engine.

    Values:
        ALLOW: No enforcement action. Event is logged for observability.
        BLOCK: Request or command is killed. Active enforcement.
        REDACT: Sensitive content is stripped before forwarding.
        ANOMALY: Detection-only. No enforcement, but event is classified
            as anomalous for reactive rules and dashboards.
        INVESTIGATE: Trigger a reactive investigation agent.
    """

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    ANOMALY = "ANOMALY"
    INVESTIGATE = "INVESTIGATE"

    @property
    def is_blocking(self) -> bool:
        """Whether this decision requires active enforcement."""
        return self in (self.BLOCK, self.REDACT)
