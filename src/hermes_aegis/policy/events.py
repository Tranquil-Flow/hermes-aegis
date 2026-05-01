"""Normalized security event types and classification.

Every security-relevant occurrence in aegis is represented as a
SecurityEvent before it reaches the audit trail.  This module defines
the classification vocabulary (EventType, Severity) and the event
dataclass itself.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Normalized security event types.

    Each type corresponds to a distinct detection source and enforcement
    path.  The policy engine uses these for severity mapping and
    coalescing decisions.
    """

    BLOCKED_SECRET = "BLOCKED_SECRET"
    DOMAIN_BLOCKED = "DOMAIN_BLOCKED"
    RATE_ANOMALY = "RATE_ANOMALY"
    DANGEROUS_COMMAND = "DANGEROUS_COMMAND"
    OUTPUT_REDACTED = "OUTPUT_REDACTED"
    HERMES_APPROVAL = "HERMES_APPROVAL"
    RATE_ESCALATION = "RATE_ESCALATION"
    UNCLASSIFIED = "UNCLASSIFIED"


class Severity(str, Enum):
    """Security event severity levels.

    Ordered from most to least critical.  The policy engine maps each
    EventType + source combination to a default severity, which can be
    overridden by PolicyRule configuration.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Default severity mapping: (EventType -> Severity)
# The policy engine consults this table when classifying events that
# don't carry an explicit severity.
DEFAULT_SEVERITY_MAP: dict[EventType, Severity] = {
    EventType.BLOCKED_SECRET: Severity.CRITICAL,
    EventType.DOMAIN_BLOCKED: Severity.HIGH,
    EventType.RATE_ANOMALY: Severity.MEDIUM,
    EventType.DANGEROUS_COMMAND: Severity.HIGH,
    EventType.OUTPUT_REDACTED: Severity.LOW,
    EventType.HERMES_APPROVAL: Severity.MEDIUM,
    EventType.RATE_ESCALATION: Severity.HIGH,
    EventType.UNCLASSIFIED: Severity.INFO,
}


@dataclass
class SecurityEvent:
    """A normalized security event flowing through the policy engine.

    Attributes:
        event_type: Classified event type (e.g. BLOCKED_SECRET, RATE_ANOMALY).
        severity: Event severity level.
        source: Name of the component that produced this event
            (e.g. ``"ProxyContentScanner"``, ``"RateLimiter"``).
        tool_name: Tool or action that triggered the event.
        args_redacted: Tool arguments with sensitive values redacted.
        decision: Policy decision applied (ALLOW, BLOCK, etc.).
        middleware: Legacy middleware name preserved for audit compatibility.
        host: Target host, if applicable.
        path: URL path, if applicable.
        reason: Human-readable explanation.
        timestamp: Unix timestamp when the event was created.
            Defaults to ``time.time()``.
        extra: Additional context specific to the event type.
    """

    event_type: EventType
    severity: Severity
    source: str
    tool_name: str = ""
    args_redacted: dict[str, Any] = field(default_factory=dict)
    decision: str = ""
    middleware: str = ""
    host: str = ""
    path: str = ""
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_audit_dict(self) -> dict[str, Any]:
        """Convert to the dict format expected by AuditTrail.log().

        Returns a dictionary whose keys match the positional arguments of
        ``AuditTrail.log()`` so the engine can forward normalized events
        straight through.
        """
        args = dict(self.args_redacted)
        if self.host:
            args["host"] = self.host
        if self.path:
            args["path"] = self.path
        if self.reason:
            args["reason"] = self.reason

        # Attach policy metadata so future readers can reconstruct
        # classification without parsing free-text reason fields.
        args["_event_type"] = self.event_type.value
        args["_severity"] = self.severity.value
        args["_source"] = self.source

        return {
            "tool_name": self.tool_name,
            "args_redacted": args,
            "decision": self.decision,
            "middleware": self.middleware,
        }

    @classmethod
    def from_raw_audit(
        cls,
        *,
        tool_name: str,
        args_redacted: dict[str, Any],
        decision: str,
        middleware: str,
    ) -> SecurityEvent:
        """Reconstruct a SecurityEvent from a legacy AuditTrail.log() call.

        This is the bridge that lets the policy engine accept the same
        call signature as ``AuditTrail.log()`` while internally
        classifying the event.  Used during the Phase 1 passthrough
        where callers have not yet been migrated to emit typed events.
        """
        args = dict(args_redacted)
        host = args.get("host", "")
        path = args.get("path", "")
        reason = args.get("reason", "")

        event_type = _infer_event_type(decision, middleware, reason)
        severity = DEFAULT_SEVERITY_MAP.get(event_type, Severity.INFO)
        source = middleware  # In the passthrough, source == middleware name

        return cls(
            event_type=event_type,
            severity=severity,
            source=source,
            tool_name=tool_name,
            args_redacted=args_redacted,
            decision=decision,
            middleware=middleware,
            host=host,
            path=path,
            reason=reason,
        )


def _infer_event_type(
    decision: str,
    middleware: str,
    reason: str,
) -> EventType:
    """Infer EventType from legacy audit fields.

    This heuristic maps the existing (decision, middleware) pairs to
    the new typed EventType enum.  It runs during the passthrough
    phase so that all events — even those from unmigrated callers —
    get classified.
    """
    # Rate limiter events
    if middleware == "RateLimiter" and decision == "ANOMALY":
        return EventType.RATE_ANOMALY

    # Rate escalation (active defense)
    if middleware == "RateEscalation":
        return EventType.RATE_ESCALATION

    # Domain allowlist blocks
    if middleware == "DomainAllowlist" and decision == "BLOCKED":
        return EventType.DOMAIN_BLOCKED

    # Secret scanner blocks
    if middleware == "ProxyContentScanner" and decision == "BLOCKED":
        return EventType.BLOCKED_SECRET

    # Dangerous command detection
    if middleware == "DangerousBlockerMiddleware":
        return EventType.DANGEROUS_COMMAND

    # Output scanning / Tirith
    if middleware in ("TirithScanner", "OutputScanner"):
        return EventType.OUTPUT_REDACTED

    # Hermes approval gateway
    if middleware in ("HermesApproval", "approval"):
        return EventType.HERMES_APPROVAL

    # Fallback: use decision as a hint
    if decision == "BLOCKED":
        return EventType.DOMAIN_BLOCKED
    if decision == "ANOMALY":
        return EventType.RATE_ANOMALY
    if decision in ("DANGEROUS_COMMAND", "AUDIT"):
        return EventType.DANGEROUS_COMMAND

    # Unknown — classify as UNCLASSIFIED so the audit log distinguishes
    # genuine approval-gate events from events whose source the engine
    # has not yet learned to recognize.
    return EventType.UNCLASSIFIED
