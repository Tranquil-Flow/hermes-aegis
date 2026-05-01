"""Policy engine for normalized security event processing.

The policy core is the single point of truth for:
- Classifying security events by type, severity, and source
- Applying policy rules to determine enforcement decisions
- Coalescing duplicate events (e.g., rate-limiter anomaly spam)
- Writing normalized entries to the audit trail

All middleware and proxy components emit SecurityEvent objects to the
PolicyEngine rather than calling AuditTrail.log() directly.
"""
from hermes_aegis.policy.events import EventType, Severity, SecurityEvent
from hermes_aegis.policy.decisions import PolicyDecision
from hermes_aegis.policy.rules import PolicyRule
from hermes_aegis.policy.engine import PolicyEngine

__all__ = [
    "EventType",
    "Severity",
    "SecurityEvent",
    "PolicyDecision",
    "PolicyRule",
    "PolicyEngine",
]
