"""Policy rule definitions.

A PolicyRule maps event patterns to enforcement decisions.  Rules are
evaluated by the PolicyEngine in priority order.  The first matching
rule determines the outcome; if no rule matches, the engine falls back
to the event's intrinsic severity and decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hermes_aegis.policy.decisions import PolicyDecision
from hermes_aegis.policy.events import EventType, Severity


@dataclass
class PolicyRule:
    """A single policy rule evaluated by the engine.

    Attributes:
        name: Human-readable identifier for logging and debugging.
        event_types: Set of EventType values this rule matches.
            Empty set means "match all types".
        severities: Set of Severity values this rule matches.
            Empty set means "match all severities".
        sources: Set of source names this rule matches.
            Empty set means "match all sources".
        decision: The PolicyDecision to apply when this rule matches.
        priority: Lower numbers are evaluated first. Rules with the
            same priority are evaluated in insertion order.
        cooldown_seconds: Minimum time between successive matches for
            the same event signature.  Used for coalescing.
        extra: Rule-specific configuration (e.g., threshold overrides).
    """

    name: str
    event_types: set[EventType] = field(default_factory=set)
    severities: set[Severity] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    decision: PolicyDecision = PolicyDecision.ALLOW
    priority: int = 100
    cooldown_seconds: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    def matches(
        self,
        event_type: EventType,
        severity: Severity,
        source: str,
    ) -> bool:
        """Check whether this rule matches the given event attributes.

        Empty constraint sets are treated as wildcards (match anything).
        """
        if self.event_types and event_type not in self.event_types:
            return False
        if self.severities and severity not in self.severities:
            return False
        if self.sources and source not in self.sources:
            return False
        return True
