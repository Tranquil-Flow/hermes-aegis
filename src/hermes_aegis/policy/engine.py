"""Central policy engine for security event processing.

The PolicyEngine is the single writer to the audit trail.  All security
components (proxy addon, middleware, reactive agents) emit SecurityEvent
objects to the engine instead of calling AuditTrail.log() directly.

Phase 2 behaviour:
  The engine classifies events, applies coalescing to RATE_ANOMALY events
  (one audit entry per host per window), tracks session state, and writes
  normalized entries with policy metadata (_event_type, _severity, _source).

  Legacy callers continue to use ``log()`` with the same signature as
  ``AuditTrail.log()`` — the engine wraps it transparently.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.policy.decisions import PolicyDecision
from hermes_aegis.policy.events import (
    DEFAULT_SEVERITY_MAP,
    EventType,
    SecurityEvent,
    Severity,
    _infer_event_type,
)
from hermes_aegis.policy.rules import PolicyRule

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    """In-memory counters for the current aegis session.

    Updated by the PolicyEngine as events are processed.  Queried by
    the status banner and audit summary commands.
    """

    session_id: str = ""
    started_at: float = field(default_factory=time.time)
    event_counts: dict[str, int] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    source_counts: dict[str, int] = field(default_factory=dict)

    def record(self, event: SecurityEvent) -> None:
        """Increment counters for a classified event."""
        et = event.event_type.value
        self.event_counts[et] = self.event_counts.get(et, 0) + 1

        sev = event.severity.value
        self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1

        src = event.source
        self.source_counts[src] = self.source_counts.get(src, 0) + 1


class PolicyEngine:
    """Central policy engine for security event classification and audit.

    Usage (Phase 2)::

        engine = PolicyEngine(audit_trail=trail, coalesce_window=1.0)
        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com", "reason": "domain blocked"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

    The engine will:
    1. Infer the EventType from (decision, middleware)
    2. Assign a Severity from the default mapping
    3. Check coalescing (suppress duplicate RATE_ANOMALY per host+window)
    4. Update SessionState counters
    5. Write the event to the AuditTrail with policy metadata appended

    Attributes:
        trail: The AuditTrail instance to write to.
        rules: Ordered list of PolicyRule objects to evaluate.
        session: In-memory SessionState for the current session.
        coalesce_window: Time window (seconds) for RATE_ANOMALY coalescing.
    """

    def __init__(
        self,
        audit_trail: AuditTrail | None = None,
        rules: list[PolicyRule] | None = None,
        coalesce_window: float = 1.0,
    ) -> None:
        self.trail = audit_trail
        self.rules: list[PolicyRule] = sorted(
            rules or [],
            key=lambda r: r.priority,
        )
        self.session = SessionState()
        self.coalesce_window = coalesce_window

        # Coalescing state: maps coalesce_key -> last-written timestamp.
        # Entries older than 2 * coalesce_window are pruned opportunistically
        # so the dict stays bounded by the count of *recently active* hosts
        # rather than the count of distinct hosts seen over the session.
        self._coalesced: dict[str, float] = {}
        # Coalescing counters: how many events were suppressed per active key
        # (pruned alongside _coalesced).
        self._coalesce_counts: dict[str, int] = {}
        # Last prune time — used to throttle the eviction pass.
        self._last_prune: float = time.time()
        # Lifetime counter for total suppressed events — never pruned, used by
        # coalesced_suppressed() to report all-time totals.
        self._total_suppressed: int = 0

    # ------------------------------------------------------------------
    # Legacy passthrough API (duck-compatible with AuditTrail.log())
    # ------------------------------------------------------------------

    def log(
        self,
        tool_name: str,
        args_redacted: dict[str, Any],
        decision: str,
        middleware: str,
        result_hash: str | None = None,
    ) -> None:
        """Accept a legacy AuditTrail.log() call and process it.

        This is the Phase 2 bridge: callers use the same signature as
        ``AuditTrail.log()`` but the engine classifies the event,
        applies coalescing, and appends policy metadata before writing
        to the trail.
        """
        event = SecurityEvent.from_raw_audit(
            tool_name=tool_name,
            args_redacted=args_redacted,
            decision=decision,
            middleware=middleware,
        )
        self.process(event, result_hash=result_hash)

    # ------------------------------------------------------------------
    # Typed event API (for migrated callers)
    # ------------------------------------------------------------------

    def emit(self, event: SecurityEvent) -> None:
        """Process a typed SecurityEvent.

        This is the API that callers will use once they're migrated
        off the legacy ``log()`` signature.
        """
        self.process(event)

    # ------------------------------------------------------------------
    # Internal processing
    # ------------------------------------------------------------------

    def process(
        self,
        event: SecurityEvent,
        result_hash: str | None = None,
    ) -> None:
        """Classify, coalesce, count, and write an event to the audit trail."""
        # 1. Evaluate policy rules (Phase 2: rules evaluated but passthrough)
        self._apply_rules(event)

        # 2. Update session counters (always, even if coalesced)
        self.session.record(event)

        # 3. Check coalescing — suppress if duplicate within window
        if self._should_coalesce(event):
            return

        # 4. Write to audit trail with policy metadata
        if self.trail is not None:
            audit_dict = event.to_audit_dict()
            self.trail.log(
                tool_name=audit_dict["tool_name"],
                args_redacted=audit_dict["args_redacted"],
                decision=audit_dict["decision"],
                middleware=audit_dict["middleware"],
                result_hash=result_hash,
            )

    def _apply_rules(self, event: SecurityEvent) -> None:
        """Evaluate policy rules against an event.

        Phase 2: rules are evaluated but do not change the event's
        decision.  This is a no-op when no rules are configured.
        """
        for rule in self.rules:
            if rule.matches(event.event_type, event.severity, event.source):
                logger.debug(
                    "Rule %s matched event %s from %s",
                    rule.name,
                    event.event_type.value,
                    event.source,
                )
                break

    # ------------------------------------------------------------------
    # Coalescing
    # ------------------------------------------------------------------

    def _coalesce_key(self, event: SecurityEvent) -> str | None:
        """Generate a coalescing key for dedup-eligible events.

        Returns None for event types that should never be coalesced.
        """
        if event.event_type == EventType.RATE_ANOMALY:
            return f"rate:{event.host or 'unknown'}"
        return None

    def _should_coalesce(self, event: SecurityEvent) -> bool:
        """Check if this event should be suppressed as a duplicate.

        Uses a sliding window: if we already wrote an event with the
        same coalesce key within ``coalesce_window`` seconds, suppress
        the new one and increment the suppressed counter.
        """
        key = self._coalesce_key(event)
        if key is None:
            return False

        self._maybe_prune(event.timestamp)

        last_time = self._coalesced.get(key)
        if last_time is not None and event.timestamp - last_time < self.coalesce_window:
            # Suppress — within the coalescing window
            self._coalesce_counts[key] = self._coalesce_counts.get(key, 0) + 1
            self._total_suppressed += 1
            return True

        # First event in this window — record it but do not count it as suppressed
        self._coalesced[key] = event.timestamp
        return False

    def _maybe_prune(self, now: float) -> None:
        """Drop coalesce entries that fell out of their window.

        Throttled to at most one pass per coalesce_window so the cost
        amortizes across calls.
        """
        if now - self._last_prune < self.coalesce_window:
            return
        cutoff = now - self.coalesce_window
        stale = [k for k, ts in self._coalesced.items() if ts < cutoff]
        for k in stale:
            self._coalesced.pop(k, None)
            self._coalesce_counts.pop(k, None)
        self._last_prune = now

    # ------------------------------------------------------------------
    # Query helpers (for status banner and audit summarize)
    # ------------------------------------------------------------------

    def session_event_count(self, event_type: EventType | None = None) -> int:
        """Return event count for the current session.

        Args:
            event_type: If provided, count only events of this type.
                If None, return total count.
        """
        if event_type is None:
            return sum(self.session.event_counts.values())
        return self.session.event_counts.get(event_type.value, 0)

    def session_severity_count(self, severity: Severity) -> int:
        """Return severity count for the current session."""
        return self.session.severity_counts.get(severity.value, 0)

    def session_source_count(self, source: str) -> int:
        """Return source count for the current session."""
        return self.session.source_counts.get(source, 0)

    def coalesced_suppressed(self, key: str | None = None) -> int:
        """Return the number of coalesced (suppressed) events.

        Args:
            key: If provided, return the count for this specific key — note
                that this is ``0`` for keys whose window has expired and been
                pruned.
            key=None: lifetime total across the engine, including pruned keys.
        """
        if key is None:
            return self._total_suppressed
        return self._coalesce_counts.get(key, 0)
