"""Sequence trigger — ordered multi-event pattern matching within a time window.

A :class:`SequenceTrigger` matches when a specific ordered sequence of events
occurs within a configurable time window, even if other (noise) events
intervene.

Example::

    seq = SequenceTrigger(
        steps=[
            Step(decision="BLOCKED", middleware="ProxyContentScanner"),
            Step(decision="ANOMALY", middleware="RateLimiter"),
            Step(decision="DANGEROUS_COMMAND"),
        ],
        window="120s",
    )
    if seq.check(entries):
        # Escalate — this looks like a coordinated attack

Algorithm notes:
- Walks entries in order, advancing the step pointer on each match.
- Non-matching entries are skipped (noise tolerance).
- The sequence must complete (all steps matched) within the time window.
- If the chosen first match leads to a window-expired completion (or no
  completion at all), the search rewinds to the entry **after** the original
  first match and retries. This guarantees that any in-window sequence
  reachable from a later step-0 match will still be detected even when an
  earlier (out-of-window) step-0 match shadowed it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from hermes_aegis.reactive.rules import parse_duration


@dataclass
class Step:
    """A single step in a sequence pattern.

    Matches an audit entry based on decision and/or middleware filters.
    At least one filter must be set — a step with all fields ``None``
    will never match (this is intentional; if you want a wildcard step,
    use ``decision_in`` with a broad list).
    """
    decision: str | None = None
    decision_in: list[str] | None = None
    middleware: str | None = None
    middleware_in: list[str] | None = None

    def matches(self, entry: dict) -> bool:
        """Check if an audit entry matches this step's filters."""
        ed = entry.get("decision", "")
        em = entry.get("middleware", "")

        if self.decision is not None and ed != self.decision:
            return False
        if self.decision_in is not None and ed not in self.decision_in:
            return False
        if self.middleware is not None and em != self.middleware:
            return False
        if self.middleware_in is not None and em not in self.middleware_in:
            return False

        # At least one filter must be set and matched
        if (self.decision is None and self.decision_in is None
                and self.middleware is None and self.middleware_in is None):
            return False

        return True


@dataclass
class SequenceTrigger:
    """Matches an ordered sequence of events within a time window.

    Attributes:
        steps: Ordered list of steps that must match in sequence.
        window: Maximum time span (as duration string like ``"120s"``)
            between the first and last matching events.
    """
    steps: list[Step] = field(default_factory=list)
    window: str = "120s"

    @property
    def window_seconds(self) -> float:
        return parse_duration(self.window)

    def check(self, entries: list[dict]) -> bool:
        """Return True if *entries* contain a complete in-window sequence.

        Convenience wrapper around :meth:`find_match_end`.
        """
        return self.find_match_end(entries) is not None

    def find_match_end(self, entries: list[dict]) -> float | None:
        """Find the first complete in-window match and return the timestamp
        of its last step.

        The algorithm walks through entries in order, advancing the step
        pointer when a step matches. Intervening non-matching entries are
        skipped (noise tolerance). On window-expiry the search rewinds to
        the entry after the original step-0 match — this prevents an
        out-of-window early match from shadowing a later in-window sequence.

        Returns:
            Timestamp of the entry that satisfied the final step, or
            ``None`` if no complete in-window match exists.
        """
        if not self.steps or not entries:
            return None

        window = self.window_seconds
        start = 0
        n = len(entries)

        while start < n:
            step_idx = 0
            first_ts: float | None = None
            first_idx: int | None = None
            i = start
            matched = False

            while i < n:
                if self.steps[step_idx].matches(entries[i]):
                    ts = entries[i].get("timestamp", time.time())
                    if first_ts is None:
                        first_ts = ts
                        first_idx = i
                    step_idx += 1
                    if step_idx >= len(self.steps):
                        if (ts - first_ts) <= window:
                            return ts
                        matched = True
                        break
                i += 1

            if first_idx is None:
                return None
            if matched:
                start = first_idx + 1
                continue
            return None

        return None
