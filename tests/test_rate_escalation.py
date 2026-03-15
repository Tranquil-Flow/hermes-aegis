"""Tests for rate_escalation module."""
from __future__ import annotations

import time
import threading
import pytest
from unittest.mock import patch

from hermes_aegis.middleware.rate_escalation import (
    HostEscalation,
    RateEscalationTracker,
)


# ---------------------------------------------------------------------------
# HostEscalation dataclass tests
# ---------------------------------------------------------------------------

class TestHostEscalation:

    def test_is_blocked_below_threshold(self):
        h = HostEscalation(host="example.com", escalation_level=2)
        assert h.is_blocked is False

    def test_is_blocked_at_threshold(self):
        h = HostEscalation(host="example.com", escalation_level=3)
        assert h.is_blocked is True

    def test_is_blocked_above_threshold(self):
        h = HostEscalation(host="example.com", escalation_level=5)
        assert h.is_blocked is True

    def test_is_cooling_in_future(self):
        h = HostEscalation(host="example.com", cooldown_until=time.time() + 100)
        assert h.is_cooling is True

    def test_is_cooling_in_past(self):
        h = HostEscalation(host="example.com", cooldown_until=time.time() - 100)
        assert h.is_cooling is False

    def test_defaults(self):
        h = HostEscalation(host="x.com")
        assert h.anomaly_count == 0
        assert h.escalation_level == 0
        assert h.is_blocked is False
        assert h.is_cooling is False


# ---------------------------------------------------------------------------
# RateEscalationTracker tests
# ---------------------------------------------------------------------------

class TestRateEscalationTracker:

    def test_first_anomaly_sets_level_1(self):
        tracker = RateEscalationTracker()
        result = tracker.record_anomaly("api.example.com")
        assert result.anomaly_count == 1
        assert result.escalation_level == 1  # threshold (1,) matched

    def test_escalation_levels_progress(self):
        tracker = RateEscalationTracker()
        # thresholds = (1, 2, 4) → levels 1, 2, 3 at counts 1, 2, 4
        r1 = tracker.record_anomaly("h")
        assert r1.escalation_level == 1

        r2 = tracker.record_anomaly("h")
        assert r2.escalation_level == 2
        assert r2.anomaly_count == 2

        r3 = tracker.record_anomaly("h")
        assert r3.escalation_level == 2  # count=3, still < 4
        assert r3.anomaly_count == 3

        r4 = tracker.record_anomaly("h")
        assert r4.escalation_level == 3  # count=4 → blocked
        assert r4.anomaly_count == 4
        assert r4.is_blocked is True

    def test_get_state_returns_none_for_unknown(self):
        tracker = RateEscalationTracker()
        assert tracker.get_state("unknown.host") is None

    def test_get_state_returns_copy(self):
        tracker = RateEscalationTracker()
        tracker.record_anomaly("h")
        s1 = tracker.get_state("h")
        s2 = tracker.get_state("h")
        assert s1 is not s2
        assert s1.host == s2.host
        assert s1.anomaly_count == s2.anomaly_count

    def test_is_escalated(self):
        tracker = RateEscalationTracker()
        assert tracker.is_escalated("h") is False
        tracker.record_anomaly("h")  # level 1
        assert tracker.is_escalated("h") is False
        tracker.record_anomaly("h")  # level 2
        assert tracker.is_escalated("h") is True

    def test_is_blocked(self):
        tracker = RateEscalationTracker()
        assert tracker.is_blocked("h") is False
        for _ in range(4):
            tracker.record_anomaly("h")
        assert tracker.is_blocked("h") is True

    def test_reset_clears_host(self):
        tracker = RateEscalationTracker()
        tracker.record_anomaly("h")
        tracker.reset("h")
        assert tracker.get_state("h") is None
        assert tracker.is_escalated("h") is False

    def test_reset_unknown_host_is_noop(self):
        tracker = RateEscalationTracker()
        tracker.reset("nonexistent")  # should not raise

    def test_reset_all(self):
        tracker = RateEscalationTracker()
        tracker.record_anomaly("a")
        tracker.record_anomaly("b")
        tracker.reset_all()
        assert tracker.get_state("a") is None
        assert tracker.get_state("b") is None

    def test_get_all_escalated(self):
        tracker = RateEscalationTracker()
        tracker.record_anomaly("a")  # level 1
        tracker.record_anomaly("b")
        tracker.record_anomaly("b")  # level 2
        result = tracker.get_all_escalated()
        hosts = {r.host for r in result}
        assert "a" in hosts
        assert "b" in hosts
        assert len(result) == 2

    def test_get_all_escalated_excludes_level_0(self):
        tracker = RateEscalationTracker()
        # No anomalies recorded → nothing returned
        assert tracker.get_all_escalated() == []

    def test_decay_resets_after_period(self):
        tracker = RateEscalationTracker(decay_period=1.0)
        tracker.record_anomaly("h")
        tracker.record_anomaly("h")
        assert tracker.is_escalated("h") is True

        # Simulate time passing beyond decay
        with patch("hermes_aegis.middleware.rate_escalation.time") as mock_time:
            # record_anomaly was called at real time, now we pretend it's later
            pass

        # Easier approach: manipulate internal state directly
        state = tracker._hosts["h"]
        state.last_anomaly = time.time() - 2.0  # 2s ago, decay is 1s
        assert tracker.is_escalated("h") is False
        assert tracker.get_state("h").escalation_level == 0

    def test_decay_resets_on_next_record(self):
        tracker = RateEscalationTracker(decay_period=0.5)
        # Build up to level 3
        for _ in range(4):
            tracker.record_anomaly("h")
        assert tracker.is_blocked("h") is True

        # Simulate decay by backdating last_anomaly
        tracker._hosts["h"].last_anomaly = time.time() - 1.0

        # Next anomaly should start fresh (count resets, then +1 = level 1)
        result = tracker.record_anomaly("h")
        assert result.anomaly_count == 1
        assert result.escalation_level == 1
        assert result.is_blocked is False

    def test_cooldown_is_set(self):
        tracker = RateEscalationTracker(cooldown_period=30.0)
        result = tracker.record_anomaly("h")
        assert result.cooldown_until > time.time()
        assert result.is_cooling is True

    def test_cooldown_expires(self):
        tracker = RateEscalationTracker(cooldown_period=0.0)
        result = tracker.record_anomaly("h")
        # With 0 cooldown, should not be cooling (or barely)
        # cooldown_until = now + 0.0 → essentially now
        time.sleep(0.01)
        state = tracker.get_state("h")
        assert state.is_cooling is False

    def test_multiple_hosts_independent(self):
        tracker = RateEscalationTracker()
        tracker.record_anomaly("a")
        tracker.record_anomaly("a")
        tracker.record_anomaly("b")
        assert tracker.get_state("a").escalation_level == 2
        assert tracker.get_state("b").escalation_level == 1

    def test_thread_safety(self):
        """Basic concurrent access test — no crashes or data corruption."""
        tracker = RateEscalationTracker()
        errors = []

        def hammer(host: str, count: int):
            try:
                for _ in range(count):
                    tracker.record_anomaly(host)
                    tracker.get_state(host)
                    tracker.is_escalated(host)
                    tracker.is_blocked(host)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=hammer, args=(f"host-{i}", 50))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread safety errors: {errors}"

        # Verify each host has 50 anomalies (unless decayed)
        for i in range(10):
            state = tracker.get_state(f"host-{i}")
            assert state is not None
            assert state.anomaly_count == 50

    def test_custom_thresholds(self):
        tracker = RateEscalationTracker(escalation_thresholds=(5, 10, 20))
        for _ in range(4):
            tracker.record_anomaly("h")
        assert tracker.get_state("h").escalation_level == 0  # below 5

        tracker.record_anomaly("h")  # count=5
        assert tracker.get_state("h").escalation_level == 1

        for _ in range(5):
            tracker.record_anomaly("h")  # count=10
        assert tracker.get_state("h").escalation_level == 2

    def test_get_all_escalated_excludes_decayed(self):
        tracker = RateEscalationTracker(decay_period=1.0)
        tracker.record_anomaly("h")
        # Backdate to trigger decay
        tracker._hosts["h"].last_anomaly = time.time() - 2.0
        assert tracker.get_all_escalated() == []
