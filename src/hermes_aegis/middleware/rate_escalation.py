"""Rate limit escalation — bridges anomaly detection with approval system.

When the proxy detects rate anomalies for a host, this module tracks the
escalation state and can trigger approval checks or block subsequent
requests to that host.
"""
from __future__ import annotations

import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HostEscalation:
    host: str
    anomaly_count: int = 0
    first_anomaly: float = 0.0
    last_anomaly: float = 0.0
    cooldown_until: float = 0.0
    escalation_level: int = 0  # 0=normal, 1=warning, 2=elevated, 3=blocked

    @property
    def is_cooling(self) -> bool:
        return time.time() < self.cooldown_until

    @property
    def is_blocked(self) -> bool:
        return self.escalation_level >= 3


class RateEscalationTracker:
    """Tracks rate limit escalation state per host.

    Escalation levels:
        0 (normal): No anomalies detected
        1 (warning): 1 anomaly in window — log at elevated level
        2 (elevated): 2-3 anomalies — trigger approval backend check
        3 (blocked): 4+ anomalies — block requests to this host

    Escalation decays after cooldown_period seconds without new anomalies.
    """

    def __init__(
        self,
        cooldown_period: float = 60.0,
        escalation_thresholds: tuple[int, ...] = (1, 2, 4),
        decay_period: float = 300.0,
    ):
        self._cooldown_period = cooldown_period
        self._thresholds = escalation_thresholds
        self._decay_period = decay_period
        self._hosts: dict[str, HostEscalation] = {}
        self._lock = threading.Lock()

    def _copy_state(self, state: HostEscalation) -> HostEscalation:
        """Return a snapshot copy of the host escalation state."""
        return HostEscalation(
            **{f.name: getattr(state, f.name) for f in state.__dataclass_fields__.values()}
        )

    def record_anomaly(self, host: str) -> HostEscalation:
        with self._lock:
            now = time.time()
            if host not in self._hosts:
                self._hosts[host] = HostEscalation(
                    host=host, first_anomaly=now,
                )

            state = self._hosts[host]

            # Decay check: if no anomaly for decay_period, reset
            if state.last_anomaly and (now - state.last_anomaly) > self._decay_period:
                state.anomaly_count = 0
                state.escalation_level = 0

            state.anomaly_count += 1
            state.last_anomaly = now

            # Determine escalation level based on thresholds
            level = 0
            for i, threshold in enumerate(self._thresholds):
                if state.anomaly_count >= threshold:
                    level = i + 1
            state.escalation_level = level

            # Set cooldown
            state.cooldown_until = now + self._cooldown_period

            return self._copy_state(state)

    def get_state(self, host: str) -> HostEscalation | None:
        with self._lock:
            state = self._hosts.get(host)
            if state is None:
                return None
            # Check decay
            now = time.time()
            if state.last_anomaly and (now - state.last_anomaly) > self._decay_period:
                state.anomaly_count = 0
                state.escalation_level = 0
            return self._copy_state(state)

    def is_escalated(self, host: str) -> bool:
        state = self.get_state(host)
        return state is not None and state.escalation_level >= 2

    def is_blocked(self, host: str) -> bool:
        state = self.get_state(host)
        return state is not None and state.is_blocked

    def reset(self, host: str) -> None:
        with self._lock:
            self._hosts.pop(host, None)

    def reset_all(self) -> None:
        with self._lock:
            self._hosts.clear()

    def get_all_escalated(self) -> list[HostEscalation]:
        with self._lock:
            now = time.time()
            result = []
            for state in self._hosts.values():
                if state.last_anomaly and (now - state.last_anomaly) > self._decay_period:
                    continue
                if state.escalation_level >= 1:
                    result.append(self._copy_state(state))
            return result
