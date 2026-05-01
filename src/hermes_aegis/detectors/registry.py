"""Detector registry — collects and orchestrates multiple detectors."""
from __future__ import annotations

from hermes_aegis.detectors.base import Detector, DetectorMatch


class DetectorRegistry:
    """Collects detectors and runs them all via :meth:`scan_all`.

    Example::

        reg = DetectorRegistry()
        reg.register(ApiKeysDetector())
        matches = reg.scan_all(text)
    """

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        """Register a detector.  Overwrites any existing detector with the same name."""
        self._detectors[detector.name] = detector

    def get(self, name: str) -> Detector | None:
        """Look up a detector by name, or return ``None``."""
        return self._detectors.get(name)

    def list_detectors(self) -> list[Detector]:
        """Return all registered detectors."""
        return list(self._detectors.values())

    def scan_all(self, text: str) -> list[DetectorMatch]:
        """Run every registered detector on *text* and return merged results."""
        matches: list[DetectorMatch] = []
        for det in self._detectors.values():
            matches.extend(det.scan(text))
        return matches
