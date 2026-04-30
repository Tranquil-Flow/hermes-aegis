"""Base types for the modular detector framework."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetectorMatch:
    """A single secret detection result.

    Attributes:
        detector_name: Name of the detector module that produced this match
            (e.g. ``"api_keys"``, ``"cloud"``).
        pattern_name: Specific pattern that matched
            (e.g. ``"openai_api_key"``, ``"aws_access_key_id"``).
        matched_text: The literal text that matched.
        start: Start index in the scanned text.
        end: End index (exclusive) in the scanned text.
        severity: Severity level — ``"low"``, ``"medium"``, ``"high"``,
            or ``"critical"``. Defaults to ``"medium"``.
    """

    detector_name: str
    pattern_name: str
    matched_text: str
    start: int
    end: int
    severity: str = "medium"


class Detector:
    """Abstract base for secret detectors.

    Subclasses must implement :meth:`scan`.
    """

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description

    def scan(self, text: str) -> list[DetectorMatch]:
        """Scan *text* and return a list of matches.

        Must be overridden by subclasses.
        """
        raise NotImplementedError
