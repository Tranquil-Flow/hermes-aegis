"""Connection strings detector — PostgreSQL, MySQL, MongoDB, Redis, AMQP."""
from __future__ import annotations

import re

from hermes_aegis.detectors.base import Detector, DetectorMatch

_CONNECTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # PostgreSQL / generic SQL: postgresql:// or postgres:// with password
    ("postgres_connection_string",
     re.compile(
         r"postgres(?:ql)?://[^\s:\"']+:[^\s@\"']+@[^\s\"']+",
         re.IGNORECASE,
     ),
     "critical"),
    # MySQL
    ("mysql_connection_string",
     re.compile(
         r"mysql://[^\s:\"']+:[^\s@\"']+@[^\s\"']+",
         re.IGNORECASE,
     ),
     "critical"),
    # MongoDB (mongodb:// or mongodb+srv://)
    ("mongodb_connection_string",
     re.compile(
         r"mongodb(?:\+srv)?://[^\s:\"']+:[^\s@\"']+@[^\s\"']+",
         re.IGNORECASE,
     ),
     "critical"),
    # Redis with password
    ("redis_connection_string",
     re.compile(
         r"redis(?:s)?://:[^\s@\"']+@[^\s\"']+",
         re.IGNORECASE,
     ),
     "critical"),
    # AMQP / RabbitMQ
    ("amqp_connection_string",
     re.compile(
         r"amqp(?:s)?://[^\s:\"']+:[^\s@\"']+@[^\s\"']+",
         re.IGNORECASE,
     ),
     "critical"),
    # Generic JDBC connection strings
    ("jdbc_connection_string",
     re.compile(
         r"jdbc:[a-z]+://[^\s:\"']+:[^\s@\"']+@[^\s\"']+",
         re.IGNORECASE,
     ),
     "critical"),
]


class ConnectionStringsDetector(Detector):
    """Detects database and message queue connection strings with embedded credentials."""

    def __init__(self) -> None:
        super().__init__(
            name="connection_strings",
            description="Database and MQ connection strings: PostgreSQL, MySQL, MongoDB, Redis, AMQP",
        )

    def scan(self, text: str) -> list[DetectorMatch]:
        matches: list[DetectorMatch] = []
        for pattern_name, pattern, severity in _CONNECTION_PATTERNS:
            for m in pattern.finditer(text):
                matches.append(DetectorMatch(
                    detector_name=self.name,
                    pattern_name=pattern_name,
                    matched_text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    severity=severity,
                ))
        return matches
