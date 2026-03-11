from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AuditEntry:
    data: str
    timestamp: str
    prev_hash: str
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        payload = json.dumps(
            {"data": self.data, "timestamp": self.timestamp, "prev_hash": self.prev_hash},
            sort_keys=True,
        )
        self.hash = hashlib.sha256(payload.encode()).hexdigest()


class AuditTrail:
    """Append-only audit log with SHA-256 hash chain for tamper detection."""

    def __init__(self) -> None:
        self.chain: list[AuditEntry] = []

    def add(self, data: str) -> None:
        prev_hash = self.chain[-1].hash if self.chain else ""
        entry = AuditEntry(
            data=data,
            timestamp=datetime.now(timezone.utc).isoformat(),
            prev_hash=prev_hash,
        )
        self.chain.append(entry)

    def verify(self) -> bool:
        """Return True if the chain is intact, False if any entry was tampered with."""
        for i, entry in enumerate(self.chain):
            expected_prev = self.chain[i - 1].hash if i > 0 else ""
            if entry.prev_hash != expected_prev:
                return False
            payload = json.dumps(
                {"data": entry.data, "timestamp": entry.timestamp, "prev_hash": entry.prev_hash},
                sort_keys=True,
            )
            if entry.hash != hashlib.sha256(payload.encode()).hexdigest():
                return False
        return True
