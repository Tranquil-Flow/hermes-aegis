from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AuditEntry:
    timestamp: float | str
    prev_hash: str
    tool_name: str = ""
    args_redacted: dict[str, Any] = field(default_factory=dict)
    decision: str = ""
    middleware: str = ""
    result_hash: str | None = None
    data: str = ""
    entry_hash: str = ""

    def __post_init__(self) -> None:
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()

    @property
    def hash(self) -> str:
        return self.entry_hash

    def _hash_payload(self) -> dict[str, Any]:
        if self.data:
            return {
                "data": self.data,
                "timestamp": self.timestamp,
                "prev_hash": self.prev_hash,
            }

        payload: dict[str, Any] = {
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "args_redacted": self.args_redacted,
            "decision": self.decision,
            "middleware": self.middleware,
            "prev_hash": self.prev_hash,
        }
        if self.result_hash is not None:
            payload["result_hash"] = self.result_hash
        return payload

    def _compute_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self._hash_payload(), sort_keys=True).encode()
        ).hexdigest()


class AuditTrail:
    """Append-only audit log with SHA-256 hash chain for tamper detection."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path is not None else None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self.chain: list[AuditEntry] = []

    def add(self, data: str) -> None:
        prev_hash = self.chain[-1].hash if self.chain else ""
        self.chain.append(
            AuditEntry(
                data=data,
                timestamp=datetime.now(timezone.utc).isoformat(),
                prev_hash=prev_hash,
            )
        )

    def verify(self) -> bool:
        for index, entry in enumerate(self.chain):
            expected_prev = self.chain[index - 1].hash if index > 0 else ""
            if entry.prev_hash != expected_prev:
                return False
            if entry.hash != entry._compute_hash():
                return False
        return True

    def _get_last_hash(self) -> str:
        if self._path is None or not self._path.exists():
            return "genesis"
        last_line = ""
        for line in self._path.read_text().splitlines():
            if line.strip():
                last_line = line
        if not last_line:
            return "genesis"
        return json.loads(last_line).get("entry_hash", "genesis")

    def log(
        self,
        tool_name: str,
        args_redacted: dict[str, Any],
        decision: str,
        middleware: str,
        result_hash: str | None = None,
    ) -> None:
        if self._path is None:
            raise RuntimeError("AuditTrail.log() requires a file path")

        entry = AuditEntry(
            timestamp=time.time(),
            tool_name=tool_name,
            args_redacted=args_redacted,
            decision=decision,
            middleware=middleware,
            prev_hash=self._get_last_hash(),
            result_hash=result_hash,
        )
        serialized = {
            "timestamp": entry.timestamp,
            "tool_name": entry.tool_name,
            "args_redacted": entry.args_redacted,
            "decision": entry.decision,
            "middleware": entry.middleware,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
        }
        if entry.result_hash is not None:
            serialized["result_hash"] = entry.result_hash

        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(serialized) + "\n")

    def read_all(self) -> list[AuditEntry]:
        if self._path is None or not self._path.exists():
            return []

        entries: list[AuditEntry] = []
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            entries.append(
                AuditEntry(
                    timestamp=data["timestamp"],
                    tool_name=data["tool_name"],
                    args_redacted=data["args_redacted"],
                    decision=data["decision"],
                    middleware=data["middleware"],
                    prev_hash=data["prev_hash"],
                    result_hash=data.get("result_hash"),
                    entry_hash=data["entry_hash"],
                )
            )
        return entries

    def verify_chain(self) -> bool:
        if self._path is None or not self._path.exists():
            return True

        expected_prev = "genesis"
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            entry = AuditEntry(
                timestamp=raw["timestamp"],
                tool_name=raw["tool_name"],
                args_redacted=raw["args_redacted"],
                decision=raw["decision"],
                middleware=raw["middleware"],
                prev_hash=raw["prev_hash"],
                result_hash=raw.get("result_hash"),
                entry_hash=raw["entry_hash"],
            )
            if entry.prev_hash != expected_prev:
                return False
            if entry.hash != entry._compute_hash():
                return False
            expected_prev = entry.hash
        return True
