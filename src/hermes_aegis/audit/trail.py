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
    """A single entry in the tamper-evident audit hash chain.

    Each entry hashes its own content together with the previous entry's hash,
    forming a linked chain where any modification invalidates all subsequent
    entries.

    Attributes:
        timestamp: Unix timestamp (float) or ISO-8601 string when the entry
            was created.
        prev_hash: SHA-256 hex digest of the preceding entry, or empty string
            for the first entry in a chain.
        tool_name: Name of the tool that was invoked.
        args_redacted: Tool arguments with sensitive values already redacted.
        decision: Middleware decision for this invocation (e.g. "allow",
            "block", "redact").
        middleware: Name of the middleware layer that produced the decision.
        result_hash: Optional SHA-256 hex digest of the tool result payload,
            for result integrity verification.
        data: Arbitrary free-form data string used for simple ``add()``-style
            entries that do not originate from a tool call.
        entry_hash: SHA-256 hex digest of this entry's canonical payload.
            Computed automatically on construction when not supplied.
    """

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
        """Compute and store the entry hash if one was not provided."""
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()

    @property
    def hash(self) -> str:
        """Return the SHA-256 hex digest for this entry.

        Returns:
            The ``entry_hash`` field, which is computed at construction time.
        """
        return self.entry_hash

    def _hash_payload(self) -> dict[str, Any]:
        """Build the canonical dictionary used as input to the hash function.

        When ``data`` is set (free-form entry), the payload contains only the
        data string, timestamp, and previous hash.  For tool-call entries the
        full set of structured fields is included.

        Returns:
            A dictionary whose JSON serialisation (with sorted keys) is the
            pre-image for the SHA-256 digest.
        """
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
        """Compute the SHA-256 hex digest of this entry's canonical payload.

        Returns:
            A 64-character lowercase hexadecimal SHA-256 digest string.
        """
        return hashlib.sha256(
            json.dumps(self._hash_payload(), sort_keys=True).encode()
        ).hexdigest()


class AuditTrail:
    """Append-only audit log with SHA-256 hash chain for tamper detection.

    Two usage modes are supported:

    * **In-memory** (``path=None``): entries are appended to ``self.chain``
      and can be verified with :meth:`verify`.
    * **File-backed** (``path`` supplied): entries are serialised as
      newline-delimited JSON and appended to the given file.  The chain can
      be verified later with :meth:`verify_chain`.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        """Initialise the audit trail.

        Args:
            path: Optional filesystem path for the NDJSON log file.  Parent
                directories are created if they do not exist.  When ``None``
                the trail operates in in-memory mode only.
        """
        self._path = Path(path) if path is not None else None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self.chain: list[AuditEntry] = []

    def add(self, data: str) -> None:
        """Append a free-form data entry to the in-memory chain.

        Args:
            data: Arbitrary string payload to record.
        """
        prev_hash = self.chain[-1].hash if self.chain else ""
        self.chain.append(
            AuditEntry(
                data=data,
                timestamp=datetime.now(timezone.utc).isoformat(),
                prev_hash=prev_hash,
            )
        )

    def verify(self) -> bool:
        """Verify the integrity of the in-memory chain.

        Checks that each entry's ``prev_hash`` matches the preceding entry's
        digest and that the stored ``entry_hash`` matches a freshly computed
        digest.

        Returns:
            ``True`` if the entire chain is intact; ``False`` on the first
            detected inconsistency.
        """
        for index, entry in enumerate(self.chain):
            expected_prev = self.chain[index - 1].hash if index > 0 else ""
            if entry.prev_hash != expected_prev:
                return False
            if entry.hash != entry._compute_hash():
                return False
        return True

    def _get_last_hash(self) -> str:
        """Read the ``entry_hash`` of the last record in the log file.

        Used to chain new file-backed entries to the existing tail.

        Returns:
            The hex digest of the last entry, or an empty string if the file
            does not exist or is empty.
        """
        if self._path is None or not self._path.exists():
            return ""
        last_line = ""
        for line in self._path.read_text().splitlines():
            if line.strip():
                last_line = line
        if not last_line:
            return ""
        return json.loads(last_line).get("entry_hash", "")

    def log(
        self,
        tool_name: str,
        args_redacted: dict[str, Any],
        decision: str,
        middleware: str,
        result_hash: str | None = None,
    ) -> None:
        """Append a tool-call entry to the file-backed log.

        Args:
            tool_name: Name of the tool that was invoked.
            args_redacted: Tool arguments with sensitive values redacted.
            decision: Middleware decision (e.g. ``"allow"``, ``"block"``).
            middleware: Name of the middleware layer that made the decision.
            result_hash: Optional SHA-256 digest of the tool result payload.

        Raises:
            RuntimeError: If this ``AuditTrail`` was not initialised with a
                file path.
        """
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
        """Deserialise all entries from the log file.

        Returns:
            A list of :class:`AuditEntry` objects in chronological order, or
            an empty list if the file does not exist or is empty.
        """
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
        """Verify the integrity of the file-backed log.

        Re-reads every entry from disk and checks:

        * ``prev_hash`` equals the previous entry's digest (or empty string
          for the first entry).
        * The stored ``entry_hash`` matches the re-computed digest.

        Returns:
            ``True`` if the entire persisted chain is intact; ``False`` on the
            first detected inconsistency.  Also returns ``True`` when the file
            does not exist or is empty (vacuously valid).
        """
        if self._path is None or not self._path.exists():
            return True

        expected_prev = ""
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
