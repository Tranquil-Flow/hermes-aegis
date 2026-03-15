"""Audit file watcher — tails audit.jsonl for new entries.

Polls the file every second, yields new lines to a callback.
Persists read position across restarts.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

OFFSET_FILE_NAME = ".watcher-offset"
PERSIST_INTERVAL = 30.0  # seconds between offset saves


class AuditFileWatcher:
    """Tail an append-only JSONL audit file and call back on new entries."""

    def __init__(
        self,
        audit_path: Path,
        callback: Callable[[dict[str, Any]], None],
        poll_interval: float = 1.0,
    ) -> None:
        self._audit_path = audit_path
        self._callback = callback
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._offset_path = audit_path.parent / OFFSET_FILE_NAME
        self._offset: int = 0
        self._first_line_hash: str = ""
        self._last_persist: float = 0.0

    def start(self) -> None:
        """Start watching in a background daemon thread."""
        self._load_offset()
        self._thread = threading.Thread(target=self._run, daemon=True, name="aegis-watcher")
        self._thread.start()

    def stop(self) -> None:
        """Signal the watcher to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self._persist_offset()

    def _run(self) -> None:
        """Main loop: poll file for new lines."""
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception:
                logger.exception("Watcher poll error")
            self._stop_event.wait(self._poll_interval)

    def _poll_once(self) -> None:
        if not self._audit_path.exists():
            return

        file_size = self._audit_path.stat().st_size
        if file_size < self._offset:
            # File was truncated/rotated — start from beginning
            logger.info("Audit file rotated, resetting offset to 0")
            self._offset = 0
            self._first_line_hash = ""

        if file_size == self._offset:
            return  # No new data

        with open(self._audit_path, "r", encoding="utf-8") as f:
            # Verify first-line hash if we have a saved offset
            if self._offset > 0 and self._first_line_hash:
                first_line = f.readline()
                current_hash = hashlib.sha256(first_line.encode()).hexdigest()[:16]
                if current_hash != self._first_line_hash:
                    logger.info("First-line hash mismatch — file replaced, resetting")
                    self._offset = 0
                    f.seek(0)
                else:
                    f.seek(self._offset)
            elif self._offset > 0:
                f.seek(self._offset)
            else:
                # Record first-line hash
                first_line = f.readline()
                if first_line.strip():
                    self._first_line_hash = hashlib.sha256(first_line.encode()).hexdigest()[:16]
                f.seek(self._offset)

            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                    self._callback(entry)
                except json.JSONDecodeError:
                    logger.warning("Malformed audit line at offset %d", self._offset)
                except Exception:
                    logger.exception("Callback error for audit entry")

            self._offset = f.tell()

        # Periodically persist offset
        now = time.monotonic()
        if now - self._last_persist > PERSIST_INTERVAL:
            self._persist_offset()
            self._last_persist = now

    def _load_offset(self) -> None:
        """Load saved offset if the file hasn't been rotated."""
        if not self._offset_path.exists():
            # Seek to end on first start
            if self._audit_path.exists():
                self._offset = self._audit_path.stat().st_size
                # Record first-line hash
                with open(self._audit_path, "r") as f:
                    first_line = f.readline()
                    if first_line.strip():
                        self._first_line_hash = hashlib.sha256(first_line.encode()).hexdigest()[:16]
            return

        try:
            data = json.loads(self._offset_path.read_text())
            saved_offset = data.get("offset", 0)
            saved_hash = data.get("first_line_hash", "")

            if not saved_hash:
                # No hash recorded — trust saved offset (may be 0 = start)
                self._offset = saved_offset
                return

            if self._audit_path.exists():
                with open(self._audit_path, "r") as f:
                    first_line = f.readline()
                    current_hash = hashlib.sha256(first_line.encode()).hexdigest()[:16]
                    if current_hash == saved_hash:
                        self._offset = saved_offset
                        self._first_line_hash = saved_hash
                        return

            # Hash mismatch — file was rotated, start from end
            if self._audit_path.exists():
                self._offset = self._audit_path.stat().st_size
        except (json.JSONDecodeError, OSError):
            if self._audit_path.exists():
                self._offset = self._audit_path.stat().st_size

    def _persist_offset(self) -> None:
        """Save current offset and first-line hash to disk."""
        try:
            self._offset_path.parent.mkdir(parents=True, exist_ok=True)
            self._offset_path.write_text(json.dumps({
                "offset": self._offset,
                "first_line_hash": self._first_line_hash,
            }))
        except OSError:
            logger.warning("Failed to persist watcher offset")
