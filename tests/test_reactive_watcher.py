"""Tests for audit file watcher."""
from __future__ import annotations

import json
import time
import pytest

from hermes_aegis.reactive.watcher import AuditFileWatcher


class TestAuditFileWatcher:
    def test_reads_new_lines(self, tmp_path):
        """Watcher calls back for new lines added to the audit file."""
        audit_file = tmp_path / "audit.jsonl"
        audit_file.write_text("")

        received = []

        def callback(entry):
            received.append(entry)

        watcher = AuditFileWatcher(audit_file, callback, poll_interval=0.1)
        # Don't persist offset to tmp_path's parent for test isolation
        watcher._offset_path = tmp_path / ".watcher-offset"
        watcher._offset = 0  # Start from beginning
        watcher._first_line_hash = ""

        watcher.start()
        try:
            # Write entries
            entry1 = {"timestamp": 1.0, "decision": "BLOCKED", "middleware": "test"}
            entry2 = {"timestamp": 2.0, "decision": "ANOMALY", "middleware": "test"}
            with open(audit_file, "a") as f:
                f.write(json.dumps(entry1) + "\n")
                f.write(json.dumps(entry2) + "\n")

            time.sleep(0.5)
        finally:
            watcher.stop()

        assert len(received) == 2
        assert received[0]["decision"] == "BLOCKED"
        assert received[1]["decision"] == "ANOMALY"

    def test_handles_empty_file(self, tmp_path):
        """Watcher handles empty audit file without errors."""
        audit_file = tmp_path / "audit.jsonl"
        audit_file.write_text("")

        received = []
        watcher = AuditFileWatcher(audit_file, lambda e: received.append(e), poll_interval=0.1)
        watcher._offset_path = tmp_path / ".watcher-offset"
        watcher._offset = 0

        watcher.start()
        time.sleep(0.3)
        watcher.stop()

        assert received == []

    def test_handles_missing_file(self, tmp_path):
        """Watcher handles non-existent audit file gracefully."""
        audit_file = tmp_path / "nonexistent.jsonl"
        received = []

        watcher = AuditFileWatcher(audit_file, lambda e: received.append(e), poll_interval=0.1)
        watcher._offset_path = tmp_path / ".watcher-offset"
        watcher.start()
        time.sleep(0.3)
        watcher.stop()

        assert received == []

    def test_offset_persistence(self, tmp_path):
        """Watcher persists and restores read offset."""
        audit_file = tmp_path / "audit.jsonl"
        entry = {"timestamp": 1.0, "decision": "BLOCKED", "middleware": "test"}
        audit_file.write_text(json.dumps(entry) + "\n")

        received = []
        watcher = AuditFileWatcher(audit_file, lambda e: received.append(e), poll_interval=0.1)
        watcher._offset_path = tmp_path / ".watcher-offset"
        # Write offset file pointing to beginning so _load_offset reads from start
        (tmp_path / ".watcher-offset").write_text(json.dumps({"offset": 0, "first_line_hash": ""}))
        watcher.start()
        time.sleep(0.3)
        watcher.stop()

        assert len(received) == 1

        # Second watcher should resume from saved offset
        received2 = []
        watcher2 = AuditFileWatcher(audit_file, lambda e: received2.append(e), poll_interval=0.1)
        watcher2._offset_path = tmp_path / ".watcher-offset"
        watcher2._load_offset()
        watcher2.start()
        time.sleep(0.3)
        watcher2.stop()

        # Should not re-process the first entry
        assert received2 == []

    def test_detects_rotation(self, tmp_path):
        """Watcher resets when file content changes (rotation)."""
        audit_file = tmp_path / "audit.jsonl"
        entry1 = {"timestamp": 1.0, "decision": "BLOCKED", "middleware": "test"}
        audit_file.write_text(json.dumps(entry1) + "\n")

        received = []
        watcher = AuditFileWatcher(audit_file, lambda e: received.append(e), poll_interval=0.1)
        watcher._offset_path = tmp_path / ".watcher-offset"
        (tmp_path / ".watcher-offset").write_text(json.dumps({"offset": 0, "first_line_hash": ""}))
        watcher.start()
        time.sleep(0.3)
        watcher.stop()

        assert len(received) == 1

        # "Rotate" the file — write different content
        entry2 = {"timestamp": 2.0, "decision": "ANOMALY", "middleware": "new"}
        audit_file.write_text(json.dumps(entry2) + "\n")

        received2 = []
        watcher2 = AuditFileWatcher(audit_file, lambda e: received2.append(e), poll_interval=0.1)
        watcher2._offset_path = tmp_path / ".watcher-offset"
        # start() calls _load_offset(), which should detect the hash mismatch
        # from the rotated file and reset to end. So we need to verify the
        # detection works by checking that a THIRD entry appended after start
        # is picked up.
        watcher2.start()
        time.sleep(0.2)

        # Append a third entry after watcher started
        entry3 = {"timestamp": 3.0, "decision": "COMPLETED", "middleware": "new"}
        with open(audit_file, "a") as f:
            f.write(json.dumps(entry3) + "\n")

        time.sleep(0.3)
        watcher2.stop()

        # Should pick up entry3 (appended after start)
        assert len(received2) >= 1
        assert any(e["decision"] == "COMPLETED" for e in received2)
