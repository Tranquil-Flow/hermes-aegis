"""Tests for report generator and scheduler components."""
from __future__ import annotations

import json
import time
import pytest
from pathlib import Path

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.reports.generator import (
    build_report_prompt,
    compute_audit_stats,
    get_last_report_time,
    set_last_report_time,
)


@pytest.fixture
def audit_path(tmp_path):
    """Create an audit trail with sample entries."""
    path = tmp_path / "audit.jsonl"
    trail = AuditTrail(path)

    trail.log(
        tool_name="test_tool",
        args_redacted={"host": "evil.com", "reason": "secret detected"},
        decision="BLOCKED",
        middleware="ProxyContentScanner",
    )
    trail.log(
        tool_name="test_tool",
        args_redacted={"host": "api.example.com"},
        decision="COMPLETED",
        middleware="AuditTrailMiddleware",
    )
    trail.log(
        tool_name="rate_check",
        args_redacted={"rate": 100},
        decision="ANOMALY",
        middleware="RateLimiter",
    )

    return path


class TestComputeAuditStats:
    def test_basic_stats(self, audit_path):
        trail = AuditTrail(audit_path)
        entries = trail.read_all()
        stats = compute_audit_stats(entries)

        assert stats["total_events"] == 3
        assert "BLOCKED" in stats["decisions"]
        assert "COMPLETED" in stats["decisions"]
        assert "ANOMALY" in stats["decisions"]
        assert stats["decisions"]["BLOCKED"] == 1

    def test_empty_entries(self):
        stats = compute_audit_stats([])
        assert stats["total_events"] == 0
        assert stats["decisions"] == {}

    def test_host_extraction(self, audit_path):
        trail = AuditTrail(audit_path)
        entries = trail.read_all()
        stats = compute_audit_stats(entries)

        assert "evil.com" in stats["top_hosts"]

    def test_time_range(self, audit_path):
        trail = AuditTrail(audit_path)
        entries = trail.read_all()
        stats = compute_audit_stats(entries)

        assert "time_range" in stats
        assert "start" in stats["time_range"]
        assert "end" in stats["time_range"]


class TestBuildReportPrompt:
    def test_includes_statistics(self, audit_path):
        prompt = build_report_prompt(audit_path)
        assert "Audit Statistics" in prompt
        assert "BLOCKED" in prompt

    def test_empty_audit(self, tmp_path):
        empty_path = tmp_path / "empty.jsonl"
        empty_path.write_text("")
        prompt = build_report_prompt(empty_path)
        assert "No new audit events" in prompt

    def test_since_filter(self, audit_path):
        # All entries were just created, so filtering from future should yield nothing
        prompt = build_report_prompt(audit_path, since=time.time() + 1000)
        assert "No new audit events" in prompt


class TestLastReportTime:
    def test_round_trip(self, tmp_path, monkeypatch):
        ts_file = tmp_path / ".last-report-timestamp"
        monkeypatch.setattr(
            "hermes_aegis.reports.generator.LAST_REPORT_FILE", ts_file
        )

        assert get_last_report_time() == 0.0

        set_last_report_time(1234567890.0)
        assert get_last_report_time() == 1234567890.0

    def test_corrupt_file(self, tmp_path, monkeypatch):
        ts_file = tmp_path / ".last-report-timestamp"
        ts_file.write_text("not a number")
        monkeypatch.setattr(
            "hermes_aegis.reports.generator.LAST_REPORT_FILE", ts_file
        )

        assert get_last_report_time() == 0.0
