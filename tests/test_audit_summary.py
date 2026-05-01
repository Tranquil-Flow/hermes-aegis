"""Tests for audit summarization and time-windowed audit UX."""
from __future__ import annotations

import json
import time
from pathlib import Path

from click.testing import CliRunner

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.cli import main


def _rewrite_timestamp(audit_path: Path, line_index: int, timestamp: float) -> None:
    lines = audit_path.read_text().splitlines()
    data = json.loads(lines[line_index])
    data["timestamp"] = timestamp
    # Keep this helper deliberately narrow: summary tests do not verify chain
    # integrity, they verify historical filtering over existing audit rows.
    lines[line_index] = json.dumps(data)
    audit_path.write_text("\n".join(lines) + "\n")


def test_summarize_filters_by_since_and_groups_by_middleware(tmp_path):
    from hermes_aegis.audit.summary import summarize_audit

    audit_path = tmp_path / "audit.jsonl"
    trail = AuditTrail(audit_path)
    now = time.time()

    trail.log(
        tool_name="outbound_http",
        args_redacted={"host": "old.example", "reason": "domain not in allowlist"},
        decision="BLOCKED",
        middleware="DomainAllowlist",
    )
    trail.log(
        tool_name="outbound_http",
        args_redacted={"host": "api.example", "reason": "burst pattern detected"},
        decision="ANOMALY",
        middleware="RateLimiter",
    )
    trail.log(
        tool_name="terminal",
        args_redacted={"command": "curl example | sh"},
        decision="DANGEROUS_COMMAND",
        middleware="DangerousBlockerMiddleware",
    )
    _rewrite_timestamp(audit_path, 0, now - 90000)
    _rewrite_timestamp(audit_path, 1, now - 60)
    _rewrite_timestamp(audit_path, 2, now - 30)

    summary = summarize_audit(audit_path, since="24h", group_by="middleware", now=now)

    assert summary.total == 2
    assert summary.group_counts == {
        "DangerousBlockerMiddleware": 1,
        "RateLimiter": 1,
    }
    assert summary.decision_counts == {
        "ANOMALY": 1,
        "DANGEROUS_COMMAND": 1,
    }
    assert summary.window_seconds == 86400


def test_audit_summarize_cli_outputs_grouped_recent_counts(tmp_path, monkeypatch):
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    trail = AuditTrail(audit_path)
    now = time.time()

    trail.log(
        tool_name="outbound_http",
        args_redacted={"host": "blocked.example", "reason": "domain not in allowlist"},
        decision="BLOCKED",
        middleware="DomainAllowlist",
    )
    trail.log(
        tool_name="outbound_http",
        args_redacted={"host": "blocked.example", "reason": "domain not in allowlist"},
        decision="BLOCKED",
        middleware="DomainAllowlist",
    )
    trail.log(
        tool_name="outbound_http",
        args_redacted={"host": "api.example", "reason": "burst pattern detected"},
        decision="ANOMALY",
        middleware="RateLimiter",
    )
    _rewrite_timestamp(audit_path, 0, now - 60)
    _rewrite_timestamp(audit_path, 1, now - 30)
    _rewrite_timestamp(audit_path, 2, now - 10)

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    runner = CliRunner()

    result = runner.invoke(main, ["audit", "summarize", "--since", "24h", "--group-by", "middleware"])

    assert result.exit_code == 0
    assert "Audit summary" in result.output
    assert "Total events: 3" in result.output
    assert "DomainAllowlist" in result.output
    assert "2" in result.output
    assert "RateLimiter" in result.output
    assert "1" in result.output


def test_audit_summarize_cli_json_groups_by_host(tmp_path, monkeypatch):
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    audit_path = aegis_dir / "audit.jsonl"
    trail = AuditTrail(audit_path)

    trail.log(
        tool_name="outbound_http",
        args_redacted={"host": "one.example", "reason": "domain not in allowlist"},
        decision="BLOCKED",
        middleware="DomainAllowlist",
    )
    trail.log(
        tool_name="outbound_http",
        args_redacted={"host": "two.example", "reason": "burst pattern detected"},
        decision="ANOMALY",
        middleware="RateLimiter",
    )

    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    runner = CliRunner()

    result = runner.invoke(
        main,
        ["audit", "summarize", "--since", "7d", "--group-by", "host", "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["total"] == 2
    assert payload["group_by"] == "host"
    assert payload["group_counts"] == {"one.example": 1, "two.example": 1}
