"""Tests for circuit breaker actions."""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.reactive.actions import (
    CircuitBreakerExecutor,
    VAULT_LOCK_FILE,
    VALID_ACTIONS,
)


@pytest.fixture
def audit_trail(tmp_path):
    return AuditTrail(tmp_path / "audit.jsonl")


@pytest.fixture
def executor(audit_trail):
    return CircuitBreakerExecutor(audit_trail=audit_trail, hermes_pid=None)


class TestCircuitBreakerExecutor:
    def test_rejects_unknown_action(self, executor):
        result = executor.execute(
            action_name="do_evil",
            params={},
            justification="test",
            rule_name="test-rule",
            allowed_actions=["do_evil"],
        )
        assert result is False

    def test_rejects_disallowed_action(self, executor):
        result = executor.execute(
            action_name="kill_proxy",
            params={},
            justification="test",
            rule_name="test-rule",
            allowed_actions=["lock_vault"],
        )
        assert result is False

    @patch("hermes_aegis.reactive.actions.CircuitBreakerExecutor._action_lock_vault")
    def test_executes_allowed_action(self, mock_lock, executor):
        result = executor.execute(
            action_name="lock_vault",
            params={"reason": "test"},
            justification="testing",
            rule_name="test-rule",
            allowed_actions=["lock_vault"],
        )
        assert result is True
        mock_lock.assert_called_once_with({"reason": "test"})

    def test_logs_action_to_audit(self, executor, audit_trail, tmp_path):
        with patch.object(executor, "_action_lock_vault"):
            executor.execute(
                action_name="lock_vault",
                params={},
                justification="test",
                rule_name="test-rule",
                allowed_actions=["lock_vault"],
            )

        entries = audit_trail.read_all()
        assert len(entries) == 1
        assert entries[0].decision == "CIRCUIT_BREAKER"
        assert entries[0].args_redacted["action"] == "lock_vault"

    def test_lock_vault_creates_sentinel(self, tmp_path):
        audit = AuditTrail(tmp_path / "audit.jsonl")
        lock_file = tmp_path / "vault.lock"

        with patch("hermes_aegis.reactive.actions.VAULT_LOCK_FILE", lock_file):
            executor = CircuitBreakerExecutor(audit, hermes_pid=None)
            executor._action_lock_vault({"reason": "test"})

        assert lock_file.exists()
        data = json.loads(lock_file.read_text())
        assert data["reason"] == "test"

    def test_block_domain_adds_to_blocklist(self, tmp_path):
        audit = AuditTrail(tmp_path / "audit.jsonl")
        blocklist_file = tmp_path / "blocklist.json"

        with patch("hermes_aegis.reactive.actions.BLOCKLIST_FILE", blocklist_file):
            executor = CircuitBreakerExecutor(audit, hermes_pid=None)
            executor._action_block_domain({"domain": "evil.com"})

        assert blocklist_file.exists()
        blocklist = json.loads(blocklist_file.read_text())
        assert "evil.com" in blocklist

    def test_block_domain_no_duplicates(self, tmp_path):
        audit = AuditTrail(tmp_path / "audit.jsonl")
        blocklist_file = tmp_path / "blocklist.json"
        blocklist_file.write_text(json.dumps(["evil.com"]))

        with patch("hermes_aegis.reactive.actions.BLOCKLIST_FILE", blocklist_file):
            executor = CircuitBreakerExecutor(audit, hermes_pid=None)
            executor._action_block_domain({"domain": "evil.com"})

        blocklist = json.loads(blocklist_file.read_text())
        assert blocklist.count("evil.com") == 1

    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_kill_proxy(self, mock_stop, executor):
        executor._action_kill_proxy({})
        mock_stop.assert_called_once()

    def test_kill_hermes_with_pid(self, audit_trail):
        executor = CircuitBreakerExecutor(audit_trail, hermes_pid=99999)
        with patch("os.kill") as mock_kill:
            mock_kill.side_effect = ProcessLookupError
            executor._action_kill_hermes({})
            # Should not raise — handles ProcessLookupError gracefully

    def test_tighten_rate_limit(self, tmp_path):
        audit = AuditTrail(tmp_path / "audit.jsonl")
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"rate_limit_requests": 50}))

        with patch("hermes_aegis.reactive.actions.AEGIS_DIR", tmp_path):
            executor = CircuitBreakerExecutor(audit, hermes_pid=None)
            executor._action_tighten_rate_limit({"factor": 0.5})

        data = json.loads(config_path.read_text())
        assert data["rate_limit_requests"] == 25

    def test_shrink_allowlist(self, tmp_path):
        audit = AuditTrail(tmp_path / "audit.jsonl")
        allowlist_path = tmp_path / "domain-allowlist.json"
        allowlist_path.write_text(json.dumps(["good.com", "evil.com"]))

        with patch("hermes_aegis.reactive.actions.AEGIS_DIR", tmp_path):
            executor = CircuitBreakerExecutor(audit, hermes_pid=None)
            executor._action_shrink_allowlist({"domain": "evil.com"})

        data = json.loads(allowlist_path.read_text())
        assert "evil.com" not in data
        assert "good.com" in data
