"""Tests for the reactive agent manager."""
from __future__ import annotations

import json
import time
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.reactive.actions import CircuitBreakerExecutor
from hermes_aegis.reactive.manager import ReactiveAgentManager
from hermes_aegis.reactive.rules import ReactiveRule, Trigger, save_rules


@pytest.fixture
def setup_manager(tmp_path):
    """Create a manager with test rules and return (manager, rules_path, audit_trail)."""
    rules_path = tmp_path / "rules.json"
    audit_path = tmp_path / "audit.jsonl"

    def _make(rules):
        save_rules(rules_path, rules)
        audit_trail = AuditTrail(audit_path)
        executor = CircuitBreakerExecutor(audit_trail, hermes_pid=None)
        manager = ReactiveAgentManager(
            rules_path=rules_path,
            audit_trail=audit_trail,
            actions_executor=executor,
            agent_factory=lambda model, prompt, max_iterations: "Mock agent response",
        )
        return manager, audit_trail

    return _make


class TestReactiveAgentManager:
    def test_notify_rule_fires_on_match(self, setup_manager):
        rules = [
            ReactiveRule(
                name="block-alert",
                type="notify",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="0s",
                message_template="Blocked: {reason}",
            ),
        ]
        manager, _ = setup_manager(rules)

        entry = {
            "timestamp": time.time(),
            "decision": "BLOCKED",
            "middleware": "ProxyContentScanner",
            "tool_name": "test",
            "args_redacted": {"host": "evil.com", "reason": "secret detected"},
        }

        fired = manager.evaluate(entry)
        assert len(fired) == 1
        assert fired[0].name == "block-alert"

    def test_cooldown_prevents_rapid_firing(self, setup_manager):
        rules = [
            ReactiveRule(
                name="test-rule",
                type="notify",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="60s",
                message_template="test",
            ),
        ]
        manager, _ = setup_manager(rules)

        entry = {
            "timestamp": time.time(),
            "decision": "BLOCKED",
            "middleware": "test",
            "tool_name": "test",
            "args_redacted": {},
        }

        # First evaluation should fire
        fired1 = manager.evaluate(entry)
        assert len(fired1) == 1

        # Second evaluation within cooldown should NOT fire
        fired2 = manager.evaluate(entry)
        assert len(fired2) == 0

    def test_threshold_trigger_accumulates(self, setup_manager):
        rules = [
            ReactiveRule(
                name="threshold-test",
                type="notify",
                trigger=Trigger(decision="BLOCKED", count=3, window="60s"),
                cooldown="0s",
                message_template="test",
            ),
        ]
        manager, _ = setup_manager(rules)

        entry = {
            "timestamp": time.time(),
            "decision": "BLOCKED",
            "middleware": "test",
            "tool_name": "test",
            "args_redacted": {},
        }

        # Should not fire until threshold
        assert len(manager.evaluate(entry)) == 0
        assert len(manager.evaluate(entry)) == 0
        # Third event should trigger
        assert len(manager.evaluate(entry)) == 1

    def test_disabled_rule_does_not_fire(self, setup_manager):
        rules = [
            ReactiveRule(
                name="disabled-rule",
                type="notify",
                enabled=False,
                trigger=Trigger(decision="BLOCKED"),
                cooldown="0s",
            ),
        ]
        manager, _ = setup_manager(rules)

        entry = {
            "timestamp": time.time(),
            "decision": "BLOCKED",
            "middleware": "test",
            "tool_name": "test",
            "args_redacted": {},
        }

        fired = manager.evaluate(entry)
        assert len(fired) == 0

    def test_non_matching_entry_ignored(self, setup_manager):
        rules = [
            ReactiveRule(
                name="blocked-only",
                type="notify",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="0s",
            ),
        ]
        manager, _ = setup_manager(rules)

        entry = {
            "timestamp": time.time(),
            "decision": "COMPLETED",
            "middleware": "test",
            "tool_name": "test",
            "args_redacted": {},
        }

        fired = manager.evaluate(entry)
        assert len(fired) == 0

    def test_reload_rules(self, tmp_path):
        rules_path = tmp_path / "rules.json"
        save_rules(rules_path, [ReactiveRule(name="initial")])

        audit = AuditTrail(tmp_path / "audit.jsonl")
        executor = CircuitBreakerExecutor(audit)
        manager = ReactiveAgentManager(rules_path, audit, executor)

        assert len(manager.rules) == 1

        save_rules(rules_path, [
            ReactiveRule(name="first"),
            ReactiveRule(name="second"),
        ])
        manager.reload_rules()
        assert len(manager.rules) == 2

    def test_investigate_checks_global_spawn_limit(self, setup_manager):
        rules = [
            ReactiveRule(
                name="investigate-test",
                type="investigate",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="0s",
                prompt="Test investigation",
            ),
        ]
        manager, _ = setup_manager(rules)

        # Fill up the spawn rate limit
        for _ in range(5):
            manager._spawn_times.append(time.time())

        entry = {
            "timestamp": time.time(),
            "decision": "BLOCKED",
            "middleware": "test",
            "tool_name": "test",
            "args_redacted": {},
        }

        # Should fire (rule matched) but _handle_investigate should skip
        # due to rate limit — the rule still appears in fired list
        fired = manager.evaluate(entry)
        assert len(fired) == 1

    def test_multiple_rules_can_fire(self, setup_manager):
        rules = [
            ReactiveRule(
                name="rule-a",
                type="notify",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="0s",
                message_template="Alert A",
            ),
            ReactiveRule(
                name="rule-b",
                type="notify",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="0s",
                message_template="Alert B",
            ),
        ]
        manager, _ = setup_manager(rules)

        entry = {
            "timestamp": time.time(),
            "decision": "BLOCKED",
            "middleware": "test",
            "tool_name": "test",
            "args_redacted": {},
        }

        fired = manager.evaluate(entry)
        assert len(fired) == 2
