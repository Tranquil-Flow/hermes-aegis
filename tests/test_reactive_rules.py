"""Tests for reactive rules engine — loading, matching, duration parsing."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from hermes_aegis.reactive.rules import (
    ReactiveRule,
    Trigger,
    default_rules,
    load_rules,
    parse_duration,
    save_rules,
)


class TestParseDuration:
    def test_seconds(self):
        assert parse_duration("60s") == 60.0

    def test_minutes(self):
        assert parse_duration("5m") == 300.0

    def test_hours(self):
        assert parse_duration("2h") == 7200.0

    def test_days(self):
        assert parse_duration("1d") == 86400.0

    def test_bare_number_defaults_to_seconds(self):
        assert parse_duration("30") == 30.0

    def test_float_value(self):
        assert parse_duration("1.5m") == 90.0

    def test_whitespace(self):
        assert parse_duration("  10s  ") == 10.0

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_duration("abc")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_duration("")


class TestTrigger:
    def test_matches_exact_decision(self):
        t = Trigger(decision="BLOCKED")
        assert t.matches_entry("BLOCKED", "ProxyContentScanner")
        assert not t.matches_entry("ANOMALY", "ProxyContentScanner")

    def test_matches_decision_in(self):
        t = Trigger(decision_in=["BLOCKED", "ANOMALY"])
        assert t.matches_entry("BLOCKED", "any")
        assert t.matches_entry("ANOMALY", "any")
        assert not t.matches_entry("COMPLETED", "any")

    def test_matches_middleware(self):
        t = Trigger(middleware="ProxyContentScanner")
        assert t.matches_entry("BLOCKED", "ProxyContentScanner")
        assert not t.matches_entry("BLOCKED", "RateLimiter")

    def test_matches_middleware_in(self):
        t = Trigger(middleware_in=["ProxyContentScanner", "DomainAllowlist"])
        assert t.matches_entry("BLOCKED", "ProxyContentScanner")
        assert not t.matches_entry("BLOCKED", "RateLimiter")

    def test_combined_filters(self):
        t = Trigger(decision="BLOCKED", middleware="ProxyContentScanner")
        assert t.matches_entry("BLOCKED", "ProxyContentScanner")
        assert not t.matches_entry("BLOCKED", "RateLimiter")
        assert not t.matches_entry("ANOMALY", "ProxyContentScanner")

    def test_empty_trigger_matches_all(self):
        t = Trigger()
        assert t.matches_entry("BLOCKED", "ProxyContentScanner")
        assert t.matches_entry("ANOMALY", "RateLimiter")

    def test_is_threshold(self):
        t = Trigger(count=3, window="60s")
        assert t.is_threshold
        assert t.window_seconds == 60.0

    def test_not_threshold(self):
        t = Trigger(decision="BLOCKED")
        assert not t.is_threshold


class TestReactiveRule:
    def test_cooldown_seconds(self):
        r = ReactiveRule(name="test", cooldown="5m")
        assert r.cooldown_seconds == 300.0

    def test_resolved_report_path(self):
        r = ReactiveRule(name="test", report_path="~/.hermes-aegis/reports/")
        assert r.resolved_report_path == Path.home() / ".hermes-aegis" / "reports"

    def test_defaults(self):
        r = ReactiveRule(name="test")
        assert r.enabled is True
        assert r.severity == "medium"
        assert r.type == "notify"
        assert r.allowed_actions == []


class TestLoadSaveRules:
    def test_load_missing_file(self, tmp_path):
        rules = load_rules(tmp_path / "nonexistent.json")
        assert rules == []

    def test_round_trip(self, tmp_path):
        rules = default_rules()
        path = tmp_path / "rules.json"
        save_rules(path, rules)
        loaded = load_rules(path)
        assert len(loaded) == len(rules)
        for orig, loaded_rule in zip(rules, loaded):
            assert orig.name == loaded_rule.name
            assert orig.type == loaded_rule.type
            assert orig.severity == loaded_rule.severity

    def test_default_rules_structure(self):
        rules = default_rules()
        assert len(rules) == 3
        names = {r.name for r in rules}
        assert "block-alert" in names
        assert "anomaly-reporter" in names
        assert "exfiltration-response" in names

    def test_load_notify_rule(self, tmp_path):
        path = tmp_path / "rules.json"
        path.write_text(json.dumps({
            "rules": [{
                "name": "test-notify",
                "type": "notify",
                "trigger": {"decision": "BLOCKED"},
                "cooldown": "2m",
                "message_template": "Blocked: {reason}",
            }]
        }))
        rules = load_rules(path)
        assert len(rules) == 1
        assert rules[0].type == "notify"
        assert rules[0].message_template == "Blocked: {reason}"

    def test_load_investigate_rule_with_actions(self, tmp_path):
        path = tmp_path / "rules.json"
        path.write_text(json.dumps({
            "rules": [{
                "name": "test-investigate",
                "type": "investigate",
                "severity": "critical",
                "trigger": {"decision_in": ["BLOCKED"], "count": 5, "window": "120s"},
                "cooldown": "15m",
                "allowed_actions": ["kill_proxy", "lock_vault"],
            }]
        }))
        rules = load_rules(path)
        assert len(rules) == 1
        assert rules[0].allowed_actions == ["kill_proxy", "lock_vault"]
        assert rules[0].trigger.is_threshold
        assert rules[0].trigger.count == 5

    def test_save_preserves_enabled_state(self, tmp_path):
        path = tmp_path / "rules.json"
        rules = [ReactiveRule(name="disabled-test", enabled=False)]
        save_rules(path, rules)
        loaded = load_rules(path)
        assert loaded[0].enabled is False
