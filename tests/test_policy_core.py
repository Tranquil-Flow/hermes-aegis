"""Tests for the policy core (Phase 1).

Verifies:
- EventType inference from legacy (decision, middleware) pairs
- SecurityEvent classification and serialization
- PolicyEngine passthrough: legacy log() calls produce identical
  audit trail entries with policy metadata appended
- SessionState counters track events correctly
- PolicyRule matching logic
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.policy.decisions import PolicyDecision
from hermes_aegis.policy.engine import PolicyEngine, SessionState
from hermes_aegis.policy.events import (
    DEFAULT_SEVERITY_MAP,
    EventType,
    SecurityEvent,
    Severity,
    _infer_event_type,
)
from hermes_aegis.policy.rules import PolicyRule


# ======================================================================
# EventType inference
# ======================================================================


class TestEventTypeInference:
    """_infer_event_type correctly maps legacy audit fields."""

    def test_rate_limiter_anomaly(self):
        assert _infer_event_type("ANOMALY", "RateLimiter", "burst") == EventType.RATE_ANOMALY

    def test_domain_allowlist_blocked(self):
        assert _infer_event_type("BLOCKED", "DomainAllowlist", "domain not in allowlist") == EventType.DOMAIN_BLOCKED

    def test_proxy_content_scanner_blocked(self):
        assert _infer_event_type("BLOCKED", "ProxyContentScanner", "secret detected") == EventType.BLOCKED_SECRET

    def test_dangerous_command_blocker(self):
        assert _infer_event_type("BLOCKED", "DangerousBlockerMiddleware", "rm -rf") == EventType.DANGEROUS_COMMAND

    def test_dangerous_command_audit(self):
        assert _infer_event_type("AUDIT", "DangerousBlockerMiddleware", "curl | sh") == EventType.DANGEROUS_COMMAND

    def test_tirith_scanner(self):
        assert _infer_event_type("REDACT", "TirithScanner", "homograph url") == EventType.OUTPUT_REDACTED

    def test_output_scanner(self):
        assert _infer_event_type("REDACT", "OutputScanner", "secret in output") == EventType.OUTPUT_REDACTED

    def test_hermes_approval(self):
        assert _infer_event_type("BLOCKED", "HermesApproval", "needs approval") == EventType.HERMES_APPROVAL

    def test_rate_escalation(self):
        assert _infer_event_type("BLOCKED", "RateEscalation", "host blocked") == EventType.RATE_ESCALATION

    def test_fallback_blocked(self):
        assert _infer_event_type("BLOCKED", "UnknownMiddleware", "something") == EventType.DOMAIN_BLOCKED

    def test_fallback_anomaly(self):
        assert _infer_event_type("ANOMALY", "UnknownMiddleware", "something") == EventType.RATE_ANOMALY

    def test_fallback_dangerous_command(self):
        assert _infer_event_type("DANGEROUS_COMMAND", "Something", "cmd") == EventType.DANGEROUS_COMMAND

    def test_fallback_unknown(self):
        assert _infer_event_type("ALLOW", "UnknownMiddleware", "ok") == EventType.HERMES_APPROVAL


# ======================================================================
# Default severity map
# ======================================================================


class TestDefaultSeverityMap:
    """Every EventType has a default severity."""

    def test_all_event_types_have_severity(self):
        for et in EventType:
            assert et in DEFAULT_SEVERITY_MAP, f"{et} missing from DEFAULT_SEVERITY_MAP"

    def test_blocked_secret_is_critical(self):
        assert DEFAULT_SEVERITY_MAP[EventType.BLOCKED_SECRET] == Severity.CRITICAL

    def test_domain_blocked_is_high(self):
        assert DEFAULT_SEVERITY_MAP[EventType.DOMAIN_BLOCKED] == Severity.HIGH

    def test_rate_anomaly_is_medium(self):
        assert DEFAULT_SEVERITY_MAP[EventType.RATE_ANOMALY] == Severity.MEDIUM

    def test_dangerous_command_is_high(self):
        assert DEFAULT_SEVERITY_MAP[EventType.DANGEROUS_COMMAND] == Severity.HIGH

    def test_output_redacted_is_low(self):
        assert DEFAULT_SEVERITY_MAP[EventType.OUTPUT_REDACTED] == Severity.LOW

    def test_rate_escalation_is_high(self):
        assert DEFAULT_SEVERITY_MAP[EventType.RATE_ESCALATION] == Severity.HIGH


# ======================================================================
# SecurityEvent
# ======================================================================


class TestSecurityEvent:
    """SecurityEvent dataclass construction and serialization."""

    def test_from_raw_audit_classifies_domain_block(self):
        event = SecurityEvent.from_raw_audit(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com", "reason": "domain not in allowlist"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )
        assert event.event_type == EventType.DOMAIN_BLOCKED
        assert event.severity == Severity.HIGH
        assert event.source == "DomainAllowlist"
        assert event.host == "evil.com"

    def test_from_raw_audit_classifies_secret_block(self):
        event = SecurityEvent.from_raw_audit(
            tool_name="outbound_http",
            args_redacted={"host": "pastebin.com", "reason": "API key detected"},
            decision="BLOCKED",
            middleware="ProxyContentScanner",
        )
        assert event.event_type == EventType.BLOCKED_SECRET
        assert event.severity == Severity.CRITICAL

    def test_from_raw_audit_classifies_rate_anomaly(self):
        event = SecurityEvent.from_raw_audit(
            tool_name="outbound_http",
            args_redacted={"host": "api.example.com", "reason": "burst pattern"},
            decision="ANOMALY",
            middleware="RateLimiter",
        )
        assert event.event_type == EventType.RATE_ANOMALY
        assert event.severity == Severity.MEDIUM

    def test_to_audit_dict_includes_policy_metadata(self):
        event = SecurityEvent(
            event_type=EventType.BLOCKED_SECRET,
            severity=Severity.CRITICAL,
            source="ProxyContentScanner",
            tool_name="outbound_http",
            decision="BLOCKED",
            middleware="ProxyContentScanner",
            host="evil.com",
            reason="secret detected",
        )
        d = event.to_audit_dict()
        assert d["tool_name"] == "outbound_http"
        assert d["decision"] == "BLOCKED"
        assert d["middleware"] == "ProxyContentScanner"
        assert d["args_redacted"]["_event_type"] == "BLOCKED_SECRET"
        assert d["args_redacted"]["_severity"] == "CRITICAL"
        assert d["args_redacted"]["_source"] == "ProxyContentScanner"
        assert d["args_redacted"]["host"] == "evil.com"
        assert d["args_redacted"]["reason"] == "secret detected"

    def test_timestamp_defaults_to_now(self):
        before = time.time()
        event = SecurityEvent(
            event_type=EventType.RATE_ANOMALY,
            severity=Severity.MEDIUM,
            source="RateLimiter",
        )
        after = time.time()
        assert before <= event.timestamp <= after


# ======================================================================
# SessionState
# ======================================================================


class TestSessionState:
    """SessionState counters update correctly."""

    def _make_event(self, event_type, severity, source):
        return SecurityEvent(
            event_type=event_type,
            severity=severity,
            source=source,
        )

    def test_event_count_increments(self):
        state = SessionState()
        state.record(self._make_event(EventType.DOMAIN_BLOCKED, Severity.HIGH, "DomainAllowlist"))
        state.record(self._make_event(EventType.DOMAIN_BLOCKED, Severity.HIGH, "DomainAllowlist"))
        state.record(self._make_event(EventType.BLOCKED_SECRET, Severity.CRITICAL, "ProxyContentScanner"))
        assert state.event_counts == {
            "DOMAIN_BLOCKED": 2,
            "BLOCKED_SECRET": 1,
        }

    def test_severity_count_increments(self):
        state = SessionState()
        state.record(self._make_event(EventType.BLOCKED_SECRET, Severity.CRITICAL, "src"))
        state.record(self._make_event(EventType.DOMAIN_BLOCKED, Severity.HIGH, "src"))
        assert state.severity_counts == {"CRITICAL": 1, "HIGH": 1}

    def test_source_count_increments(self):
        state = SessionState()
        state.record(self._make_event(EventType.RATE_ANOMALY, Severity.MEDIUM, "RateLimiter"))
        assert state.source_counts == {"RateLimiter": 1}


# ======================================================================
# PolicyEngine — passthrough
# ======================================================================


class TestPolicyEnginePassthrough:
    """PolicyEngine.log() produces audit trail entries with policy metadata."""

    def test_log_writes_to_audit_trail(self, tmp_path):
        trail = AuditTrail(tmp_path / "audit.jsonl")
        engine = PolicyEngine(audit_trail=trail)

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com", "reason": "domain not in allowlist"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        entries = trail.read_all()
        assert len(entries) == 1
        entry = entries[0]
        assert entry.decision == "BLOCKED"
        assert entry.middleware == "DomainAllowlist"

    def test_log_appends_policy_metadata(self, tmp_path):
        trail = AuditTrail(tmp_path / "audit.jsonl")
        engine = PolicyEngine(audit_trail=trail)

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com", "reason": "domain not in allowlist"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        # Read raw line to check metadata
        raw = json.loads((tmp_path / "audit.jsonl").read_text().strip())
        args = raw["args_redacted"]
        assert args["_event_type"] == "DOMAIN_BLOCKED"
        assert args["_severity"] == "HIGH"
        assert args["_source"] == "DomainAllowlist"

    def test_log_updates_session_state(self):
        engine = PolicyEngine()

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "x", "reason": "secret"},
            decision="BLOCKED",
            middleware="ProxyContentScanner",
        )
        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "y", "reason": "domain"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        assert engine.session_event_count() == 2
        assert engine.session_event_count(EventType.BLOCKED_SECRET) == 1
        assert engine.session_event_count(EventType.DOMAIN_BLOCKED) == 1

    def test_log_preserves_existing_audit_format(self, tmp_path):
        """Entries written by PolicyEngine must be readable by AuditTrail.read_all()."""
        trail = AuditTrail(tmp_path / "audit.jsonl")
        engine = PolicyEngine(audit_trail=trail)

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        entries = trail.read_all()
        assert len(entries) == 1
        assert entries[0].tool_name == "outbound_http"
        assert entries[0].decision == "BLOCKED"
        assert entries[0].entry_hash  # hash-chain integrity maintained

    def test_emit_typed_event(self, tmp_path):
        """The typed emit() API also writes to trail."""
        trail = AuditTrail(tmp_path / "audit.jsonl")
        engine = PolicyEngine(audit_trail=trail)

        event = SecurityEvent(
            event_type=EventType.RATE_ANOMALY,
            severity=Severity.MEDIUM,
            source="RateLimiter",
            tool_name="outbound_http",
            decision="ANOMALY",
            middleware="RateLimiter",
            host="api.example.com",
            reason="burst detected",
        )
        engine.emit(event)

        entries = trail.read_all()
        assert len(entries) == 1
        assert entries[0].decision == "ANOMALY"
        assert entries[0].middleware == "RateLimiter"

    def test_engine_without_trail_does_not_crash(self):
        """Engine with no trail still tracks session state."""
        engine = PolicyEngine()

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "x"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        assert engine.session_event_count() == 1

    def test_hash_chain_integrity_with_multiple_events(self, tmp_path):
        """Multiple events through the engine maintain chain integrity."""
        trail = AuditTrail(tmp_path / "audit.jsonl")
        engine = PolicyEngine(audit_trail=trail)

        for i in range(5):
            engine.log(
                tool_name="outbound_http",
                args_redacted={"host": f"host{i}.example"},
                decision="BLOCKED",
                middleware="DomainAllowlist",
            )

        assert trail.verify_chain() is True

    def test_mixed_legacy_and_typed_events(self, tmp_path):
        """Both log() and emit() produce valid chain entries."""
        trail = AuditTrail(tmp_path / "audit.jsonl")
        engine = PolicyEngine(audit_trail=trail)

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "legacy.example"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        engine.emit(SecurityEvent(
            event_type=EventType.BLOCKED_SECRET,
            severity=Severity.CRITICAL,
            source="ProxyContentScanner",
            tool_name="outbound_http",
            decision="BLOCKED",
            middleware="ProxyContentScanner",
        ))

        assert len(trail.read_all()) == 2
        assert trail.verify_chain() is True


# ======================================================================
# PolicyEngine — query helpers
# ======================================================================


class TestPolicyEngineQueryHelpers:
    """Session-scoped counter queries work correctly."""

    def test_session_event_count_by_type(self):
        engine = PolicyEngine()
        engine.session.record(SecurityEvent(
            event_type=EventType.DOMAIN_BLOCKED,
            severity=Severity.HIGH,
            source="DomainAllowlist",
        ))
        engine.session.record(SecurityEvent(
            event_type=EventType.DOMAIN_BLOCKED,
            severity=Severity.HIGH,
            source="DomainAllowlist",
        ))
        engine.session.record(SecurityEvent(
            event_type=EventType.RATE_ANOMALY,
            severity=Severity.MEDIUM,
            source="RateLimiter",
        ))

        assert engine.session_event_count() == 3
        assert engine.session_event_count(EventType.DOMAIN_BLOCKED) == 2
        assert engine.session_event_count(EventType.RATE_ANOMALY) == 1
        assert engine.session_event_count(EventType.BLOCKED_SECRET) == 0

    def test_session_severity_count(self):
        engine = PolicyEngine()
        engine.session.record(SecurityEvent(
            event_type=EventType.BLOCKED_SECRET,
            severity=Severity.CRITICAL,
            source="src",
        ))
        assert engine.session_severity_count(Severity.CRITICAL) == 1
        assert engine.session_severity_count(Severity.LOW) == 0

    def test_session_source_count(self):
        engine = PolicyEngine()
        engine.session.record(SecurityEvent(
            event_type=EventType.RATE_ANOMALY,
            severity=Severity.MEDIUM,
            source="RateLimiter",
        ))
        assert engine.session_source_count("RateLimiter") == 1
        assert engine.session_source_count("ProxyContentScanner") == 0


# ======================================================================
# PolicyRule matching
# ======================================================================


class TestPolicyRuleMatching:
    """PolicyRule.matches() correctly filters events."""

    def test_match_all_when_no_constraints(self):
        rule = PolicyRule(name="catch-all")
        assert rule.matches(EventType.BLOCKED_SECRET, Severity.CRITICAL, "any_source")

    def test_match_by_event_type(self):
        rule = PolicyRule(name="secret-only", event_types={EventType.BLOCKED_SECRET})
        assert rule.matches(EventType.BLOCKED_SECRET, Severity.CRITICAL, "src")
        assert not rule.matches(EventType.DOMAIN_BLOCKED, Severity.HIGH, "src")

    def test_match_by_severity(self):
        rule = PolicyRule(name="critical-only", severities={Severity.CRITICAL})
        assert rule.matches(EventType.BLOCKED_SECRET, Severity.CRITICAL, "src")
        assert not rule.matches(EventType.DOMAIN_BLOCKED, Severity.HIGH, "src")

    def test_match_by_source(self):
        rule = PolicyRule(name="proxy-only", sources={"ProxyContentScanner"})
        assert rule.matches(EventType.BLOCKED_SECRET, Severity.CRITICAL, "ProxyContentScanner")
        assert not rule.matches(EventType.BLOCKED_SECRET, Severity.CRITICAL, "RateLimiter")

    def test_match_intersection(self):
        rule = PolicyRule(
            name="critical-secrets-from-proxy",
            event_types={EventType.BLOCKED_SECRET},
            severities={Severity.CRITICAL},
            sources={"ProxyContentScanner"},
        )
        assert rule.matches(EventType.BLOCKED_SECRET, Severity.CRITICAL, "ProxyContentScanner")
        assert not rule.matches(EventType.BLOCKED_SECRET, Severity.HIGH, "ProxyContentScanner")
        assert not rule.matches(EventType.BLOCKED_SECRET, Severity.CRITICAL, "OtherScanner")

    def test_rules_sorted_by_priority(self):
        r1 = PolicyRule(name="low", priority=200)
        r2 = PolicyRule(name="high", priority=10)
        r3 = PolicyRule(name="mid", priority=100)
        engine = PolicyEngine(rules=[r1, r2, r3])
        assert [r.name for r in engine.rules] == ["high", "mid", "low"]


# ======================================================================
# PolicyDecision
# ======================================================================


class TestPolicyDecision:
    """PolicyDecision enum properties."""

    def test_block_is_blocking(self):
        assert PolicyDecision.BLOCK.is_blocking is True

    def test_redact_is_blocking(self):
        assert PolicyDecision.REDACT.is_blocking is True

    def test_allow_is_not_blocking(self):
        assert PolicyDecision.ALLOW.is_blocking is False

    def test_anomaly_is_not_blocking(self):
        assert PolicyDecision.ANOMALY.is_blocking is False

    def test_investigate_is_not_blocking(self):
        assert PolicyDecision.INVESTIGATE.is_blocking is False
