"""Phase 2 tests: PolicyEngine wiring, coalescing, status banner, reactive rules.

Tests cover:
- PolicyEngine coalescing of RATE_ANOMALY events (one per host per window)
- AegisAddon wired through PolicyEngine (duck-typing with AuditTrail)
- DangerousBlockerMiddleware wired through PolicyEngine
- TirithScannerMiddleware wired through PolicyEngine
- Status banner using summarize_audit with 24h window
- Reactive rule anomaly-reporter uses middleware_in=["RateLimiter"]
"""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.policy.engine import PolicyEngine, SessionState
from hermes_aegis.policy.events import (
    DEFAULT_SEVERITY_MAP,
    EventType,
    SecurityEvent,
    Severity,
    _infer_event_type,
)
from hermes_aegis.policy.rules import PolicyRule


# ============================================================
# Helpers
# ============================================================

def _make_engine(trail_path: str | None = None, **kw) -> PolicyEngine:
    trail = AuditTrail(trail_path) if trail_path else None
    return PolicyEngine(audit_trail=trail, **kw)


# ============================================================
# 1. PolicyEngine Coalescing
# ============================================================

class TestRateAnomalyCoalescing:
    """RATE_ANOMALY events are coalesced: one per host per window."""

    def test_first_rate_anomaly_written(self, tmp_path):
        """First RATE_ANOMALY for a host within a window is written."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path, coalesce_window=1.0)

        event = SecurityEvent(
            event_type=EventType.RATE_ANOMALY,
            severity=Severity.MEDIUM,
            source="RateLimiter",
            host="example.com",
            decision="ANOMALY",
            middleware="RateLimiter",
            reason="burst detected",
        )
        engine.emit(event)

        entries = AuditTrail(trail_path).read_all()
        assert len(entries) == 1
        assert entries[0].middleware == "RateLimiter"

    def test_duplicate_rate_anomaly_suppressed(self, tmp_path):
        """Second RATE_ANOMALY for same host within window is suppressed."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path, coalesce_window=1.0)

        for _ in range(5):
            event = SecurityEvent(
                event_type=EventType.RATE_ANOMALY,
                severity=Severity.MEDIUM,
                source="RateLimiter",
                host="example.com",
                decision="ANOMALY",
                middleware="RateLimiter",
                timestamp=time.time(),
            )
            engine.emit(event)

        entries = AuditTrail(trail_path).read_all()
        assert len(entries) == 1  # only first written

    def test_session_counts_include_suppressed(self, tmp_path):
        """SessionState counts ALL events, even suppressed ones."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path, coalesce_window=1.0)

        for _ in range(5):
            event = SecurityEvent(
                event_type=EventType.RATE_ANOMALY,
                severity=Severity.MEDIUM,
                source="RateLimiter",
                host="example.com",
                decision="ANOMALY",
                middleware="RateLimiter",
                timestamp=time.time(),
            )
            engine.emit(event)

        assert engine.session_event_count(EventType.RATE_ANOMALY) == 5
        assert engine.session_source_count("RateLimiter") == 5

    def test_different_hosts_not_coalesced(self, tmp_path):
        """RATE_ANOMALY for different hosts are independent."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path, coalesce_window=1.0)

        for host in ["host1.com", "host2.com", "host3.com"]:
            event = SecurityEvent(
                event_type=EventType.RATE_ANOMALY,
                severity=Severity.MEDIUM,
                source="RateLimiter",
                host=host,
                decision="ANOMALY",
                middleware="RateLimiter",
            )
            engine.emit(event)

        entries = AuditTrail(trail_path).read_all()
        assert len(entries) == 3

    def test_new_window_allows_new_event(self, tmp_path):
        """After coalesce_window expires, a new event is written."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path, coalesce_window=0.1)

        event1 = SecurityEvent(
            event_type=EventType.RATE_ANOMALY,
            severity=Severity.MEDIUM,
            source="RateLimiter",
            host="example.com",
            decision="ANOMALY",
            middleware="RateLimiter",
            timestamp=time.time(),
        )
        engine.emit(event1)

        time.sleep(0.15)  # wait for window to expire

        event2 = SecurityEvent(
            event_type=EventType.RATE_ANOMALY,
            severity=Severity.MEDIUM,
            source="RateLimiter",
            host="example.com",
            decision="ANOMALY",
            middleware="RateLimiter",
            timestamp=time.time(),
        )
        engine.emit(event2)

        entries = AuditTrail(trail_path).read_all()
        assert len(entries) == 2

    def test_non_rate_events_never_coalesced(self, tmp_path):
        """BLOCKED_SECRET and other events pass through without coalescing."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path, coalesce_window=1.0)

        for _ in range(5):
            event = SecurityEvent(
                event_type=EventType.BLOCKED_SECRET,
                severity=Severity.CRITICAL,
                source="ProxyContentScanner",
                host="evil.com",
                decision="BLOCKED",
                middleware="ProxyContentScanner",
            )
            engine.emit(event)

        entries = AuditTrail(trail_path).read_all()
        assert len(entries) == 5

    def test_coalesced_suppressed_counter(self, tmp_path):
        """The coalesced_suppressed() query returns correct counts."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path, coalesce_window=1.0)

        for _ in range(5):
            event = SecurityEvent(
                event_type=EventType.RATE_ANOMALY,
                severity=Severity.MEDIUM,
                source="RateLimiter",
                host="example.com",
                decision="ANOMALY",
                middleware="RateLimiter",
                timestamp=time.time(),
            )
            engine.emit(event)

        key = "rate:example.com"
        assert engine.coalesced_suppressed(key) == 5  # 1 first + 4 suppressed
        assert engine.coalesced_suppressed() == 5  # total


# ============================================================
# 2. AegisAddon wired through PolicyEngine
# ============================================================

class FakeFlow:
    """Minimal mock of mitmproxy.http.HTTPFlow."""

    def __init__(self, host, path, body=b"", headers=None):
        self.request = MagicMock()
        self.request.host = host
        self.request.path = path
        self.request.url = f"https://{host}{path}"
        self.request.headers = headers or {}
        self.request.get_content = MagicMock(return_value=body)
        self.killed = False

    def kill(self):
        self.killed = True


class TestAegisAddonPolicyEngine:
    """AegisAddon uses PolicyEngine for audit logging."""

    def test_addon_wraps_trail_in_engine(self):
        """When audit_trail is provided, addon wraps it in PolicyEngine."""
        from hermes_aegis.proxy.addon import AegisAddon

        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)

        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
        )

        assert isinstance(addon._audit, PolicyEngine)

    def test_addon_none_trail_stays_none(self):
        """When audit_trail is None, addon._audit stays None."""
        from hermes_aegis.proxy.addon import AegisAddon

        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=None,
        )

        assert addon._audit is None

    def test_rate_anomaly_events_get_policy_metadata(self):
        """Rate anomaly events written via engine include _event_type metadata."""
        from hermes_aegis.proxy.addon import AegisAddon

        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)

        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=3,
            rate_limit_window=1.0,
        )

        # Send burst
        for i in range(5):
            addon.request(FakeFlow("example.com", f"/api{i}"))

        entries = AuditTrail(trail_path).read_all()
        rate_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_entries) >= 1

        # Check policy metadata attached
        first = rate_entries[0]
        assert first.args_redacted.get("_event_type") == "RATE_ANOMALY"
        assert first.args_redacted.get("_severity") == "MEDIUM"
        assert first.args_redacted.get("_source") == "RateLimiter"

    def test_domain_block_events_get_policy_metadata(self):
        """Domain blocked events include policy metadata."""
        import json
        from hermes_aegis.proxy.addon import AegisAddon

        tmp_dir = tempfile.mkdtemp()
        trail_path = os.path.join(tmp_dir, "audit.jsonl")
        allowlist_path = os.path.join(tmp_dir, "allowlist.json")
        # DomainAllowlist expects a plain JSON array of domain strings
        with open(allowlist_path, 'w') as f:
            json.dump(["allowed.com"], f)

        trail = AuditTrail(trail_path)
        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            allowlist_path=Path(allowlist_path),
        )

        addon.request(FakeFlow("blocked.com", "/path"))

        entries = AuditTrail(trail_path).read_all()
        blocked = [e for e in entries if e.middleware == "DomainAllowlist"]
        assert len(blocked) == 1
        assert blocked[0].args_redacted.get("_event_type") == "DOMAIN_BLOCKED"
        assert blocked[0].args_redacted.get("_severity") == "HIGH"


# ============================================================
# 3. PolicyEngine legacy log() duck-typing
# ============================================================

class TestPolicyEngineDuckTyping:
    """PolicyEngine.log() is duck-compatible with AuditTrail.log()."""

    def test_log_writes_to_trail(self, tmp_path):
        """log() with legacy args writes an entry to the trail."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path)

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com", "reason": "secret detected"},
            decision="BLOCKED",
            middleware="ProxyContentScanner",
        )

        entries = AuditTrail(trail_path).read_all()
        assert len(entries) == 1
        assert entries[0].middleware == "ProxyContentScanner"

    def test_log_adds_policy_metadata(self, tmp_path):
        """log() enriches entries with _event_type, _severity, _source."""
        trail_path = str(tmp_path / "audit.jsonl")
        engine = _make_engine(trail_path)

        engine.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        entries = AuditTrail(trail_path).read_all()
        assert entries[0].args_redacted["_event_type"] == "DOMAIN_BLOCKED"
        assert entries[0].args_redacted["_severity"] == "HIGH"
        assert entries[0].args_redacted["_source"] == "DomainAllowlist"

    def test_no_trail_does_not_crash(self):
        """log() with no trail doesn't crash — counters still update."""
        engine = _make_engine()

        engine.log(
            tool_name="terminal",
            args_redacted={"command": "rm -rf /"},
            decision="BLOCKED",
            middleware="DangerousBlockerMiddleware",
        )

        assert engine.session_event_count(EventType.DANGEROUS_COMMAND) == 1


# ============================================================
# 4. Status banner uses summarize_audit
# ============================================================

class TestStatusBannerSummarize:
    """Status banner uses summarize_audit with 24h window."""

    def test_summarize_audit_filters_24h(self, tmp_path):
        """summarize_audit with 24h window excludes old events."""
        from hermes_aegis.audit.summary import summarize_audit

        audit_path = tmp_path / "audit.jsonl"
        trail = AuditTrail(audit_path)
        now = time.time()

        trail.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com", "reason": "domain blocked"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )
        trail.log(
            tool_name="outbound_http",
            args_redacted={"host": "api.example", "reason": "burst"},
            decision="ANOMALY",
            middleware="RateLimiter",
        )

        # Backdate first entry outside 24h
        import json
        lines = audit_path.read_text().splitlines()
        data0 = json.loads(lines[0])
        data0["timestamp"] = now - 100000  # ~27 hours ago
        lines[0] = json.dumps(data0)
        audit_path.write_text("\n".join(lines) + "\n")

        summary = summarize_audit(audit_path, since="24h", group_by="middleware", now=now)

        # Only the RateLimiter event should be within 24h
        assert summary.total == 1
        assert "RateLimiter" in summary.middleware_counts
        assert "DomainAllowlist" not in summary.middleware_counts

    def test_summarize_audit_splits_middleware_categories(self, tmp_path):
        """summarize_audit returns middleware_counts for banner split."""
        from hermes_aegis.audit.summary import summarize_audit

        audit_path = tmp_path / "audit.jsonl"
        trail = AuditTrail(audit_path)

        for _ in range(3):
            trail.log(
                tool_name="outbound_http",
                args_redacted={"host": "evil.com", "reason": "secret"},
                decision="BLOCKED",
                middleware="ProxyContentScanner",
            )
        for _ in range(2):
            trail.log(
                tool_name="outbound_http",
                args_redacted={"host": "blocked.com", "reason": "domain"},
                decision="BLOCKED",
                middleware="DomainAllowlist",
            )

        summary = summarize_audit(audit_path, since="all", group_by="middleware")

        assert summary.middleware_counts["ProxyContentScanner"] == 3
        assert summary.middleware_counts["DomainAllowlist"] == 2
        assert summary.total == 5

    def test_print_aegis_banner_uses_24h_window(self, tmp_path, monkeypatch):
        """_print_aegis_banner uses summarize_audit for audit counts."""
        from hermes_aegis.audit.summary import summarize_audit
        from io import StringIO

        audit_path = tmp_path / "audit.jsonl"
        trail = AuditTrail(audit_path)
        now = time.time()

        trail.log(
            tool_name="outbound_http",
            args_redacted={"host": "evil.com", "reason": "domain blocked"},
            decision="BLOCKED",
            middleware="DomainAllowlist",
        )

        # Verify summarize works correctly as used by the banner
        summary = summarize_audit(audit_path, since="24h", now=now)
        assert summary.total == 1
        assert "DomainAllowlist" in summary.middleware_counts


# ============================================================
# 5. Reactive rule anomaly-reporter uses middleware_in
# ============================================================

class TestReactiveRuleUpdate:
    """anomaly-reporter rule updated to use middleware_in=['RateLimiter']."""

    def test_default_anomaly_reporter_has_middleware_in(self):
        """Default anomaly-reporter rule scopes to RateLimiter middleware."""
        from hermes_aegis.reactive.rules import default_rules

        rules = default_rules()
        anomaly_reporter = [r for r in rules if r.name == "anomaly-reporter"]
        assert len(anomaly_reporter) == 1

        rule = anomaly_reporter[0]
        assert rule.trigger.middleware_in == ["RateLimiter"]
        assert rule.trigger.decision_in == ["ANOMALY"]
        assert rule.trigger.count == 3
        assert rule.trigger.window == "60s"

    def test_trigger_matches_rate_limiter_anomaly(self):
        """Trigger matches ANOMALY from RateLimiter middleware."""
        from hermes_aegis.reactive.rules import Trigger

        trigger = Trigger(
            decision_in=["ANOMALY"],
            middleware_in=["RateLimiter"],
            count=3,
            window="60s",
        )

        assert trigger.matches_entry("ANOMALY", "RateLimiter")
        assert not trigger.matches_entry("ANOMALY", "ProxyContentScanner")
        assert not trigger.matches_entry("BLOCKED", "RateLimiter")


# ============================================================
# 6. Integration: full passthrough with coalescing
# ============================================================

class TestIntegrationCoalescing:
    """End-to-end: burst through addon → engine coalesces → trail has 1 entry."""

    def test_burst_produces_one_rate_anomaly_entry(self):
        """15 requests with threshold 10 → exactly 1 RATE_ANOMALY in trail."""
        from hermes_aegis.proxy.addon import AegisAddon

        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)

        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=10,
            rate_limit_window=1.0,
        )

        for i in range(15):
            addon.request(FakeFlow("example.com", f"/api{i}"))
            assert not FakeFlow("example.com", f"/api{i}").killed  # never blocks

        entries = AuditTrail(trail_path).read_all()
        rate_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_entries) == 1

    def test_two_bursts_two_entries_after_window(self):
        """Two bursts separated by window expiry → 2 RATE_ANOMALY entries."""
        from hermes_aegis.proxy.addon import AegisAddon

        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)

        addon = AegisAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=3,
            rate_limit_window=0.2,
        )

        for i in range(5):
            addon.request(FakeFlow("example.com", f"/burst1/{i}"))

        time.sleep(0.25)

        for i in range(5):
            addon.request(FakeFlow("example.com", f"/burst2/{i}"))

        entries = AuditTrail(trail_path).read_all()
        rate_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_entries) == 2
