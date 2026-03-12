"""Tests for network rate limiting feature.

Tests burst pattern detection, normal traffic flow, per-host isolation,
and configuration management for the rate limiting feature.
"""
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.config.settings import Settings
from hermes_aegis.proxy.addon import ArmorAddon


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


class TestRateLimiting:
    """Test rate limiting burst detection."""

    def test_burst_detection_triggers_audit_log(self):
        """Test that burst patterns are detected and logged."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=10,
            rate_limit_window=1.0,
        )

        # Send burst of requests to same host (more than limit)
        for i in range(15):
            flow = FakeFlow("example.com", f"/api/endpoint{i}")
            addon.request(flow)
            # Don't kill flow - rate limiting is detection only
            assert not flow.killed

        # Check audit log for rate limit anomalies
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        
        # Should have multiple anomaly logs after exceeding threshold
        assert len(rate_limit_entries) >= 5
        
        # Check that anomaly details are logged
        first_anomaly = rate_limit_entries[0]
        assert first_anomaly.decision == "ANOMALY"
        assert first_anomaly.tool_name == "outbound_http"
        assert "host" in first_anomaly.args_redacted
        assert "reason" in first_anomaly.args_redacted
        assert "burst pattern detected" in first_anomaly.args_redacted["reason"]
        assert "requests_in_window" in first_anomaly.args_redacted
        assert first_anomaly.args_redacted["requests_in_window"] >= 10

    def test_normal_traffic_not_flagged(self):
        """Test that normal request rates don't trigger alerts."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=50,
            rate_limit_window=1.0,
        )

        # Send normal amount of requests
        for i in range(10):
            flow = FakeFlow("example.com", f"/page{i}")
            addon.request(flow)
            assert not flow.killed

        # Check that no rate limiting anomalies were logged
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_limit_entries) == 0

    def test_per_host_isolation(self):
        """Test that rate limiting is tracked per-host."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=10,
            rate_limit_window=1.0,
        )

        # Send burst to host1
        for i in range(15):
            flow = FakeFlow("host1.com", f"/api{i}")
            addon.request(flow)

        # Send normal requests to host2
        for i in range(5):
            flow = FakeFlow("host2.com", f"/api{i}")
            addon.request(flow)

        # Check audit log
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        
        # Should only have anomalies for host1
        hosts_flagged = {e.args_redacted["host"] for e in rate_limit_entries}
        assert "host1.com" in hosts_flagged
        assert "host2.com" not in hosts_flagged

    def test_sliding_window_expiration(self):
        """Test that old requests expire from the sliding window."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=10,
            rate_limit_window=0.5,  # 500ms window
        )

        # Send some requests
        for i in range(5):
            flow = FakeFlow("example.com", f"/api{i}")
            addon.request(flow)

        # Wait for window to expire
        time.sleep(0.6)

        # Send more requests - should not trigger (old ones expired)
        for i in range(5):
            flow = FakeFlow("example.com", f"/api2_{i}")
            addon.request(flow)

        # Check that no rate limiting anomalies were logged
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_limit_entries) == 0

    def test_rate_limiting_with_llm_providers(self):
        """Test that rate limiting applies to LLM provider requests."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        addon = ArmorAddon(
            vault_secrets={"OPENAI_API_KEY": "sk-test123"},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=10,
            rate_limit_window=1.0,
        )

        # Send burst to OpenAI (LLM provider)
        for i in range(15):
            flow = FakeFlow("api.openai.com", "/v1/chat/completions")
            addon.request(flow)
            # Should inject key AND check rate limit
            assert not flow.killed  # Rate limiting doesn't block

        # Check audit log for rate limit anomalies
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_limit_entries) > 0
        
        # Verify OpenAI was flagged
        assert any(e.args_redacted["host"] == "api.openai.com" for e in rate_limit_entries)

    def test_rate_limiting_does_not_block(self):
        """Test that rate limiting logs but doesn't block requests."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=["secret123"],
            audit_trail=trail,
            rate_limit_requests=5,
            rate_limit_window=1.0,
        )

        # Send burst that exceeds rate limit
        for i in range(20):
            flow = FakeFlow("example.com", f"/api{i}")
            addon.request(flow)
            # Rate limiting should NEVER block (detection only)
            assert not flow.killed

    def test_adjustable_thresholds(self):
        """Test that rate limit thresholds can be configured."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        # Test with custom threshold
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=3,  # Very low threshold
            rate_limit_window=1.0,
        )

        # Send 5 requests (exceeds threshold of 3)
        for i in range(5):
            flow = FakeFlow("example.com", f"/api{i}")
            addon.request(flow)

        # Should have anomalies logged
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_limit_entries) >= 2

    def test_no_audit_trail_does_not_crash(self):
        """Test that rate limiting works without audit trail."""
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=None,  # No audit trail
            rate_limit_requests=10,
            rate_limit_window=1.0,
        )

        # Send burst - should not crash
        for i in range(20):
            flow = FakeFlow("example.com", f"/api{i}")
            addon.request(flow)
            assert not flow.killed


class TestRateLimitingConfig:
    """Test rate limiting configuration management."""

    def test_config_defaults(self):
        """Test that default rate limit settings are present."""
        config_path = Path(tempfile.mkdtemp()) / "config.json"
        settings = Settings(config_path)
        
        # Check defaults
        assert settings.get("rate_limit_requests") == 50
        assert settings.get("rate_limit_window") == 1.0

    def test_config_set_rate_limit_requests(self):
        """Test setting rate_limit_requests via config."""
        config_path = Path(tempfile.mkdtemp()) / "config.json"
        settings = Settings(config_path)
        
        settings.set("rate_limit_requests", 100)
        assert settings.get("rate_limit_requests") == 100
        
        # Reload and verify persistence
        settings2 = Settings(config_path)
        assert settings2.get("rate_limit_requests") == 100

    def test_config_set_rate_limit_window(self):
        """Test setting rate_limit_window via config."""
        config_path = Path(tempfile.mkdtemp()) / "config.json"
        settings = Settings(config_path)
        
        settings.set("rate_limit_window", 2.5)
        assert settings.get("rate_limit_window") == 2.5
        
        # Reload and verify persistence
        settings2 = Settings(config_path)
        assert settings2.get("rate_limit_window") == 2.5

    def test_config_custom_window(self):
        """Test rate limiting with custom window size."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        # Create addon with 2-second window
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            rate_limit_requests=20,
            rate_limit_window=2.0,  # 2 second window
        )

        # Send 25 requests over time
        for i in range(25):
            flow = FakeFlow("example.com", f"/api{i}")
            addon.request(flow)
            if i == 10:
                # Pause in the middle
                time.sleep(0.3)

        # Should have some anomalies
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        assert len(rate_limit_entries) > 0
        
        # Check that window_seconds is correctly logged
        assert rate_limit_entries[0].args_redacted["window_seconds"] == 2.0


class TestRateLimitingIntegration:
    """Integration tests for rate limiting with other features."""

    def test_rate_limiting_with_content_scanning(self):
        """Test rate limiting doesn't interfere with content scanning."""
        trail_path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        trail = AuditTrail(trail_path)
        
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=["secret-token-xyz"],
            audit_trail=trail,
            rate_limit_requests=10,
            rate_limit_window=1.0,
        )

        # Send burst with one containing a secret
        for i in range(15):
            if i == 7:
                # This one contains a secret and should be blocked
                flow = FakeFlow("evil.com", "/steal", body=b"data=secret-token-xyz")
            else:
                flow = FakeFlow("evil.com", f"/api{i}")
            
            addon.request(flow)
            
            if i == 7:
                # Should be blocked by content scanner
                assert flow.killed
            else:
                # Others not blocked (just rate limit logged)
                assert not flow.killed

        # Check both types of logs
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        scanner_entries = [e for e in entries if e.middleware == "ProxyContentScanner"]
        
        assert len(rate_limit_entries) > 0  # Rate limit anomalies
        assert len(scanner_entries) == 1  # One blocked by scanner

    def test_rate_limiting_with_allowlist(self):
        """Test rate limiting works with domain allowlist."""
        import json
        temp_dir = tempfile.mkdtemp()
        trail_path = os.path.join(temp_dir, "audit.jsonl")
        allowlist_path = os.path.join(temp_dir, "allowlist.json")
        
        # Create allowlist with both domains (both allowed so rate limiting is checked)
        with open(allowlist_path, 'w') as f:
            json.dump({"domains": ["allowed.com", "another.com"]}, f)
        
        trail = AuditTrail(trail_path)
        addon = ArmorAddon(
            vault_secrets={},
            vault_values=[],
            audit_trail=trail,
            allowlist_path=Path(allowlist_path),
            rate_limit_requests=10,
            rate_limit_window=1.0,
        )

        # Send burst to allowed domain
        for i in range(15):
            flow = FakeFlow("allowed.com", f"/api{i}")
            addon.request(flow)
            assert not flow.killed  # Not blocked

        # Send burst to another allowed domain
        for i in range(15):
            flow = FakeFlow("another.com", f"/api{i}")
            addon.request(flow)
            assert not flow.killed  # Not blocked

        # Check rate limiting logged for both
        entries = trail.read_all()
        rate_limit_entries = [e for e in entries if e.middleware == "RateLimiter"]
        
        # Should have rate limit anomalies for both hosts
        hosts = {e.args_redacted["host"] for e in rate_limit_entries}
        assert "allowed.com" in hosts
        assert "another.com" in hosts
