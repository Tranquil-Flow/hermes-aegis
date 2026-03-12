"""Performance benchmarks for hermes-aegis components."""
import os
import tempfile
import time

import pytest

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.environment import find_available_port, wait_for_proxy_ready
from hermes_aegis.patterns.secrets import scan_for_secrets


class TestScannerPerformance:
    """Benchmark secret scanning performance."""

    def test_scan_short_text(self):
        """Scanner should handle short text in <1ms."""
        text = "Hello, this is a normal message with no secrets."
        start = time.perf_counter()
        for _ in range(1000):
            scan_for_secrets(text)
        elapsed = time.perf_counter() - start

        per_call_us = (elapsed / 1000) * 1_000_000
        print(f"Short text scan: {per_call_us:.1f}us per call")
        assert per_call_us < 1000, f"Scanner too slow: {per_call_us:.0f}us"

    def test_scan_with_secrets(self):
        """Scanner should detect secrets in <2ms even with matches."""
        text = (
            "Here is my key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu "
            "and also sk-ant-api03-AAAAAAAAAA_BBBBBBBBBB-CCCCCCCCCC "
            "and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        start = time.perf_counter()
        for _ in range(1000):
            matches = scan_for_secrets(text)
        elapsed = time.perf_counter() - start

        per_call_us = (elapsed / 1000) * 1_000_000
        print(f"Secret text scan: {per_call_us:.1f}us per call ({len(matches)} matches)")
        assert per_call_us < 2000, f"Scanner too slow with secrets: {per_call_us:.0f}us"
        assert len(matches) > 0

    def test_scan_large_text(self):
        """Scanner should handle 100KB text in <50ms."""
        text = "Normal text without secrets. " * 5000  # ~140KB
        start = time.perf_counter()
        for _ in range(100):
            scan_for_secrets(text)
        elapsed = time.perf_counter() - start

        per_call_ms = (elapsed / 100) * 1000
        print(f"Large text scan (100KB): {per_call_ms:.1f}ms per call")
        assert per_call_ms < 50, f"Scanner too slow on large text: {per_call_ms:.0f}ms"

    def test_scan_with_exact_values(self):
        """Exact value matching performance."""
        text = "Here is some text with a secret_value_12345678 embedded in it." * 100
        exact = ["secret_value_12345678", "another_secret_99", "third_secret_xyz"]

        start = time.perf_counter()
        for _ in range(100):
            matches = scan_for_secrets(text, exact_values=exact)
        elapsed = time.perf_counter() - start

        per_call_ms = (elapsed / 100) * 1000
        print(f"Exact value scan: {per_call_ms:.1f}ms per call ({len(matches)} matches)")
        assert per_call_ms < 50, f"Exact match too slow: {per_call_ms:.0f}ms"
        assert len(matches) > 0


class TestAuditTrailPerformance:
    """Benchmark audit trail performance."""

    def test_audit_write_throughput(self):
        """Should sustain >1000 entries/sec."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            trail = AuditTrail(path)
            count = 1000

            start = time.perf_counter()
            for i in range(count):
                trail.log(
                    tool_name="test_tool",
                    args_redacted={"arg": f"value_{i}"},
                    decision="ALLOW",
                    middleware="bench",
                )
            elapsed = time.perf_counter() - start

            rate = count / elapsed
            print(f"Audit write: {rate:.0f} entries/sec ({elapsed*1000:.0f}ms for {count})")
            assert rate > 1000, f"Audit write too slow: {rate:.0f}/sec"
        finally:
            os.unlink(path)

    def test_audit_verify_chain(self):
        """Chain verification should be fast for reasonable sizes."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            trail = AuditTrail(path)
            for i in range(500):
                trail.log(
                    tool_name="test",
                    args_redacted={"i": i},
                    decision="ALLOW",
                    middleware="bench",
                )

            start = time.perf_counter()
            for _ in range(10):
                valid = trail.verify_chain()
            elapsed = time.perf_counter() - start

            per_call_ms = (elapsed / 10) * 1000
            print(f"Chain verify (500 entries): {per_call_ms:.1f}ms")
            assert valid
            assert per_call_ms < 500, f"Chain verify too slow: {per_call_ms:.0f}ms"
        finally:
            os.unlink(path)


class TestPortFinding:
    """Benchmark port finding."""

    def test_find_port_speed(self):
        """Port finding should be fast."""
        start = time.perf_counter()
        for _ in range(100):
            find_available_port(start=10000, end=10100)
        elapsed = time.perf_counter() - start

        per_call_ms = (elapsed / 100) * 1000
        print(f"Port finding: {per_call_ms:.1f}ms per call")
        assert per_call_ms < 10, f"Port finding too slow: {per_call_ms:.0f}ms"
