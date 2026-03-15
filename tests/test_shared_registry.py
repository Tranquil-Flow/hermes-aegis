# tests/test_shared_registry.py
"""Tests for the shared pattern registry module."""
from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

from hermes_aegis.patterns.secrets import SECRET_PATTERNS, PatternMatch
from hermes_aegis.patterns import shared_registry


class TestAegisPatternsAlwaysPresent:
    """Aegis patterns must always be present regardless of hermes availability."""

    def test_aegis_patterns_in_merged(self):
        patterns = shared_registry.get_all_patterns()
        merged_names = {name for name, _ in patterns}
        aegis_names = {name for name, _ in SECRET_PATTERNS}
        assert aegis_names.issubset(merged_names)

    def test_aegis_patterns_count_at_least(self):
        patterns = shared_registry.get_all_patterns()
        # Must have at least as many as aegis alone
        assert len(patterns) >= len(SECRET_PATTERNS)

    def test_patterns_are_compiled(self):
        for name, pat in shared_registry.get_all_patterns():
            assert isinstance(name, str)
            assert isinstance(pat, re.Pattern)


class TestGracefulFallback:
    """When hermes-agent is not installed, everything should still work."""

    def test_hermes_not_available(self):
        # In this test environment, hermes is not installed
        assert shared_registry.is_hermes_available() is False

    def test_hermes_patterns_none(self):
        assert shared_registry.get_hermes_patterns() is None

    def test_get_all_returns_aegis_only(self):
        patterns = shared_registry.get_all_patterns()
        aegis_names = {name for name, _ in SECRET_PATTERNS}
        merged_names = {name for name, _ in patterns}
        assert merged_names == aegis_names


class TestScanAll:
    """scan_all should work with aegis-only patterns."""

    def test_scan_openai_key(self):
        text = "my key is sk-proj-abc123def456ghi789jkl012mno"
        matches = shared_registry.scan_all(text)
        assert any(m.pattern_name == "openai_api_key" for m in matches)

    def test_scan_github_token(self):
        text = "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"
        matches = shared_registry.scan_all(text)
        assert any(m.pattern_name == "github_token" for m in matches)

    def test_scan_no_secrets(self):
        text = "This is a perfectly safe string with no secrets."
        matches = shared_registry.scan_all(text)
        assert len(matches) == 0

    def test_scan_with_exact_values(self):
        secret = "my-super-secret-value-12345"
        text = f"The password is {secret} and that's it."
        matches = shared_registry.scan_all(text, exact_values=[secret])
        exact = [m for m in matches if m.pattern_name.startswith("exact_match")]
        assert len(exact) > 0

    def test_scan_returns_pattern_match(self):
        text = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test123"
        matches = shared_registry.scan_all(text)
        for m in matches:
            assert isinstance(m, PatternMatch)
            assert isinstance(m.start, int)
            assert isinstance(m.end, int)


class TestDeduplication:
    """Test that patterns with the same name are deduplicated, aegis wins."""

    def test_merge_deduplicates_by_name(self):
        hermes_fake = [
            ("openai_api_key", re.compile(r"sk-FAKE")),
            ("hermes_only_pattern", re.compile(r"HERMES_SECRET_[A-Z]+")),
        ]
        merged = shared_registry._merge_patterns(SECRET_PATTERNS, hermes_fake)
        names = [name for name, _ in merged]

        # No duplicate names
        assert len(names) == len(set(names))

        # hermes_only_pattern should be added
        assert "hermes_only_pattern" in names

        # openai_api_key should use aegis version (first occurrence wins)
        for name, pat in merged:
            if name == "openai_api_key":
                # Should be the aegis pattern, not the fake one
                assert pat.pattern != "sk-FAKE"
                break

    def test_merge_with_none_hermes(self):
        merged = shared_registry._merge_patterns(SECRET_PATTERNS, None)
        assert len(merged) == len(SECRET_PATTERNS)

    def test_merge_empty_hermes(self):
        merged = shared_registry._merge_patterns(SECRET_PATTERNS, [])
        assert len(merged) == len(SECRET_PATTERNS)


class TestMockHermesDiscovery:
    """Test merge behavior when hermes patterns are mocked in."""

    def test_scan_all_with_hermes_patterns(self):
        fake_hermes = [
            ("hermes_custom", re.compile(r"HERMES_KEY_[A-Za-z0-9]{10,}")),
        ]

        with patch.object(shared_registry, "_hermes_patterns", fake_hermes), \
             patch.object(shared_registry, "_hermes_available", True):
            patterns = shared_registry.get_all_patterns()
            names = {n for n, _ in patterns}
            assert "hermes_custom" in names

            # scan_all should find hermes patterns too
            text = "key is HERMES_KEY_abcdef1234567890"
            matches = shared_registry.scan_all(text)
            assert any(m.pattern_name == "hermes_custom" for m in matches)

    def test_is_hermes_available_with_mock(self):
        with patch.object(shared_registry, "_hermes_available", True):
            assert shared_registry.is_hermes_available() is True

    def test_get_hermes_patterns_with_mock(self):
        fake = [("test_pat", re.compile(r"TEST"))]
        with patch.object(shared_registry, "_hermes_patterns", fake):
            result = shared_registry.get_hermes_patterns()
            assert result is not None
            assert len(result) == 1
            assert result[0][0] == "test_pat"


class TestResetDiscovery:
    """Test the reset_discovery utility."""

    def test_reset_clears_state(self):
        shared_registry.reset_discovery()
        assert shared_registry._discovery_done is False
        assert shared_registry._hermes_patterns is None
        assert shared_registry._hermes_available is False
        # Re-run discovery to restore state
        shared_registry._run_discovery()
