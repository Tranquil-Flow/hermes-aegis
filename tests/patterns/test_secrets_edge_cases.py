# hermes-aegis/tests/patterns/test_secrets_edge_cases.py
"""Edge case tests for secrets pattern scanning.

Tests cover:
- Base64-encoded secrets detection via exact_values
- URL-encoded secrets detection via exact_values
- Hex-encoded secrets detection via exact_values
- Reversed secrets detection via exact_values
- Short secret rejection (< 8 chars)
- Multi-match scanning
- Embedded secrets in JSON/YAML-like text
- Case variations in api_key patterns
- Boundary conditions for pattern lengths
"""
from __future__ import annotations

import base64
from urllib.parse import quote

import pytest

from hermes_aegis.patterns.secrets import scan_for_secrets, PatternMatch


class TestBase64EdgeCases:
    """Tests for base64-encoded secret detection."""

    def test_detects_base64_encoded_exact_value(self):
        """Secret encoded in base64 should be detected via exact_values."""
        secret = "my-secret-api-token-xyz123"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"Authorization: Basic {encoded}"
        matches = scan_for_secrets(text, exact_values=[secret])
        names = [m.pattern_name for m in matches]
        assert "exact_match_base64" in names

    def test_base64_match_points_to_correct_span(self):
        """PatternMatch span should correctly reference the base64 substring."""
        secret = "very-secret-password-abc9"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"data={encoded}&other=stuff"
        matches = scan_for_secrets(text, exact_values=[secret])
        b64_matches = [m for m in matches if m.pattern_name == "exact_match_base64"]
        assert len(b64_matches) > 0
        m = b64_matches[0]
        assert text[m.start:m.end] == encoded

    def test_base64_not_triggered_for_short_secret(self):
        """Secrets shorter than 8 chars should be ignored entirely."""
        secret = "tiny"  # < 8 chars
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"header={encoded}"
        matches = scan_for_secrets(text, exact_values=[secret])
        assert len(matches) == 0

    def test_base64_not_triggered_when_not_present(self):
        """No match if the base64-encoded form is absent from text."""
        secret = "not-in-base64-form-abc12"
        text = "plain text without any encoded values here"
        matches = scan_for_secrets(text, exact_values=[secret])
        assert len(matches) == 0

    def test_multiple_base64_occurrences(self):
        """All occurrences of base64-encoded secret should be found."""
        secret = "repeat-secret-token-xyz9"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"{encoded} and then {encoded} again"
        matches = scan_for_secrets(text, exact_values=[secret])
        b64_matches = [m for m in matches if m.pattern_name == "exact_match_base64"]
        assert len(b64_matches) == 2


class TestURLEncodingEdgeCases:
    """Tests for URL-encoded secret detection."""

    def test_detects_url_encoded_secret(self):
        """Secret with special chars URL-encoded should be detected."""
        secret = "my/secret+token=value&xyz"
        url_encoded = quote(secret)
        assert url_encoded != secret  # must actually change
        text = f"https://api.example.com/auth?key={url_encoded}"
        matches = scan_for_secrets(text, exact_values=[secret])
        names = [m.pattern_name for m in matches]
        assert "exact_match_urlencoded" in names

    def test_no_url_match_when_no_special_chars(self):
        """Plain alphanumeric secrets produce no extra url_encoded match."""
        secret = "alreadycleantoken12345678"
        # URL-encode of a plain secret equals itself — no url-encoded variant match
        url_encoded = quote(secret)
        assert url_encoded == secret
        text = f"token={secret}"
        matches = scan_for_secrets(text, exact_values=[secret])
        # Should get exact_match but NOT exact_match_urlencoded
        urlenc_matches = [m for m in matches if m.pattern_name == "exact_match_urlencoded"]
        assert len(urlenc_matches) == 0

    def test_url_encoded_match_span_is_correct(self):
        """Span of url_encoded match should reference the encoded substring."""
        secret = "pass/word+val=123&extra"
        url_encoded = quote(secret)
        text = f"query={url_encoded}&other=1"
        matches = scan_for_secrets(text, exact_values=[secret])
        urlenc_matches = [m for m in matches if m.pattern_name == "exact_match_urlencoded"]
        assert len(urlenc_matches) > 0
        m = urlenc_matches[0]
        assert text[m.start:m.end] == url_encoded


class TestHexEncodingEdgeCases:
    """Tests for hex-encoded secret detection."""

    def test_detects_hex_encoded_secret(self):
        """Secret encoded as hex string should be detected."""
        secret = "my-hex-secret-token-abcd"
        hex_val = secret.encode().hex()
        text = f"raw_key={hex_val}"
        matches = scan_for_secrets(text, exact_values=[secret])
        names = [m.pattern_name for m in matches]
        assert "exact_match_hex" in names

    def test_hex_match_span_correct(self):
        """Hex match span should correctly reference the hex substring."""
        secret = "another-secret-token-1234"
        hex_val = secret.encode().hex()
        text = f"prefix_{hex_val}_suffix"
        matches = scan_for_secrets(text, exact_values=[secret])
        hex_matches = [m for m in matches if m.pattern_name == "exact_match_hex"]
        assert len(hex_matches) > 0
        m = hex_matches[0]
        assert text[m.start:m.end] == hex_val


class TestReversedSecretEdgeCases:
    """Tests for reversed secret detection."""

    def test_detects_reversed_secret(self):
        """Reversed secret should be detected via exact_match_reversed."""
        secret = "forward-secret-value-xyz9"
        reversed_val = secret[::-1]
        text = f"encoded={reversed_val}"
        matches = scan_for_secrets(text, exact_values=[secret])
        names = [m.pattern_name for m in matches]
        assert "exact_match_reversed" in names

    def test_reversed_match_span_correct(self):
        """Reversed match span should reference the reversed substring."""
        secret = "reverse-me-token-abcde123"
        reversed_val = secret[::-1]
        text = f"data={reversed_val}&end"
        matches = scan_for_secrets(text, exact_values=[secret])
        rev_matches = [m for m in matches if m.pattern_name == "exact_match_reversed"]
        assert len(rev_matches) > 0
        m = rev_matches[0]
        assert text[m.start:m.end] == reversed_val


class TestExactMatchEdgeCases:
    """Tests for direct exact_values matching."""

    def test_exact_match_found_inline(self):
        """Secret appearing verbatim should be found as exact_match."""
        secret = "verbatim-secret-abc123xyz"
        text = f"config = '{secret}'"
        matches = scan_for_secrets(text, exact_values=[secret])
        exact = [m for m in matches if m.pattern_name == "exact_match"]
        assert len(exact) == 1
        assert exact[0].matched_text == secret

    def test_multiple_secrets_in_exact_values(self):
        """Multiple secrets in exact_values should each be found."""
        s1 = "first-secret-alpha-12345"
        s2 = "second-secret-beta-67890"
        text = f"token1={s1} token2={s2}"
        matches = scan_for_secrets(text, exact_values=[s1, s2])
        found = {m.matched_text for m in matches if m.pattern_name == "exact_match"}
        assert s1 in found
        assert s2 in found

    def test_secret_boundary_exactly_8_chars(self):
        """Secret of exactly 8 chars (minimum) should still be scanned."""
        secret = "ab1cd2ef"  # exactly 8 chars
        text = f"pass={secret}"
        matches = scan_for_secrets(text, exact_values=[secret])
        exact = [m for m in matches if m.pattern_name == "exact_match"]
        assert len(exact) == 1

    def test_secret_7_chars_rejected(self):
        """Secret of 7 chars should be ignored (below minimum threshold)."""
        secret = "tooshrt"  # 7 chars
        text = f"pass={secret}"
        matches = scan_for_secrets(text, exact_values=[secret])
        assert len(matches) == 0

    def test_no_exact_values_returns_only_pattern_matches(self):
        """Without exact_values, only pattern-based matches are returned."""
        text = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        matches = scan_for_secrets(text)
        assert all(m.pattern_name != "exact_match" for m in matches)

    def test_empty_text_returns_no_matches(self):
        """Empty string produces no matches."""
        matches = scan_for_secrets("", exact_values=["some-secret-value-12"])
        assert matches == []

    def test_none_exact_values_treated_as_empty(self):
        """None exact_values should not raise and only return pattern matches."""
        text = "normal text with no secrets"
        matches = scan_for_secrets(text, exact_values=None)
        assert isinstance(matches, list)


class TestPatternMatchDataclass:
    """Tests for the PatternMatch dataclass structure."""

    def test_pattern_match_fields(self):
        """PatternMatch should have required fields with correct types."""
        m = PatternMatch(
            pattern_name="test_pattern",
            matched_text="some-value",
            start=5,
            end=15,
        )
        assert m.pattern_name == "test_pattern"
        assert m.matched_text == "some-value"
        assert m.start == 5
        assert m.end == 15

    def test_scan_returns_list_of_pattern_match(self):
        """scan_for_secrets should return a list of PatternMatch instances."""
        text = "sk-abcdefghijklmnopqrstuvwxyz12345678"
        matches = scan_for_secrets(text)
        for m in matches:
            assert isinstance(m, PatternMatch)


class TestCombinedPatternAndExactMatches:
    """Tests combining regex pattern matches with exact_values."""

    def test_regex_and_exact_both_fire(self):
        """Both pattern-based and exact-match results returned in one call."""
        secret = "my-literal-token-xyz12345"
        # Also include an openai-style key that triggers pattern match
        text = f"key=sk-proj-ABCDE12345fghijklmnopqrstuvwxyz {secret}"
        matches = scan_for_secrets(text, exact_values=[secret])
        pattern_hits = [m for m in matches if m.pattern_name != "exact_match"]
        exact_hits = [m for m in matches if m.pattern_name == "exact_match"]
        assert len(pattern_hits) > 0
        assert len(exact_hits) > 0

    def test_embedded_secret_in_json(self):
        """Secret embedded in JSON-like text is detected correctly."""
        secret = "json-secret-token-abc99xyz"
        text = f'{{"api_key": "{secret}", "other": "value"}}'
        matches = scan_for_secrets(text, exact_values=[secret])
        exact = [m for m in matches if m.pattern_name == "exact_match"]
        assert len(exact) >= 1

    def test_secret_in_url_query_string(self):
        """Secret appearing in URL query string detected via exact_match."""
        secret = "url-query-secret-abc123de"
        text = f"https://api.example.com/resource?token={secret}&format=json"
        matches = scan_for_secrets(text, exact_values=[secret])
        exact = [m for m in matches if m.pattern_name == "exact_match"]
        assert len(exact) == 1
