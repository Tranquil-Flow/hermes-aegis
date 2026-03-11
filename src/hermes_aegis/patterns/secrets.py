# hermes-aegis/src/hermes_aegis/patterns/secrets.py
from __future__ import annotations

import base64
import re
from dataclasses import dataclass


@dataclass
class PatternMatch:
    pattern_name: str
    matched_text: str
    start: int
    end: int


# Named constants for direct use in tests and middleware
AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
GITHUB_TOKEN = re.compile(r"ghp_[A-Za-z0-9_]{34,}")
JWT = re.compile(r"[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
DB_CREDENTIALS = re.compile(r"(?:password|passwd|pwd)\s*=\s*\S+", re.IGNORECASE)
GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_-]{35,}")
SLACK_TOKEN = re.compile(r"xox[bpsa]-[0-9A-Za-z-]{10,}")
TWITTER_API_KEY = re.compile(r"[0-9a-f]{32}")

SECRET_PATTERNS = [
    ("openai_api_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("anthropic_api_key", re.compile(r"sk-ant-(?:api\d+-)?[A-Za-z0-9_-]{20,}")),
    ("aws_secret_key", re.compile(r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}")),
    ("aws_secret_value", re.compile(r"(?<=AWS_SECRET_ACCESS_KEY[=:\s])[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("generic_bearer", re.compile(r"Bearer\s+[A-Za-z0-9_\-.]{20,}")),
    ("generic_api_key", re.compile(r"(?:api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*[A-Za-z0-9_\-]{20,}", re.IGNORECASE)),
]


def scan_for_secrets(
    text: str,
    exact_values: list[str] | None = None,
) -> list[PatternMatch]:
    """Scan text for secret patterns and exact vault value matches."""
    matches: list[PatternMatch] = []

    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(PatternMatch(
                pattern_name=name,
                matched_text=m.group(),
                start=m.start(),
                end=m.end(),
            ))

    if exact_values:
        for val in exact_values:
            if len(val) < 8:
                continue
            # Plain text match
            idx = text.find(val)
            if idx != -1:
                matches.append(PatternMatch(
                    pattern_name="exact_match",
                    matched_text=val,
                    start=idx,
                    end=idx + len(val),
                ))
            # Base64 encoded match
            b64_val = base64.b64encode(val.encode()).decode()
            idx = text.find(b64_val)
            if idx != -1:
                matches.append(PatternMatch(
                    pattern_name="exact_match_base64",
                    matched_text=b64_val,
                    start=idx,
                    end=idx + len(b64_val),
                ))
            # URL encoded match
            from urllib.parse import quote
            url_val = quote(val)
            if url_val != val:
                idx = text.find(url_val)
                if idx != -1:
                    matches.append(PatternMatch(
                        pattern_name="exact_match_urlencoded",
                        matched_text=url_val,
                        start=idx,
                        end=idx + len(url_val),
                    ))
            # Hex encoded match
            hex_val = val.encode().hex()
            idx = text.find(hex_val)
            if idx != -1:
                matches.append(PatternMatch(
                    pattern_name="exact_match_hex",
                    matched_text=hex_val,
                    start=idx,
                    end=idx + len(hex_val),
                ))
            # Reversed match
            rev_val = val[::-1]
            idx = text.find(rev_val)
            if idx != -1:
                matches.append(PatternMatch(
                    pattern_name="exact_match_reversed",
                    matched_text=rev_val,
                    start=idx,
                    end=idx + len(rev_val),
                ))

    return matches
