"""API key detector — OpenAI, Anthropic, GitHub, generic bearer/API key, RPC URLs."""
from __future__ import annotations

import re

from hermes_aegis.detectors.base import Detector, DetectorMatch

# Patterns ported from patterns/secrets.py SECRET_PATTERNS (api-key category)
_API_KEY_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("openai_api_key",
     re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
     "high"),
    ("anthropic_api_key",
     re.compile(r"sk-ant-(?:api\d+-)?[A-Za-z0-9_-]{20,}"),
     "high"),
    ("github_token",
     re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
     "high"),
    ("generic_bearer",
     re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
     "medium"),
    ("generic_api_key",
     re.compile(
         r"(?:api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*[A-Za-z0-9_\-]{20,}",
         re.IGNORECASE,
     ),
     "medium"),
    ("rpc_url_with_key",
     re.compile(
         r"https?://(?:eth-mainnet\.g\.alchemy\.com/v2|mainnet\.infura\.io/v3|"
         r"[a-z-]+\.quiknode\.pro)/[A-Za-z0-9_-]{20,}"
     ),
     "high"),
]


class ApiKeysDetector(Detector):
    """Detects API keys, bearer tokens, and RPC URLs with embedded keys."""

    def __init__(self) -> None:
        super().__init__(
            name="api_keys",
            description="API key patterns: OpenAI, Anthropic, GitHub, generic bearer, RPC URLs",
        )

    def scan(self, text: str) -> list[DetectorMatch]:
        matches: list[DetectorMatch] = []
        for pattern_name, pattern, severity in _API_KEY_PATTERNS:
            for m in pattern.finditer(text):
                matches.append(DetectorMatch(
                    detector_name=self.name,
                    pattern_name=pattern_name,
                    matched_text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    severity=severity,
                ))
        return matches
