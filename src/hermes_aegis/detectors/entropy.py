"""Entropy detector — flags high-entropy strings likely to be secrets.

This is a Layer 1 (catch-all) detector. It catches tokens that don't match
any known format but have Shannon entropy above a threshold, suggesting
they are randomly generated secrets or API keys.

Algorithm:
1. Split text into candidate tokens (sequences of base64url-safe chars, hex,
   or alphanumeric) that are >= min_length chars long.
2. Compute Shannon entropy per candidate.
3. Flag candidates above the entropy threshold.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from hermes_aegis.detectors.base import Detector, DetectorMatch

# Minimum length to consider — shorter strings have unreliable entropy
_DEFAULT_MIN_LENGTH = 20

# Shannon entropy threshold (bits per character).
# Base64-encoded 20-byte random ≈ 4.0 bits/char
# English text ≈ 3.5-4.5 but with lots of repetition
# Pure random hex ≈ 4.0 bits/char
_DEFAULT_ENTROPY_THRESHOLD = 3.8

# Token extraction patterns: long runs of base64url-safe or hex chars
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

# Ignore tokens that look like known patterns (these are caught by specific detectors)
_SKIP_PREFIXES = (
    "sk-", "sk-ant-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "-----BEGIN ", "Bearer ",
)


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of *s*."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_likely_repetitive(s: str) -> bool:
    """Reject strings that are mostly repeated characters."""
    counts = Counter(s)
    if len(counts) <= 3:
        return True
    most_common = counts.most_common(1)[0][1]
    return most_common > len(s) * 0.5


class EntropyDetector(Detector):
    """Flags high-entropy strings likely to be secrets.

    Args:
        min_length: Minimum candidate token length (default 20).
        entropy_threshold: Shannon entropy threshold in bits/char (default 3.8).
    """

    def __init__(
        self,
        min_length: int = _DEFAULT_MIN_LENGTH,
        entropy_threshold: float = _DEFAULT_ENTROPY_THRESHOLD,
    ) -> None:
        super().__init__(
            name="entropy",
            description="High-entropy string detection (catch-all for unknown secret formats)",
        )
        self._min_length = min_length
        self._entropy_threshold = entropy_threshold

    def scan(self, text: str) -> list[DetectorMatch]:
        matches: list[DetectorMatch] = []

        for m in _CANDIDATE_RE.finditer(text):
            candidate = m.group()

            # Skip if too short
            if len(candidate) < self._min_length:
                continue

            # Skip known prefixes (handled by specific detectors)
            if any(candidate.startswith(prefix) for prefix in _SKIP_PREFIXES):
                continue

            # Skip repetitive strings
            if _is_likely_repetitive(candidate):
                continue

            entropy = _shannon_entropy(candidate)
            if entropy >= self._entropy_threshold:
                matches.append(DetectorMatch(
                    detector_name=self.name,
                    pattern_name="high_entropy_string",
                    matched_text=candidate,
                    start=m.start(),
                    end=m.end(),
                    severity="low",
                ))

        return matches
