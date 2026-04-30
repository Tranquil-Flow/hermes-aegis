"""Private keys detector — RSA, EC, DSA, OpenSSH, PGP private key blocks."""
from __future__ import annotations

import re

from hermes_aegis.detectors.base import Detector, DetectorMatch

_PRIVATE_KEY_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # RSA private key
    ("rsa_private_key",
     re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
     "critical"),
    # EC private key
    ("ec_private_key",
     re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
     "critical"),
    # DSA private key
    ("dsa_private_key",
     re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
     "critical"),
    # OpenSSH private key
    ("openssh_private_key",
     re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
     "critical"),
    # Generic PKCS#8 private key (no algorithm prefix)
    ("pkcs8_private_key",
     re.compile(r"-----BEGIN PRIVATE KEY-----"),
     "critical"),
    # PGP private key block
    ("pgp_private_key",
     re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
     "critical"),
    # PuTTY private key
    ("putty_private_key",
     re.compile(r"PuTTY-User-Key-File-\d"),
     "critical"),
    # Encrypted private key
    ("encrypted_private_key",
     re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
     "critical"),
]

# Patterns we explicitly do NOT flag as private keys
_EXCLUDE_PATTERNS = [
    re.compile(r"-----BEGIN PUBLIC KEY-----"),
    re.compile(r"-----BEGIN CERTIFICATE-----"),
    re.compile(r"-----BEGIN CERTIFICATE REQUEST-----"),
    re.compile(r"-----BEGIN X509 CERTIFICATE-----"),
]


class PrivateKeysDetector(Detector):
    """Detects private key blocks in various formats."""

    def __init__(self) -> None:
        super().__init__(
            name="private_keys",
            description="Private key blocks: RSA, EC, DSA, OpenSSH, PGP, PuTTY, PKCS#8",
        )

    def scan(self, text: str) -> list[DetectorMatch]:
        matches: list[DetectorMatch] = []

        # Check for exclusion patterns first — if a line is a public key/cert, skip
        excluded_spans: set[tuple[int, int]] = set()
        for ex_pattern in _EXCLUDE_PATTERNS:
            for m in ex_pattern.finditer(text):
                excluded_spans.add((m.start(), m.end()))

        for pattern_name, pattern, severity in _PRIVATE_KEY_PATTERNS:
            for m in pattern.finditer(text):
                # Only flag if this match doesn't overlap with an exclusion
                overlap = any(
                    m.start() < ex_end and m.end() > ex_start
                    for ex_start, ex_end in excluded_spans
                )
                if not overlap:
                    matches.append(DetectorMatch(
                        detector_name=self.name,
                        pattern_name=pattern_name,
                        matched_text=m.group(),
                        start=m.start(),
                        end=m.end(),
                        severity=severity,
                    ))
        return matches
