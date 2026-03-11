# hermes-aegis/src/hermes_aegis/patterns/crypto.py
from __future__ import annotations

import re
from dataclasses import dataclass

from hermes_aegis.patterns.secrets import PatternMatch

# BIP39 first 20 words for seed phrase detection (sample — full list at runtime)
BIP39_SAMPLE_WORDS = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account",
    "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
}

# Named constants for direct use in tests and middleware
SSH_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
PEM_PRIVATE_KEY = re.compile(r"-----BEGIN PRIVATE KEY-----")
PEM_PUBLIC_KEY = re.compile(r"-----BEGIN PUBLIC KEY-----")

CRYPTO_PATTERNS = [
    # Ethereum/EVM + Substrate SR25519: 0x + 64 hex chars (private key)
    ("ethereum_or_substrate_private_key", re.compile(r"0x[0-9a-fA-F]{64}(?![0-9a-fA-F])")),
    # Bitcoin WIF: starts with 5, K, or L + base58 chars (51 chars for uncompressed, 52 for compressed)
    ("bitcoin_wif", re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![1-9A-HJ-NP-Za-km-z])")),
    # BIP32 extended private key
    ("bip32_xprv", re.compile(r"xprv[1-9A-HJ-NP-Za-km-z]{107,108}")),
    # Solana: base58 ed25519 key (64 bytes = ~87 base58 chars, anchored to avoid false positives)
    ("solana_private_key", re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{87,88}(?![1-9A-HJ-NP-Za-km-z])")),
]


def _detect_bip39_seed_phrase(text: str) -> list[PatternMatch]:
    """Detect BIP39 seed phrases (12 or 24 word sequences from wordlist)."""
    lower = text.lower()
    # Build word positions for accurate start/end calculation
    word_positions: list[tuple[str, int]] = []
    i = 0
    for word in lower.split():
        idx = lower.find(word, i)
        word_positions.append((word, idx))
        i = idx + len(word)

    matches = []
    words = [w for w, _ in word_positions]
    for length in (12, 24):
        if len(words) < length:
            continue
        for i in range(len(words) - length + 1):
            candidate = words[i:i + length]
            bip39_count = sum(1 for w in candidate if w in BIP39_SAMPLE_WORDS)
            if bip39_count >= length * 0.5:
                start = word_positions[i][1]
                end_word_idx = i + length - 1
                end = word_positions[end_word_idx][1] + len(words[end_word_idx])
                matches.append(PatternMatch(
                    pattern_name="bip39_seed_phrase",
                    matched_text=lower[start:end],
                    start=start,
                    end=end,
                ))
    return matches


def scan_for_crypto_keys(text: str) -> list[PatternMatch]:
    """Scan text for cryptocurrency private key patterns."""
    matches: list[PatternMatch] = []

    for name, pattern in CRYPTO_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(PatternMatch(
                pattern_name=name,
                matched_text=m.group(),
                start=m.start(),
                end=m.end(),
            ))

    matches.extend(_detect_bip39_seed_phrase(text))

    return matches
