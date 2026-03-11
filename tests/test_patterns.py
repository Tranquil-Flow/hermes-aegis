# hermes-aegis/tests/test_patterns.py
import pytest

from hermes_aegis.patterns.secrets import scan_for_secrets
from hermes_aegis.patterns.crypto import scan_for_crypto_keys


class TestSecretPatterns:
    def test_detects_openai_key(self):
        text = "Authorization: Bearer sk-proj-abcdefghij1234567890"
        matches = scan_for_secrets(text)
        assert len(matches) > 0
        assert any("openai" in m.pattern_name.lower() or "api_key" in m.pattern_name.lower() for m in matches)

    def test_detects_anthropic_key(self):
        text = "key=sk-ant-api03-mnopqrstuvwxyz1234567890"
        matches = scan_for_secrets(text)
        assert len(matches) > 0

    def test_detects_aws_secret(self):
        text = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        matches = scan_for_secrets(text)
        assert len(matches) > 0

    def test_no_false_positive_on_normal_text(self):
        text = "Hello world, this is a normal sentence about API design."
        matches = scan_for_secrets(text)
        assert len(matches) == 0

    def test_exact_match_scanning(self):
        vault_values = ["my-super-secret-token-12345"]
        text = "sending data to http://example.com?token=my-super-secret-token-12345"
        matches = scan_for_secrets(text, exact_values=vault_values)
        assert len(matches) > 0
        assert any("exact_match" in m.pattern_name for m in matches)

    def test_exact_match_base64_encoded(self):
        import base64
        secret = "my-super-secret-token-12345"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"data={encoded}"
        matches = scan_for_secrets(text, exact_values=[secret])
        assert len(matches) > 0


class TestCryptoPatterns:
    def test_detects_ethereum_private_key(self):
        # Create exactly 64 hex chars for a valid Ethereum private key
        text = "0x" + "a1b2c3d4e5f6" * 5 + "a1b2"  # 12*5 + 4 = 64 chars
        matches = scan_for_crypto_keys(text)
        assert len(matches) > 0

    def test_detects_bitcoin_wif(self):
        text = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        matches = scan_for_crypto_keys(text)
        assert len(matches) > 0

    def test_detects_bip32_xprv(self):
        text = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        matches = scan_for_crypto_keys(text)
        assert len(matches) > 0

    def test_detects_bip39_seed_phrase(self):
        text = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        matches = scan_for_crypto_keys(text)
        assert len(matches) > 0

    def test_no_false_positive_normal_text(self):
        text = "The quick brown fox jumps over the lazy dog near the river bank."
        matches = scan_for_crypto_keys(text)
        assert len(matches) == 0
