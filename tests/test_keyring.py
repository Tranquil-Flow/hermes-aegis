from unittest.mock import patch, MagicMock

import pytest

from hermes_aegis.vault.keyring_store import get_or_create_master_key

SERVICE_NAME = "hermes-aegis"
KEY_NAME = "master-key"


class TestKeyring:
    @patch("hermes_aegis.vault.keyring_store.keyring")
    def test_returns_existing_key(self, mock_kr):
        mock_kr.get_password.return_value = "dGVzdGtleTE2Ynl0ZXM="
        key = get_or_create_master_key()
        mock_kr.get_password.assert_called_once_with(SERVICE_NAME, KEY_NAME)
        assert key == b"dGVzdGtleTE2Ynl0ZXM="

    @patch("hermes_aegis.vault.keyring_store.keyring")
    def test_creates_new_key_if_missing(self, mock_kr):
        mock_kr.get_password.return_value = None
        key = get_or_create_master_key()
        mock_kr.set_password.assert_called_once()
        assert key is not None
        # Verify it's a valid Fernet key
        from cryptography.fernet import Fernet
        Fernet(key)  # Should not raise
