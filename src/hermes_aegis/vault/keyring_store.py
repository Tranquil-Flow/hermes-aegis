from __future__ import annotations

import keyring
from cryptography.fernet import Fernet

SERVICE_NAME = "hermes-aegis"
KEY_NAME = "master-key"


def get_or_create_master_key() -> bytes:
    """Retrieve master key from OS keyring, or generate and store one.
    
    NOTE: In headless environments (SSH, Docker build, etc.) where keyring
    is unavailable, this will raise an error. For production, consider adding
    a fallback to file-based key storage with appropriate warnings.
    """
    try:
        existing = keyring.get_password(SERVICE_NAME, KEY_NAME)
        if existing:
            return existing.encode()
        new_key = Fernet.generate_key()
        keyring.set_password(SERVICE_NAME, KEY_NAME, new_key.decode())
        return new_key
    except keyring.errors.KeyringError as e:
        # Keyring unavailable (headless, SSH, etc.)
        raise RuntimeError(
            "OS keyring is unavailable. hermes-aegis requires keyring access "
            "to store the master encryption key securely. "
            "This can happen in headless/SSH environments. "
            "Workaround: Run setup locally and copy the vault to the server."
        ) from e
