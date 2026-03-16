# hermes-aegis/src/hermes_aegis/vault/store.py
from __future__ import annotations

import json
from pathlib import Path

from cryptography.fernet import Fernet

VAULT_LOCK_FILE = Path.home() / ".hermes-aegis" / "vault.lock"


def is_vault_locked() -> bool:
    """Check if the vault is locked by a circuit breaker sentinel.

    The circuit breaker locks the vault when anomalies (e.g., rate escalation)
    are detected, preventing further access to credentials until manually unlocked.

    Returns:
        True if a lock sentinel file exists, False otherwise.
    """
    return VAULT_LOCK_FILE.exists()


def unlock_vault() -> bool:
    """Remove the vault lock sentinel, allowing credential access to resume.

    The circuit breaker can automatically lock the vault on security anomalies.
    This function allows manual unlocking after the threat is resolved.

    Returns:
        True if a lock file existed and was removed, False if no lock was present.
    """
    if VAULT_LOCK_FILE.exists():
        VAULT_LOCK_FILE.unlink()
        return True
    return False


class VaultStore:
    """Fernet-encrypted key-value secret storage.

    Secrets are encrypted individually. The vault file is a JSON dict
    of {key: encrypted_value_b64}. No bulk export or enumeration of
    values is exposed — only keys can be listed.
    """

    def __init__(self, path: Path, master_key: bytes) -> None:
        self._path = Path(path)
        self._fernet = Fernet(master_key)
        self._data: dict[str, str] = {}
        if self._path.exists():
            raw = json.loads(self._path.read_text())
            self._data = raw

    def get(self, key: str) -> str | None:
        """Retrieve and decrypt a value from the vault.

        Args:
            key: The secret key name to retrieve.

        Returns:
            The decrypted secret value, or None if the key does not exist.

        Raises:
            RuntimeError: If the vault is locked by the circuit breaker.
        """
        if is_vault_locked():
            raise RuntimeError(
                "Vault is locked by circuit breaker. "
                "Unlock with: hermes-aegis vault unlock"
            )
        encrypted = self._data.get(key)
        if encrypted is None:
            return None
        return self._fernet.decrypt(encrypted.encode()).decode()

    def set(self, key: str, value: str) -> None:
        """Encrypt and store a value in the vault.

        Args:
            key: The secret key name to store under.
            value: The plaintext secret value to encrypt and store.
        """
        self._data[key] = self._fernet.encrypt(value.encode()).decode()
        self._save()

    def remove(self, key: str) -> None:
        """Remove a key-value pair from the vault.

        Args:
            key: The secret key name to remove. Does nothing if the key doesn't exist.
        """
        self._data.pop(key, None)
        self._save()

    def list_keys(self) -> list[str]:
        """Return a list of all key names stored in the vault.

        Returns:
            A list of string key names. Values are not exposed.
        """
        return list(self._data.keys())

    def get_all_values(self) -> list[str]:
        """Return all decrypted values for content scanning.
        Internal API — used by scanner, NOT exposed to tools.
        """
        if is_vault_locked():
            raise RuntimeError(
                "Vault is locked by circuit breaker. "
                "Unlock with: hermes-aegis vault unlock"
            )
        return [
            self._fernet.decrypt(v.encode()).decode()
            for v in self._data.values()
        ]

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data))
        tmp.replace(self._path)  # atomic on POSIX; safe against mid-write corruption
