# hermes-aegis/src/hermes_aegis/vault/store.py
from __future__ import annotations

import json
from pathlib import Path

from cryptography.fernet import Fernet


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
        encrypted = self._data.get(key)
        if encrypted is None:
            return None
        return self._fernet.decrypt(encrypted.encode()).decode()

    def set(self, key: str, value: str) -> None:
        self._data[key] = self._fernet.encrypt(value.encode()).decode()
        self._save()

    def remove(self, key: str) -> None:
        self._data.pop(key, None)
        self._save()

    def list_keys(self) -> list[str]:
        return list(self._data.keys())

    def get_all_values(self) -> list[str]:
        """Return all decrypted values for content scanning.
        Internal API — used by scanner, NOT exposed to tools.
        """
        return [
            self._fernet.decrypt(v.encode()).decode()
            for v in self._data.values()
        ]

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data))
        tmp.replace(self._path)  # atomic on POSIX; safe against mid-write corruption
