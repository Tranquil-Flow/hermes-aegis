# hermes-aegis/src/hermes_aegis/vault/migrate.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hermes_aegis.vault.store import VaultStore


@dataclass
class MigrationResult:
    migrated_count: int
    skipped_keys: list[str]


def migrate_env_to_vault(
    env_path: Path,
    vault_path: Path,
    master_key: bytes,
    delete_original: bool = False,
) -> MigrationResult:
    """Migrate .env file secrets into encrypted vault."""
    env_path = Path(env_path)
    if not env_path.exists():
        return MigrationResult(migrated_count=0, skipped_keys=[])

    vault = VaultStore(vault_path, master_key)
    count = 0

    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        vault.set(key, value)
        count += 1

    if delete_original:
        # Best-effort secure delete: overwrite then remove
        size = env_path.stat().st_size
        env_path.write_bytes(b"\x00" * size)
        env_path.unlink()

    return MigrationResult(migrated_count=count, skipped_keys=[])
