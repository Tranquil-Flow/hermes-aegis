# hermes-aegis/src/hermes_aegis/vault/migrate.py
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from hermes_aegis.vault.store import VaultStore


@dataclass
class MigrationResult:
    migrated_count: int
    skipped_keys: list[str]


@dataclass
class DiscoveredSecret:
    """A secret found during discovery scan."""
    key_name: str
    value: str
    source: str  # "env", "hermes_config", "dotenv"
    preview: str  # First 8 chars + ellipsis for display


def discover_secrets() -> list[DiscoveredSecret]:
    """Scan environment and Hermes config for API keys to import.
    
    Returns list of discovered secrets with their sources.
    """
    discovered = []
    
    # Known API key names to look for
    key_names = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GROQ_API_KEY",
        "TOGETHER_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "ALCHEMY_API_KEY",
        "INFURA_API_KEY",
    ]
    
    # 1. Scan environment variables
    for key_name in key_names:
        value = os.getenv(key_name)
        if value:
            discovered.append(DiscoveredSecret(
                key_name=key_name,
                value=value,
                source="env",
                preview=f"{value[:8]}..." if len(value) > 8 else value
            ))
    
    # 2. Scan ~/.hermes/config.yaml (if exists)
    hermes_config = Path.home() / ".hermes" / "config.yaml"
    if hermes_config.exists():
        try:
            import yaml
            config = yaml.safe_load(hermes_config.read_text())
            if config:
                # Look for keys in common locations
                for key_name in key_names:
                    # Check top-level
                    if key_name.lower() in config:
                        value = config[key_name.lower()]
                        if value:
                            discovered.append(DiscoveredSecret(
                                key_name=key_name,
                                value=str(value),
                                source="hermes_config",
                                preview=f"{str(value)[:8]}..." if len(str(value)) > 8 else str(value)
                            ))
                    # Check api_keys section
                    if "api_keys" in config and key_name in config["api_keys"]:
                        value = config["api_keys"][key_name]
                        if value:
                            discovered.append(DiscoveredSecret(
                                key_name=key_name,
                                value=str(value),
                                source="hermes_config",
                                preview=f"{str(value)[:8]}..." if len(str(value)) > 8 else str(value)
                            ))
        except Exception:
            # Ignore YAML parsing errors
            pass
    
    # 3. Scan ~/.hermes/.env (if exists)
    hermes_env = Path.home() / ".hermes" / ".env"
    if hermes_env.exists():
        try:
            for line in hermes_env.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key in key_names and value:
                    discovered.append(DiscoveredSecret(
                        key_name=key,
                        value=value,
                        source="dotenv",
                        preview=f"{value[:8]}..." if len(value) > 8 else value
                    ))
        except Exception:
            pass
    
    # Deduplicate by key_name (prefer env > hermes_config > dotenv)
    seen = {}
    priority = {"env": 0, "hermes_config": 1, "dotenv": 2}
    for secret in discovered:
        if secret.key_name not in seen or priority[secret.source] < priority[seen[secret.key_name].source]:
            seen[secret.key_name] = secret
    
    return list(seen.values())


def import_discovered_secrets(
    secrets: list[DiscoveredSecret],
    vault_path: Path,
    master_key: bytes,
) -> MigrationResult:
    """Import discovered secrets into vault.
    
    Args:
        secrets: List of secrets to import
        vault_path: Path to vault file
        master_key: Master encryption key
    
    Returns:
        MigrationResult with count of imported secrets
    """
    vault = VaultStore(vault_path, master_key)
    count = 0
    
    for secret in secrets:
        vault.set(secret.key_name, secret.value)
        count += 1
    
    return MigrationResult(migrated_count=count, skipped_keys=[])


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
