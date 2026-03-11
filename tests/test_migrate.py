# hermes-aegis/tests/test_migrate.py
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from hermes_aegis.vault.migrate import migrate_env_to_vault
from hermes_aegis.vault.store import VaultStore


@pytest.fixture
def env_file(tmp_path):
    p = tmp_path / ".env"
    p.write_text(
        "OPENAI_API_KEY=sk-test-key-123\n"
        "ANTHROPIC_API_KEY=sk-ant-test-456\n"
        "# This is a comment\n"
        "\n"
        "SOME_VAR=value with spaces\n"
    )
    return p


@pytest.fixture
def master_key():
    return Fernet.generate_key()


class TestMigration:
    def test_migrates_all_keys(self, tmp_path, env_file, master_key):
        vault_path = tmp_path / "vault.enc"
        result = migrate_env_to_vault(env_file, vault_path, master_key)
        vault = VaultStore(vault_path, master_key)
        assert vault.get("OPENAI_API_KEY") == "sk-test-key-123"
        assert vault.get("ANTHROPIC_API_KEY") == "sk-ant-test-456"
        assert vault.get("SOME_VAR") == "value with spaces"
        assert result.migrated_count == 3

    def test_skips_comments_and_blank_lines(self, tmp_path, env_file, master_key):
        vault_path = tmp_path / "vault.enc"
        result = migrate_env_to_vault(env_file, vault_path, master_key)
        vault = VaultStore(vault_path, master_key)
        assert result.migrated_count == 3

    def test_overwrites_original_with_best_effort(self, tmp_path, env_file, master_key):
        vault_path = tmp_path / "vault.enc"
        migrate_env_to_vault(env_file, vault_path, master_key, delete_original=True)
        assert not env_file.exists()

    def test_no_env_file_returns_zero(self, tmp_path, master_key):
        vault_path = tmp_path / "vault.enc"
        fake_env = tmp_path / "nonexistent.env"
        result = migrate_env_to_vault(fake_env, vault_path, master_key)
        assert result.migrated_count == 0
