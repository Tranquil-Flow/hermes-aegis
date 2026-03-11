# hermes-aegis/tests/test_vault.py
import os
import tempfile

import pytest

from hermes_aegis.vault.store import VaultStore


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.enc"


@pytest.fixture
def master_key():
    from cryptography.fernet import Fernet
    return Fernet.generate_key()


class TestVaultStore:
    def test_set_and_get(self, vault_path, master_key):
        vault = VaultStore(vault_path, master_key)
        vault.set("API_KEY", "***")
        assert vault.get("API_KEY") == "***"

    def test_get_missing_key_returns_none(self, vault_path, master_key):
        vault = VaultStore(vault_path, master_key)
        assert vault.get("NONEXISTENT") is None

    def test_persistence_across_instances(self, vault_path, master_key):
        vault1 = VaultStore(vault_path, master_key)
        vault1.set("TOKEN", "abc123")
        vault2 = VaultStore(vault_path, master_key)
        assert vault2.get("TOKEN") == "abc123"

    def test_list_keys_no_values(self, vault_path, master_key):
        vault = VaultStore(vault_path, master_key)
        vault.set("KEY_A", "secret_a")
        vault.set("KEY_B", "secret_b")
        keys = vault.list_keys()
        assert set(keys) == {"KEY_A", "KEY_B"}

    def test_remove_key(self, vault_path, master_key):
        vault = VaultStore(vault_path, master_key)
        vault.set("TEMP", "value")
        vault.remove("TEMP")
        assert vault.get("TEMP") is None

    def test_wrong_key_raises(self, vault_path, master_key):
        from cryptography.fernet import Fernet
        vault = VaultStore(vault_path, master_key)
        vault.set("SECRET", "data")
        wrong_key = Fernet.generate_key()
        vault2 = VaultStore(vault_path, wrong_key)
        with pytest.raises(Exception):
            vault2.get("SECRET")

    def test_no_bulk_export(self, vault_path, master_key):
        vault = VaultStore(vault_path, master_key)
        assert not hasattr(vault, "get_all")
        assert not hasattr(vault, "export")
        assert not hasattr(vault, "dump")

    def test_vault_values_returns_all_for_scanning(self, vault_path, master_key):
        vault = VaultStore(vault_path, master_key)
        vault.set("A", "secret1")
        vault.set("B", "secret2")
        values = vault.get_all_values()
        assert set(values) == {"secret1", "secret2"}
