"""Tests for the v0.3.0 Anthropic-OAuth credential coupling fixes.

Background: storing an Anthropic OAuth token (sk-ant-oat01-*) in the aegis
vault or ~/.hermes/.env causes hermes-agent to register a priority-0
env-sourced credential that can never be refreshed. Once the token rotates,
every Anthropic call 401s with "Invalid bearer token" — even though a healthy
claude_code OAuth credential with a refresh token sits at priority 1.

These tests cover the three coordinated fixes:
  1. `vault set` refuses OAuth tokens (with --allow-oauth escape hatch)
  2. `_sync_vault_to_env()` skips _NEVER_INJECT_ENV keys and scrubs
     pre-existing OAuth lines from .env
  3. `_refresh_hermes_auth()` walks credential_pool.anthropic when
     providers.nous.agent_key is unavailable
  4. `vault doctor` diagnoses + heals the stale-OAuth state
"""
import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from cryptography.fernet import Fernet

from hermes_aegis.cli import main, _is_anthropic_oauth_token


_OAUTH_ACCESS = "sk-ant-oat01-" + "A" * 100
_OAUTH_REFRESH = "sk-ant-ort01-" + "B" * 100
_API_KEY = "sk-ant-api03-" + "C" * 80
_NOUS_PORTAL_KEY = "sk-nous-" + "D" * 32


def _fernet_key() -> bytes:
    """Generate a valid Fernet master key for VaultStore tests."""
    return Fernet.generate_key()


class TestOAuthDetection:
    def test_detects_access_token(self):
        assert _is_anthropic_oauth_token(_OAUTH_ACCESS) is True

    def test_detects_refresh_token(self):
        assert _is_anthropic_oauth_token(_OAUTH_REFRESH) is True

    def test_does_not_flag_api_key(self):
        assert _is_anthropic_oauth_token(_API_KEY) is False

    def test_does_not_flag_random_string(self):
        assert _is_anthropic_oauth_token("ZAI_API_KEY_xxxx") is False

    def test_handles_non_string(self):
        assert _is_anthropic_oauth_token(None) is False  # type: ignore[arg-type]
        assert _is_anthropic_oauth_token(b"sk-ant-oat01-x") is False  # type: ignore[arg-type]

    def test_handles_leading_whitespace(self):
        assert _is_anthropic_oauth_token("  " + _OAUTH_ACCESS) is True


class TestVaultSetGuard:
    """vault set must refuse OAuth tokens unless --allow-oauth is given."""

    def _setup_vault(self, tmp_path):
        vault_path = tmp_path / "vault.enc"
        return vault_path

    def test_vault_set_rejects_oauth_access_token(self, tmp_path):
        vault_path = self._setup_vault(tmp_path)
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["vault", "set", "ANTHROPIC_TOKEN", "--value", _OAUTH_ACCESS]
            )
        assert result.exit_code == 2, result.output
        assert "Refusing to store" in result.output
        assert "hermes model" in result.output

    def test_vault_set_rejects_oauth_refresh_token(self, tmp_path):
        vault_path = self._setup_vault(tmp_path)
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path):
            runner = CliRunner()
            result = runner.invoke(
                main, ["vault", "set", "ANTHROPIC_TOKEN", "--value", _OAUTH_REFRESH]
            )
        assert result.exit_code == 2, result.output
        assert "Refusing to store" in result.output

    def test_vault_set_allows_api_key(self, tmp_path):
        vault_path = self._setup_vault(tmp_path)
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli._restart_proxy_if_running"):
            runner = CliRunner()
            result = runner.invoke(
                main, ["vault", "set", "ANTHROPIC_API_KEY", "--value", _API_KEY]
            )
        assert result.exit_code == 0, result.output
        assert "saved" in result.output

    def test_vault_set_allow_oauth_flag_overrides(self, tmp_path):
        vault_path = self._setup_vault(tmp_path)
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli._restart_proxy_if_running"):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "vault", "set", "ANTHROPIC_TOKEN",
                    "--value", _OAUTH_ACCESS, "--allow-oauth",
                ],
            )
        assert result.exit_code == 0, result.output


class TestSyncVaultToEnvSkipsOAuth:
    """_sync_vault_to_env must not write OAuth tokens to .env, and must
    scrub pre-existing OAuth lines on each run."""

    def test_pre_existing_oauth_line_in_env_is_removed(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            f"# header\n"
            f"ANTHROPIC_TOKEN={_OAUTH_ACCESS}\n"
            f"ZAI_API_KEY=zai-real-key\n"
        )
        # Empty vault — but the .env still has a stale OAuth entry.
        vault_path = tmp_path / "vault.enc"

        from hermes_aegis.vault.store import VaultStore
        from hermes_aegis.vault.keyring_store import get_or_create_master_key

        # Create a vault with a non-OAuth key so _sync_vault_to_env runs
        master = _fernet_key()
        vault = VaultStore(vault_path, master)
        vault.set("ZAI_API_KEY", "zai-real-key")

        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli.HERMES_ENV", env_file), \
             patch(
                "hermes_aegis.vault.keyring_store.get_or_create_master_key",
                return_value=master,
             ):
            from hermes_aegis.cli import _sync_vault_to_env
            _sync_vault_to_env()

        result = env_file.read_text()
        assert "ANTHROPIC_TOKEN=" not in result, result
        assert "ZAI_API_KEY=zai-real-key" in result

    def test_oauth_in_vault_is_not_synced_to_env(self, tmp_path):
        """Even if a vault somehow has an OAuth token (e.g. from --allow-oauth
        or an upgrade from an older version), the .env sync must skip it."""
        env_file = tmp_path / ".env"
        vault_path = tmp_path / "vault.enc"

        from hermes_aegis.vault.store import VaultStore

        master = _fernet_key()
        vault = VaultStore(vault_path, master)
        # Bypass the CLI guard — write OAuth to vault directly.
        vault.set("ANTHROPIC_TOKEN", _OAUTH_ACCESS)
        vault.set("ZAI_API_KEY", "zai-real-key")

        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli.HERMES_ENV", env_file), \
             patch(
                "hermes_aegis.vault.keyring_store.get_or_create_master_key",
                return_value=master,
             ):
            from hermes_aegis.cli import _sync_vault_to_env
            _sync_vault_to_env()

        result = env_file.read_text()
        assert "ANTHROPIC_TOKEN=" not in result, result
        assert "ZAI_API_KEY=zai-real-key" in result


class TestNousAgentKeyBridgeFilter:
    """The bridge from providers.nous.agent_key → ANTHROPIC_API_KEY only
    activates for real Anthropic key shapes. sk-nous-* portal keys must
    NOT be bridged or they'll be sent to api.anthropic.com and 401."""

    def test_sk_nous_not_bridged(self, tmp_path):
        from hermes_aegis.cli import _read_hermes_auth_credentials

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": _NOUS_PORTAL_KEY}}
        }))
        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file):
            assert _read_hermes_auth_credentials() == {}

    def test_sk_ant_api_still_bridged(self, tmp_path):
        from hermes_aegis.cli import _read_hermes_auth_credentials

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": _API_KEY}}
        }))
        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file):
            assert _read_hermes_auth_credentials() == {"ANTHROPIC_API_KEY": _API_KEY}

    def test_refresh_skips_sk_nous_in_nous_provider(self, tmp_path):
        """Even with sk-nous-* in nous.agent_key, refresh must walk the
        credential_pool to find a working OAuth credential."""
        from hermes_aegis.proxy import addon as addon_mod
        from hermes_aegis.proxy.addon import AegisAddon

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": _NOUS_PORTAL_KEY}},
            "credential_pool": {
                "anthropic": [
                    {
                        "id": "x", "priority": 0, "source": "claude_code",
                        "access_token": "sk-ant-oat01-FRESH",
                        "last_status": "ok",
                        "expires_at_ms": 9_999_999_999_999,
                    }
                ]
            },
        }))

        a = AegisAddon(vault_secrets={}, vault_values=[])
        original = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            assert a._refresh_hermes_auth(force=True) is True
        finally:
            addon_mod._HERMES_AUTH_FILE = original

        assert a._vault_secrets["ANTHROPIC_API_KEY"] == "sk-ant-oat01-FRESH"


class TestInjectorShapeGuard:
    """The Anthropic injector must not overwrite the agent's headers with
    a token that isn't recognizably Anthropic-shaped."""

    def test_sk_nous_does_not_overwrite_agent_bearer(self):
        from hermes_aegis.proxy.injector import inject_api_key

        agent_headers = {
            "Authorization": "Bearer sk-ant-oat01-AGENT-OWN-TOKEN",
            "anthropic-beta": "oauth-2025-04-20",
        }
        new_headers = inject_api_key(
            "api.anthropic.com",
            "/v1/messages",
            agent_headers,
            {"ANTHROPIC_API_KEY": _NOUS_PORTAL_KEY},
        )
        assert new_headers["Authorization"] == "Bearer sk-ant-oat01-AGENT-OWN-TOKEN"

    def test_sk_ant_api_uses_x_api_key(self):
        from hermes_aegis.proxy.injector import inject_api_key

        new_headers = inject_api_key(
            "api.anthropic.com",
            "/v1/messages",
            {"x-api-key": "placeholder"},
            {"ANTHROPIC_API_KEY": _API_KEY},
        )
        assert new_headers["x-api-key"] == _API_KEY

    def test_sk_ant_oat_uses_bearer(self):
        from hermes_aegis.proxy.injector import inject_api_key

        new_headers = inject_api_key(
            "api.anthropic.com",
            "/v1/messages",
            {"x-api-key": "placeholder"},
            {"ANTHROPIC_API_KEY": _OAUTH_ACCESS},
        )
        assert new_headers["Authorization"] == "Bearer " + _OAUTH_ACCESS


class TestRefreshFromCredentialPool:
    """_refresh_hermes_auth must walk credential_pool.anthropic when
    providers.nous.agent_key is unavailable, and skip exhausted entries."""

    def _make_addon(self, vault_secrets=None):
        from hermes_aegis.proxy.addon import AegisAddon
        return AegisAddon(
            vault_secrets=vault_secrets or {},
            vault_values=[],
        )

    def test_falls_through_to_credential_pool(self, tmp_path):
        """No nous.agent_key → use claude_code entry from credential_pool."""
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {},
            "credential_pool": {
                "anthropic": [
                    {
                        "id": "1", "label": "ANTHROPIC_TOKEN",
                        "priority": 0, "source": "env:ANTHROPIC_TOKEN",
                        "access_token": _OAUTH_ACCESS,
                        "last_status": "exhausted",
                        "last_error_code": 401,
                    },
                    {
                        "id": "2", "label": "claude_code",
                        "priority": 1, "source": "claude_code",
                        "access_token": "sk-ant-oat01-FRESH",
                        "refresh_token": _OAUTH_REFRESH,
                        "last_status": "ok",
                        "expires_at_ms": 9_999_999_999_999,
                    },
                ]
            },
        }))

        a = self._make_addon()
        original = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            assert a._refresh_hermes_auth(force=True) is True
        finally:
            addon_mod._HERMES_AUTH_FILE = original

        assert a._vault_secrets["ANTHROPIC_API_KEY"] == "sk-ant-oat01-FRESH"

    def test_skips_exhausted_entries(self, tmp_path):
        """Even at priority 0, exhausted entries are skipped."""
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {},
            "credential_pool": {
                "anthropic": [
                    {
                        "id": "1", "priority": 0,
                        "source": "env:ANTHROPIC_TOKEN",
                        "access_token": "sk-ant-oat01-DEAD",
                        "last_status": "exhausted",
                    },
                ]
            },
        }))

        a = self._make_addon()
        original = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            updated = a._refresh_hermes_auth(force=True)
        finally:
            addon_mod._HERMES_AUTH_FILE = original

        # No usable credential → no update.
        assert updated is False
        assert "ANTHROPIC_API_KEY" not in a._vault_secrets

    def test_skips_expired_entries(self, tmp_path):
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {},
            "credential_pool": {
                "anthropic": [
                    {
                        "id": "1", "priority": 0,
                        "source": "claude_code",
                        "access_token": "sk-ant-oat01-EXPIRED",
                        "last_status": "ok",
                        "expires_at_ms": 1,  # epoch — long-expired
                    },
                ]
            },
        }))

        a = self._make_addon()
        original = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            updated = a._refresh_hermes_auth(force=True)
        finally:
            addon_mod._HERMES_AUTH_FILE = original

        assert updated is False

    def test_nous_agent_key_still_preferred_when_present(self, tmp_path):
        """Backward compat: when nous.agent_key exists, it wins."""
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": "sk-ant-api03-NOUS"}},
            "credential_pool": {
                "anthropic": [
                    {
                        "id": "2", "priority": 1,
                        "source": "claude_code",
                        "access_token": "sk-ant-oat01-FRESH",
                        "last_status": "ok",
                        "expires_at_ms": 9_999_999_999_999,
                    },
                ]
            },
        }))

        a = self._make_addon()
        original = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            assert a._refresh_hermes_auth(force=True) is True
        finally:
            addon_mod._HERMES_AUTH_FILE = original

        assert a._vault_secrets["ANTHROPIC_API_KEY"] == "sk-ant-api03-NOUS"


class TestVaultDoctor:
    def _setup(self, tmp_path, *, vault_oauth: bool, env_oauth: bool, exhausted: bool):
        vault_path = tmp_path / "vault.enc"
        env_file = tmp_path / ".env"
        auth_file = tmp_path / "auth.json"

        from hermes_aegis.vault.store import VaultStore
        master = _fernet_key()
        vault = VaultStore(vault_path, master)
        vault.set("ZAI_API_KEY", "zai-key")
        if vault_oauth:
            vault.set("ANTHROPIC_TOKEN", _OAUTH_ACCESS)

        env_lines = ["# top", "ZAI_API_KEY=zai-key"]
        if env_oauth:
            env_lines.append(f"ANTHROPIC_TOKEN={_OAUTH_ACCESS}")
        env_file.write_text("\n".join(env_lines) + "\n")

        pool = []
        if exhausted:
            pool.append({
                "id": "1", "label": "ANTHROPIC_TOKEN",
                "priority": 0, "source": "env:ANTHROPIC_TOKEN",
                "access_token": _OAUTH_ACCESS,
                "last_status": "exhausted",
                "last_error_code": 401,
            })
        pool.append({
            "id": "2", "label": "claude_code",
            "priority": 1, "source": "claude_code",
            "access_token": "sk-ant-oat01-FRESH",
            "last_status": "ok",
            "expires_at_ms": 9_999_999_999_999,
        })
        auth_file.write_text(json.dumps({
            "providers": {},
            "credential_pool": {"anthropic": pool},
        }))

        return vault_path, env_file, auth_file, master

    def test_doctor_reports_clean_state(self, tmp_path):
        vault_path, env_file, auth_file, master = self._setup(
            tmp_path, vault_oauth=False, env_oauth=False, exhausted=False
        )
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli.HERMES_ENV", env_file), \
             patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file), \
             patch(
                "hermes_aegis.vault.keyring_store.get_or_create_master_key",
                return_value=master,
             ):
            runner = CliRunner()
            result = runner.invoke(main, ["vault", "doctor"])
        assert result.exit_code == 0, result.output
        assert "No credential-coupling issues" in result.output

    def test_doctor_reports_dirty_state(self, tmp_path):
        vault_path, env_file, auth_file, master = self._setup(
            tmp_path, vault_oauth=True, env_oauth=True, exhausted=True
        )
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli.HERMES_ENV", env_file), \
             patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file), \
             patch(
                "hermes_aegis.vault.keyring_store.get_or_create_master_key",
                return_value=master,
             ):
            runner = CliRunner()
            result = runner.invoke(main, ["vault", "doctor"])
        assert result.exit_code == 0, result.output
        assert "OAuth token stored in vault" in result.output
        assert "OAuth token in ~/.hermes/.env" in result.output
        assert "Exhausted env-sourced" in result.output
        assert "--fix" in result.output

    def test_doctor_fix_heals_state(self, tmp_path):
        vault_path, env_file, auth_file, master = self._setup(
            tmp_path, vault_oauth=True, env_oauth=True, exhausted=True
        )
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli.HERMES_ENV", env_file), \
             patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file), \
             patch("hermes_aegis.cli._restart_proxy_if_running"), \
             patch(
                "hermes_aegis.vault.keyring_store.get_or_create_master_key",
                return_value=master,
             ):
            runner = CliRunner()
            result = runner.invoke(main, ["vault", "doctor", "--fix"])
        assert result.exit_code == 0, result.output
        assert "Applied:" in result.output

        # Vault no longer has OAuth.
        from hermes_aegis.vault.store import VaultStore
        vault = VaultStore(vault_path, master)
        assert "ANTHROPIC_TOKEN" not in vault.list_keys()
        assert "ZAI_API_KEY" in vault.list_keys()

        # .env scrubbed.
        env_text = env_file.read_text()
        assert "ANTHROPIC_TOKEN=" not in env_text
        assert "ZAI_API_KEY=zai-key" in env_text

        # Auth pool no longer has the exhausted env entry.
        store = json.loads(auth_file.read_text())
        pool = store["credential_pool"]["anthropic"]
        assert all(e.get("source", "") != "env:ANTHROPIC_TOKEN" for e in pool)
        assert any(e.get("source") == "claude_code" for e in pool)

    def test_doctor_idempotent_after_fix(self, tmp_path):
        vault_path, env_file, auth_file, master = self._setup(
            tmp_path, vault_oauth=True, env_oauth=True, exhausted=True
        )
        with patch("hermes_aegis.cli.VAULT_PATH", vault_path), \
             patch("hermes_aegis.cli.HERMES_ENV", env_file), \
             patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file), \
             patch("hermes_aegis.cli._restart_proxy_if_running"), \
             patch(
                "hermes_aegis.vault.keyring_store.get_or_create_master_key",
                return_value=master,
             ):
            runner = CliRunner()
            runner.invoke(main, ["vault", "doctor", "--fix"])
            second = runner.invoke(main, ["vault", "doctor"])
        assert "No credential-coupling issues" in second.output
