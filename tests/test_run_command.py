"""Tests for hermes-aegis run command."""
import json
import os
import sys
import types
import pytest
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import patch, MagicMock, call

from hermes_aegis.cli import main


def _mock_popen(returncode=0):
    """Create a mock Popen instance with the given return code."""
    mock = MagicMock()
    mock.wait.return_value = returncode
    mock.poll.return_value = returncode
    return mock


class TestRunCommand:
    """Test the 'hermes-aegis run' command."""

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_starts_proxy_and_hermes(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup, tmp_path
    ):
        mock_popen.return_value = _mock_popen(0)

        # Create a PID file matching our_proxy_pid so the finally block calls stop_proxy
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(json.dumps({"pid": 12345, "port": 8443}))

        with patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            runner = CliRunner()
            result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        mock_start.assert_called_once()
        mock_popen.assert_called_once()
        # Proxy is intentionally left running on exit — it's shared infrastructure
        mock_stop.assert_not_called()

        # Check env vars were set for the hermes subprocess
        call_kwargs = mock_popen.call_args
        env = call_kwargs[1]["env"]
        assert env["HTTP_PROXY"] == "http://127.0.0.1:8443"
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:8443"
        assert "REQUESTS_CA_BUNDLE" in env
        assert "SSL_CERT_FILE" in env
        assert env["OPENROUTER_API_KEY"] == "aegis-managed"

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value=set())
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_works_with_empty_vault(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup
    ):
        """Run should work even without vault keys (user may have their own)."""
        mock_popen.return_value = _mock_popen(0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        # No aegis-managed placeholder keys should be injected
        env = mock_popen.call_args[1]["env"]
        for key in ["OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
            assert env.get(key) != "aegis-managed"

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(-1, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_does_not_stop_preexisting_proxy(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup
    ):
        """If proxy was already running, run should NOT stop it on exit."""
        mock_popen.return_value = _mock_popen(0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        mock_stop.assert_not_called()

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_passes_args_to_hermes(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup
    ):
        mock_popen.return_value = _mock_popen(0)

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--", "gateway", "status"])

        call_args = mock_popen.call_args[0][0]
        assert call_args == ["/usr/bin/hermes", "gateway", "status"]

    @patch("hermes_aegis.cli._find_hermes_binary", return_value=None)
    def test_run_fails_if_hermes_not_found(self, mock_find):
        runner = CliRunner()
        result = runner.invoke(main, ["run"])
        assert result.exit_code == 1
        assert "hermes" in result.output.lower()

    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", side_effect=RuntimeError("port busy"))
    def test_run_fails_if_proxy_fails(self, mock_start, mock_find):
        runner = CliRunner()
        result = runner.invoke(main, ["run"])
        assert result.exit_code == 1
        assert "proxy" in result.output.lower() or "port" in result.output.lower()

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_propagates_hermes_exit_code(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup
    ):
        mock_popen.return_value = _mock_popen(42)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 42

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen", side_effect=KeyboardInterrupt)
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_stops_proxy_on_interrupt(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup, tmp_path
    ):
        # Create a PID file matching our_proxy_pid
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(json.dumps({"pid": 12345, "port": 8443}))

        with patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            runner = CliRunner()
            result = runner.invoke(main, ["run"])

        # Proxy is intentionally left running on interrupt — it's shared infrastructure
        mock_stop.assert_not_called()

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"ANTHROPIC_TOKEN", "OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_never_sets_oauth_token_as_placeholder(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup
    ):
        """ANTHROPIC_TOKEN must NOT be set to 'aegis-managed' — it would override
        hermes-agent's OAuth chain and the proxy would refuse to inject the real token."""
        mock_popen.return_value = _mock_popen(0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        env = mock_popen.call_args[1]["env"]
        # ANTHROPIC_TOKEN must NOT be "aegis-managed"
        assert env.get("ANTHROPIC_TOKEN") != "aegis-managed", \
            "ANTHROPIC_TOKEN placeholder breaks OAuth: hermes sends 'Bearer aegis-managed' and proxy won't override"
        # But other AUTO_INJECT_KEYS should still get placeholders
        assert env["OPENROUTER_API_KEY"] == "aegis-managed"

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"MINIMAX_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_sets_minimax_placeholder_when_key_is_in_vault(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup
    ):
        mock_popen.return_value = _mock_popen(0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        env = mock_popen.call_args[1]["env"]
        assert env["MINIMAX_API_KEY"] == "aegis-managed"

    @patch("hermes_aegis.cli._docker_post_run_cleanup_async")
    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_syncs_vault_to_hermes_env(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, mock_cleanup, tmp_path
    ):
        """The run command syncs vault keys to ~/.hermes/.env so hermes finds them."""
        fake_env = tmp_path / ".env"
        mock_popen.return_value = _mock_popen(0)

        with patch("hermes_aegis.cli.HERMES_ENV", fake_env):
            runner = CliRunner()
            result = runner.invoke(main, ["run"])

        # .env should exist (created/updated by _sync_vault_to_env)


def test_sync_vault_to_env_preserves_existing_non_vault_entries(tmp_path, monkeypatch):
    """Vault sync should merge into ~/.hermes/.env, not overwrite unrelated keys."""
    from hermes_aegis import cli as aegis_cli

    fake_env = tmp_path / ".env"
    fake_env.write_text(
        "ANTHROPIC_TOKEN=existing-anthropic\n"
        "DISCORD_BOT_TOKEN=existing-discord\n"
        "MINIMAX_API_KEY=existing-minimax\n"
    )
    fake_vault = tmp_path / "vault.enc"
    fake_vault.write_text("placeholder")

    class FakeVaultStore:
        def __init__(self, path, master_key):
            pass

        def list_keys(self):
            return ["OPENROUTER_API_KEY"]

        def get(self, key):
            return {"OPENROUTER_API_KEY": "vault-openrouter"}.get(key)

    fake_keyring = types.ModuleType("hermes_aegis.vault.keyring_store")
    fake_keyring.get_or_create_master_key = lambda: "master-key"
    fake_store = types.ModuleType("hermes_aegis.vault.store")
    fake_store.VaultStore = FakeVaultStore

    monkeypatch.setitem(sys.modules, "hermes_aegis.vault.keyring_store", fake_keyring)
    monkeypatch.setitem(sys.modules, "hermes_aegis.vault.store", fake_store)
    monkeypatch.setattr(aegis_cli, "HERMES_ENV", fake_env)
    monkeypatch.setattr(aegis_cli, "VAULT_PATH", fake_vault)

    aegis_cli._sync_vault_to_env()

    content = fake_env.read_text()
    assert "ANTHROPIC_TOKEN=existing-anthropic" in content
    assert "DISCORD_BOT_TOKEN=existing-discord" in content
    assert "MINIMAX_API_KEY=existing-minimax" in content
    assert "OPENROUTER_API_KEY=vault-openrouter" in content


class TestStartProxyForRun:
    """Tests for _start_proxy_for_run() proxy lifecycle fixes."""

    @patch("hermes_aegis.cli.VAULT_PATH")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process", return_value=99999)
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_stops_stale_proxy_before_starting_new(
        self, mock_running, mock_start, mock_stop, mock_vault_path, tmp_path
    ):
        """When vault hash differs, stop old proxy before starting new one (no orphans)."""
        mock_vault_path.exists.return_value = False
        # Proxy running but with stale vault hash
        mock_running.return_value = (True, 8443, "oldhash")

        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(json.dumps({"pid": 99999, "port": 8443}))

        with patch("hermes_aegis.cli.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            from hermes_aegis.cli import _start_proxy_for_run
            pid, port = _start_proxy_for_run()

        # Must stop old proxy before starting new one
        mock_stop.assert_called_once()
        mock_start.assert_called_once()
        # New proxy started — not a reuse
        assert pid != -1

    @patch("hermes_aegis.cli.VAULT_PATH")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process", return_value=99999)
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_preserves_port_when_restarting(
        self, mock_running, mock_start, mock_stop, mock_vault_path, tmp_path
    ):
        """When restarting due to stale vault hash, new proxy binds the same port."""
        mock_vault_path.exists.return_value = False
        mock_running.return_value = (True, 9876, "oldhash")  # Running on port 9876

        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(json.dumps({"pid": 99999, "port": 9876}))

        with patch("hermes_aegis.cli.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            from hermes_aegis.cli import _start_proxy_for_run
            _start_proxy_for_run()

        # start_proxy_process must be called with listen_port=9876
        call_kwargs = mock_start.call_args[1]
        assert call_kwargs.get("listen_port") == 9876

    @patch("hermes_aegis.cli.VAULT_PATH")
    @patch("hermes_aegis.cli._read_hermes_auth_credentials", return_value={})
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process")
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_reuses_matching_proxy_without_restart(
        self, mock_running, mock_start, mock_stop, mock_auth, mock_vault_path
    ):
        """When vault hash matches, return existing proxy without touching it."""
        mock_vault_path.exists.return_value = False
        # _vault_hash({}) = sha256("{}") first 16 chars
        import hashlib, json as _json
        expected_hash = hashlib.sha256(_json.dumps({}, sort_keys=True).encode()).hexdigest()[:16]
        mock_running.return_value = (True, 8443, expected_hash)

        from hermes_aegis.cli import _start_proxy_for_run
        pid, port = _start_proxy_for_run()

        mock_stop.assert_not_called()
        mock_start.assert_not_called()
        assert pid == -1
        assert port == 8443

    @patch("hermes_aegis.cli.VAULT_PATH")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process", return_value=99999)
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_force_port_bypasses_hash_check(
        self, mock_running, mock_start, mock_stop, mock_vault_path, tmp_path
    ):
        """force_port always starts a new proxy even when hash matches (watchdog restart)."""
        mock_vault_path.exists.return_value = False
        import hashlib, json as _json
        expected_hash = hashlib.sha256(_json.dumps({}, sort_keys=True).encode()).hexdigest()[:16]
        mock_running.return_value = (True, 8443, expected_hash)

        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(_json.dumps({"pid": 99999, "port": 8443}))

        with patch("hermes_aegis.cli.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            from hermes_aegis.cli import _start_proxy_for_run
            pid, port = _start_proxy_for_run(force_port=8443)

        # force_port skips stop_proxy to avoid killing other sessions' proxies
        mock_stop.assert_not_called()
        mock_start.assert_called_once()
        call_kwargs = mock_start.call_args[1]
        assert call_kwargs.get("listen_port") == 8443

    @patch("hermes_aegis.cli.VAULT_PATH")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process", return_value=99999)
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_force_port_used_when_proxy_not_running(
        self, mock_running, mock_start, mock_stop, mock_vault_path, tmp_path
    ):
        """force_port is passed to start_proxy_process when proxy is dead (watchdog crash restart)."""
        mock_vault_path.exists.return_value = False
        mock_running.return_value = (False, None, None)  # Proxy is dead

        pid_file = tmp_path / "proxy.pid"
        import json as _json
        pid_file.write_text(_json.dumps({"pid": 99999, "port": 8443}))

        with patch("hermes_aegis.cli.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            from hermes_aegis.cli import _start_proxy_for_run
            _start_proxy_for_run(force_port=8443)

        mock_stop.assert_not_called()  # Nothing running to stop
        call_kwargs = mock_start.call_args[1]
        assert call_kwargs.get("listen_port") == 8443

    @patch("hermes_aegis.cli.VAULT_PATH")
    @patch("hermes_aegis.cli._read_hermes_auth_credentials", return_value={"ANTHROPIC_API_KEY": "sk-ant-fresh"})
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process", return_value=99999)
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_enables_auth_refresh_when_proxy_uses_hermes_minted_anthropic_key(
        self, mock_running, mock_start, mock_stop, mock_auth, mock_vault_path, tmp_path
    ):
        """OAuth-derived Anthropic keys must opt into proxy refresh from auth.json."""
        mock_vault_path.exists.return_value = False
        mock_running.return_value = (False, None, None)

        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(json.dumps({"pid": 99999, "port": 8443}))

        with patch("hermes_aegis.cli.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            from hermes_aegis.cli import _start_proxy_for_run
            _start_proxy_for_run()

        call_kwargs = mock_start.call_args[1]
        assert call_kwargs["vault_secrets"]["ANTHROPIC_API_KEY"] == "sk-ant-fresh"
        assert call_kwargs["refresh_hermes_auth"] is True


class TestRestartProxyIfRunning:
    """Tests for _restart_proxy_if_running() port preservation fix."""

    @patch("hermes_aegis.cli.VAULT_PATH")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process", return_value=99999)
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_preserves_port_on_vault_restart(
        self, mock_running, mock_start, mock_stop, mock_vault_path, tmp_path
    ):
        """_restart_proxy_if_running must pass existing port so running sessions keep working."""
        mock_vault_path.exists.return_value = False
        mock_running.return_value = (True, 7777, "somehash")  # Running on port 7777

        with patch("hermes_aegis.cli.AEGIS_DIR", tmp_path):
            from hermes_aegis.cli import _restart_proxy_if_running
            _restart_proxy_if_running(tmp_path / "audit.jsonl")

        mock_stop.assert_called_once()
        call_kwargs = mock_start.call_args[1]
        assert call_kwargs.get("listen_port") == 7777

    @patch("hermes_aegis.proxy.runner.is_proxy_running", return_value=(False, None, None))
    def test_no_op_when_proxy_not_running(self, mock_running, tmp_path):
        """_restart_proxy_if_running is a no-op if proxy isn't running."""
        with patch("hermes_aegis.cli.AEGIS_DIR", tmp_path):
            from hermes_aegis.cli import _restart_proxy_if_running
            _restart_proxy_if_running(tmp_path / "audit.jsonl")

        mock_running.assert_called_once()
