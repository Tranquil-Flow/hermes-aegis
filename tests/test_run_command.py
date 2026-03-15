"""Tests for hermes-aegis run command."""
import json
import os
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

    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_starts_proxy_and_hermes(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, tmp_path
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

    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value=set())
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_works_with_empty_vault(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner
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

    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(-1, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_does_not_stop_preexisting_proxy(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner
    ):
        """If proxy was already running, run should NOT stop it on exit."""
        mock_popen.return_value = _mock_popen(0)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 0
        mock_stop.assert_not_called()

    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_passes_args_to_hermes(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner
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

    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_propagates_hermes_exit_code(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner
    ):
        mock_popen.return_value = _mock_popen(42)

        runner = CliRunner()
        result = runner.invoke(main, ["run"])

        assert result.exit_code == 42

    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen", side_effect=KeyboardInterrupt)
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_stops_proxy_on_interrupt(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, tmp_path
    ):
        # Create a PID file matching our_proxy_pid
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(json.dumps({"pid": 12345, "port": 8443}))

        with patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):
            runner = CliRunner()
            result = runner.invoke(main, ["run"])

        # Proxy is intentionally left running on interrupt — it's shared infrastructure
        mock_stop.assert_not_called()

    @patch("hermes_aegis.cli._print_aegis_banner")
    @patch("hermes_aegis.cli._find_hermes_binary", return_value="/usr/bin/hermes")
    @patch("hermes_aegis.cli._start_proxy_for_run", return_value=(12345, 8443))
    @patch("hermes_aegis.cli._get_vault_provider_keys", return_value={"OPENROUTER_API_KEY"})
    @patch("subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    def test_run_does_not_modify_hermes_env_file(
        self, mock_stop, mock_popen, mock_vault_keys, mock_start, mock_find, mock_banner, tmp_path
    ):
        """The run command must NEVER write to ~/.hermes/.env."""
        fake_env = tmp_path / ".env"
        fake_env.write_text("OPENROUTER_API_KEY=sk-real-key\n")
        original_content = fake_env.read_text()

        mock_popen.return_value = _mock_popen(0)

        with patch("hermes_aegis.cli.HERMES_ENV", fake_env):
            runner = CliRunner()
            result = runner.invoke(main, ["run"])

        # .env file must be completely untouched
        assert fake_env.read_text() == original_content


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
    @patch("hermes_aegis.proxy.runner.stop_proxy")
    @patch("hermes_aegis.proxy.runner.start_proxy_process")
    @patch("hermes_aegis.proxy.runner.is_proxy_running")
    def test_reuses_matching_proxy_without_restart(
        self, mock_running, mock_start, mock_stop, mock_vault_path
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
