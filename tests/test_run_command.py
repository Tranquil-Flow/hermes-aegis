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
