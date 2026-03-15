"""Tests for new CLI commands (install, uninstall, start, stop, status)."""
import json
import pytest
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import patch, MagicMock

from hermes_aegis.cli import main
from hermes_aegis import __version__


class TestCLIBasic:
    def test_main_no_command(self):
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code == 0
        assert f'hermes-aegis v{__version__}' in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "install" in result.output
        assert "uninstall" in result.output
        assert "start" in result.output
        assert "stop" in result.output
        assert "status" in result.output
        assert "setup" in result.output


class TestInstallCommand:
    @patch("hermes_aegis.cli._check_hermes_installed", return_value=True)
    @patch("hermes_aegis.utils.ensure_mitmproxy_ca_cert")
    @patch("hermes_aegis.hook.clean_old_setup", return_value=[])
    @patch("hermes_aegis.hook.install_hook")
    def test_install_calls_hook_installer(self, mock_install, mock_clean, mock_cert, mock_hermes):
        mock_install.return_value = Path("/tmp/fake-hook")
        mock_cert.return_value = Path("/tmp/fake-cert.pem")

        runner = CliRunner()
        result = runner.invoke(main, ["install"])
        assert result.exit_code == 0
        mock_install.assert_called_once()
        mock_clean.assert_called_once()

    @patch("hermes_aegis.cli._check_hermes_installed", return_value=True)
    @patch("hermes_aegis.utils.ensure_mitmproxy_ca_cert", side_effect=RuntimeError("no mitmdump"))
    @patch("hermes_aegis.hook.clean_old_setup", return_value=[])
    @patch("hermes_aegis.hook.install_hook")
    def test_install_fails_on_cert_error(self, mock_install, mock_clean, mock_cert, mock_hermes):
        mock_install.return_value = Path("/tmp/fake-hook")

        runner = CliRunner()
        result = runner.invoke(main, ["install"])
        assert result.exit_code == 1
        assert "Error" in result.output

    @patch("hermes_aegis.cli._check_hermes_installed", return_value=False)
    def test_install_fails_without_hermes(self, mock_hermes):
        runner = CliRunner()
        result = runner.invoke(main, ["install"])
        assert result.exit_code == 1
        assert "hermes agent not found" in result.output.lower()

    @patch("hermes_aegis.cli._check_hermes_installed", return_value=True)
    @patch("hermes_aegis.utils.ensure_mitmproxy_ca_cert")
    @patch("hermes_aegis.hook.clean_old_setup", return_value=[])
    @patch("hermes_aegis.hook.install_hook")
    def test_install_does_not_write_hermes_env(self, mock_install, mock_clean, mock_cert, mock_hermes, tmp_path):
        """Install must never write to ~/.hermes/.env."""
        mock_install.return_value = Path("/tmp/fake-hook")
        mock_cert.return_value = Path("/tmp/fake-cert.pem")

        fake_env = tmp_path / ".env"
        # Don't create the file — install should not create it either

        with patch("hermes_aegis.cli.HERMES_ENV", fake_env):
            runner = CliRunner()
            result = runner.invoke(main, ["install"])

        assert not fake_env.exists(), "install must not create ~/.hermes/.env"


class TestUninstallCommand:
    @patch("hermes_aegis.hook.uninstall_hook", return_value=True)
    def test_uninstall_removes_hook(self, mock_uninstall):
        runner = CliRunner()
        result = runner.invoke(main, ["uninstall"])
        assert result.exit_code == 0
        assert "removed" in result.output.lower()
        mock_uninstall.assert_called_once()

    @patch("hermes_aegis.hook.uninstall_hook", return_value=False)
    def test_uninstall_not_found(self, mock_uninstall):
        runner = CliRunner()
        result = runner.invoke(main, ["uninstall"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()


class TestStopCommand:
    @patch("hermes_aegis.proxy.runner.stop_proxy", return_value=True)
    def test_stop_success(self, mock_stop):
        runner = CliRunner()
        result = runner.invoke(main, ["stop"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    @patch("hermes_aegis.proxy.runner.stop_proxy", return_value=False)
    def test_stop_not_running(self, mock_stop):
        runner = CliRunner()
        result = runner.invoke(main, ["stop"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()


class TestStatusCommand:
    @patch("hermes_aegis.cli.VAULT_PATH", Path("/tmp/nonexistent-vault.enc"))
    @patch("hermes_aegis.cli._check_hermes_installed", return_value=False)
    @patch("hermes_aegis.utils.docker_available", return_value=False)
    @patch("hermes_aegis.hook.is_hook_installed", return_value=False)
    @patch("hermes_aegis.proxy.runner.is_proxy_running", return_value=(False, None, None))
    def test_status_all_off(self, mock_proxy, mock_hook, mock_docker, mock_hermes):
        runner = CliRunner()
        result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()
        assert "not installed" in result.output.lower()
        assert "not found" in result.output.lower()

    @patch("hermes_aegis.cli.VAULT_PATH", Path("/tmp/nonexistent-vault.enc"))
    @patch("hermes_aegis.cli._check_hermes_installed", return_value=True)
    @patch("hermes_aegis.utils.docker_available", return_value=True)
    @patch("hermes_aegis.hook.is_hook_installed", return_value=True)
    @patch("hermes_aegis.proxy.runner.is_proxy_running", return_value=(True, 8443, None))
    def test_status_all_on(self, mock_proxy, mock_hook, mock_docker, mock_hermes):
        runner = CliRunner()
        result = runner.invoke(main, ["status"])
        assert result.exit_code == 0
        assert "running" in result.output.lower()
        assert "installed" in result.output.lower()
        assert "available" in result.output.lower()
