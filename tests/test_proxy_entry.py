"""Tests for proxy/entry.py — addon loading from config file."""
import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch

from hermes_aegis.proxy.addon import AegisAddon


class TestLoadAddon:
    def test_load_with_no_config_file(self, tmp_path):
        config_path = tmp_path / "proxy-config.json"

        with patch("hermes_aegis.proxy.entry.CONFIG_PATH", config_path):
            from hermes_aegis.proxy.entry import _load_addon
            addon = _load_addon()

        assert isinstance(addon, AegisAddon)

    def test_load_with_config_file(self, tmp_path):
        config_path = tmp_path / "proxy-config.json"
        config = {
            "vault_secrets": {"OPENAI_API_KEY": "sk-test-123"},
            "vault_values": ["sk-test-123"],
            "rate_limit_requests": 100,
            "rate_limit_window": 2.0,
        }
        config_path.write_text(json.dumps(config))

        with patch("hermes_aegis.proxy.entry.CONFIG_PATH", config_path):
            from hermes_aegis.proxy.entry import _load_addon
            addon = _load_addon()

        assert isinstance(addon, AegisAddon)

        # Secrets should be removed from config after loading
        safe_config = json.loads(config_path.read_text())
        assert "vault_secrets" not in safe_config
        assert "vault_values" not in safe_config
        assert safe_config["started"] is True
        assert safe_config["rate_limit_requests"] == 100

    def test_config_file_permissions_set(self, tmp_path):
        config_path = tmp_path / "proxy-config.json"
        config = {
            "vault_secrets": {},
            "vault_values": [],
        }
        config_path.write_text(json.dumps(config))

        with patch("hermes_aegis.proxy.entry.CONFIG_PATH", config_path):
            from hermes_aegis.proxy.entry import _load_addon
            _load_addon()

        # File should be mode 0600
        stat = config_path.stat()
        assert oct(stat.st_mode & 0o777) == "0o600"


class TestStartProxyProcess:
    @patch("hermes_aegis.proxy.runner.wait_for_proxy_ready", return_value=True)
    @patch("hermes_aegis.proxy.runner.subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.find_available_port", return_value=8450)
    def test_writes_config_and_starts_process(self, mock_port, mock_popen, mock_wait, tmp_path):
        from hermes_aegis.proxy.runner import start_proxy_process

        mock_proc = mock_popen.return_value
        mock_proc.pid = 12345

        config_file = tmp_path / "proxy-config.json"
        pid_file = tmp_path / "proxy.pid"

        with patch("hermes_aegis.proxy.runner.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.CONFIG_FILE", config_file), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):

            pid = start_proxy_process(
                vault_secrets={"KEY": "val"},
                vault_values=["val"],
                listen_port=8450,
            )

        assert pid == 12345
        assert pid_file.exists()
        pid_info = json.loads(pid_file.read_text())
        assert pid_info["pid"] == 12345
        assert pid_info["port"] == 8450

        # Config was written
        assert config_file.exists()

    @patch("hermes_aegis.proxy.runner.wait_for_proxy_ready", return_value=False)
    @patch("hermes_aegis.proxy.runner.subprocess.Popen")
    def test_raises_on_startup_failure(self, mock_popen, mock_wait, tmp_path):
        from hermes_aegis.proxy.runner import start_proxy_process

        mock_proc = mock_popen.return_value
        mock_proc.pid = 99999

        config_file = tmp_path / "proxy-config.json"
        pid_file = tmp_path / "proxy.pid"

        with patch("hermes_aegis.proxy.runner.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.CONFIG_FILE", config_file), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):

            with pytest.raises(RuntimeError, match="Proxy failed to start"):
                start_proxy_process(
                    vault_secrets={},
                    vault_values=[],
                    listen_port=8450,
                )

        # Cleanup should have happened
        mock_proc.terminate.assert_called_once()
        assert not pid_file.exists()
        assert not config_file.exists()

    @patch("hermes_aegis.proxy.runner.wait_for_proxy_ready", return_value=True)
    @patch("hermes_aegis.proxy.runner.subprocess.Popen")
    @patch("hermes_aegis.proxy.runner.find_available_port", return_value=8443)
    def test_auto_finds_port_when_not_specified(self, mock_port, mock_popen, mock_wait, tmp_path):
        from hermes_aegis.proxy.runner import start_proxy_process

        mock_proc = mock_popen.return_value
        mock_proc.pid = 11111

        config_file = tmp_path / "proxy-config.json"
        pid_file = tmp_path / "proxy.pid"

        with patch("hermes_aegis.proxy.runner.AEGIS_DIR", tmp_path), \
             patch("hermes_aegis.proxy.runner.CONFIG_FILE", config_file), \
             patch("hermes_aegis.proxy.runner.PID_FILE", pid_file):

            start_proxy_process(vault_secrets={}, vault_values=[])

        mock_port.assert_called_once()
        pid_info = json.loads(pid_file.read_text())
        assert pid_info["port"] == 8443
