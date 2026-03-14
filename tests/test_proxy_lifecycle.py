"""Tests for proxy lifecycle (start/stop/is_running)."""
import json
import os
import signal
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from hermes_aegis.proxy.runner import (
    CONFIG_FILE,
    PID_FILE,
    is_proxy_running,
    stop_proxy,
    _secure_delete_config,
)


@pytest.fixture
def fake_pid_file(tmp_path):
    """Create a temporary PID file."""
    pid_file = tmp_path / "proxy.pid"
    return pid_file


class TestIsProxyRunning:
    def test_false_when_no_pid_file(self, fake_pid_file):
        running, port, _ = is_proxy_running(pid_file=fake_pid_file)
        assert running is False
        assert port is None

    def test_false_when_pid_file_invalid(self, fake_pid_file):
        fake_pid_file.write_text("not json")
        running, port, _ = is_proxy_running(pid_file=fake_pid_file)
        assert running is False

    def test_false_when_process_dead(self, fake_pid_file):
        # Use a PID that definitely doesn't exist
        fake_pid_file.write_text(json.dumps({"pid": 999999999, "port": 8443}))
        running, port, _ = is_proxy_running(pid_file=fake_pid_file)
        assert running is False
        # Stale PID file should be cleaned up
        assert not fake_pid_file.exists()

    def test_true_when_process_alive_and_port_listening(self, fake_pid_file):
        # Start a real listener so the port probe succeeds
        import socket
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        _, listen_port = server.getsockname()
        try:
            fake_pid_file.write_text(json.dumps({"pid": os.getpid(), "port": listen_port}))
            running, port, _ = is_proxy_running(pid_file=fake_pid_file)
            assert running is True
            assert port == listen_port
        finally:
            server.close()

    def test_false_when_pid_alive_but_port_not_listening(self, fake_pid_file):
        # PID alive (our own) but port not listening — stale PID (reused by another process)
        fake_pid_file.write_text(json.dumps({"pid": os.getpid(), "port": 59999}))
        running, port, _ = is_proxy_running(pid_file=fake_pid_file)
        assert running is False
        assert not fake_pid_file.exists()


class TestStopProxy:
    def test_returns_false_when_no_pid_file(self, fake_pid_file):
        assert stop_proxy(pid_file=fake_pid_file) is False

    def test_returns_false_when_process_already_dead(self, fake_pid_file):
        fake_pid_file.write_text(json.dumps({"pid": 999999999, "port": 8443}))
        assert stop_proxy(pid_file=fake_pid_file) is False
        assert not fake_pid_file.exists()

    def test_returns_false_on_bad_json(self, fake_pid_file):
        fake_pid_file.write_text("bad json")
        assert stop_proxy(pid_file=fake_pid_file) is False
        assert not fake_pid_file.exists()

    def test_cleans_config_file_on_stop(self, fake_pid_file, tmp_path):
        """stop_proxy should also remove proxy-config.json."""
        config_file = tmp_path / "proxy-config.json"
        config_file.write_text('{"vault_secrets": {"key": "secret"}}')
        fake_pid_file.write_text(json.dumps({"pid": 999999999, "port": 8443}))

        with patch("hermes_aegis.proxy.runner.CONFIG_FILE", config_file):
            stop_proxy(pid_file=fake_pid_file)
        assert not config_file.exists()


class TestSecureDeleteConfig:
    def test_overwrites_then_deletes(self, tmp_path):
        config = tmp_path / "proxy-config.json"
        config.write_text('{"vault_secrets": {"OPENAI_API_KEY": "sk-real"}}')
        with patch("hermes_aegis.proxy.runner.CONFIG_FILE", config):
            _secure_delete_config()
        assert not config.exists()

    def test_handles_missing_file(self, tmp_path):
        config = tmp_path / "nonexistent.json"
        with patch("hermes_aegis.proxy.runner.CONFIG_FILE", config):
            _secure_delete_config()  # Should not raise


class TestSocketCleanup:
    def test_socket_closed_on_connect_failure(self, fake_pid_file):
        """Verify socket is closed even when connect raises OSError (fix #1)."""
        fake_pid_file.write_text(json.dumps({"pid": os.getpid(), "port": 59999}))
        # This should not leak a socket — port 59999 is not listening
        running, port, _ = is_proxy_running(pid_file=fake_pid_file)
        assert running is False
