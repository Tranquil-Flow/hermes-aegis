"""Tests for proxy lifecycle (start/stop/is_running)."""
import json
import os
import signal
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from hermes_aegis.proxy.runner import (
    PID_FILE,
    is_proxy_running,
    stop_proxy,
)


@pytest.fixture
def fake_pid_file(tmp_path):
    """Create a temporary PID file."""
    pid_file = tmp_path / "proxy.pid"
    return pid_file


class TestIsProxyRunning:
    def test_false_when_no_pid_file(self, fake_pid_file):
        running, port = is_proxy_running(pid_file=fake_pid_file)
        assert running is False
        assert port is None

    def test_false_when_pid_file_invalid(self, fake_pid_file):
        fake_pid_file.write_text("not json")
        running, port = is_proxy_running(pid_file=fake_pid_file)
        assert running is False

    def test_false_when_process_dead(self, fake_pid_file):
        # Use a PID that definitely doesn't exist
        fake_pid_file.write_text(json.dumps({"pid": 999999999, "port": 8443}))
        running, port = is_proxy_running(pid_file=fake_pid_file)
        assert running is False
        # Stale PID file should be cleaned up
        assert not fake_pid_file.exists()

    def test_true_when_process_alive(self, fake_pid_file):
        # Use our own PID (guaranteed to be alive)
        fake_pid_file.write_text(json.dumps({"pid": os.getpid(), "port": 8443}))
        running, port = is_proxy_running(pid_file=fake_pid_file)
        assert running is True
        assert port == 8443


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
