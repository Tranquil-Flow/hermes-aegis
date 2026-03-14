"""Tests for utility functions."""
import pytest

from hermes_aegis.utils import (
    docker_available,
    find_available_port,
    strip_secret_env_vars,
    wait_for_proxy_ready,
)


class TestFindAvailablePort:
    def test_returns_port_in_range(self):
        port = find_available_port(start=9000, end=9100)
        assert 9000 <= port < 9100

    def test_port_is_bindable(self):
        import socket
        port = find_available_port(start=9200, end=9300)
        sock = socket.socket()
        try:
            sock.bind(("localhost", port))
        except OSError:
            pytest.fail(f"Port {port} claimed available but binding failed")
        finally:
            sock.close()

    def test_raises_if_no_port_available(self):
        import socket
        # Bind a port to make the single-port range unavailable
        sock = socket.socket()
        sock.bind(("localhost", 0))
        port = sock.getsockname()[1]
        try:
            with pytest.raises(RuntimeError, match="No available port"):
                find_available_port(start=port, end=port + 1)
        finally:
            sock.close()


class TestWaitForProxyReady:
    def test_returns_false_on_timeout(self):
        assert wait_for_proxy_ready(port=9999, timeout=0.5) is False


class TestStripSecretEnvVars:
    def test_strips_known_keys(self):
        env = {
            "OPENAI_API_KEY": "sk-123",
            "ANTHROPIC_API_KEY": "sk-ant-456",
            "PATH": "/usr/bin",
            "HOME": "/home/user",
        }
        clean = strip_secret_env_vars(env)
        assert "OPENAI_API_KEY" not in clean
        assert "ANTHROPIC_API_KEY" not in clean
        assert clean["PATH"] == "/usr/bin"
        assert clean["HOME"] == "/home/user"

    def test_strips_secret_like_keys(self):
        env = {
            "MY_PASSWORD": "pass123",
            "DB_SECRET": "dbsec",
            "NORMAL_VAR": "ok",
        }
        clean = strip_secret_env_vars(env)
        assert "MY_PASSWORD" not in clean
        assert "DB_SECRET" not in clean
        assert clean["NORMAL_VAR"] == "ok"

    def test_empty_dict(self):
        assert strip_secret_env_vars({}) == {}


class TestDockerAvailable:
    def test_returns_bool(self):
        assert isinstance(docker_available(), bool)
