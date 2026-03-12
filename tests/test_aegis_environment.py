"""Tests for AegisEnvironment backend."""
import pytest  
from pathlib import Path
from unittest.mock import MagicMock, patch

from hermes_aegis.environment import AegisEnvironment, docker_available, find_available_port, wait_for_proxy_ready


class TestAegisEnvironment:
    """Test AegisEnvironment backend initialization and execution."""

    def test_detects_tier_correctly(self):
        """Should detect Tier 1 when Docker unavailable, Tier 2 when available."""
        env = AegisEnvironment()
        
        # Tier depends on Docker availability
        if docker_available():
            assert env._tier == 2
        else:
            assert env._tier == 1
        
        env.cleanup()

    def test_strips_secrets_from_env(self):
        """Should strip secret-looking environment variables."""
        env_with_secrets = {
            "OPENAI_API_KEY": "sk-secret123",
            "NORMAL_VAR": "safe_value",
            "AWS_SECRET_ACCESS_KEY": "aws-secret456",
            "MY_PASSWORD": "pass123",
            "PATH": "/usr/bin"
        }
        
        env = AegisEnvironment(env=env_with_secrets)
        cleaned = env._strip_secret_env_vars(env_with_secrets)
        
        # Secrets should be stripped
        assert "OPENAI_API_KEY" not in cleaned
        assert "AWS_SECRET_ACCESS_KEY" not in cleaned
        assert "MY_PASSWORD" not in cleaned
        
        # Normal vars should pass through
        assert cleaned["NORMAL_VAR"] == "safe_value"
        assert cleaned["PATH"] == "/usr/bin"
        
        env.cleanup()

    def test_adds_proxy_env_vars_when_tier2(self):
        """Tier 2 should add proxy environment variables."""
        with patch('hermes_aegis.environment.docker_available', return_value=True):
            env = AegisEnvironment()
            
            # Check proxy vars were set
            if hasattr(env, '_clean_env'):
                assert "HTTP_PROXY" in env._clean_env
                assert "host.docker.internal" in env._clean_env["HTTP_PROXY"]
                assert "HTTPS_PROXY" in env._clean_env
                assert "REQUESTS_CA_BUNDLE" in env._clean_env
            
            env.cleanup()

    @patch('hermes_aegis.environment.docker_available')
    def test_tier1_uses_local_when_no_docker(self, mock_docker):
        """Should fall back to Tier 1 when Docker not available."""
        mock_docker.return_value = False
        
        env = AegisEnvironment()
        
        assert env._tier == 1
        env.cleanup()

    @patch('hermes_aegis.environment.docker_available')
    def test_execute_delegates_to_inner(self, mock_docker):
        """execute() should delegate to inner environment."""
        mock_docker.return_value = False  # Use Tier 1 to avoid proxy startup
        
        env = AegisEnvironment()
        
        # Mock the inner environment
        env._inner = MagicMock()
        env._inner.execute.return_value = {"output": "test output", "returncode": 0}
        
        result = env.execute("ls -la")
        
        env._inner.execute.assert_called_once_with("ls -la", "", timeout=None, stdin_data=None)
        assert result["output"] == "test output"
        assert result["returncode"] == 0
        
        env.cleanup()

    def test_cleanup_calls_inner_cleanup(self):
        """cleanup() should cleanup inner environment."""
        env = AegisEnvironment()
        env._inner = MagicMock()
        
        env.cleanup()
        
        env._inner.cleanup.assert_called_once()


class TestUtilityFunctions:
    """Test helper functions."""

    def test_find_available_port(self):
        """Should find an available port in range."""
        port = find_available_port(start=9000, end=9100)
        
        assert 9000 <= port < 9100
        
        # Verify port is actually available
        import socket
        sock = socket.socket()
        try:
            sock.bind(('localhost', port))
            sock.close()
        except OSError:
            pytest.fail(f"Port {port} claimed to be available but binding failed")

    def test_wait_for_proxy_ready_timeout(self):
        """Should return False if proxy doesn't start."""
        # Pick a port nothing is listening on
        result = wait_for_proxy_ready(port=9999, timeout=1)
        
        assert result is False

    def test_docker_available(self):
        """Should detect Docker availability."""
        result = docker_available()
        
        # Result depends on environment
        assert isinstance(result, bool)
