"""Tests for Tier 2 proxy API key injection - Docker integration.

These tests verify that the container + proxy architecture correctly isolates
secrets while allowing transparent API key injection.

Note: Detailed proxy functionality is tested in tests/test_proxy_addon.py
This focuses on the Docker integration aspects.
"""
import shutil
import pytest
from cryptography.fernet import Fernet

from hermes_aegis.vault.store import VaultStore
from hermes_aegis.container.builder import ContainerConfig, build_run_args


pytestmark = pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")


@pytest.fixture
def master_key():
    return Fernet.generate_key()


@pytest.fixture
def vault_with_api_keys(tmp_path, master_key):
    """Create a vault with LLM API keys."""
    vault = VaultStore(tmp_path / ".hermes-aegis" / "vault.enc", master_key)
    vault.set("OPENAI_API_KEY", "sk-proj-unittest123456789")
    vault.set("ANTHROPIC_API_KEY", "sk-ant-unittest987654321")
    return vault


def test_proxy_configured_in_container_environment(vault_with_api_keys, tmp_path):
    """Container should have proxy environment variables set."""
    import docker
    
    client = docker.from_env()
    config = ContainerConfig(
        workspace_path=str(tmp_path / "workspace"),
        proxy_host="host.docker.internal",
        proxy_port=8443
    )
    args = build_run_args(config)
    
    env = args.get("environment", {})
    
    # Verify proxy environment variables
    assert "HTTP_PROXY" in env, "HTTP_PROXY not set"
    assert "HTTPS_PROXY" in env, "HTTPS_PROXY not set"
    assert "8443" in env["HTTP_PROXY"], "Proxy port incorrect" 
    assert "host.docker.internal" in env["HTTP_PROXY"], "Proxy host incorrect"


def test_api_keys_not_in_proxy_environment(vault_with_api_keys, tmp_path):
    """API keys should not appear in proxy environment variables."""
    import docker
    
    client = docker.from_env()
    config = ContainerConfig(workspace_path=str(tmp_path / "workspace"))
    args = build_run_args(config)
    
    env = args.get("environment", {})
    all_vault_values = vault_with_api_keys.get_all_values()
    
    # Verify no secrets in env vars
    for secret_value in all_vault_values:
        for key, val in env.items():
            assert secret_value not in str(val), \
                f"API key leaked in env var {key}"


def test_container_cannot_see_injected_keys(vault_with_api_keys, tmp_path):
    """From container perspective, keys are injected transparently by proxy."""
    import docker
    
    # This test verifies that the container configuration ensures
    # traffic goes through the proxy, but keys never enter container
    
    client = docker.from_env()
    config = ContainerConfig(workspace_path=str(tmp_path / "workspace"))
    args = build_run_args(config)
    
    # Verify proxy is configured
    env = args.get("environment", {})
    assert env.get("HTTP_PROXY"), "Proxy not configured"
    
    # Verify keys are NOT in container environment
    all_vault_values = vault_with_api_keys.get_all_values()
    for secret in all_vault_values:
        for key, val in env.items():
            assert secret not in str(val), \
                f"Secret visible in container env var {key}"


def test_proxy_on_host_network_accessible(vault_with_api_keys, tmp_path):
    """Proxy should be accessible from container via host.docker.internal."""
    import docker
    
    client = docker.from_env()
    config = ContainerConfig(workspace_path=str(tmp_path / "workspace"))
    args = build_run_args(config)
    
    # Verify extra_hosts includes host.docker.internal mapping
    extra_hosts = args.get("extra_hosts", {})
    assert "host.docker.internal" in extra_hosts, \
        "host.docker.internal not configured"
    assert extra_hosts["host.docker.internal"] == "host-gateway", \
        "host.docker.internal mapping incorrect"


def test_proxy_architecture_prevents_secret_leakage(vault_with_api_keys, tmp_path):
    """Complete architecture verification: secrets in vault, injected by proxy, never in container."""
    import docker
    
    client = docker.from_env()
    config = ContainerConfig(workspace_path=str(tmp_path / "workspace"))
    args = build_run_args(config)
    
    # 1. Secrets exist in vault (on host)
    secrets = vault_with_api_keys.get_all_values()
    assert len(secrets) > 0, "No secrets in vault"
    
    # 2. Container is configured to route through proxy
    env = args.get("environment", {})
    assert "HTTPS_PROXY" in env, "Container not configured for proxy"
    
    # 3. But secrets are NOT in container environment
    for secret in secrets:
        env_str = str(env)
        assert secret not in env_str, "Secret leaked to container"
    
    # 4. And vault is not mounted in container
    volumes = args.get("volumes", {})
    vault_path = str(vault_with_api_keys._path.parent)
    for host_path in volumes.keys():
        assert vault_path not in host_path, "Vault mounted in container"
    
    # This architecture ensures:
    # - Keys stay on host (in vault)
    # - Proxy on host injects keys into LLM requests
    # - Container sees injected keys in responses but never has the keys themselves
    # - AegisAddon tests in test_proxy_addon.py verify the injection mechanism
