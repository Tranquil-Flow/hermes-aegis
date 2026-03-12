"""Tests for Tier 2 container secret isolation.

These tests verify that secrets in the vault are NOT accessible inside containers.
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
def vault_with_secrets(tmp_path, master_key):
    """Create a vault with test secrets."""
    vault = VaultStore(tmp_path / ".hermes-aegis" / "vault.enc", master_key)
    vault.set("OPENAI_API_KEY", "sk-proj-test123456789")
    vault.set("ANTHROPIC_API_KEY", "sk-ant-test987654321")
    vault.set("AWS_SECRET_KEY", "aws-secret-abc123")
    return vault


def test_secrets_not_in_container_environment(vault_with_secrets, tmp_path):
    """Secrets should not appear in container environment variables."""
    import docker
    
    client = docker.from_env()
    config = ContainerConfig(workspace_path=str(tmp_path / "workspace"))
    args = build_run_args(config)
    
    # Check that no secret values appear in environment
    env = args.get("environment", {})
    all_vault_values = vault_with_secrets.get_all_values()
    
    for secret_value in all_vault_values:
        for key, val in env.items():
            assert secret_value not in str(val), f"Secret leaked in env var {key}"


def test_vault_path_not_in_container_volumes(vault_with_secrets, tmp_path):
    """Vault file path should not be mounted as a volume."""
    import docker
    
    client = docker.from_env()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    vault_path = str(vault_with_secrets._path.parent)
    
    config = ContainerConfig(workspace_path=str(workspace))
    args = build_run_args(config)
    
    # Check volumes - vault path should not be mounted
    volumes = args.get("volumes", {})
    for host_path in volumes.keys():
        assert vault_path not in host_path, f"Vault path {vault_path} exposed in volumes"


def test_no_home_directory_mounted(vault_with_secrets, tmp_path):
    """Home directory should not be mounted (vault lives in ~/.hermes-aegis)."""
    import docker
    import os
    
    client = docker.from_env()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    home_dir = os.path.expanduser("~")
    
    config = ContainerConfig(workspace_path=str(workspace))
    args = build_run_args(config)
    
    # Check volumes - home directory should not be mounted
    # Exception: CA cert (read-only, not sensitive)
    volumes = args.get("volumes", {})
    for host_path in volumes.keys():
        # CA cert is acceptable (read-only, not a secret)
        if "mitmproxy-ca-cert.pem" in host_path:
            continue
        assert not host_path.startswith(home_dir), \
            f"Home directory {home_dir} exposed in volumes at {host_path}"


def test_container_user_not_root(vault_with_secrets, tmp_path):
    """Container should run as non-root user to limit filesystem access."""
    import docker
    
    client = docker.from_env()
    config = ContainerConfig(workspace_path=str(tmp_path / "workspace"))
    args = build_run_args(config)
    
    # Verify user is not root
    user = args.get("user")
    assert user is not None, "No user specified, container will run as root"
    assert user != "root", "Container runs as root"
    assert user != "0", "Container runs as root (UID 0)"


def test_container_filesystem_readonly(vault_with_secrets, tmp_path):
    """Container filesystem should be read-only to prevent secret exfiltration via disk."""
    import docker
    
    client = docker.from_env()
    config = ContainerConfig(workspace_path=str(tmp_path / "workspace"))
    args = build_run_args(config)
    
    # Verify read-only mode
    assert args.get("read_only") is True, "Container filesystem is writable"


def test_workspace_is_only_writable_mount(vault_with_secrets, tmp_path):
    """Only the workspace should be writable, preventing secret persistence."""
    import docker
    
    client = docker.from_env()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = ContainerConfig(workspace_path=str(workspace))
    args = build_run_args(config)
    
    # Check volumes
    volumes = args.get("volumes", {})
    
    # Count writable volumes (excludes CA cert which is read-only)
    writable_volumes = {k: v for k, v in volumes.items() if v.get("mode") != "ro"}
    
    # Should only have one writable volume - the workspace
    assert len(writable_volumes) == 1, f"Expected 1 writable volume, got {len(writable_volumes)}"
    
    # Verify workspace is mounted
    workspace_vol = volumes.get(str(workspace))
    assert workspace_vol is not None, "Workspace not mounted"
    assert workspace_vol["bind"] == "/workspace", "Workspace bind path incorrect"
    assert workspace_vol["mode"] == "rw", "Workspace should be read-write"
