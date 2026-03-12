"""Test network isolation with internal Docker network."""
import pytest
import docker
import shutil

from hermes_aegis.container.builder import ensure_network, ARMOR_NETWORK


pytestmark = pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")


@pytest.fixture
def docker_client():
    """Docker client with cleanup."""
    client = docker.from_env()
    yield client
    # Cleanup any test containers
    try:
        for container in client.containers.list(all=True):
            if "test-aegis" in container.name:
                container.remove(force=True)
    except Exception:
        pass


def test_network_is_internal(docker_client):
    """Aegis network should be internal (no direct internet access)."""
    network_name = ensure_network(docker_client)
    
    try:
        net = docker_client.networks.get(network_name)
        
        # Verify network is internal
        assert net.attrs.get("Internal") is True, \
            "Network is not internal - containers can bypass proxy!"
        
    finally:
        # Cleanup test network
        try:
            net = docker_client.networks.get(network_name)
            # Remove all containers from network first
            for container in net.containers:
                try:
                    net.disconnect(container, force=True)
                except Exception:
                    pass
            net.remove()
        except Exception:
            pass


def test_container_cannot_reach_internet_directly(docker_client):
    """Container on internal network should not reach internet."""
    network_name = ensure_network(docker_client)
    
    container = None
    try:
        # Start a simple container on internal network
        container = docker_client.containers.run(
            "python:3.11-slim",
            command='python3 -c "import socket; socket.create_connection((\'8.8.8.8\', 53), timeout=2)"',
            network=network_name,
            remove=False,  # Manuel cleanup for testing
            detach=False,
        )
        
        # Should fail to connect
        pytest.fail("Container reached internet directly - network not isolated!")
        
    except docker.errors.ContainerError as e:
        # Expected - connection should fail
        assert e.exit_status != 0, "Container connected to internet"
        
    finally:
        # Cleanup
        if container is not None:
            try:
                if hasattr(container, 'remove'):
                    container.remove(force=True)
            except Exception:
                pass
        
        # Cleanup network
        try:
            net = docker_client.networks.get(network_name)
            for cont in net.containers:
                try:
                    net.disconnect(cont, force=True)
                except Exception:
                    pass
            net.remove()
        except Exception:
            pass


def test_container_can_reach_host_via_host_docker_internal(docker_client):
    """Container should be able to reach host via host.docker.internal."""
    network_name = ensure_network(docker_client)
    
    container = None
    try:
        # Start container that tests host connectivity
        # This verifies proxy connectivity will work
        container = docker_client.containers.run(
            "python:3.11-slim",
            command='python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect((\'host.docker.internal\', 22)); print(\'CONNECTED\')"',
            network=network_name,
            extra_hosts={"host.docker.internal": "host-gateway"},
            remove=False,
            detach=False,
        )
        
        # Connection attempt made (might fail if nothing on port 22, but shouldn't be "no route")
        # We just want to verify host.docker.internal resolves
        
    except docker.errors.ContainerError as e:
        # Check error message - should be "connection refused" not "no route"
        if "Network is unreachable" in e.stderr.decode():
            pytest.fail("host.docker.internal not reachable - proxy won't work!")
        # Connection refused is OK - means host is reachable, just nothing on port 22
        
    finally:
        # Cleanup
        if container is not None:
            try:
                if hasattr(container, 'remove'):
                    container.remove(force=True)
            except Exception:
                pass
        
        try:
            net = docker_client.networks.get(network_name)
            for cont in net.containers:
                try:
                    net.disconnect(cont, force=True)
                except Exception:
                    pass
            net.remove()
        except Exception:
            pass
