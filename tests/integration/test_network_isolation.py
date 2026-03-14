"""Test network isolation with internal Docker network."""
import pytest
import docker
import shutil

from hermes_aegis.container.builder import ensure_network, AEGIS_NETWORK


pytestmark = pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")


@pytest.fixture
def docker_client():
    """Docker client with cleanup."""
    client = docker.from_env()
    created_containers = []
    created_networks = []

    yield client, created_containers, created_networks

    for container in created_containers:
        try:
            container.remove(force=True)
        except Exception:
            pass

    for network_name in created_networks:
        try:
            net = client.networks.get(network_name)
            for container in net.containers:
                try:
                    net.disconnect(container, force=True)
                except Exception:
                    pass
            net.remove()
        except Exception:
            pass


@pytest.fixture
def test_image(docker_client):
    """Find a locally available image with Python (no pull needed)."""
    client, _, _ = docker_client

    candidates = [
        "ofac-auto-updater:latest",
        "ofac-auto-updater:test",
    ]

    for image_name in candidates:
        try:
            client.images.get(image_name)
            return image_name
        except Exception:
            continue

    pytest.skip("No Python-capable Docker images available locally")


def test_network_is_internal(docker_client):
    """Aegis network should be internal (no direct internet access)."""
    client, _, networks = docker_client
    network_name = ensure_network(client)
    networks.append(network_name)

    net = client.networks.get(network_name)
    assert net.attrs.get("Internal") is True, \
        "Network is not internal - containers can bypass proxy!"


def test_container_cannot_reach_internet_directly(docker_client, test_image):
    """Container on internal network should not reach internet."""
    client, containers, networks = docker_client
    network_name = ensure_network(client)
    networks.append(network_name)

    container = client.containers.run(
        test_image,
        command='python3 -c "import socket; socket.create_connection((\'8.8.8.8\', 53), timeout=3)"',
        network=network_name,
        remove=False,
        detach=True,
    )
    containers.append(container)

    result = container.wait(timeout=10)
    logs = container.logs().decode()
    print(f"Container output: {logs}")

    # Non-zero exit = connection failed = network isolation working
    assert result["StatusCode"] != 0, \
        f"Container reached internet directly - network not isolated! Output: {logs}"


def test_host_docker_internal_resolves(docker_client, test_image):
    """host.docker.internal should resolve via extra_hosts on internal network.

    NOTE: On Docker Desktop for Mac with internal networks, the resolved IP
    may not be routable (Network is unreachable). This is expected — production
    Tier 2 will use a sidecar proxy container on the same internal network.
    This test verifies DNS resolution works via extra_hosts entry.
    """
    client, containers, networks = docker_client
    network_name = ensure_network(client)
    networks.append(network_name)

    container = client.containers.run(
        test_image,
        command='python3 -c "import socket; info=socket.getaddrinfo(\'host.docker.internal\', None); print(f\'RESOLVED:{info[0][4][0]}\')"',
        network=network_name,
        extra_hosts={"host.docker.internal": "host-gateway"},
        remove=False,
        detach=True,
    )
    containers.append(container)

    result = container.wait(timeout=10)
    logs = container.logs().decode()
    print(f"Container output: {logs}")

    assert "RESOLVED:" in logs, f"host.docker.internal did not resolve: {logs}"
