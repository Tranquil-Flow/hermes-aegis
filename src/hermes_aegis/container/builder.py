from __future__ import annotations

from dataclasses import dataclass


AEGIS_NETWORK = "hermes-aegis-net"


@dataclass
class ContainerConfig:
    workspace_path: str
    proxy_host: str = "host.docker.internal"
    proxy_port: int = 8443
    image_name: str = "hermes-aegis:latest"
    pids_limit: int = 256


def ensure_network(client) -> str:
    """Create a Docker network used by hermes-aegis-managed containers.
    
    Network is internal (no direct internet access) to force all traffic
    through the host-side proxy. This blocks DNS tunneling, direct TCP,
    and raw socket attacks.
    """

    try:
        net = client.networks.get(AEGIS_NETWORK)
        # Verify it's internal
        if not net.attrs.get("Internal", False):
            # Network exists but not internal - recreate it
            net.remove()
            raise Exception("recreate")
    except Exception:
        client.networks.create(
            AEGIS_NETWORK,
            driver="bridge",
            internal=True,  # No direct internet - all traffic via proxy
            labels={"managed-by": "hermes-aegis"},
        )
    return AEGIS_NETWORK


def build_run_args(config: ContainerConfig) -> dict:
    """Build Docker run arguments with hardening defaults."""
    from pathlib import Path

    proxy_url = f"http://{config.proxy_host}:{config.proxy_port}"
    cert_path = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")
    
    volumes = {
        config.workspace_path: {"bind": "/workspace", "mode": "rw"},
    }
    
    # Add CA cert if it exists (for HTTPS through proxy)
    if Path(cert_path).exists():
        volumes[cert_path] = {"bind": "/certs/mitmproxy-ca-cert.pem", "mode": "ro"}
    
    return {
        "image": config.image_name,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
        "read_only": True,
        "pids_limit": config.pids_limit,
        "mem_limit": "512m",
        "cpu_quota": 50000,
        "cpu_period": 100000,
        "user": "hermes",
        "volumes": volumes,
        "tmpfs": {
            "/tmp": "size=256m",
            "/var/tmp": "size=64m",
        },
        "environment": {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NO_PROXY": "localhost,127.0.0.1",
            "HOME": "/home/hermes",
            "REQUESTS_CA_BUNDLE": "/certs/mitmproxy-ca-cert.pem",
            "SSL_CERT_FILE": "/certs/mitmproxy-ca-cert.pem",
            "AEGIS_ACTIVE": "1",
            "AEGIS_CONTAINER_ISOLATED": "1",
        },
        "network": AEGIS_NETWORK,
        "extra_hosts": {
            "host.docker.internal": "host-gateway",
        },
        "detach": True,
        "auto_remove": True,  # Cleanup container on exit
    }
