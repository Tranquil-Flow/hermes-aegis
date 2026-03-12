from __future__ import annotations

from dataclasses import dataclass


ARMOR_NETWORK = "hermes-aegis-net"


@dataclass
class ContainerConfig:
    workspace_path: str
    proxy_host: str = "host.docker.internal"
    proxy_port: int = 8443
    image_name: str = "hermes-aegis:latest"
    pids_limit: int = 256


def ensure_network(client) -> str:
    """Create a Docker network used by hermes-aegis-managed containers."""

    try:
        client.networks.get(ARMOR_NETWORK)
    except Exception:
        client.networks.create(
            ARMOR_NETWORK,
            driver="bridge",
            internal=False,
            labels={"managed-by": "hermes-aegis"},
        )
    return ARMOR_NETWORK


def build_run_args(config: ContainerConfig) -> dict:
    """Build Docker run arguments with hardening defaults."""

    proxy_url = f"http://{config.proxy_host}:{config.proxy_port}"
    return {
        "image": config.image_name,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
        "read_only": True,
        "pids_limit": config.pids_limit,
        "user": "hermes",
        "volumes": {
            config.workspace_path: {"bind": "/workspace", "mode": "rw"},
        },
        "tmpfs": {
            "/tmp": "size=256m",
            "/var/tmp": "size=64m",
        },
        "environment": {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NO_PROXY": "localhost,127.0.0.1",
            "HOME": "/home/hermes",
        },
        "network": ARMOR_NETWORK,
        "extra_hosts": {
            "host.docker.internal": "host-gateway",
        },

        "detach": True,
    }
