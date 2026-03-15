"""Container-Aegis handshake protocol.

When hermes runs inside a Docker container managed by aegis, this module
provides the coordination protocol:
- Aegis sets AEGIS_CONTAINER_ISOLATED=1 in the container
- The container has network isolation (internal Docker network)
- Aegis handles all network security (proxy, allowlist, secret blocking)
- Hermes can query the protection level to adjust its own checks
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class ProtectionLevel(Enum):
    NONE = "none"              # No aegis protection
    PROXY_ONLY = "proxy"       # MITM proxy active, no container
    CONTAINER_ONLY = "container"  # Container isolation, no proxy (unlikely)
    FULL = "full"              # Both proxy and container isolation


@dataclass
class AegisProtectionStatus:
    level: ProtectionLevel
    aegis_active: bool
    container_isolated: bool
    proxy_host: str | None
    proxy_port: int | None
    
    @property
    def network_secured(self) -> bool:
        return self.aegis_active and (self.container_isolated or self.proxy_host is not None)
    
    @property
    def can_relax_file_checks(self) -> bool:
        return self.container_isolated  # Container has read-only root
    
    @property
    def can_relax_network_checks(self) -> bool:
        return self.aegis_active  # Proxy handles network security


def detect_protection() -> AegisProtectionStatus:
    aegis_active = os.getenv("AEGIS_ACTIVE") == "1"
    container_isolated = os.getenv("AEGIS_CONTAINER_ISOLATED") == "1"
    
    proxy_host = None
    proxy_port = None
    https_proxy = os.getenv("HTTPS_PROXY", "")
    if https_proxy:
        # Parse http://host:port
        try:
            from urllib.parse import urlparse
            parsed = urlparse(https_proxy)
            proxy_host = parsed.hostname
            proxy_port = parsed.port
        except Exception:
            pass
    
    if aegis_active and container_isolated:
        level = ProtectionLevel.FULL
    elif aegis_active:
        level = ProtectionLevel.PROXY_ONLY
    elif container_isolated:
        level = ProtectionLevel.CONTAINER_ONLY
    else:
        level = ProtectionLevel.NONE
    
    return AegisProtectionStatus(
        level=level,
        aegis_active=aegis_active,
        container_isolated=container_isolated,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
    )
