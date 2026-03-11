from __future__ import annotations

from typing import Iterator

try:
    import docker
except ImportError:  # pragma: no cover - exercised via patching in tests
    docker = None

from hermes_aegis.container.builder import ContainerConfig, build_run_args, ensure_network


class ContainerRunner:
    """Manages the lifecycle of the hardened Hermes container."""

    def __init__(
        self,
        workspace_path: str,
        proxy_host: str = "host.docker.internal",
        proxy_port: int = 8443,
        image_name: str = "hermes-aegis:latest",
    ) -> None:
        if docker is None:
            raise RuntimeError("docker SDK is not installed")

        self._config = ContainerConfig(
            workspace_path=workspace_path,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            image_name=image_name,
        )
        self._client = docker.from_env()
        self._container = None

    def start(self) -> None:
        ensure_network(self._client)
        args = build_run_args(self._config)
        image = args.pop("image")
        self._container = self._client.containers.run(image, **args)

    def stop(self) -> None:
        if self._container is not None:
            self._container.stop(timeout=10)
            self._container.remove(force=True)
            self._container = None

    def logs(self, follow: bool = False) -> Iterator[bytes]:
        if self._container is None:
            return iter(())
        return iter(self._container.logs(stream=True, follow=follow))

    @property
    def is_running(self) -> bool:
        if self._container is None:
            return False
        self._container.reload()
        return self._container.status == "running"
