from unittest.mock import MagicMock, patch

import pytest

import hermes_aegis.container.runner as container_runner
from hermes_aegis.container.builder import ContainerConfig, build_run_args, ensure_network
from hermes_aegis.container.runner import ContainerRunner


class TestContainerConfig:
    def test_default_hardening_flags(self):
        config = ContainerConfig(workspace_path="/home/user/project")

        args = build_run_args(config)

        assert args["cap_drop"] == ["ALL"]
        assert args["security_opt"] == ["no-new-privileges"]
        assert args["read_only"] is True
        assert args["pids_limit"] == 256
        assert args["user"] == "hermes"

    def test_workspace_volume(self):
        config = ContainerConfig(workspace_path="/home/user/project")

        args = build_run_args(config)

        assert "/home/user/project" in args["volumes"]

    def test_proxy_env(self):
        config = ContainerConfig(
            workspace_path="/tmp",
            proxy_host="host.docker.internal",
            proxy_port=8443,
        )

        args = build_run_args(config)

        assert "HTTP_PROXY" in args["environment"]
        assert "8443" in args["environment"]["HTTP_PROXY"]

    def test_no_secrets_in_env(self):
        config = ContainerConfig(workspace_path="/tmp")

        args = build_run_args(config)
        env = args["environment"]

        for key in env:
            assert "SECRET" not in key.upper() or key.startswith("HTTP")
            assert "API_KEY" not in key.upper()

    def test_resource_limits(self):
        config = ContainerConfig(workspace_path="/tmp")

        args = build_run_args(config)

        assert args["mem_limit"] == "512m"
        assert args["cpu_quota"] == 50000
        assert args["cpu_period"] == 100000
        assert args["pids_limit"] == 256

    def test_ensure_network_reuses_existing_internal_network(self):
        client = MagicMock()
        network = MagicMock()
        network.attrs = {"Internal": True}
        client.networks.get.return_value = network

        name = ensure_network(client)

        assert name == "hermes-aegis-net"
        network.remove.assert_not_called()
        client.networks.create.assert_not_called()

    def test_ensure_network_recreates_non_internal_network(self):
        client = MagicMock()
        network = MagicMock()
        network.attrs = {"Internal": False}
        client.networks.get.return_value = network

        name = ensure_network(client)

        assert name == "hermes-aegis-net"
        network.remove.assert_called_once()
        client.networks.create.assert_called_once_with(
            "hermes-aegis-net",
            driver="bridge",
            internal=True,
            labels={"managed-by": "hermes-aegis"},
        )

    def test_ensure_network_creates_missing_network(self):
        client = MagicMock()
        client.networks.get.side_effect = Exception("missing")

        name = ensure_network(client)

        assert name == "hermes-aegis-net"
        client.networks.create.assert_called_once_with(
            "hermes-aegis-net",
            driver="bridge",
            internal=True,
            labels={"managed-by": "hermes-aegis"},
        )


class TestContainerRunner:
    @patch("hermes_aegis.container.runner.docker")
    def test_start_creates_container(self, mock_docker):
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container

        runner = ContainerRunner(workspace_path="/tmp/test")
        runner.start()

        mock_client.containers.run.assert_called_once()
        call_kwargs = mock_client.containers.run.call_args[1]
        assert call_kwargs["cap_drop"] == ["ALL"]
        assert call_kwargs["read_only"] is True

    @patch("hermes_aegis.container.runner.docker")
    def test_stop_kills_container(self, mock_docker):
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container

        runner = ContainerRunner(workspace_path="/tmp/test")
        runner.start()
        runner.stop()

        mock_container.stop.assert_called_once()

    @patch("hermes_aegis.container.runner.docker")
    def test_logs_streams_output(self, mock_docker):
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_container = MagicMock()
        mock_container.logs.return_value = [b"line1\n", b"line2\n"]
        mock_client.containers.run.return_value = mock_container

        runner = ContainerRunner(workspace_path="/tmp/test")
        runner.start()
        logs = list(runner.logs())

        assert len(logs) == 2

    def test_raises_clear_error_when_docker_sdk_missing(self, monkeypatch):
        monkeypatch.setattr(container_runner, "docker", None)

        with pytest.raises(RuntimeError, match="docker SDK is not installed"):
            ContainerRunner(workspace_path="/tmp/test")

    @patch("hermes_aegis.container.runner.docker")
    def test_is_running_false_before_start(self, mock_docker):
        mock_docker.from_env.return_value = MagicMock()

        runner = ContainerRunner(workspace_path="/tmp/test")

        assert runner.is_running is False

    @patch("hermes_aegis.container.runner.docker")
    def test_is_running_reloads_container_status(self, mock_docker):
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_client.containers.run.return_value = mock_container

        runner = ContainerRunner(workspace_path="/tmp/test")
        runner.start()

        assert runner.is_running is True
        mock_container.reload.assert_called_once()
