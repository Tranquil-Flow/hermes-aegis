"""Tests for docker_post_run_cleanup — image/cache/network cleanup only.

Container cleanup is intentionally omitted from the cleanup function
because hermes-agent uses --rm (auto-remove) on all containers, and
touching containers risks interfering with concurrent hermes sessions.
"""
from unittest.mock import patch, MagicMock
import subprocess

from hermes_aegis.utils import docker_post_run_cleanup


def test_cleanup_skips_when_docker_unavailable():
    """Cleanup returns empty dict when Docker is not available."""
    with patch("hermes_aegis.utils.docker_available", return_value=False):
        result = docker_post_run_cleanup()
    assert result == {}


def test_cleanup_prunes_dangling_images():
    """Cleanup prunes dangling images and reports reclaimed space."""
    def side_effect(cmd, **kwargs):
        if "image" in cmd and "prune" in cmd:
            return MagicMock(stdout="Total reclaimed space: 1.2GB\n", returncode=0)
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "dangling_images" in result
    assert "1.2GB" in result["dangling_images"]


def test_cleanup_prunes_old_build_cache():
    """Cleanup removes build cache older than 7 days."""
    def side_effect(cmd, **kwargs):
        if "builder" in cmd and "prune" in cmd:
            assert "until=168h" in cmd, "Must filter to cache older than 7 days"
            return MagicMock(stdout="Total reclaimed space: 500MB\n", returncode=0)
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "build_cache" in result
    assert "500MB" in result["build_cache"]


def test_cleanup_removes_unused_network():
    """Cleanup removes aegis network when no containers are connected."""
    def side_effect(cmd, **kwargs):
        if "network" in cmd and "inspect" in cmd:
            return MagicMock(stdout="0\n", returncode=0)
        if "network" in cmd and "rm" in cmd:
            return MagicMock(returncode=0)
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "network" in result


def test_network_rm_failure_is_silent():
    """Network rm failure (race with container attach) doesn't report cleanup."""
    def side_effect(cmd, **kwargs):
        if "network" in cmd and "inspect" in cmd:
            return MagicMock(stdout="0\n", returncode=0)
        if "network" in cmd and "rm" in cmd:
            return MagicMock(returncode=1, stderr="network has active endpoints")
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "network" not in result


def test_network_skipped_when_containers_attached():
    """Network is not removed when containers are still using it."""
    def side_effect(cmd, **kwargs):
        if "network" in cmd and "inspect" in cmd:
            return MagicMock(stdout="3\n", returncode=0)
        return MagicMock(stdout="", returncode=1)

    calls = []
    original_side_effect = side_effect

    def tracking_side_effect(cmd, **kwargs):
        calls.append(list(cmd))
        return original_side_effect(cmd, **kwargs)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=tracking_side_effect):
        result = docker_post_run_cleanup()

    assert "network" not in result
    # Verify no "docker network rm" call was made (inspect is fine)
    network_rm_calls = [
        c for c in calls if len(c) >= 3 and c[0] == "docker" and c[1] == "network" and c[2] == "rm"
    ]
    assert not network_rm_calls, "Should not attempt network rm when containers are attached"


def test_cleanup_survives_all_docker_errors():
    """Cleanup doesn't raise if every Docker command fails."""
    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run",
               side_effect=subprocess.TimeoutExpired("docker", 10)):
        result = docker_post_run_cleanup()

    assert result == {}


def test_cleanup_never_touches_containers():
    """Verify cleanup never runs docker ps, docker rm, or docker stop."""
    calls = []

    def side_effect(cmd, **kwargs):
        calls.append(list(cmd))
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        docker_post_run_cleanup()

    for call in calls:
        cmd_str = " ".join(str(c) for c in call)
        assert "docker ps" not in cmd_str, f"Should never list containers: {cmd_str}"
        assert "docker rm" not in cmd_str, f"Should never remove containers: {cmd_str}"
        assert "docker stop" not in cmd_str, f"Should never stop containers: {cmd_str}"
        assert "docker kill" not in cmd_str, f"Should never kill containers: {cmd_str}"
