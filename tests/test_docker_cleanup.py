"""Tests for docker_post_run_cleanup — concurrent session safety."""
from unittest.mock import patch, MagicMock, call
import subprocess

from hermes_aegis.utils import docker_post_run_cleanup, _other_aegis_sessions_running


def test_cleanup_skips_when_docker_unavailable():
    """Cleanup returns empty dict when Docker is not available."""
    with patch("hermes_aegis.utils.docker_available", return_value=False):
        result = docker_post_run_cleanup()
    assert result == {}


def test_cleanup_removes_stopped_containers():
    """Cleanup removes stopped minisweagent containers."""
    mock_ps = MagicMock(stdout="abc123\ndef456\n", returncode=0)
    mock_rm = MagicMock(returncode=0)

    def side_effect(cmd, **kwargs):
        if "ps" in cmd:
            return mock_ps
        if "rm" in cmd:
            assert "--force" in cmd, "Must use --force for race tolerance"
            assert "abc123" in cmd and "def456" in cmd
            return mock_rm
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils._other_aegis_sessions_running", return_value=False), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert result["containers"] == "2"


def test_cleanup_handles_no_stopped_containers():
    """Cleanup handles case where no stopped containers exist."""
    def side_effect(cmd, **kwargs):
        if "ps" in cmd:
            return MagicMock(stdout="", returncode=0)
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils._other_aegis_sessions_running", return_value=False), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "containers" not in result


def test_cleanup_survives_docker_errors():
    """Cleanup doesn't raise if Docker commands fail."""
    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils._other_aegis_sessions_running", return_value=False), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 10)):
        result = docker_post_run_cleanup()

    assert result == {}


def test_cleanup_prunes_dangling_images():
    """Cleanup prunes dangling images and reports reclaimed space."""
    def side_effect(cmd, **kwargs):
        if "image" in cmd and "prune" in cmd:
            return MagicMock(stdout="Total reclaimed space: 1.2GB\n", returncode=0)
        if "ps" in cmd:
            return MagicMock(stdout="", returncode=0)
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils._other_aegis_sessions_running", return_value=False), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "dangling_images" in result
    assert "1.2GB" in result["dangling_images"]


# --- Concurrent session safety ---


def test_skips_image_and_network_cleanup_when_other_sessions_active():
    """When other aegis sessions are running, only clean stopped containers."""
    calls_made = []

    def side_effect(cmd, **kwargs):
        calls_made.append(cmd)
        if "ps" in cmd:
            return MagicMock(stdout="abc123\n", returncode=0)
        if "rm" in cmd:
            return MagicMock(returncode=0)
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils._other_aegis_sessions_running", return_value=True), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    # Should have removed the stopped container
    assert result["containers"] == "1"
    # Should NOT have called image prune, builder prune, or network rm
    all_args = [str(c) for c in calls_made]
    assert not any("image" in str(c) and "prune" in str(c) for c in calls_made), \
        "Should not prune images when other sessions active"
    assert not any("builder" in str(c) for c in calls_made), \
        "Should not prune build cache when other sessions active"
    assert not any("network" in str(c) for c in calls_made), \
        "Should not touch network when other sessions active"


def test_full_cleanup_when_last_session():
    """When this is the only session, full cleanup runs."""
    calls_made = []

    def side_effect(cmd, **kwargs):
        calls_made.append(list(cmd))
        if "ps" in cmd:
            return MagicMock(stdout="", returncode=0)
        if "image" in cmd and "prune" in cmd:
            return MagicMock(stdout="Total reclaimed space: 500MB\n", returncode=0)
        if "builder" in cmd:
            return MagicMock(stdout="Total reclaimed space: 200MB\n", returncode=0)
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils._other_aegis_sessions_running", return_value=False), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "dangling_images" in result
    assert "build_cache" in result


def test_other_sessions_detection_single():
    """Single session (self) returns False."""
    # pgrep returns our own PID only
    mock_result = MagicMock(stdout="12345\n", returncode=0)
    with patch("hermes_aegis.utils.subprocess.run", return_value=mock_result):
        assert _other_aegis_sessions_running() is False


def test_other_sessions_detection_multiple():
    """Multiple sessions returns True."""
    mock_result = MagicMock(stdout="12345\n67890\n", returncode=0)
    with patch("hermes_aegis.utils.subprocess.run", return_value=mock_result):
        assert _other_aegis_sessions_running() is True


def test_other_sessions_assumes_yes_on_error():
    """If pgrep fails, assume other sessions exist (safe default)."""
    with patch("hermes_aegis.utils.subprocess.run",
               side_effect=subprocess.TimeoutExpired("pgrep", 5)):
        assert _other_aegis_sessions_running() is True


def test_network_rm_failure_is_silent():
    """Network rm failure (race with another session) doesn't report cleanup."""
    def side_effect(cmd, **kwargs):
        if "ps" in cmd:
            return MagicMock(stdout="", returncode=0)
        if "network" in cmd and "inspect" in cmd:
            return MagicMock(stdout="0\n", returncode=0)
        if "network" in cmd and "rm" in cmd:
            # Another session attached a container between inspect and rm
            return MagicMock(returncode=1, stderr="network has active endpoints")
        return MagicMock(stdout="", returncode=1)

    with patch("hermes_aegis.utils.docker_available", return_value=True), \
         patch("hermes_aegis.utils._other_aegis_sessions_running", return_value=False), \
         patch("hermes_aegis.utils.subprocess.run", side_effect=side_effect):
        result = docker_post_run_cleanup()

    assert "network" not in result, "Should not report network cleanup on rm failure"
