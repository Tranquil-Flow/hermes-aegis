"""Tier auto-detection for hermes-aegis."""
import shutil
import subprocess


def docker_available() -> bool:
    """Check if Docker daemon is running and accessible."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def detect_tier(force_tier1: bool = False) -> int:
    """Return 1 or 2 based on available infrastructure."""
    if force_tier1:
        return 1
    return 2 if docker_available() else 1
