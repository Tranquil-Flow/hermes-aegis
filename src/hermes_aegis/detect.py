"""Tier auto-detection for hermes-aegis."""
import os
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


def docker_image_available() -> bool:
    """Check if hermes-aegis Docker image is built."""
    if not docker_available():
        return False
    try:
        result = subprocess.run(
            ["docker", "images", "-q", "hermes-aegis:latest"],
            capture_output=True,
            timeout=5,
            text=True,
        )
        return bool(result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def detect_tier(force_tier1: bool = False) -> int:
    """Return 1 or 2 based on available infrastructure.
    
    Args:
        force_tier1: Explicitly force Tier 1 mode
        
    Returns:
        1 for Tier 1 (in-process), 2 for Tier 2 (container)
        
    Tier selection priority:
    1. force_tier1 parameter = True → Tier 1
    2. AEGIS_FORCE_TIER1 env var set → Tier 1
    3. force_tier1 in config → Tier 1
    4. Docker available AND image built → Tier 2
    5. Default → Tier 1
    """
    # Check explicit force flag
    if force_tier1:
        return 1
    
    # Check environment variable
    if os.getenv("AEGIS_FORCE_TIER1"):
        return 1
    
    # Check config (if available)
    try:
        from pathlib import Path
        from hermes_aegis.config.settings import Settings
        config_path = Path.home() / ".hermes-aegis" / "config.json"
        if config_path.exists():
            settings = Settings(config_path)
            if settings.get("force_tier1"):
                return 1
    except Exception:
        pass  # Config not available or broken, continue
    
    # Auto-detect based on Docker + image availability
    return 2 if docker_image_available() else 1
