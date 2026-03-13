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


def get_hermes_backend() -> str:
    """Get Hermes Agent's configured backend setting.
    
    Returns:
        Backend name (local/docker/ssh/modal/etc) or 'local' if not found
    """
    try:
        from pathlib import Path
        import yaml
        
        # Check environment variable first
        terminal_backend = os.getenv("TERMINAL_BACKEND")
        if terminal_backend:
            return terminal_backend
        
        # Check Hermes config file
        hermes_config = Path.home() / ".hermes" / "config.yaml"
        if hermes_config.exists():
            with open(hermes_config) as f:
                config = yaml.safe_load(f) or {}
                backend = config.get("terminal", {}).get("backend") or config.get("backend")
                if backend:
                    return backend
    except Exception:
        pass
    
    return "local"  # Default


def detect_tier(force_tier1: bool = False) -> int:
    """Return 1 or 2 based on infrastructure and Hermes backend setting.
    
    Args:
        force_tier1: Explicitly force Tier 1 mode
        
    Returns:
        1 for Tier 1 (in-process), 2 for Tier 2 (container)
        
    Tier selection priority:
    1. force_tier1 parameter = True → Tier 1
    2. AEGIS_FORCE_TIER1 env var set → Tier 1
    3. force_tier1 in Aegis config → Tier 1
    4. Hermes backend: docker → Tier 2 (if image available, else warn & Tier 1)
    5. Hermes backend: local/ssh/etc → Tier 1
    6. Auto-detect: Docker + image available → Tier 2
    7. Default → Tier 1
    """
    # Check explicit force flag
    if force_tier1:
        return 1
    
    # Check environment variable
    if os.getenv("AEGIS_FORCE_TIER1"):
        return 1
    
    # Check Aegis config (if available)
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
    
    # Check Hermes backend setting
    hermes_backend = get_hermes_backend()
    if hermes_backend == "docker":
        # User wants Docker backend → use Tier 2 if available
        if docker_image_available():
            return 2
        else:
            # Image not built - print warning and fall back to Tier 1
            import sys
            print("⚠️  Hermes backend set to 'docker' but Aegis Tier 2 image not built.", file=sys.stderr)
            print("   Run: hermes-aegis setup", file=sys.stderr)
            print("   Falling back to Aegis Tier 1.", file=sys.stderr)
            return 1
    
    # For local/ssh/modal/etc backends, use Tier 1
    if hermes_backend in ["local", "ssh", "modal", "singularity", "daytona"]:
        return 1
    
    # Auto-detect based on Docker + image availability (legacy behavior)
    return 2 if docker_image_available() else 1
