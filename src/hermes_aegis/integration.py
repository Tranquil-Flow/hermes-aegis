"""Hermes Agent integration — register TERMINAL_ENV=aegis backend.

Usage:
    # In Hermes config or startup, add to PYTHONPATH and import:
    import hermes_aegis.integration

    # Or call explicitly:
    from hermes_aegis.integration import register_aegis_backend
    register_aegis_backend()

    # Then set TERMINAL_ENV=aegis to use AegisEnvironment.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_PATCHED = False


# Auto-inject display hook if Aegis is active
if os.getenv("TERMINAL_ENV") == "aegis":
    try:
        from hermes_aegis.display import inject_aegis_status_hook
        inject_aegis_status_hook()
    except Exception:
        pass  # Fail silently


def register_aegis_backend() -> bool:
    """Monkey-patch Hermes's _create_environment to support TERMINAL_ENV=aegis.

    Returns True if patching succeeded, False if Hermes is not importable.
    """
    global _PATCHED
    if _PATCHED:
        return True

    try:
        import sys
        from pathlib import Path

        # Ensure Hermes is on path
        hermes_path = Path.home() / ".hermes" / "hermes-agent"
        if str(hermes_path) not in sys.path:
            sys.path.insert(0, str(hermes_path))

        import tools.terminal_tool as tt

        original_create = tt._create_environment

        def _patched_create_environment(env_type, image, cwd, timeout,
                                        ssh_config=None, container_config=None,
                                        task_id="default"):
            if env_type == "aegis":
                from hermes_aegis.environment import AegisEnvironment
                return AegisEnvironment(
                    image=image,
                    cwd=cwd,
                    timeout=timeout,
                )
            return original_create(
                env_type, image, cwd, timeout,
                ssh_config=ssh_config,
                container_config=container_config,
                task_id=task_id,
            )

        tt._create_environment = _patched_create_environment
        _PATCHED = True
        logger.info("Registered TERMINAL_ENV=aegis backend with Hermes")
        return True

    except ImportError as e:
        logger.debug("Hermes not found, skipping registration: %s", e)
        return False
    except Exception as e:
        logger.warning("Failed to register aegis backend: %s", e)
        return False
