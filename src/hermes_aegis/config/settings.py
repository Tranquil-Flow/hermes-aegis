"""Persistent configuration management for hermes-aegis.

Stores settings in ~/.hermes-aegis/config.json with a simple key-value structure.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


class HermesConfig:
    """Read-only access to the Hermes agent config at ~/.hermes/config.yaml.

    Provides typed accessors for common fields and a generic dotted-key
    ``get()`` helper.  All accessors degrade gracefully when the config file
    is missing or unreadable — they return ``None`` / empty defaults instead
    of raising.
    """

    def __init__(self, hermes_dir: Optional[Path] = None) -> None:
        self._hermes_dir = hermes_dir or Path.home() / ".hermes"
        self._config_path = self._hermes_dir / "config.yaml"
        self._data: Optional[dict[str, Any]] = None
        self._loaded = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> dict[str, Any]:
        """Parse config.yaml once and cache the result."""
        if not self._loaded:
            self._loaded = True
            if self._config_path.is_file():
                try:
                    with open(self._config_path, "r") as f:
                        raw = yaml.safe_load(f)
                    if isinstance(raw, dict):
                        self._data = raw
                    else:
                        logger.warning(
                            "Hermes config at %s is not a mapping — ignoring",
                            self._config_path,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to read Hermes config at %s: %s",
                        self._config_path,
                        exc,
                    )
        return self._data or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the hermes config.yaml exists and is readable."""
        try:
            return self._config_path.is_file() and bool(self._ensure_loaded())
        except Exception:  # noqa: BLE001
            return False

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Retrieve a value using a dotted key path.

        Example::

            hc.get("terminal.backend")       # -> "docker"
            hc.get("model.provider", "local") # -> "anthropic"
        """
        data = self._ensure_loaded()
        parts = dotted_key.split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return default
            if current is None:
                return default
        return current

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def terminal_backend(self) -> Optional[str]:
        """Return the terminal backend name (e.g. 'docker', 'local', 'ssh')."""
        return self.get("terminal.backend")

    @property
    def model(self) -> Optional[str]:
        """Return the model name (e.g. 'claude-sonnet-4-20250514')."""
        return self.get("model.name")

    @property
    def session_settings(self) -> dict[str, Any]:
        """Return the ``session`` block as a dict (empty if absent)."""
        val = self.get("session")
        return val if isinstance(val, dict) else {}

    @property
    def volumes(self) -> list[str]:
        """Return the configured volume mounts (empty list if absent)."""
        val = self.get("terminal.volumes")
        return val if isinstance(val, list) else []

    @property
    def is_docker_backend(self) -> bool:
        """Return True if the terminal backend is 'docker'."""
        return self.terminal_backend == "docker"


class Settings:
    """Manage persistent configuration settings."""

    def __init__(self, config_path: Path):
        """Initialize settings manager.

        Args:
            config_path: Path to config.json file
        """
        self.config_path = config_path
        self._data: dict[str, Any] = {}
        self._mtime: float = 0.0
        self._hermes_config: Optional[HermesConfig] = None
        self.load()

    @property
    def hermes_config(self) -> HermesConfig:
        """Lazy-loaded accessor for the Hermes agent config (~/.hermes/config.yaml)."""
        if self._hermes_config is None:
            self._hermes_config = HermesConfig()
        return self._hermes_config

    def load(self) -> None:
        """Load settings from JSON file. Creates empty dict if file doesn't exist."""
        if not self.config_path.exists():
            self._data = self._get_defaults()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("Config must be a JSON object")
                self._data = data
                # Merge with defaults for any missing keys
                for key, value in self._get_defaults().items():
                    if key not in self._data:
                        self._data[key] = value
            try:
                self._mtime = self.config_path.stat().st_mtime
            except OSError:
                pass
        except (json.JSONDecodeError, ValueError) as e:
            # If file is corrupted, start with defaults
            logger.warning(
                "Corrupted config at %s (%s) — falling back to defaults",
                self.config_path, e,
            )
            self._data = self._get_defaults()

    def save(self) -> None:
        """Save settings to JSON file."""
        # Ensure parent directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            json.dump(self._data, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        try:
            if self.config_path.exists() and self.config_path.stat().st_mtime != self._mtime:
                self.load()
        except OSError:
            pass
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        self._data[key] = value
        self.save()

    def get_all(self) -> dict[str, Any]:
        """Get all configuration settings.
        
        Returns:
            Dictionary of all settings
        """
        return self._data.copy()

    @staticmethod
    def _get_defaults() -> dict[str, Any]:
        """Get default configuration values.
        
        Returns:
            Dictionary of default settings
        """
        return {
            # Dangerous command handling: "audit" (default) or "block"
            "dangerous_commands": "audit",
            # Rate limiting: max requests per time window (defaults: 50 requests in 1 second)
            "rate_limit_requests": 50,
            "rate_limit_window": 1.0,
        }
