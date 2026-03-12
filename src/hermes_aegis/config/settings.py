"""Persistent configuration management for hermes-aegis.

Stores settings in ~/.hermes-aegis/config.json with a simple key-value structure.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


class Settings:
    """Manage persistent configuration settings."""

    def __init__(self, config_path: Path):
        """Initialize settings manager.
        
        Args:
            config_path: Path to config.json file
        """
        self.config_path = config_path
        self._data: dict[str, Any] = {}
        self.load()

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
        except (json.JSONDecodeError, ValueError):
            # If file is corrupted, start with defaults
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
