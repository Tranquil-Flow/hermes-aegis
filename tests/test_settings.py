"""Tests for hermes_aegis.config.settings module."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from hermes_aegis.config.settings import Settings


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    return tmp_path / "config.json"


def test_default_creation_when_file_missing(config_path: Path):
    """Settings creates defaults when config file doesn't exist."""
    assert not config_path.exists()
    s = Settings(config_path)
    assert s.get("dangerous_commands") == "audit"
    assert s.get("rate_limit_requests") == 50
    assert s.get("rate_limit_window") == 1.0


def test_save_creates_file(config_path: Path):
    """save() creates the JSON file on disk."""
    s = Settings(config_path)
    s.save()
    assert config_path.exists()
    data = json.loads(config_path.read_text())
    assert data["dangerous_commands"] == "audit"
    assert data["rate_limit_requests"] == 50


def test_save_creates_parent_dirs(tmp_path: Path):
    """save() creates parent directories if they don't exist."""
    nested = tmp_path / "a" / "b" / "config.json"
    s = Settings(nested)
    s.save()
    assert nested.exists()


def test_get_returns_default_for_unknown_key(config_path: Path):
    """get() returns default for keys that don't exist."""
    s = Settings(config_path)
    assert s.get("nonexistent") is None
    assert s.get("nonexistent", "fallback") == "fallback"
    assert s.get("nonexistent", 42) == 42


def test_set_and_get(config_path: Path):
    """set() stores value retrievable via get()."""
    s = Settings(config_path)
    s.set("dangerous_commands", "block")
    assert s.get("dangerous_commands") == "block"


def test_set_auto_saves(config_path: Path):
    """set() automatically persists to disk."""
    s = Settings(config_path)
    s.set("rate_limit_requests", 100)
    data = json.loads(config_path.read_text())
    assert data["rate_limit_requests"] == 100


def test_set_custom_key(config_path: Path):
    """set() works with arbitrary new keys."""
    s = Settings(config_path)
    s.set("custom_key", {"nested": True})
    assert s.get("custom_key") == {"nested": True}


def test_persistence_across_instances(config_path: Path):
    """Settings persisted by one instance are loaded by another."""
    s1 = Settings(config_path)
    s1.set("dangerous_commands", "block")
    s1.set("custom", "value")

    s2 = Settings(config_path)
    assert s2.get("dangerous_commands") == "block"
    assert s2.get("custom") == "value"
    # Defaults still present
    assert s2.get("rate_limit_requests") == 50


def test_auto_reload_on_external_modification(config_path: Path):
    """get() reloads when file mtime changes."""
    s = Settings(config_path)
    s.save()

    # Externally modify the file
    data = json.loads(config_path.read_text())
    data["dangerous_commands"] = "block"
    # Ensure mtime differs (some filesystems have 1s granularity)
    time.sleep(0.05)
    config_path.write_text(json.dumps(data))
    # Force mtime difference
    import os
    os.utime(config_path, (time.time() + 10, time.time() + 10))

    assert s.get("dangerous_commands") == "block"


def test_get_all_returns_copy(config_path: Path):
    """get_all() returns a copy, not the internal dict."""
    s = Settings(config_path)
    all_settings = s.get_all()
    assert isinstance(all_settings, dict)
    assert all_settings["dangerous_commands"] == "audit"

    # Mutating the copy should not affect the Settings instance
    all_settings["dangerous_commands"] = "MUTATED"
    assert s.get("dangerous_commands") == "audit"


def test_get_all_contains_all_defaults(config_path: Path):
    """get_all() contains all default keys."""
    s = Settings(config_path)
    all_settings = s.get_all()
    assert "dangerous_commands" in all_settings
    assert "rate_limit_requests" in all_settings
    assert "rate_limit_window" in all_settings


def test_load_merges_defaults_for_missing_keys(config_path: Path):
    """Loading a partial config merges in missing default keys."""
    config_path.write_text(json.dumps({"dangerous_commands": "block"}))
    s = Settings(config_path)
    assert s.get("dangerous_commands") == "block"
    assert s.get("rate_limit_requests") == 50
    assert s.get("rate_limit_window") == 1.0


def test_corrupted_file_falls_back_to_defaults(config_path: Path):
    """Corrupted JSON file triggers fallback to defaults."""
    config_path.write_text("not valid json {{{")
    s = Settings(config_path)
    assert s.get("dangerous_commands") == "audit"
    assert s.get("rate_limit_requests") == 50


def test_non_dict_json_falls_back_to_defaults(config_path: Path):
    """JSON file containing non-dict value falls back to defaults."""
    config_path.write_text(json.dumps([1, 2, 3]))
    s = Settings(config_path)
    assert s.get("dangerous_commands") == "audit"


def test_load_explicit_reload(config_path: Path):
    """Explicit load() refreshes from disk."""
    s = Settings(config_path)
    s.save()

    # Write directly to file
    config_path.write_text(json.dumps({"rate_limit_requests": 999}))
    s.load()
    assert s.get("rate_limit_requests") == 999
