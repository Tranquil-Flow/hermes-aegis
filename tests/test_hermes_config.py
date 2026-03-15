"""Tests for HermesConfig and Settings.hermes_config integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from hermes_aegis.config.settings import HermesConfig, Settings

SAMPLE_CONFIG = {
    "model": {
        "provider": "anthropic",
        "name": "claude-sonnet-4-20250514",
    },
    "terminal": {
        "backend": "docker",
        "image": "hermes-sandbox",
        "volumes": ["/home/user/projects:/workspace/projects"],
    },
    "session": {
        "id_prefix": "hermes",
        "timeout": 300,
    },
}


@pytest.fixture
def hermes_dir(tmp_path: Path) -> Path:
    """Create a temporary hermes dir with a valid config.yaml."""
    hdir = tmp_path / ".hermes"
    hdir.mkdir()
    with open(hdir / "config.yaml", "w") as f:
        yaml.dump(SAMPLE_CONFIG, f)
    return hdir


@pytest.fixture
def empty_hermes_dir(tmp_path: Path) -> Path:
    """A hermes dir that does NOT contain config.yaml."""
    hdir = tmp_path / ".hermes-missing"
    hdir.mkdir()
    return hdir


# ── HermesConfig: missing config ─────────────────────────────────────


class TestHermesConfigMissing:
    def test_is_available_false(self, empty_hermes_dir: Path):
        hc = HermesConfig(hermes_dir=empty_hermes_dir)
        assert hc.is_available() is False

    def test_terminal_backend_none(self, empty_hermes_dir: Path):
        hc = HermesConfig(hermes_dir=empty_hermes_dir)
        assert hc.terminal_backend is None

    def test_model_none(self, empty_hermes_dir: Path):
        hc = HermesConfig(hermes_dir=empty_hermes_dir)
        assert hc.model is None

    def test_session_settings_empty(self, empty_hermes_dir: Path):
        hc = HermesConfig(hermes_dir=empty_hermes_dir)
        assert hc.session_settings == {}

    def test_volumes_empty(self, empty_hermes_dir: Path):
        hc = HermesConfig(hermes_dir=empty_hermes_dir)
        assert hc.volumes == []

    def test_is_docker_backend_false(self, empty_hermes_dir: Path):
        hc = HermesConfig(hermes_dir=empty_hermes_dir)
        assert hc.is_docker_backend is False

    def test_get_returns_default(self, empty_hermes_dir: Path):
        hc = HermesConfig(hermes_dir=empty_hermes_dir)
        assert hc.get("terminal.backend", "fallback") == "fallback"


# ── HermesConfig: valid config ───────────────────────────────────────


class TestHermesConfigValid:
    def test_is_available(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.is_available() is True

    def test_terminal_backend(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.terminal_backend == "docker"

    def test_model(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.model == "claude-sonnet-4-20250514"

    def test_session_settings(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.session_settings == {"id_prefix": "hermes", "timeout": 300}

    def test_volumes(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.volumes == ["/home/user/projects:/workspace/projects"]

    def test_is_docker_backend_true(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.is_docker_backend is True

    def test_is_docker_backend_false_for_local(self, tmp_path: Path):
        hdir = tmp_path / ".hermes-local"
        hdir.mkdir()
        cfg = {"terminal": {"backend": "local"}}
        with open(hdir / "config.yaml", "w") as f:
            yaml.dump(cfg, f)
        hc = HermesConfig(hermes_dir=hdir)
        assert hc.is_docker_backend is False


# ── Dotted key access ────────────────────────────────────────────────


class TestDottedKeyAccess:
    def test_top_level_key(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        model_block = hc.get("model")
        assert isinstance(model_block, dict)
        assert model_block["provider"] == "anthropic"

    def test_nested_key(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.get("model.provider") == "anthropic"

    def test_deeply_nested(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.get("session.timeout") == 300

    def test_missing_key_returns_default(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        assert hc.get("nonexistent.key", 42) == 42

    def test_partial_path_returns_default(self, hermes_dir: Path):
        hc = HermesConfig(hermes_dir=hermes_dir)
        # "model.provider.sub" — provider is a string, not a dict
        assert hc.get("model.provider.sub", "nope") == "nope"


# ── Settings.hermes_config lazy loading ──────────────────────────────


class TestSettingsHermesConfig:
    def test_lazy_loading(self, tmp_path: Path):
        config_json = tmp_path / "config.json"
        settings = Settings(config_path=config_json)
        # _hermes_config is None until first access
        assert settings._hermes_config is None
        hc = settings.hermes_config
        assert isinstance(hc, HermesConfig)
        # Second access returns same instance
        assert settings.hermes_config is hc


# ── Integration: Settings reads both aegis + hermes config ───────────


class TestIntegration:
    def test_both_configs(self, tmp_path: Path, hermes_dir: Path):
        # Set up aegis config
        config_json = tmp_path / "config.json"
        config_json.write_text(json.dumps({"dangerous_commands": "block"}))

        settings = Settings(config_path=config_json)
        # Override the hermes_config with one pointing at our fixture
        settings._hermes_config = HermesConfig(hermes_dir=hermes_dir)

        # Aegis config works
        assert settings.get("dangerous_commands") == "block"

        # Hermes config works through settings
        assert settings.hermes_config.terminal_backend == "docker"
        assert settings.hermes_config.model == "claude-sonnet-4-20250514"


# ── Edge cases ───────────────────────────────────────────────────────


class TestEdgeCases:
    def test_corrupted_yaml(self, tmp_path: Path):
        hdir = tmp_path / ".hermes-bad"
        hdir.mkdir()
        (hdir / "config.yaml").write_text(": :\n  - [invalid yaml {{{}}")
        hc = HermesConfig(hermes_dir=hdir)
        # Should not raise
        assert hc.terminal_backend is None
        assert hc.is_available() is False

    def test_non_dict_yaml(self, tmp_path: Path):
        hdir = tmp_path / ".hermes-list"
        hdir.mkdir()
        (hdir / "config.yaml").write_text("- item1\n- item2\n")
        hc = HermesConfig(hermes_dir=hdir)
        assert hc.is_available() is False
        assert hc.volumes == []
