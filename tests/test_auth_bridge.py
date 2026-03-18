"""Tests for hermes auth.json → aegis vault bridge."""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


class TestReadHermesAuthCredentials:
    """Test _read_hermes_auth_credentials from cli.py."""

    def test_no_auth_file(self, tmp_path):
        """Returns empty dict when auth.json doesn't exist."""
        from hermes_aegis.cli import _read_hermes_auth_credentials

        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", tmp_path / "nonexistent.json"):
            result = _read_hermes_auth_credentials()
        assert result == {}

    def test_valid_nous_agent_key(self, tmp_path):
        """Extracts agent_key from nous provider."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "version": 1,
            "providers": {
                "nous": {
                    "access_token": "oauth-token-xxx",
                    "agent_key": "sk-ant-api03-test-key-123",
                    "agent_key_expires_at": "2026-03-18T20:00:00Z",
                }
            }
        }))

        from hermes_aegis.cli import _read_hermes_auth_credentials
        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file):
            result = _read_hermes_auth_credentials()

        assert result == {"ANTHROPIC_API_KEY": "sk-ant-api03-test-key-123"}

    def test_empty_agent_key(self, tmp_path):
        """Skips empty or whitespace-only agent keys."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "version": 1,
            "providers": {
                "nous": {"agent_key": "  "}
            }
        }))

        from hermes_aegis.cli import _read_hermes_auth_credentials
        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file):
            result = _read_hermes_auth_credentials()

        assert result == {}

    def test_no_nous_provider(self, tmp_path):
        """Returns empty when nous provider is missing."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "version": 1,
            "providers": {"openai": {"api_key": "sk-xxx"}}
        }))

        from hermes_aegis.cli import _read_hermes_auth_credentials
        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file):
            result = _read_hermes_auth_credentials()

        assert result == {}

    def test_corrupt_json(self, tmp_path):
        """Handles corrupt auth.json gracefully."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text("{invalid json")

        from hermes_aegis.cli import _read_hermes_auth_credentials
        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file):
            result = _read_hermes_auth_credentials()

        assert result == {}

    def test_strips_whitespace(self, tmp_path):
        """Strips whitespace from agent key."""
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {
                "nous": {"agent_key": "  sk-ant-key  "}
            }
        }))

        from hermes_aegis.cli import _read_hermes_auth_credentials
        with patch("hermes_aegis.cli.HERMES_AUTH_FILE", auth_file):
            result = _read_hermes_auth_credentials()

        assert result == {"ANTHROPIC_API_KEY": "sk-ant-key"}


class TestAddonAuthRefresh:
    """Test the addon's _refresh_hermes_auth method."""

    def _make_addon(self, vault_secrets=None, vault_values=None):
        """Create a minimal AegisAddon for testing."""
        from hermes_aegis.proxy.addon import AegisAddon
        return AegisAddon(
            vault_secrets=vault_secrets or {},
            vault_values=vault_values or [],
        )

    def test_refresh_picks_up_new_key(self, tmp_path):
        """Refresh reads new key from auth.json."""
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": "sk-ant-new-key"}}
        }))

        a = self._make_addon()
        original_path = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            updated = a._refresh_hermes_auth(force=True)
        finally:
            addon_mod._HERMES_AUTH_FILE = original_path

        assert updated is True
        assert a._vault_secrets["ANTHROPIC_API_KEY"] == "sk-ant-new-key"

    def test_refresh_no_change(self, tmp_path):
        """Returns False when key hasn't changed."""
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": "sk-ant-same"}}
        }))

        a = self._make_addon(vault_secrets={"ANTHROPIC_API_KEY": "sk-ant-same"})
        original_path = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            updated = a._refresh_hermes_auth(force=True)
        finally:
            addon_mod._HERMES_AUTH_FILE = original_path

        assert updated is False

    def test_refresh_respects_interval(self, tmp_path):
        """Doesn't re-read auth.json too frequently."""
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": "sk-ant-key1"}}
        }))

        a = self._make_addon()
        original_path = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            # First call with force=True
            a._refresh_hermes_auth(force=True)
            assert a._vault_secrets["ANTHROPIC_API_KEY"] == "sk-ant-key1"

            # Update the file
            auth_file.write_text(json.dumps({
                "providers": {"nous": {"agent_key": "sk-ant-key2"}}
            }))

            # Without force, should be throttled (just refreshed)
            updated = a._refresh_hermes_auth(force=False)
            assert updated is False
            assert a._vault_secrets["ANTHROPIC_API_KEY"] == "sk-ant-key1"

            # With force, should pick up new key
            updated = a._refresh_hermes_auth(force=True)
            assert updated is True
            assert a._vault_secrets["ANTHROPIC_API_KEY"] == "sk-ant-key2"
        finally:
            addon_mod._HERMES_AUTH_FILE = original_path

    def test_refresh_adds_to_vault_values(self, tmp_path):
        """New key gets added to vault_values for scanner protection."""
        from hermes_aegis.proxy import addon as addon_mod

        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "providers": {"nous": {"agent_key": "sk-ant-secret"}}
        }))

        vault_values = ["other-secret"]
        a = self._make_addon(vault_values=vault_values)
        original_path = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = auth_file
            a._refresh_hermes_auth(force=True)
        finally:
            addon_mod._HERMES_AUTH_FILE = original_path

        assert "sk-ant-secret" in vault_values

    def test_refresh_missing_file(self):
        """Handles missing auth.json gracefully."""
        from hermes_aegis.proxy import addon as addon_mod

        a = self._make_addon()
        original_path = addon_mod._HERMES_AUTH_FILE
        try:
            addon_mod._HERMES_AUTH_FILE = Path("/nonexistent/auth.json")
            updated = a._refresh_hermes_auth(force=True)
        finally:
            addon_mod._HERMES_AUTH_FILE = original_path

        assert updated is False
