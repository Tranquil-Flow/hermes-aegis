"""Tests for the provider preset map and the allowlist CLI subcommands
that consume it (``providers``, ``add-provider``, ``sync-from-hermes``)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_aegis.cli import main as cli_main
from hermes_aegis.config.provider_presets import (
    PROVIDER_PRESETS,
    get_provider_hosts,
    is_valid_hostname,
    list_providers,
    suggest_provider,
)


# ---------------------------------------------------------------------------
# Static map invariants
# ---------------------------------------------------------------------------

class TestPresetMap:
    def test_has_at_least_15_entries(self):
        assert len(PROVIDER_PRESETS) >= 15

    def test_all_keys_are_lowercase_strings(self):
        for name in PROVIDER_PRESETS:
            assert isinstance(name, str)
            assert name == name.lower()
            assert " " not in name

    def test_all_values_are_non_empty_lists(self):
        for name, hosts in PROVIDER_PRESETS.items():
            assert isinstance(hosts, list), f"{name} value is not a list"
            assert hosts, f"{name} has empty host list"

    def test_every_host_is_a_valid_hostname(self):
        """No `https://` prefixes, no paths, no ports."""
        for name, hosts in PROVIDER_PRESETS.items():
            for h in hosts:
                assert is_valid_hostname(h), (
                    f"{name}: '{h}' is not a bare hostname"
                )

    def test_no_duplicate_hosts_within_preset(self):
        for name, hosts in PROVIDER_PRESETS.items():
            assert len(hosts) == len(set(hosts)), (
                f"{name} has duplicate host entries"
            )

    def test_known_problem_hosts_are_present(self):
        """The hosts that triggered the post-R6 breakage must be covered."""
        zai = PROVIDER_PRESETS["zai"]
        assert "open.bigmodel.cn" in zai
        assert "api.z.ai" in zai
        firecrawl_nous = PROVIDER_PRESETS["firecrawl-nous"]
        assert "firecrawl-gateway.nousresearch.com" in firecrawl_nous

    def test_list_providers_is_sorted(self):
        listed = list_providers()
        assert listed == sorted(listed)
        assert set(listed) == set(PROVIDER_PRESETS.keys())

    def test_get_provider_hosts_returns_none_for_unknown(self):
        assert get_provider_hosts("not-a-real-provider") is None

    def test_get_provider_hosts_returns_hosts_for_known(self):
        assert get_provider_hosts("openai") == ["api.openai.com"]


class TestHostnameValidator:
    @pytest.mark.parametrize("good", [
        "api.openai.com", "openrouter.ai", "open.bigmodel.cn",
        "firecrawl-gateway.nousresearch.com",
    ])
    def test_accepts_valid(self, good):
        assert is_valid_hostname(good)

    @pytest.mark.parametrize("bad", [
        "https://api.openai.com",   # scheme
        "api.openai.com/v1",         # path
        "api.openai.com:443",        # port
        "localhost",                 # single label
        "",                          # empty
        "192.168.1.1",               # IP literal (single-label-ish)
        "API.OPENAI.COM",            # uppercase
        "-leading.dash.com",         # invalid label
    ])
    def test_rejects_invalid(self, bad):
        assert not is_valid_hostname(bad)


class TestSuggestProvider:
    def test_returns_close_match_for_typo(self):
        suggestions = suggest_provider("opnai")
        assert "openai" in suggestions

    def test_empty_for_total_garbage(self):
        assert suggest_provider("xyzzy-not-a-thing-at-all") == []


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_aegis_dir(tmp_path, monkeypatch):
    """Point AEGIS_DIR at a tempdir so allowlist mutations are isolated."""
    aegis_dir = tmp_path / ".hermes-aegis"
    aegis_dir.mkdir()
    monkeypatch.setattr("hermes_aegis.cli.AEGIS_DIR", aegis_dir)
    return aegis_dir


@pytest.fixture
def fake_hermes_config(tmp_path, monkeypatch):
    """Stub HermesConfig so sync-from-hermes reads our fixture, not the user's."""
    hermes_dir = tmp_path / ".hermes"
    hermes_dir.mkdir()
    cfg_path = hermes_dir / "config.yaml"

    def _write(yaml_text: str) -> Path:
        cfg_path.write_text(yaml_text)
        # HermesConfig reads $HOME/.hermes/config.yaml — patch the default.
        from hermes_aegis.config import settings as settings_mod
        original_init = settings_mod.HermesConfig.__init__

        def patched_init(self, hermes_dir_arg=None):
            return original_init(self, hermes_dir_arg or hermes_dir)

        monkeypatch.setattr(settings_mod.HermesConfig, "__init__", patched_init)
        return cfg_path

    return _write


class TestAllowlistProvidersCommand:
    def test_lists_all_presets(self, isolated_aegis_dir):
        runner = CliRunner()
        result = runner.invoke(cli_main, ["allowlist", "providers"])
        assert result.exit_code == 0
        for name in PROVIDER_PRESETS:
            assert name in result.output


class TestAllowlistAddProviderCommand:
    def test_adds_all_hosts_in_preset(self, isolated_aegis_dir):
        runner = CliRunner()
        result = runner.invoke(cli_main, ["allowlist", "add-provider", "zai"])
        assert result.exit_code == 0

        allowlist_file = isolated_aegis_dir / "domain-allowlist.json"
        domains = json.loads(allowlist_file.read_text())
        assert set(domains) >= {"api.z.ai", "open.bigmodel.cn"}

    def test_idempotent_when_hosts_already_present(self, isolated_aegis_dir):
        runner = CliRunner()
        runner.invoke(cli_main, ["allowlist", "add-provider", "tavily"])
        result = runner.invoke(cli_main, ["allowlist", "add-provider", "tavily"])
        assert result.exit_code == 0
        assert "already in allowlist" in result.output

        allowlist_file = isolated_aegis_dir / "domain-allowlist.json"
        domains = json.loads(allowlist_file.read_text())
        # No duplicates
        assert domains.count("api.tavily.com") == 1

    def test_dry_run_does_not_write(self, isolated_aegis_dir):
        runner = CliRunner()
        result = runner.invoke(cli_main, [
            "allowlist", "add-provider", "tavily", "--dry-run",
        ])
        assert result.exit_code == 0
        allowlist_file = isolated_aegis_dir / "domain-allowlist.json"
        assert not allowlist_file.exists()

    def test_unknown_provider_exits_non_zero_with_suggestion(
        self, isolated_aegis_dir,
    ):
        runner = CliRunner()
        result = runner.invoke(cli_main, [
            "allowlist", "add-provider", "opnai",
        ])
        assert result.exit_code != 0
        # 'Unknown' message and 'Did you mean openai' both expected
        combined = result.output + (result.stderr if hasattr(result, "stderr") else "")
        assert "Unknown" in combined or "Unknown" in result.output
        assert "openai" in combined or "openai" in result.output


class TestSyncFromHermesCommand:
    def test_adds_hosts_from_api_urls_in_providers_block(
        self, isolated_aegis_dir, fake_hermes_config,
    ):
        fake_hermes_config(
            "providers:\n"
            "  nous:\n"
            "    api: https://inference-api.nousresearch.com/v1\n"
            "  m4pro-ollama:\n"
            "    api: http://100.84.252.4:11434/v1\n"  # IP literal — skipped
            "  modal-glm:\n"
            "    api: https://api.us-west-2.modal.direct/v1\n"
        )
        runner = CliRunner()
        result = runner.invoke(cli_main, [
            "allowlist", "sync-from-hermes", "--yes",
        ])
        assert result.exit_code == 0, result.output

        allowlist_file = isolated_aegis_dir / "domain-allowlist.json"
        domains = set(json.loads(allowlist_file.read_text()))
        assert "inference-api.nousresearch.com" in domains
        assert "api.us-west-2.modal.direct" in domains
        # IP literal must not be added
        assert "100.84.252.4" not in domains

    def test_adds_hosts_from_preset_name_match(
        self, isolated_aegis_dir, fake_hermes_config,
    ):
        """A providers: key whose name matches a preset adds the preset's hosts."""
        fake_hermes_config(
            "providers:\n"
            "  zai:\n"
            "    api: https://api.z.ai/v1\n"
        )
        runner = CliRunner()
        result = runner.invoke(cli_main, [
            "allowlist", "sync-from-hermes", "--yes",
        ])
        assert result.exit_code == 0, result.output

        allowlist_file = isolated_aegis_dir / "domain-allowlist.json"
        domains = set(json.loads(allowlist_file.read_text()))
        # Preset adds open.bigmodel.cn; api: URL adds api.z.ai
        assert "api.z.ai" in domains
        assert "open.bigmodel.cn" in domains

    def test_dry_run_does_not_write(
        self, isolated_aegis_dir, fake_hermes_config,
    ):
        fake_hermes_config(
            "providers:\n"
            "  nous:\n"
            "    api: https://inference-api.nousresearch.com/v1\n"
        )
        runner = CliRunner()
        result = runner.invoke(cli_main, [
            "allowlist", "sync-from-hermes", "--dry-run",
        ])
        assert result.exit_code == 0
        allowlist_file = isolated_aegis_dir / "domain-allowlist.json"
        assert not allowlist_file.exists()

    def test_no_hermes_config_exits_non_zero(
        self, isolated_aegis_dir, tmp_path, monkeypatch,
    ):
        """When ~/.hermes/config.yaml is absent, the command exits 1."""
        empty_hermes = tmp_path / "empty-hermes"
        empty_hermes.mkdir()
        from hermes_aegis.config import settings as settings_mod
        original_init = settings_mod.HermesConfig.__init__

        def patched_init(self, hermes_dir_arg=None):
            return original_init(self, hermes_dir_arg or empty_hermes)

        monkeypatch.setattr(settings_mod.HermesConfig, "__init__", patched_init)

        runner = CliRunner()
        result = runner.invoke(cli_main, [
            "allowlist", "sync-from-hermes", "--yes",
        ])
        assert result.exit_code == 1
