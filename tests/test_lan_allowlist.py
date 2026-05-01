"""Tests for LAN allowlist (sandbox network-outbound rules)."""
from __future__ import annotations

import json

import pytest

from hermes_aegis.config.lan_allowlist import LanAllowlist, _validate_entry


@pytest.fixture
def allowlist_path(tmp_path):
    return tmp_path / "lan-allowlist.json"


@pytest.fixture
def lan(allowlist_path):
    return LanAllowlist(allowlist_path)


class TestValidate:
    def test_accepts_ipv4_with_port(self):
        assert _validate_entry("192.168.1.112:22") == "192.168.1.112:22"

    def test_strips_whitespace(self):
        assert _validate_entry("  192.168.1.1:443  ") == "192.168.1.1:443"

    def test_rejects_wildcard_port(self):
        # Sandbox-exec can't pin host, so wildcard port = *:* = unrestricted.
        with pytest.raises(ValueError):
            _validate_entry("10.0.0.5:*")

    def test_rejects_hostname(self):
        with pytest.raises(ValueError, match="invalid LAN entry"):
            _validate_entry("example.com:80")

    def test_rejects_missing_port(self):
        with pytest.raises(ValueError):
            _validate_entry("192.168.1.1")

    def test_rejects_octet_over_255(self):
        with pytest.raises(ValueError, match="octet"):
            _validate_entry("999.0.0.1:22")

    def test_rejects_port_zero(self):
        with pytest.raises(ValueError, match="port"):
            _validate_entry("192.168.1.1:0")

    def test_rejects_port_over_65535(self):
        with pytest.raises(ValueError, match="port"):
            _validate_entry("192.168.1.1:99999")

    def test_rejects_ipv6(self):
        with pytest.raises(ValueError):
            _validate_entry("[::1]:22")


class TestLanAllowlist:
    def test_starts_empty(self, lan):
        assert lan.list() == []

    def test_add_entry(self, lan):
        lan.add("192.168.1.112:22")
        assert "192.168.1.112:22" in lan.list()

    def test_add_returns_canonical_form(self, lan):
        assert lan.add("  192.168.1.112:22 ") == "192.168.1.112:22"

    def test_add_dedupes(self, lan):
        lan.add("192.168.1.112:22")
        lan.add("192.168.1.112:22")
        assert lan.list().count("192.168.1.112:22") == 1

    def test_add_rejects_invalid(self, lan):
        with pytest.raises(ValueError):
            lan.add("not-an-ip:22")
        assert lan.list() == []

    def test_remove_existing(self, lan):
        lan.add("192.168.1.112:22")
        lan.add("192.168.1.112:11434")
        assert lan.remove("192.168.1.112:22") is True
        assert lan.list() == ["192.168.1.112:11434"]

    def test_remove_nonexistent(self, lan):
        lan.add("192.168.1.112:22")
        assert lan.remove("10.0.0.1:22") is False

    def test_persistence(self, allowlist_path):
        a = LanAllowlist(allowlist_path)
        a.add("192.168.1.112:22")
        a.add("192.168.1.112:11434")

        b = LanAllowlist(allowlist_path)
        assert b.list() == ["192.168.1.112:11434", "192.168.1.112:22"]

    def test_json_format(self, allowlist_path, lan):
        lan.add("192.168.1.5:80")
        lan.add("192.168.1.10:443")
        with open(allowlist_path) as f:
            data = json.load(f)
        assert data == ["192.168.1.10:443", "192.168.1.5:80"]

    def test_corrupted_json_falls_back_to_empty(self, allowlist_path):
        allowlist_path.write_text("not json {]")
        a = LanAllowlist(allowlist_path)
        assert a.list() == []

    def test_invalid_entries_in_file_are_dropped(self, allowlist_path):
        # File contains a mix of valid and invalid entries
        allowlist_path.write_text(json.dumps([
            "192.168.1.112:22",
            "evil.com:80",
            "192.168.1.112:11434",
        ]))
        a = LanAllowlist(allowlist_path)
        # Only the IPv4 entries survive
        assert a.list() == ["192.168.1.112:11434", "192.168.1.112:22"]

    def test_save_creates_parent_dir(self, tmp_path):
        nested = tmp_path / "a" / "b" / "lan.json"
        a = LanAllowlist(nested)
        a.add("192.168.1.1:22")
        assert nested.exists()


class TestRenderSandboxRules:
    def test_empty_renders_to_empty_string(self, lan):
        assert lan.render_sandbox_rules() == ""

    def test_single_entry_renders_as_port_only(self, lan):
        # macOS sandbox-exec only accepts * or localhost as host, so we
        # render `*:port` regardless of the entry's IP.
        lan.add("192.168.1.112:22")
        rendered = lan.render_sandbox_rules()
        assert '(allow network-outbound (remote tcp "*:22"))' in rendered
        assert ";; intent: 192.168.1.112" in rendered

    def test_multiple_ports_sorted(self, lan):
        lan.add("192.168.1.112:11434")
        lan.add("192.168.1.112:22")
        lines = [
            l for l in lan.render_sandbox_rules().splitlines()
            if l.startswith("(allow")
        ]
        assert lines == [
            '(allow network-outbound (remote tcp "*:22"))',
            '(allow network-outbound (remote tcp "*:11434"))',
        ]

    def test_dedupes_by_port(self, lan):
        # Same port across multiple hosts collapses to one rule
        lan.add("192.168.1.112:22")
        lan.add("192.168.1.50:22")
        lan.add("10.0.0.1:22")
        rules = [
            l for l in lan.render_sandbox_rules().splitlines()
            if l.startswith("(allow")
        ]
        assert rules == ['(allow network-outbound (remote tcp "*:22"))']

    def test_intent_comment_lists_all_hosts_for_port(self, lan):
        lan.add("192.168.1.112:22")
        lan.add("10.0.0.1:22")
        rendered = lan.render_sandbox_rules()
        # Comment lists both hosts for port 22
        assert ";; intent:" in rendered
        assert "192.168.1.112" in rendered
        assert "10.0.0.1" in rendered


class TestPorts:
    def test_empty(self, lan):
        assert lan.ports() == []

    def test_unique_sorted(self, lan):
        lan.add("192.168.1.112:22")
        lan.add("192.168.1.50:22")  # dup port
        lan.add("192.168.1.112:11434")
        assert lan.ports() == [22, 11434]
