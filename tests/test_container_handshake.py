"""Tests for container-aegis handshake protocol."""
from __future__ import annotations

import pytest


class TestProtectionLevel:
    def test_enum_values(self):
        from hermes_aegis.container.handshake import ProtectionLevel

        assert ProtectionLevel.NONE.value == "none"
        assert ProtectionLevel.PROXY_ONLY.value == "proxy"
        assert ProtectionLevel.CONTAINER_ONLY.value == "container"
        assert ProtectionLevel.FULL.value == "full"

    def test_all_levels(self):
        from hermes_aegis.container.handshake import ProtectionLevel

        assert len(ProtectionLevel) == 4


class TestDetectProtection:
    def test_no_protection(self, monkeypatch):
        monkeypatch.delenv("AEGIS_ACTIVE", raising=False)
        monkeypatch.delenv("AEGIS_CONTAINER_ISOLATED", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import ProtectionLevel, detect_protection

        status = detect_protection()
        assert status.level == ProtectionLevel.NONE
        assert status.aegis_active is False
        assert status.container_isolated is False
        assert status.proxy_host is None
        assert status.proxy_port is None

    def test_full_protection(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.setenv("AEGIS_CONTAINER_ISOLATED", "1")
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import ProtectionLevel, detect_protection

        status = detect_protection()
        assert status.level == ProtectionLevel.FULL
        assert status.aegis_active is True
        assert status.container_isolated is True

    def test_proxy_only(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.delenv("AEGIS_CONTAINER_ISOLATED", raising=False)
        monkeypatch.setenv("HTTPS_PROXY", "http://localhost:8443")

        from hermes_aegis.container.handshake import ProtectionLevel, detect_protection

        status = detect_protection()
        assert status.level == ProtectionLevel.PROXY_ONLY
        assert status.aegis_active is True
        assert status.container_isolated is False
        assert status.proxy_host == "localhost"
        assert status.proxy_port == 8443

    def test_container_only(self, monkeypatch):
        monkeypatch.delenv("AEGIS_ACTIVE", raising=False)
        monkeypatch.setenv("AEGIS_CONTAINER_ISOLATED", "1")
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import ProtectionLevel, detect_protection

        status = detect_protection()
        assert status.level == ProtectionLevel.CONTAINER_ONLY
        assert status.aegis_active is False
        assert status.container_isolated is True

    def test_proxy_parsing(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.setenv("AEGIS_CONTAINER_ISOLATED", "1")
        monkeypatch.setenv("HTTPS_PROXY", "http://host.docker.internal:8443")

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.proxy_host == "host.docker.internal"
        assert status.proxy_port == 8443

    def test_empty_proxy(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.setenv("HTTPS_PROXY", "")

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.proxy_host is None
        assert status.proxy_port is None


class TestAegisProtectionStatusProperties:
    def test_network_secured_full(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.setenv("AEGIS_CONTAINER_ISOLATED", "1")
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.network_secured is True

    def test_network_secured_proxy(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.delenv("AEGIS_CONTAINER_ISOLATED", raising=False)
        monkeypatch.setenv("HTTPS_PROXY", "http://localhost:8443")

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.network_secured is True

    def test_network_not_secured_none(self, monkeypatch):
        monkeypatch.delenv("AEGIS_ACTIVE", raising=False)
        monkeypatch.delenv("AEGIS_CONTAINER_ISOLATED", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.network_secured is False

    def test_can_relax_file_checks(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.setenv("AEGIS_CONTAINER_ISOLATED", "1")
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.can_relax_file_checks is True

    def test_cannot_relax_file_checks_without_container(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.delenv("AEGIS_CONTAINER_ISOLATED", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.can_relax_file_checks is False

    def test_can_relax_network_checks(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ACTIVE", "1")
        monkeypatch.delenv("AEGIS_CONTAINER_ISOLATED", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.can_relax_network_checks is True

    def test_cannot_relax_network_checks_without_aegis(self, monkeypatch):
        monkeypatch.delenv("AEGIS_ACTIVE", raising=False)
        monkeypatch.setenv("AEGIS_CONTAINER_ISOLATED", "1")
        monkeypatch.delenv("HTTPS_PROXY", raising=False)

        from hermes_aegis.container.handshake import detect_protection

        status = detect_protection()
        assert status.can_relax_network_checks is False


class TestBuilderEnvironment:
    def test_builder_includes_aegis_container_isolated(self):
        from hermes_aegis.container.builder import ContainerConfig, build_run_args

        config = ContainerConfig(workspace_path="/tmp/test-workspace")
        args = build_run_args(config)
        env = args["environment"]

        assert env["AEGIS_ACTIVE"] == "1"
        assert env["AEGIS_CONTAINER_ISOLATED"] == "1"

    def test_builder_includes_proxy_env(self):
        from hermes_aegis.container.builder import ContainerConfig, build_run_args

        config = ContainerConfig(workspace_path="/tmp/test-workspace")
        args = build_run_args(config)
        env = args["environment"]

        assert "HTTP_PROXY" in env
        assert "HTTPS_PROXY" in env


class TestPatchExists:
    def test_container_handshake_patch_in_list(self):
        from hermes_aegis.patches import _PATCHES

        names = [p.name for p in _PATCHES]
        assert "terminal_tool_container_handshake" in names

    def test_container_handshake_patch_not_critical(self):
        from hermes_aegis.patches import _PATCHES

        patch = next(p for p in _PATCHES if p.name == "terminal_tool_container_handshake")
        assert patch.critical is False

    def test_container_handshake_patch_sentinel(self):
        from hermes_aegis.patches import _PATCHES

        patch = next(p for p in _PATCHES if p.name == "terminal_tool_container_handshake")
        assert patch.sentinel == "AEGIS_CONTAINER_ISOLATED"
