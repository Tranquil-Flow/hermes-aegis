"""Tests for LibCST-based semantic patching.

These tests define the contract for SemanticPatch before implementation:
- structural anchor matching (class/method/assignment target)
- resilience to upstream RHS changes
- idempotent apply via sentinel
- revert restores original content
- graceful incompatibility when anchor is absent
"""
from __future__ import annotations

from textwrap import dedent

import pytest

import hermes_aegis.patching.types as patch_types


@pytest.fixture
def fake_agent_dir(tmp_path, monkeypatch):
    """Point semantic patching at a tmp Hermes checkout."""
    monkeypatch.setattr(patch_types, "HERMES_AGENT_DIR", tmp_path)
    return tmp_path


def test_semantic_patch_apply_after_assignment_changed_rhs(fake_agent_dir):
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    target = fake_agent_dir / "tools/environments/docker.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dedent(
        '''
        class DockerEnvironment:
            def start(self):
                self._container_id = result.stdout.strip()
                logger.info(f"started {self._container_id}")
        '''
    ).lstrip())

    patch = SemanticPatch(
        name="docker_cert_system_trust",
        file="tools/environments/docker.py",
        sentinel="_aegis_cert_trust",
        anchor=AnchorSpec(
            class_name="DockerEnvironment",
            method_name="start",
            anchor_type="assignment",
            assign_target="self._container_id",
            position="after",
        ),
        transform=TransformSpec(
            code=dedent(
                '''
                # Aegis cert trust (_aegis_cert_trust)
                install_cert()
                '''
            ).strip(),
        ),
        critical=False,
    )

    result = patch.apply()

    assert result.status == "applied"
    content = target.read_text()
    assert "self._container_id = result.stdout.strip()" in content
    assert "# Aegis cert trust (_aegis_cert_trust)" in content
    assert "install_cert()" in content
    assert content.index("self._container_id = result.stdout.strip()") < content.index("# Aegis cert trust (_aegis_cert_trust)")


def test_semantic_patch_apply_before_assignment(fake_agent_dir):
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    target = fake_agent_dir / "tools/environments/docker.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dedent(
        '''
        class DockerEnvironment:
            def _build_init_env_args(self):
                if value is not None:
                    exec_env[key] = value
        '''
    ).lstrip())

    patch = SemanticPatch(
        name="docker_exec_proxy_translate",
        file="tools/environments/docker.py",
        sentinel="host.docker.internal",
        anchor=AnchorSpec(
            class_name="DockerEnvironment",
            method_name="_build_init_env_args",
            anchor_type="assignment",
            assign_target="exec_env[key]",
            position="before",
        ),
        transform=TransformSpec(
            code=dedent(
                '''
                # translate to host.docker.internal
                value = value.replace("://127.0.0.1:", "://host.docker.internal:")
                '''
            ).strip(),
        ),
        critical=True,
    )

    result = patch.apply()

    assert result.status == "applied"
    content = target.read_text()
    assert "host.docker.internal" in content
    assert content.index("# translate to host.docker.internal") < content.index("exec_env[key] = value")


def test_semantic_patch_apply_idempotent(fake_agent_dir):
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x = 1\n")

    patch = SemanticPatch(
        name="idempotent_patch",
        file="some/file.py",
        sentinel="# PATCHED",
        anchor=AnchorSpec(anchor_type="assignment", assign_target="x", position="after"),
        transform=TransformSpec(code="# PATCHED\ny = 2"),
        critical=True,
    )

    r1 = patch.apply()
    r2 = patch.apply()

    assert r1.status == "applied"
    assert r2.status == "already_applied"
    assert target.read_text().count("# PATCHED") == 1


def test_semantic_patch_revert_roundtrip(fake_agent_dir):
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    original = "x = 1\n"
    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(original)

    patch = SemanticPatch(
        name="roundtrip_patch",
        file="some/file.py",
        sentinel="# PATCHED",
        anchor=AnchorSpec(anchor_type="assignment", assign_target="x", position="after"),
        transform=TransformSpec(code="# PATCHED\ny = 2"),
        critical=True,
    )

    apply_result = patch.apply()
    revert_result = patch.revert()

    assert apply_result.status == "applied"
    assert revert_result.status == "applied"
    assert target.read_text() == original


def test_semantic_patch_anchor_not_found_non_critical(fake_agent_dir):
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("z = 99\n")

    patch = SemanticPatch(
        name="missing_anchor",
        file="some/file.py",
        sentinel="# PATCHED",
        anchor=AnchorSpec(anchor_type="assignment", assign_target="x", position="after"),
        transform=TransformSpec(code="# PATCHED\ny = 2"),
        critical=False,
    )

    result = patch.apply()

    assert result.status == "incompatible"
    assert "anchor" in result.detail.lower()


# ---------------------------------------------------------------------------
# Call-anchor tests (anchor_type="call")
# ---------------------------------------------------------------------------

def test_call_anchor_matches_logger_info_call(fake_agent_dir):
    """Call-anchor with call_func should find a logger.info(...) statement."""
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    target = fake_agent_dir / "tools/environments/docker.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dedent(
        '''
        class DockerEnvironment:
            def _execute_container(self, all_run_args):
                logger.info(f"Docker run_args: {all_run_args}")

                # Resolve the docker executable
                self._docker_exe = find_docker() or "docker"
        '''
    ).lstrip())

    patch = SemanticPatch(
        name="docker_cert_mount",
        file="tools/environments/docker.py",
        sentinel="_aegis_cert_mount",
        anchor=AnchorSpec(
            class_name="DockerEnvironment",
            method_name="_execute_container",
            anchor_type="call",
            call_func="logger.info",
            call_arg_contains="all_run_args",
            position="after",
        ),
        transform=TransformSpec(
            code=dedent(
                '''
                # Aegis cert mount (_aegis_cert_mount)
                mount_certs(all_run_args)
                '''
            ).strip(),
        ),
        critical=False,
    )

    result = patch.apply()

    assert result.status == "applied"
    content = target.read_text()
    assert "_aegis_cert_mount" in content
    assert "mount_certs(all_run_args)" in content
    # Inserted AFTER logger.info, BEFORE "# Resolve..."
    assert content.index('logger.info(f"Docker run_args:') < content.index("_aegis_cert_mount")
    assert content.index("_aegis_cert_mount") < content.index("# Resolve the docker executable")


def test_call_anchor_not_found_returns_incompatible(fake_agent_dir):
    """Call-anchor on a non-existent call should return incompatible for non-critical."""
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("print('hello')\n")

    patch = SemanticPatch(
        name="missing_call",
        file="some/file.py",
        sentinel="# PATCHED",
        anchor=AnchorSpec(
            anchor_type="call",
            call_func="logger.info",
            position="after",
        ),
        transform=TransformSpec(code="# PATCHED"),
        critical=False,
    )

    result = patch.apply()
    assert result.status == "incompatible"


def test_call_anchor_ignores_wrong_method(fake_agent_dir):
    """Call-anchor should only match within the specified method."""
    from hermes_aegis.patching.semantic_patch import AnchorSpec, SemanticPatch, TransformSpec

    target = fake_agent_dir / "some/file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dedent(
        '''
        class MyClass:
            def other_method(self):
                logger.info("wrong place")
            def target_method(self):
                logger.info("right place")
        '''
    ).lstrip())

    patch = SemanticPatch(
        name="selective_call",
        file="some/file.py",
        sentinel="# PATCHED",
        anchor=AnchorSpec(
            class_name="MyClass",
            method_name="target_method",
            anchor_type="call",
            call_func="logger.info",
            position="after",
        ),
        transform=TransformSpec(code="# PATCHED"),
        critical=True,
    )

    result = patch.apply()
    assert result.status == "applied"
    content = target.read_text()
    # Should appear after "right place", not after "wrong place"
    assert content.index("right place") < content.index("# PATCHED")
    assert "wrong place" in content
