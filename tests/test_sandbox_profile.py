"""Tests for sandbox profile generation and pre-flight checks."""
import os
import platform
import tempfile
from pathlib import Path

import pytest


def test_generate_profile_writes_valid_sb_file():
    """Profile file is written with correct sandbox-exec syntax."""
    from hermes_aegis.sandbox.profile import generate_profile

    with tempfile.TemporaryDirectory() as tmp:
        profile_path = Path(tmp) / "sandbox.sb"
        generate_profile(profile_path)

        assert profile_path.exists()
        content = profile_path.read_text()
        assert "(version 1)" in content
        assert "(deny default)" in content
        assert "(allow process-fork process-exec)" in content
        assert '(param "WORK_DIR")' in content
        assert '(param "CACHE_DIR")' in content
        assert '(param "LOCAL_DIR")' in content
        assert "(allow mach-lookup (global-name-regex" in content
        assert "com\\.apple\\." in content
        assert "(allow iokit-open)" in content
        assert "(allow network-outbound" in content


def test_generate_profile_is_idempotent():
    """Calling generate_profile twice produces identical output."""
    from hermes_aegis.sandbox.profile import generate_profile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sandbox.sb"
        generate_profile(path)
        first = path.read_text()
        generate_profile(path)
        second = path.read_text()
        assert first == second


def test_generate_profile_creates_parent_dirs():
    """Parent directories are created if missing."""
    from hermes_aegis.sandbox.profile import generate_profile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sub" / "dir" / "sandbox.sb"
        generate_profile(path)
        assert path.exists()


def test_build_sandbox_args_includes_d_params():
    """sandbox-exec -D params are built from environment."""
    from hermes_aegis.sandbox.profile import build_sandbox_args

    env = {
        "AEGIS_SANDBOX_PROFILE": "/path/to/sandbox.sb",
        "AEGIS_SANDBOX_WORK_DIR": "/home/user/Projects",
        "AEGIS_SANDBOX_CACHE_DIR": "/home/user/.cache",
        "AEGIS_SANDBOX_LOCAL_DIR": "/home/user/.local",
    }
    args = build_sandbox_args(env)
    assert args[0] == "sandbox-exec"
    assert "-D" in args
    assert "WORK_DIR=/home/user/Projects" in args
    assert "CACHE_DIR=/home/user/.cache" in args
    assert "LOCAL_DIR=/home/user/.local" in args
    assert "-f" in args
    assert "/path/to/sandbox.sb" in args


def test_build_sandbox_args_skips_missing_params():
    """Missing env vars are omitted, not passed as empty."""
    from hermes_aegis.sandbox.profile import build_sandbox_args

    env = {
        "AEGIS_SANDBOX_PROFILE": "/path/to/sandbox.sb",
        "AEGIS_SANDBOX_WORK_DIR": "/home/user/Projects",
    }
    args = build_sandbox_args(env)
    assert "CACHE_DIR=" not in " ".join(args)
    assert "LOCAL_DIR=" not in " ".join(args)
    assert "WORK_DIR=/home/user/Projects" in args


def test_build_sandbox_args_returns_empty_when_no_profile():
    """Returns empty list when profile path is missing."""
    from hermes_aegis.sandbox.profile import build_sandbox_args

    assert build_sandbox_args({}) == []
    assert build_sandbox_args({"AEGIS_SANDBOX_PROFILE": ""}) == []


def test_is_sandbox_available_on_macos():
    """is_sandbox_available returns True on macOS with sandbox-exec."""
    from hermes_aegis.sandbox.profile import is_sandbox_available

    if platform.system() == "Darwin":
        assert is_sandbox_available() is True
    else:
        assert is_sandbox_available() is False
