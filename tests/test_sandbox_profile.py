"""Tests for sandbox profile generation and pre-flight checks."""
import json
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
        # No LAN allowlist → baseline-only profile
        generate_profile(profile_path, lan_allowlist_path=None)

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
        generate_profile(path, lan_allowlist_path=None)
        first = path.read_text()
        generate_profile(path, lan_allowlist_path=None)
        second = path.read_text()
        assert first == second


def test_generate_profile_creates_parent_dirs():
    """Parent directories are created if missing."""
    from hermes_aegis.sandbox.profile import generate_profile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sub" / "dir" / "sandbox.sb"
        generate_profile(path, lan_allowlist_path=None)
        assert path.exists()


def test_generate_profile_without_lan_matches_baseline(tmp_path):
    """Empty LAN allowlist must produce byte-identical output to no-allowlist case.

    Guards against accidentally adding stray whitespace or section headers
    when the allowlist is empty.
    """
    from hermes_aegis.sandbox.profile import generate_profile

    no_lan = tmp_path / "no_lan.sb"
    empty_lan = tmp_path / "empty_lan.sb"
    empty_allowlist = tmp_path / "lan-allowlist.json"
    empty_allowlist.write_text("[]")

    generate_profile(no_lan, lan_allowlist_path=None)
    generate_profile(empty_lan, lan_allowlist_path=empty_allowlist)
    assert no_lan.read_text() == empty_lan.read_text()


def test_generate_profile_injects_lan_rules(tmp_path):
    """LAN allowlist entries must appear as port-only network-outbound rules.

    sandbox-exec rejects literal IPs in (remote tcp …), so rules render
    as `*:port` with the user's intent IP captured in a comment.
    """
    from hermes_aegis.sandbox.profile import generate_profile

    profile = tmp_path / "sandbox.sb"
    allowlist = tmp_path / "lan-allowlist.json"
    allowlist.write_text(json.dumps([
        "192.168.1.112:22",
        "192.168.1.112:11434",
    ]))

    generate_profile(profile, lan_allowlist_path=allowlist)
    content = profile.read_text()

    # Baseline rules still present
    assert '(allow network-outbound (remote tcp "localhost:*"))' in content
    # LAN rules injected as *:port
    assert '(allow network-outbound (remote tcp "*:22"))' in content
    assert '(allow network-outbound (remote tcp "*:11434"))' in content
    # Intent IP captured in comment for each port
    assert ";; intent: 192.168.1.112" in content
    # Section header present
    assert "LAN allowlist" in content


def test_generate_profile_lan_rules_after_baseline(tmp_path):
    """LAN rules must come AFTER the localhost baseline so they're additive,
    not a replacement."""
    from hermes_aegis.sandbox.profile import generate_profile

    profile = tmp_path / "sandbox.sb"
    allowlist = tmp_path / "lan-allowlist.json"
    allowlist.write_text(json.dumps(["192.168.1.112:22"]))

    generate_profile(profile, lan_allowlist_path=allowlist)
    content = profile.read_text()

    localhost_idx = content.index('"localhost:*"')
    lan_idx = content.index('"*:22"')
    assert localhost_idx < lan_idx


def test_generate_profile_reflects_allowlist_changes(tmp_path):
    """Editing the allowlist + regenerating must update the profile."""
    from hermes_aegis.config.lan_allowlist import LanAllowlist
    from hermes_aegis.sandbox.profile import generate_profile

    profile = tmp_path / "sandbox.sb"
    allowlist_path = tmp_path / "lan-allowlist.json"

    al = LanAllowlist(allowlist_path)
    al.add("192.168.1.112:22")
    generate_profile(profile, lan_allowlist_path=allowlist_path)
    content = profile.read_text()
    assert '"*:22"' in content
    assert "192.168.1.112" in content  # intent comment

    al.remove("192.168.1.112:22")
    al.add("10.0.0.5:11434")
    generate_profile(profile, lan_allowlist_path=allowlist_path)
    content = profile.read_text()
    assert '"*:22"' not in content
    assert "192.168.1.112" not in content
    assert '"*:11434"' in content
    assert "10.0.0.5" in content


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


def test_signal_rule_allows_kill_zero_inside_sandbox(tmp_path):
    """End-to-end check: kill -0 <self_pid> must succeed inside the generated
    profile. Guards against (target self)-style predicates that compile cleanly
    but reject self-signals at runtime, breaking subprocess liveness checks.
    """
    import subprocess

    if platform.system() != "Darwin":
        pytest.skip("sandbox-exec is macOS-only")

    from hermes_aegis.sandbox.profile import generate_profile, is_sandbox_available

    if not is_sandbox_available():
        pytest.skip("sandbox-exec not available")

    profile_path = tmp_path / "sandbox.sb"
    generate_profile(profile_path, lan_allowlist_path=None)

    result = subprocess.run(
        [
            "sandbox-exec",
            "-f", str(profile_path),
            "-D", f"WORK_DIR={tmp_path}",
            "-D", f"CACHE_DIR={tmp_path}",
            "-D", f"LOCAL_DIR={tmp_path}",
            "/bin/sh", "-c", "kill -0 $$ && echo ok",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, (
        f"kill -0 self should succeed inside sandbox.\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert "ok" in result.stdout
