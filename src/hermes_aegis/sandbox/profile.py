"""Sandbox profile generation and pre-flight checks.

Generates a macOS sandbox-exec profile that:
- Denies all operations by default
- Allows Metal/MPS GPU access (com.apple.* Mach services + IOKit)
- Restricts file writes to specific directories (project, cache, tmp)
- Allows broad file reads (Python, system libs, project source)
- Restricts network to localhost only (aegis proxy handles external)
"""
from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

AEGIS_DIR = Path.home() / ".hermes-aegis"
DEFAULT_PROFILE_PATH = AEGIS_DIR / "sandbox.sb"

_PROFILE_TEMPLATE = """\
(version 1)
(deny default)

;; Process execution — children inherit sandbox (no escape)
(allow process-fork process-exec)

;; File read: broad (Python, system libs, project source)
(allow file-read*)

;; File write: restricted to specific paths
(allow file-write*
  (subpath "/private/tmp")
  (subpath "/tmp")
  (subpath "/dev")
  (subpath "/private/var/folders")
  (subpath "/var/folders")
  (subpath (param "WORK_DIR"))
  (subpath (param "CACHE_DIR"))
  (subpath (param "LOCAL_DIR"))
)

;; System
(allow sysctl-read)
(allow signal (target self))
(allow process-info*)
(allow system-socket)
(allow ipc-posix-shm*)

;; GPU: Apple Mach services only (blocks third-party services)
(allow mach-lookup (global-name-regex #"^com\\.apple\\."))
(allow iokit-open)

;; Network: localhost only (aegis proxy handles external traffic)
(allow network-outbound (remote tcp "localhost:*"))
"""


def generate_profile(path: Path | None = None) -> Path:
    """Write the sandbox profile to disk.

    Args:
        path: Where to write the profile. Defaults to ~/.hermes-aegis/sandbox.sb.

    Returns:
        The path the profile was written to.
    """
    path = path or DEFAULT_PROFILE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_PROFILE_TEMPLATE)
    return path


def build_sandbox_args(env: dict[str, str] | None = None) -> list[str]:
    """Build the sandbox-exec prefix args from environment variables.

    Reads AEGIS_SANDBOX_PROFILE and AEGIS_SANDBOX_{WORK_DIR,CACHE_DIR,LOCAL_DIR}
    from the provided env dict (or os.environ if None).

    Returns:
        List like ["sandbox-exec", "-D", "WORK_DIR=...", "-f", "profile.sb"]
        or empty list if sandbox is not configured.
    """
    env = env if env is not None else dict(os.environ)
    profile = env.get("AEGIS_SANDBOX_PROFILE", "")
    if not profile:
        return []

    args = ["sandbox-exec"]
    for key in ("WORK_DIR", "CACHE_DIR", "LOCAL_DIR"):
        val = env.get(f"AEGIS_SANDBOX_{key}", "")
        if val:
            args.extend(["-D", f"{key}={val}"])
    args.extend(["-f", profile])
    return args


def is_sandbox_available() -> bool:
    """Check if sandbox-exec is available on this platform."""
    if platform.system() != "Darwin":
        return False
    return shutil.which("sandbox-exec") is not None
