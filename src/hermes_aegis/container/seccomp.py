"""Seccomp profile generation for hermes-aegis containers.

Generates a **block-list** seccomp profile: dangerous syscalls are explicitly
denied while everything else is allowed (``defaultAction: SCMP_ACT_ALLOW``).
This matches Docker's default seccomp philosophy and avoids breaking
legitimate workloads.

The blocked syscalls cover known container-breakout and privilege-escalation
vectors. A more restrictive allow-list mode (``defaultAction: SCMP_ACT_ERRNO``
with explicit allow entries) is planned as a v0.4 hardening option.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Default output path for the generated profile
SECCOMP_PROFILE_PATH = Path.home() / ".hermes-aegis" / "seccomp-aegis.json"

# ---------------------------------------------------------------------------
# Blocked syscalls — dangerous for container breakout / privilege escalation
# ---------------------------------------------------------------------------

_BLOCKED_SYSCALLS: list[str] = [
    # Kernel keyring — potential credential theft
    "keyctl",
    "add_key",
    "request_key",
    # eBPF — kernel introspection / rootkit capability
    "bpf",
    # Process introspection — debugging / memory inspection of other processes
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    # io_uring — async I/O with history of kernel exploits
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    # userfaultfd — used in Dirty Pipe / heap-shaping exploits
    "userfaultfd",
    # Mount/filesystem manipulation — container breakout vector
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "chroot",
    "open_by_handle_at",
    "name_to_handle_at",
    # Kernel module loading
    "init_module",
    "finit_module",
    "delete_module",
    "create_module",
    "query_module",
    "get_kernel_syms",
    # Kernel reload / live-patch
    "kexec_load",
    "kexec_file_load",
    # System reboot/power-off
    "reboot",
    # Process accounting (information leak)
    "acct",
    # Clock manipulation (NTP-like)
    "clock_settime",
    "clock_adjtime",
    "settimeofday",
    "stime",
    # Namespace manipulation (beyond what Docker already sets up)
    "unshare",
    "setns",
    # Direct hardware access
    "iopl",
    "ioperm",
    # Swap / memory management
    "swapon",
    "swapoff",
    # NUMA / memory-policy manipulation
    "move_pages",
    "mbind",
    "set_mempolicy",
    # Kernel log — information leak
    "syslog",
    # Performance events — side-channel risk
    "perf_event_open",
    # Disk quota — privileged FS administration
    "quotactl",
    "quotactl_fd",
    # Legacy / obsolete
    "uselib",
    "ustat",
    "vm86",
    "vm86old",
    "personality",
    "lookup_dcookie",
    # Process compare — information leak across containers
    "kcmp",
    # NFS server control
    "nfsservctl",
]


def generate_seccomp_profile() -> str:
    """Generate a hermes-aegis seccomp profile as JSON.

    Uses a block-list approach:
    - ``defaultAction: SCMP_ACT_ALLOW`` — allow everything by default
    - Dangerous syscalls are explicitly listed with ``SCMP_ACT_ERRNO``

    Returns:
        JSON string of the seccomp profile.
    """
    profile: dict[str, Any] = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_AARCH64",
            "SCMP_ARCH_X86",
        ],
        "syscalls": [
            {
                "names": sorted(_BLOCKED_SYSCALLS),
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 1,
            },
        ],
    }
    return json.dumps(profile, indent=2)


def write_seccomp_profile(path: Path | None = None) -> Path:
    """Generate and write the seccomp profile to disk.

    Args:
        path: Output path. Defaults to :data:`SECCOMP_PROFILE_PATH`.

    Returns:
        The path the profile was written to.
    """
    target = path or SECCOMP_PROFILE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(generate_seccomp_profile())
    return target


def ensure_seccomp_profile(path: Path | None = None) -> Path:
    """Materialize the seccomp profile at *path* if it is missing.

    Side-effecting helper kept separate from
    :func:`hermes_aegis.container.builder.build_run_args` so that callers
    can introspect run-args without writing to ``$HOME``.

    Args:
        path: Output path. Defaults to :data:`SECCOMP_PROFILE_PATH`.

    Returns:
        The path of the profile (whether pre-existing or just written).
    """
    target = path or SECCOMP_PROFILE_PATH
    if not target.exists():
        write_seccomp_profile(target)
    return target
