"""Patches applied to hermes-agent source files to enable Aegis proxy integration.

Each patch is idempotent (safe to apply multiple times), reversible, and
gracefully handles the case where hermes-agent has been updated with
incompatible changes to the target files.

Usage:
    results = apply_patches()
    for r in results:
        print(r.summary())

    results = revert_patches()
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

HERMES_AGENT_DIR = Path.home() / ".hermes" / "hermes-agent"


def _invalidate_pyc(source_path: Path) -> None:
    """Delete cached .pyc files for a patched source file.

    Python may use stale bytecode from __pycache__/ instead of re-reading
    the modified .py file. Remove all matching .pyc entries to force
    recompilation on next import.
    """
    cache_dir = source_path.parent / "__pycache__"
    if not cache_dir.is_dir():
        return
    stem = source_path.stem  # e.g. "banner" from "banner.py"
    for pyc in cache_dir.glob(f"{stem}.*.pyc"):
        try:
            pyc.unlink()
        except OSError:
            pass


@dataclass
class PatchResult:
    name: str
    # "applied" | "already_applied" | "incompatible" | "skipped" | "error"
    status: str
    detail: str = ""

    def ok(self) -> bool:
        return self.status in ("applied", "already_applied")

    def summary(self) -> str:
        icons = {
            "applied": "✓",
            "already_applied": "·",
            "incompatible": "⚠",
            "skipped": "·",
            "error": "✗",
        }
        icon = icons.get(self.status, "?")
        msg = f"  {icon} {self.name}: {self.status}"
        if self.detail:
            msg += f" — {self.detail}"
        return msg


@dataclass
class FilePatch:
    """A single search-and-replace patch against a hermes-agent source file."""
    name: str
    file: str           # relative to HERMES_AGENT_DIR
    sentinel: str       # unique string present only in the patched form
    before: str         # exact text to find in the unpatched file
    after: str          # text to replace it with
    critical: bool = True  # if False, incompatibility is a warning not an error

    def path(self) -> Path:
        return HERMES_AGENT_DIR / self.file

    def apply(self) -> PatchResult:
        path = self.path()

        if not path.exists():
            status = "error" if self.critical else "skipped"
            return PatchResult(self.name, status, f"file not found: {self.file}")

        content = path.read_text()

        if self.sentinel in content:
            # Still invalidate pyc — a previous install may have written the
            # .py patch but not cleared the bytecode cache (pre-v0.1.5).
            _invalidate_pyc(path)
            return PatchResult(self.name, "already_applied")

        if self.before not in content:
            status = "error" if self.critical else "incompatible"
            return PatchResult(
                self.name, status,
                f"target pattern not found in {self.file} — "
                "hermes-agent may have changed; manual review needed"
            )

        path.write_text(content.replace(self.before, self.after, 1))
        _invalidate_pyc(path)
        return PatchResult(self.name, "applied", self.file)

    def revert(self) -> PatchResult:
        path = self.path()

        if not path.exists():
            return PatchResult(self.name, "skipped", f"file not found: {self.file}")

        content = path.read_text()

        if self.sentinel not in content:
            return PatchResult(self.name, "already_applied", "not present, nothing to revert")

        if self.after not in content:
            return PatchResult(
                self.name, "error",
                f"patched text not found verbatim in {self.file} — "
                "file may have been manually edited; revert manually"
            )

        path.write_text(content.replace(self.after, self.before, 1))
        _invalidate_pyc(path)
        return PatchResult(self.name, "applied", f"reverted {self.file}")


# ---------------------------------------------------------------------------
# Patch definitions
# ---------------------------------------------------------------------------
#
# Each patch targets a specific location in hermes-agent's source. The
# `before` string is what upstream hermes-agent ships; `after` is what
# Aegis needs. `sentinel` is a substring present only in the `after` form
# so we can detect whether the patch has already been applied.
#
# Patches are ordered by dependency: docker.py init signature must be
# patched before terminal_tool.py passes forward_env to DockerEnvironment.

_PATCHES: list[FilePatch] = [

    # -- docker.py: 1/3 — add forward_env parameter to DockerEnvironment.__init__
    FilePatch(
        name="docker_env_init_param",
        file="tools/environments/docker.py",
        sentinel="forward_env: list = None,\n    ):",
        before=(
            "        volumes: list = None,\n"
            "        network: bool = True,\n"
            "    ):"
        ),
        after=(
            "        volumes: list = None,\n"
            "        network: bool = True,\n"
            "        forward_env: list = None,\n"
            "    ):"
        ),
    ),

    # -- docker.py: 2/3 — pass forward_env to the underlying _Docker() constructor
    FilePatch(
        name="docker_env_constructor",
        file="tools/environments/docker.py",
        sentinel="forward_env=forward_env or [],",
        before=(
            "        self._inner = _Docker(\n"
            "            image=image, cwd=cwd, timeout=timeout,\n"
            "            run_args=all_run_args,\n"
            "            executable=docker_exe,\n"
            "        )"
        ),
        after=(
            "        # Aegis: forward proxy env vars so containers route through aegis proxy\n"
            "        self._inner = _Docker(\n"
            "            image=image, cwd=cwd, timeout=timeout,\n"
            "            run_args=all_run_args,\n"
            "            executable=docker_exe,\n"
            "            forward_env=forward_env or [],\n"
            "        )"
        ),
    ),

    # -- docker.py: 3/3 — translate 127.0.0.1/localhost to host.docker.internal
    #    and remap mitmproxy cert path to the in-container mount path.
    #    The upstream exec loop already iterates forward_env but passes values
    #    through unchanged — we add translation so containers can reach the proxy.
    FilePatch(
        name="docker_exec_proxy_translate",
        file="tools/environments/docker.py",
        sentinel="host.docker.internal",
        before=(
            "        for key in self._inner.config.forward_env:\n"
            "            if (value := os.getenv(key)) is not None:\n"
            "                cmd.extend([\"-e\", f\"{key}={value}\"])"
        ),
        after=(
            "        for key in self._inner.config.forward_env:\n"
            "            if (value := os.getenv(key)) is not None:\n"
            "                # Translate host-local addresses to container-reachable ones\n"
            "                value = value.replace(\"://127.0.0.1:\", \"://host.docker.internal:\")\n"
            "                value = value.replace(\"://localhost:\", \"://host.docker.internal:\")\n"
            "                # Translate host cert paths to container mount paths\n"
            "                if key in (\"REQUESTS_CA_BUNDLE\", \"SSL_CERT_FILE\") and \"/mitmproxy-ca-cert.pem\" in value:\n"
            "                    value = \"/certs/mitmproxy-ca-cert.pem\"\n"
            "                cmd.extend([\"-e\", f\"{key}={value}\"])"
        ),
    ),

    # -- terminal_tool.py — pass Aegis proxy vars when creating DockerEnvironment
    FilePatch(
        name="terminal_tool_docker_forward",
        file="tools/terminal_tool.py",
        sentinel="_aegis_forward",
        before=(
            "    elif env_type == \"docker\":\n"
            "        return _DockerEnvironment(\n"
            "            image=image, cwd=cwd, timeout=timeout,\n"
            "            cpu=cpu, memory=memory, disk=disk,\n"
            "            persistent_filesystem=persistent, task_id=task_id,\n"
            "            volumes=volumes,\n"
            "        )"
        ),
        after=(
            "    elif env_type == \"docker\":\n"
            "        # Aegis: forward proxy env vars so containers route through aegis proxy\n"
            "        _aegis_forward = [\"HTTP_PROXY\", \"HTTPS_PROXY\", \"REQUESTS_CA_BUNDLE\", \"SSL_CERT_FILE\"]\n"
            "        return _DockerEnvironment(\n"
            "            image=image, cwd=cwd, timeout=timeout,\n"
            "            cpu=cpu, memory=memory, disk=disk,\n"
            "            persistent_filesystem=persistent, task_id=task_id,\n"
            "            volumes=volumes,\n"
            "            forward_env=_aegis_forward,\n"
            "        )"
        ),
    ),

    # -- terminal_tool.py — secondary dangerous-command check via aegis scan-command
    # when AEGIS_ACTIVE=1 (gateway/non-interactive mode where hermes auto-allows).
    # Wires DangerousBlockerMiddleware patterns into the actual command execution path.
    FilePatch(
        name="terminal_tool_command_scan",
        file="tools/terminal_tool.py",
        sentinel='"hermes-aegis", "scan-command"',
        before=(
            "        # Pre-exec security checks (tirith + dangerous command detection)\n"
            "        # Skip check if force=True (user has confirmed they want to run it)\n"
            "        if not force:\n"
            "            approval = _check_all_guards(command, env_type)\n"
            "            if not approval[\"approved\"]:"
        ),
        after=(
            "        # Pre-exec security checks (tirith + dangerous command detection)\n"
            "        # Skip check if force=True (user has confirmed they want to run it)\n"
            "        if not force:\n"
            "            approval = _check_all_guards(command, env_type)\n"
            "            # Aegis secondary check: enforce blocking in non-interactive contexts\n"
            "            # (gateway mode) where hermes would otherwise auto-allow.\n"
            "            if approval.get(\"approved\") and os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "                import subprocess as _aegis_sp\n"
            "                try:\n"
            "                    _aegis_r = _aegis_sp.run(\n"
            "                        [\"hermes-aegis\", \"scan-command\", \"--\", command],\n"
            "                        capture_output=True, text=True, timeout=3,\n"
            "                    )\n"
            "                    if _aegis_r.returncode == 1:\n"
            "                        approval = {\n"
            "                            \"approved\": False,\n"
            "                            \"description\": _aegis_r.stdout.strip() or \"blocked by Aegis security\",\n"
            "                            \"pattern_key\": \"aegis\",\n"
            "                        }\n"
            "                except Exception:\n"
            "                    pass  # Aegis unavailable — fail open, don't block execution\n"
            "            if not approval[\"approved\"]:"
        ),
        critical=False,  # Gateway mode is optional — don't hard-fail if upstream changes
    ),
    # Patch 7: Forward hermes approval decisions to unified aegis audit trail
    FilePatch(
        name="terminal_tool_audit_forward",
        file="tools/terminal_tool.py",
        sentinel='"hermes-aegis", "audit"',
        before=(
            "            if not approval[\"approved\"]:\n"
            "                # Check if this is an approval_required (gateway ask mode)\n"
            "                if approval.get(\"status\") == \"approval_required\":\n"
        ),
        after=(
            "            # Aegis: forward approval decision to unified audit trail\n"
            "            if os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "                import subprocess as _aegis_audit_sp\n"
            "                try:\n"
            "                    _aegis_audit_cmd = [\n"
            "                        \"hermes-aegis\", \"audit\", \"event\",\n"
            "                        \"--type\", \"HERMES_APPROVAL\",\n"
            "                        \"--tool\", \"terminal\",\n"
            "                        \"--decision\", \"ALLOWED\" if approval[\"approved\"] else \"BLOCKED\",\n"
            "                        \"--data\", json.dumps({\"command\": command[:200], \"pattern\": approval.get(\"pattern_key\", \"\")}),\n"
            "                    ]\n"
            "                    _aegis_audit_sp.run(_aegis_audit_cmd, capture_output=True, timeout=2)\n"
            "                except Exception:\n"
            "                    pass  # Audit forwarding is best-effort\n"
            "            if not approval[\"approved\"]:\n"
            "                # Check if this is an approval_required (gateway ask mode)\n"
            "                if approval.get(\"status\") == \"approval_required\":\n"
        ),
        critical=False,
    ),

    # -- Patch 6: Show "Aegis Protection Activated" in hermes banner
    FilePatch(
        name="hermes_banner_aegis_status",
        file="hermes_cli/banner.py",
        sentinel="Aegis Protection Activated",
        before=(
            "    if session_id:\n"
            "        left_lines.append(f\"[dim {session_color}]Session: {session_id}[/]\")\n"
            "    left_content = \"\\n\".join(left_lines)"
        ),
        after=(
            "    if session_id:\n"
            "        left_lines.append(f\"[dim {session_color}]Session: {session_id}[/]\")\n"
            "    # Aegis: show protection status in hermes banner\n"
            "    import os as _aegis_os\n"
            "    if _aegis_os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "        left_lines.append(f\"[bold cyan]\U0001f6e1\ufe0f  Aegis Protection Activated[/]\")\n"
            "    left_content = \"\\n\".join(left_lines)"
        ),
        critical=False,
    ),

    # -- Patch 8: Container handshake — inject AEGIS_CONTAINER_ISOLATED awareness
    # When running in an aegis-managed container, hermes can relax file-write
    # guards since the container has read-only root and tmpfs for /tmp.
    FilePatch(
        name="terminal_tool_container_handshake",
        file="tools/terminal_tool.py",
        sentinel="AEGIS_CONTAINER_ISOLATED",
        before=(
            "        # Pre-exec security checks (tirith + dangerous command detection)\n"
            "        # Skip check if force=True (user has confirmed they want to run it)\n"
            "        if not force:\n"
        ),
        after=(
            "        # Pre-exec security checks (tirith + dangerous command detection)\n"
            "        # Skip check if force=True (user has confirmed they want to run it)\n"
            "        # Aegis container handshake: relax file-write guards in isolated containers\n"
            "        # (container has read-only root, tmpfs for /tmp, aegis handles network)\n"
            "        _aegis_container = os.getenv(\"AEGIS_CONTAINER_ISOLATED\") == \"1\"\n"
            "        if not force:\n"
        ),
        critical=False,
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_patches() -> list[PatchResult]:
    """Apply all Aegis patches to hermes-agent. Safe to call multiple times."""
    return [p.apply() for p in _PATCHES]


def revert_patches() -> list[PatchResult]:
    """Remove all Aegis patches from hermes-agent, restoring upstream code."""
    return [p.revert() for p in reversed(_PATCHES)]


def patches_status() -> list[PatchResult]:
    """Return current status of each patch without modifying any files."""
    results = []
    for p in _PATCHES:
        path = p.path()
        if not path.exists():
            results.append(PatchResult(p.name, "skipped", f"file not found: {p.file}"))
            continue
        content = path.read_text()
        if p.sentinel in content:
            results.append(PatchResult(p.name, "already_applied"))
        elif p.before in content:
            results.append(PatchResult(p.name, "skipped", "not yet applied"))
        else:
            results.append(PatchResult(
                p.name, "incompatible",
                f"neither patched nor unpatched form found in {p.file}"
            ))
    return results
