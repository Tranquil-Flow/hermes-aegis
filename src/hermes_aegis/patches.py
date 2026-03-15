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
            return PatchResult(self.name, "already_applied")

        if self.before not in content:
            status = "error" if self.critical else "incompatible"
            return PatchResult(
                self.name, status,
                f"target pattern not found in {self.file} — "
                "hermes-agent may have changed; manual review needed"
            )

        path.write_text(content.replace(self.before, self.after, 1))
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
