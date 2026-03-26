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
# Patches are ordered by dependency.
#
# NOTE: Hermes v0.3.0 added native forward_env support to DockerEnvironment
# (init param, self._forward_env, config-driven docker_forward_env).
# Patches 1-2 (docker_env_init_param, docker_env_constructor) and 4
# (terminal_tool_docker_forward) were removed — upstream handles this now.
# Aegis injects proxy env vars via TERMINAL_DOCKER_FORWARD_ENV at runtime.

_PATCHES: list[FilePatch] = [

    # -- docker.py: translate 127.0.0.1/localhost to host.docker.internal
    #    and remap mitmproxy cert path to the in-container mount path.
    #    Upstream's exec loop iterates self._forward_env but passes values
    #    through unchanged — we add translation so containers can reach the proxy.
    #    v0.3.0 changed the loop from self._inner.config.forward_env to
    #    self._forward_env and added hermes_env fallback.
    FilePatch(
        name="docker_exec_proxy_translate",
        file="tools/environments/docker.py",
        sentinel="host.docker.internal",
        before=(
            "        for key in self._forward_env:\n"
            "            value = os.getenv(key)\n"
            "            if value is None:\n"
            "                value = hermes_env.get(key)\n"
            "            if value is not None:\n"
            "                cmd.extend([\"-e\", f\"{key}={value}\"])"
        ),
        after=(
            "        for key in self._forward_env:\n"
            "            value = os.getenv(key)\n"
            "            if value is None:\n"
            "                value = hermes_env.get(key)\n"
            "            if value is not None:\n"
            "                # Translate host-local addresses to container-reachable ones\n"
            "                value = value.replace(\"://127.0.0.1:\", \"://host.docker.internal:\")\n"
            "                value = value.replace(\"://localhost:\", \"://host.docker.internal:\")\n"
            "                # Translate host cert paths to container mount paths\n"
            "                if key in (\"REQUESTS_CA_BUNDLE\", \"SSL_CERT_FILE\", \"GIT_SSL_CAINFO\", \"NODE_EXTRA_CA_CERTS\", \"CURL_CA_BUNDLE\", \"PIP_CERT\") and \"/mitmproxy-ca-cert.pem\" in value:\n"
            "                    value = \"/certs/mitmproxy-ca-cert.pem\"\n"
            "                cmd.extend([\"-e\", f\"{key}={value}\"])"
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

    # -- Patch 6a: Show "Aegis Protection Activated" in hermes banner (hermes_cli/banner.py)
    # Hermes v0.2.0 has a DUPLICATE build_welcome_banner in cli.py that overrides
    # this one, but we patch both for forward-compatibility.
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

    # -- Patch 6b: Show "Aegis Protection Activated" in hermes banner (cli.py)
    # Hermes v0.2.0 duplicated build_welcome_banner into cli.py (used _session_c).
    # Hermes v0.3.0 removed the cli.py copy — banner is now exclusively in
    # hermes_cli/banner.py (Patch 6a above). This patch is kept for rollback
    # compatibility but will show "incompatible" on v0.3.0+ installs (safe).
    FilePatch(
        name="cli_banner_aegis_status",
        file="cli.py",
        sentinel="Aegis Protection Activated",
        before=(
            "    if session_id:\n"
            "        left_lines.append(f\"[dim {_session_c}]Session: {session_id}[/]\")\n"
            "    left_content = \"\\n\".join(left_lines)"
        ),
        after=(
            "    if session_id:\n"
            "        left_lines.append(f\"[dim {_session_c}]Session: {session_id}[/]\")\n"
            "    # Aegis: show protection status in hermes banner\n"
            "    import os as _aegis_os\n"
            "    if _aegis_os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "        left_lines.append(f\"[bold cyan]\U0001f6e1\ufe0f  Aegis Protection Activated[/]\")\n"
            "    left_content = \"\\n\".join(left_lines)"
        ),
        critical=False,
    ),

    # -- Patch 9: Network isolation — use dedicated Docker network when AEGIS_ACTIVE=1
    # Routes all container traffic through the aegis MITM proxy on the host.
    # NOT --internal: internal networks block host access, preventing the
    # container from reaching the proxy at host.docker.internal:PORT.
    # Security is enforced at the proxy layer (secret scanning, command blocking).
    FilePatch(
        name="docker_network_isolation",
        file="tools/environments/docker.py",
        sentinel="hermes-aegis-net",
        before=(
            "        all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args\n"
            "        logger.info(f\"Docker run_args: {all_run_args}\")"
        ),
        after=(
            "        all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args\n"
            "        # Aegis: dedicated network — proxy handles traffic filtering\n"
            "        import os as _aegis_net_os\n"
            "        if _aegis_net_os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "            import subprocess as _aegis_net_sp\n"
            "            _aegis_docker = find_docker() or \"docker\"\n"
            "            _aegis_net_sp.run(\n"
            "                [_aegis_docker, \"network\", \"create\", \"hermes-aegis-net\"],\n"
            "                capture_output=True,\n"
            "            )  # Idempotent — fails silently if exists\n"
            "            all_run_args.extend([\"--network\", \"hermes-aegis-net\",\n"
            "                                 \"--add-host\", \"host.docker.internal:host-gateway\"])\n"
            "        logger.info(f\"Docker run_args: {all_run_args}\")"
        ),
        critical=False,
    ),

    # -- Patch 9a: Cert mount — bind mitmproxy CA cert into container when AEGIS_ACTIVE=1
    # Without this volume mount, the cert path translations in docker_exec_proxy_translate
    # point to /certs/mitmproxy-ca-cert.pem which doesn't exist inside the container.
    FilePatch(
        name="docker_cert_mount",
        file="tools/environments/docker.py",
        sentinel="_aegis_cert_mount",
        before=(
            "        logger.info(f\"Docker run_args: {all_run_args}\")\n"
            "\n"
            "        # Resolve the docker executable once so it works even when\n"
            "        # /usr/local/bin is not in PATH (common on macOS gateway/service).\n"
            "        docker_exe = find_docker() or \"docker\""
        ),
        after=(
            "        logger.info(f\"Docker run_args: {all_run_args}\")\n"
            "\n"
            "        # Aegis: mount mitmproxy CA cert into container when AEGIS_ACTIVE=1 (_aegis_cert_mount)\n"
            "        # Required so /certs/mitmproxy-ca-cert.pem exists inside the container\n"
            "        # (docker_exec_proxy_translate rewrites SSL_CERT_FILE to this path).\n"
            "        import os as _aegis_cert_os\n"
            "        if _aegis_cert_os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "            from pathlib import Path as _aegis_cert_Path\n"
            "            _aegis_cert_src = _aegis_cert_Path.home() / \".mitmproxy\" / \"mitmproxy-ca-cert.pem\"\n"
            "            if _aegis_cert_src.exists():\n"
            "                all_run_args.extend([\"-v\", f\"{_aegis_cert_src}:/certs/mitmproxy-ca-cert.pem:ro\"])\n"
            "\n"
            "        # Resolve the docker executable once so it works even when\n"
            "        # /usr/local/bin is not in PATH (common on macOS gateway/service).\n"
            "        docker_exe = find_docker() or \"docker\""
        ),
        critical=False,
    ),

    # -- Patch 9b: Cert trust — install mitmproxy CA into container system trust store
    # SSL_CERT_FILE is respected by Python/curl/git but Chromium ignores it.
    # Installing into /usr/local/share/ca-certificates + update-ca-certificates
    # makes it trusted by Playwright/Chromium and all other tools.
    FilePatch(
        name="docker_cert_system_trust",
        file="tools/environments/docker.py",
        sentinel="_aegis_cert_trust",
        before=(
            "        self._container_id = self._inner.container_id\n"
            "\n"
            "    @staticmethod"
        ),
        after=(
            "        self._container_id = self._inner.container_id\n"
            "\n"
            "        # Aegis: install mitmproxy CA into system trust store (_aegis_cert_trust)\n"
            "        # Chromium/Playwright ignores SSL_CERT_FILE and requires the cert in\n"
            "        # the OS trust store. update-ca-certificates makes it trusted system-wide.\n"
            "        if os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "            from pathlib import Path as _aegis_trust_Path\n"
            "            if (_aegis_trust_Path.home() / \".mitmproxy\" / \"mitmproxy-ca-cert.pem\").exists():\n"
            "                import subprocess as _aegis_trust_sp\n"
            "                _aegis_trust_sp.run(\n"
            "                    [docker_exe, \"exec\", self._container_id, \"bash\", \"-c\",\n"
            "                     \"cp /certs/mitmproxy-ca-cert.pem\"\n"
            "                     \" /usr/local/share/ca-certificates/aegis-proxy.crt\"\n"
            "                     \" && update-ca-certificates -f 2>/dev/null || true\"],\n"
            "                    capture_output=True, timeout=15,\n"
            "                )\n"
            "\n"
            "    @staticmethod"
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

    # -- Patch 10: Forward proxy env vars into Docker containers
    # terminal_tool.py builds container_config from _get_env_config() but omits
    # docker_forward_env, so DockerEnvironment._forward_env is always [].
    # This patch adds docker_forward_env to container_config so that the
    # exec_run loop (Patch 1) actually injects proxy vars via docker exec -e.
    FilePatch(
        name="terminal_tool_docker_forward_env",
        file="tools/terminal_tool.py",
        sentinel="aegis_forward_env",
        before=(
            "                            container_config = {\n"
            "                                \"container_cpu\": config.get(\"container_cpu\", 1),\n"
            "                                \"container_memory\": config.get(\"container_memory\", 5120),\n"
            "                                \"container_disk\": config.get(\"container_disk\", 51200),\n"
            "                                \"container_persistent\": config.get(\"container_persistent\", True),\n"
            "                                \"docker_volumes\": config.get(\"docker_volumes\", []),\n"
            "                                \"docker_mount_cwd_to_workspace\": config.get(\"docker_mount_cwd_to_workspace\", False),\n"
            "                            }"
        ),
        after=(
            "                            container_config = {\n"
            "                                \"container_cpu\": config.get(\"container_cpu\", 1),\n"
            "                                \"container_memory\": config.get(\"container_memory\", 5120),\n"
            "                                \"container_disk\": config.get(\"container_disk\", 51200),\n"
            "                                \"container_persistent\": config.get(\"container_persistent\", True),\n"
            "                                \"docker_volumes\": config.get(\"docker_volumes\", []),\n"
            "                                \"docker_mount_cwd_to_workspace\": config.get(\"docker_mount_cwd_to_workspace\", False),\n"
            "                                # Aegis: forward proxy env vars into Docker exec calls (aegis_forward_env)\n"
            "                                \"docker_forward_env\": config.get(\"docker_forward_env\", []),\n"
            "                            }"
        ),
        critical=False,
    ),

    # -- Patch 11a: Suppress KeyboardInterrupt during flush_memories on Ctrl+C
    # Both flush_memories call sites in cli.py catch `Exception` but not
    # `KeyboardInterrupt` (which inherits from BaseException). When Ctrl+C is
    # pressed while flush_memories is blocking on an SSL socket read through the
    # proxy, the KeyboardInterrupt escapes the except clause and propagates to
    # the top level, producing an ugly traceback. Catching BaseException silently
    # swallows the interrupt — memory flush is best-effort on exit anyway.
    FilePatch(
        name="cli_flush_memories_keyboard_interrupt_finally",
        file="cli.py",
        sentinel="flush_memories_baseexception_finally",
        before=(
            "            if self.agent and self.conversation_history:\n"
            "                try:\n"
            "                    self.agent.flush_memories(self.conversation_history)\n"
            "                except Exception:\n"
            "                    pass\n"
            "            # Shut down voice recorder"
        ),
        after=(
            "            if self.agent and self.conversation_history:\n"
            "                try:\n"
            "                    self.agent.flush_memories(self.conversation_history)\n"
            "                except BaseException:  # flush_memories_baseexception_finally\n"
            "                    pass  # KeyboardInterrupt / SSL errors on Ctrl+C are non-fatal\n"
            "            # Shut down voice recorder"
        ),
        critical=False,
    ),
    FilePatch(
        name="cli_flush_memories_keyboard_interrupt_new_session",
        file="cli.py",
        sentinel="flush_memories_baseexception_new_session",
        before=(
            "        if self.agent and self.conversation_history:\n"
            "            try:\n"
            "                self.agent.flush_memories(self.conversation_history)\n"
            "            except Exception:\n"
            "                pass\n"
            "\n"
            "        old_session_id"
        ),
        after=(
            "        if self.agent and self.conversation_history:\n"
            "            try:\n"
            "                self.agent.flush_memories(self.conversation_history)\n"
            "            except BaseException:  # flush_memories_baseexception_new_session\n"
            "                pass\n"
            "\n"
            "        old_session_id"
        ),
        critical=False,
    ),

    # -- Patch 12a: Trust MITM CA via --ignore-https-errors when aegis proxy is active.
    # The mitmproxy intercepts TLS at the network layer (transparent proxy on the
    # hermes-aegis-net Docker network). Chromium on Linux uses BoringSSL + Chrome
    # Root Store and ignores system CA stores and env vars like SSL_CERT_FILE.
    # mitmproxy validates upstream certs before re-signing, so this is safe.
    FilePatch(
        name="browser_tool_ignore_https_errors",
        file="tools/browser_tool.py",
        sentinel="_aegis_browser_ignore_https_errors",
        before=(
            "    if session_info.get(\"cdp_url\"):\n"
            "        # Cloud mode — connect to remote Browserbase browser via CDP\n"
            "        # IMPORTANT: Do NOT use --session with --cdp. In agent-browser >=0.13,\n"
            "        # --session creates a local browser instance and silently ignores --cdp.\n"
            "        backend_args = [\"--cdp\", session_info[\"cdp_url\"]]\n"
            "    else:\n"
            "        # Local mode — launch a headless Chromium instance\n"
            "        backend_args = [\"--session\", session_info[\"session_name\"]]\n"
            "\n"
            "    cmd_parts = browser_cmd.split() + backend_args + [\n"
            "        \"--json\",\n"
            "        command\n"
            "    ] + args"
        ),
        after=(
            "    if session_info.get(\"cdp_url\"):\n"
            "        # Cloud mode — connect to remote Browserbase browser via CDP\n"
            "        # IMPORTANT: Do NOT use --session with --cdp. In agent-browser >=0.13,\n"
            "        # --session creates a local browser instance and silently ignores --cdp.\n"
            "        backend_args = [\"--cdp\", session_info[\"cdp_url\"]]\n"
            "    else:\n"
            "        # Local mode — launch a headless Chromium instance\n"
            "        backend_args = [\"--session\", session_info[\"session_name\"]]\n"
            "\n"
            "    # Aegis: trust MITM CA via --ignore-https-errors when proxy is active (_aegis_browser_ignore_https_errors)\n"
            "    # mitmproxy intercepts TLS at network layer; Chromium (BoringSSL) ignores system CA stores.\n"
            "    # mitmproxy validates upstream certs before re-signing, so this is safe.\n"
            "    # Detection: AEGIS_ACTIVE=1 (primary), SSL_CERT_FILE path contains mitmproxy\n"
            "    # (set by aegis hook on host), or /certs/mitmproxy-ca-cert.pem exists (container).\n"
            "    import os as _aegis_br_os\n"
            "    _aegis_mitm_active = (\n"
            "        _aegis_br_os.getenv(\"AEGIS_ACTIVE\") == \"1\"\n"
            "        or \"mitmproxy\" in _aegis_br_os.getenv(\"SSL_CERT_FILE\", \"\")\n"
            "        or _aegis_br_os.path.exists(\"/certs/mitmproxy-ca-cert.pem\")\n"
            "    )\n"
            "    if _aegis_mitm_active:\n"
            "        backend_args = [\"--ignore-https-errors\"] + backend_args\n"
            "\n"
            "    cmd_parts = browser_cmd.split() + backend_args + [\n"
            "        \"--json\",\n"
            "        command\n"
            "    ] + args"
        ),
        critical=False,
    ),

    # -- Patch 12b: Strip proxy env vars from browser subprocess
    # browser_tool.py inherits HTTPS_PROXY from os.environ so agent-browser routes
    # HTTPS through the mitmproxy. Chromium ignores Python/Node CA env vars
    # (REQUESTS_CA_BUNDLE, SSL_CERT_FILE) so every HTTPS nav fails with
    # ERR_CERT_AUTHORITY_INVALID. Browser/CDP traffic is already TLS-secured at
    # the Browserbase level — stripping proxy vars lets Chrome connect directly.
    FilePatch(
        name="browser_tool_strip_proxy_env",
        file="tools/browser_tool.py",
        sentinel="_aegis_browser_strip_proxy",
        before=(
            "        browser_env = {**os.environ}\n"
            "\n"
            "        # Ensure PATH includes Hermes-managed Node first, then standard system dirs."
        ),
        after=(
            "        browser_env = {**os.environ}\n"
            "        # Aegis: strip proxy env vars so Chromium connects directly (_aegis_browser_strip_proxy)\n"
            "        # Routing browser traffic through mitmproxy breaks HTTPS because Chrome\n"
            "        # ignores Python/Node CA env vars. Browser/CDP is already TLS-secured.\n"
            "        for _k in (\"HTTP_PROXY\", \"HTTPS_PROXY\", \"http_proxy\", \"https_proxy\"):\n"
            "            browser_env.pop(_k, None)\n"
            "\n"
            "        # Ensure PATH includes Hermes-managed Node first, then standard system dirs."
        ),
        critical=False,
    ),

    # -- Patch 11: Suppress DEBUG-level Docker container logs from console
    # minisweagent's RichHandler prints full docker run commands at DEBUG level,
    # including all run_args. This is noisy under aegis (which adds --network
    # and --add-host flags). Raise the console handler to INFO when AEGIS_ACTIVE.
    FilePatch(
        name="minisweagent_quiet_console",
        file="mini-swe-agent/src/minisweagent/utils/log.py",
        sentinel="_aegis_quiet",
        before=(
            "    _handler = RichHandler(\n"
            "        show_path=False,\n"
            "        show_time=False,\n"
            "        show_level=False,\n"
            "        markup=True,\n"
            "    )"
        ),
        after=(
            "    _handler = RichHandler(\n"
            "        show_path=False,\n"
            "        show_time=False,\n"
            "        show_level=False,\n"
            "        markup=True,\n"
            "    )\n"
            "    # Aegis: suppress verbose DEBUG docker logs from console (_aegis_quiet)\n"
            "    import os as _aegis_quiet\n"
            "    if _aegis_quiet.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "        _handler.setLevel(logging.INFO)"
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
