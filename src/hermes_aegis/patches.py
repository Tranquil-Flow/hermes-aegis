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
import inspect
from pathlib import Path


def _resolve_hermes_agent_dir() -> Path:
    """Return the Hermes checkout used by the active hermes CLI."""
    try:
        import hermes_cli

        return Path(inspect.getfile(hermes_cli)).resolve().parent.parent
    except Exception:
        return Path.home() / ".hermes" / "hermes-agent"


HERMES_AGENT_DIR = _resolve_hermes_agent_dir()


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
#
# Hermes v0.11 plugin hooks replaced three older source patches:
# - terminal_tool_audit_forward -> post_tool_call hook
# - terminal_tool_command_scan -> fail-closed pre_tool_call hook
# - hermes_banner_aegis_status -> pre_llm_call security context
# The MITM/Docker/sandbox patches remain because they operate below the plugin
# hook boundary.

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
        # v0.7.0 refactored exec env building: values are now collected into an
        # exec_env dict (via forward_keys loop) before being passed to docker exec.
        # We intercept each forwarded value at the point of assignment to exec_env.
        before=(
            "            if value is not None:\n"
            "                exec_env[key] = value"
        ),
        after=(
            "            if value is not None:\n"
            "                # Aegis: translate host-local addresses to container-reachable ones (host.docker.internal)\n"
            "                import os as _aegis_xlat_os\n"
            "                if _aegis_xlat_os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "                    value = value.replace(\"://127.0.0.1:\", \"://host.docker.internal:\")\n"
            "                    value = value.replace(\"://localhost:\", \"://host.docker.internal:\")\n"
            "                    # Translate host cert paths to container mount paths\n"
            "                    if key in (\"REQUESTS_CA_BUNDLE\", \"SSL_CERT_FILE\", \"GIT_SSL_CAINFO\", \"NODE_EXTRA_CA_CERTS\", \"CURL_CA_BUNDLE\", \"PIP_CERT\"):\n"
            "                        if \"hermes-aegis\" in value or \"ca-bundle\" in value:\n"
            "                            value = \"/certs/aegis-ca-bundle.pem\"\n"
            "                        elif \"/mitmproxy-ca-cert.pem\" in value:\n"
            "                            value = \"/certs/mitmproxy-ca-cert.pem\"\n"
            "                exec_env[key] = value"
        ),
    ),

    FilePatch(
        name="terminal_description_neutral_env",
        file="tools/terminal_tool.py",
        sentinel="_aegis_terminal_description_neutral_env",
        before=(
            'TERMINAL_TOOL_DESCRIPTION = """Execute shell commands on a Linux environment. Filesystem usually persists between calls.'
        ),
        after=(
            'TERMINAL_TOOL_DESCRIPTION = """Execute shell commands in the configured terminal environment. Filesystem usually persists between calls.\n'
            '\n'
            'Aegis: when gateway sandbox mode is active, this is a macOS sandbox-exec environment with Metal/MPS access.  # _aegis_terminal_description_neutral_env'
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
            "        all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args + env_args\n"
            "        logger.info(f\"Docker run_args: {all_run_args}\")"
        ),
        after=(
            "        all_run_args = list(_SECURITY_ARGS) + writable_args + resource_args + volume_args + env_args\n"
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
            "        self._docker_exe = find_docker() or \"docker\""
        ),
        after=(
            "        logger.info(f\"Docker run_args: {all_run_args}\")\n"
            "\n"
            "        # Aegis: mount CA certs into container when AEGIS_ACTIVE=1 (_aegis_cert_mount)\n"
            "        # Mounts: combined bundle (system CAs + mitmproxy CA) for SSL_CERT_FILE,\n"
            "        # and the plain mitmproxy cert for Chromium system trust store installation.\n"
            "        import os as _aegis_cert_os\n"
            "        if _aegis_cert_os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "            from pathlib import Path as _aegis_cert_Path\n"
            "            _aegis_cert_src = _aegis_cert_Path.home() / \".mitmproxy\" / \"mitmproxy-ca-cert.pem\"\n"
            "            if _aegis_cert_src.exists():\n"
            "                all_run_args.extend([\"-v\", f\"{_aegis_cert_src}:/certs/mitmproxy-ca-cert.pem:ro\"])\n"
            "            _aegis_bundle_src = _aegis_cert_Path.home() / \".hermes-aegis\" / \"ca-bundle.pem\"\n"
            "            if _aegis_bundle_src.exists():\n"
            "                all_run_args.extend([\"-v\", f\"{_aegis_bundle_src}:/certs/aegis-ca-bundle.pem:ro\"])\n"
            "\n"
            "        # Resolve the docker executable once so it works even when\n"
            "        # /usr/local/bin is not in PATH (common on macOS gateway/service).\n"
            "        self._docker_exe = find_docker() or \"docker\""
        ),
        critical=False,
    ),

    # -- Patch 9b: Cert trust — install mitmproxy CA into container system trust store
    # SSL_CERT_FILE is respected by Python/curl/git but Chromium ignores it.
    # Installing into /usr/local/share/ca-certificates + update-ca-certificates
    # makes it trusted by Playwright/Chromium and all other tools.
    # v0.7.0: upstream added _build_init_env_args() + init_session() after container
    # start — we inject the cert trust before the init_env_args step.
    FilePatch(
        name="docker_cert_system_trust",
        file="tools/environments/docker.py",
        sentinel="_aegis_cert_trust",
        before=(
            "        self._container_id = result.stdout.strip()\n"
            "        logger.info(f\"Started container {container_name} ({self._container_id[:12]})\")\n"
            "\n"
            "        # Build the init-time env forwarding args"
        ),
        after=(
            "        self._container_id = result.stdout.strip()\n"
            "        logger.info(f\"Started container {container_name} ({self._container_id[:12]})\")\n"
            "\n"
            "        # Aegis: install mitmproxy CA into system trust store (_aegis_cert_trust)\n"
            "        # Chromium/Playwright ignores SSL_CERT_FILE and requires the cert in\n"
            "        # the OS trust store. update-ca-certificates makes it trusted system-wide.\n"
            "        import os as _aegis_trust_os\n"
            "        if _aegis_trust_os.getenv(\"AEGIS_ACTIVE\") == \"1\":\n"
            "            from pathlib import Path as _aegis_trust_Path\n"
            "            if (_aegis_trust_Path.home() / \".mitmproxy\" / \"mitmproxy-ca-cert.pem\").exists():\n"
            "                import subprocess as _aegis_trust_sp\n"
            "                _aegis_trust_sp.run(\n"
            "                    [self._docker_exe, \"exec\", self._container_id, \"bash\", \"-c\",\n"
            "                     \"cp /certs/mitmproxy-ca-cert.pem\"\n"
            "                     \" /usr/local/share/ca-certificates/aegis-proxy.crt\"\n"
            "                     \" && update-ca-certificates -f 2>/dev/null || true\"],\n"
            "                    capture_output=True, timeout=15,\n"
            "                )\n"
            "\n"
            "        # Build the init-time env forwarding args"
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
            "        approval_note = None\n"
            "        if not force:\n"
        ),
        after=(
            "        # Pre-exec security checks (tirith + dangerous command detection)\n"
            "        # Skip check if force=True (user has confirmed they want to run it)\n"
            "        # Aegis container handshake: relax file-write guards in isolated containers\n"
            "        # (container has read-only root, tmpfs for /tmp, aegis handles network)\n"
            "        _aegis_container = os.getenv(\"AEGIS_CONTAINER_ISOLATED\") == \"1\"\n"
            "        approval_note = None\n"
            "        if not force:\n"
        ),
        critical=False,
    ),

    # -- Patch 10: Forward proxy env vars into Docker containers
    # terminal_tool.py builds container_config from _get_env_config(). v0.7.0
    # dropped docker_forward_env from container_config, so this patch adds it back
    # and marks it with the aegis_forward_env sentinel for idempotency detection.
    FilePatch(
        name="terminal_tool_docker_forward_env",
        file="tools/terminal_tool.py",
        sentinel="aegis_forward_env",
        before=(
            "                                \"docker_mount_cwd_to_workspace\": config.get(\"docker_mount_cwd_to_workspace\", False),\n"
            "                                \"docker_forward_env\": config.get(\"docker_forward_env\", []),\n"
            "                                \"docker_env\": config.get(\"docker_env\", {}),\n"
            "                            }"
        ),
        after=(
            "                                \"docker_mount_cwd_to_workspace\": config.get(\"docker_mount_cwd_to_workspace\", False),\n"
            "                                # Aegis: forward proxy env vars into container (aegis_forward_env)\n"
            "                                \"docker_forward_env\": config.get(\"docker_forward_env\", []),\n"
            "                                \"docker_env\": config.get(\"docker_env\", {}),\n"
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
            "                except (Exception, KeyboardInterrupt):\n"
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
        # v0.7.0: upstream added _notify_session_boundary() after the except block
        before=(
            "        if self.agent and self.conversation_history:\n"
            "            try:\n"
            "                self.agent.flush_memories(self.conversation_history)\n"
            "            except (Exception, KeyboardInterrupt):\n"
            "                pass\n"
            "            # Trigger memory extraction on the old session before session_id rotates.\n"
            "            self.agent.commit_memory_session(self.conversation_history)\n"
            "            self._notify_session_boundary(\"on_session_finalize\")"
        ),
        after=(
            "        if self.agent and self.conversation_history:\n"
            "            try:\n"
            "                self.agent.flush_memories(self.conversation_history)\n"
            "            except BaseException:  # flush_memories_baseexception_new_session\n"
            "                pass\n"
            "            # Trigger memory extraction on the old session before session_id rotates.\n"
            "            self.agent.commit_memory_session(self.conversation_history)\n"
            "            self._notify_session_boundary(\"on_session_finalize\")"
        ),
        critical=False,
    ),

    # -- Patch 12a: Trust MITM CA via --ignore-https-errors when aegis proxy is active.
    # The mitmproxy intercepts TLS at the network layer (transparent proxy on the
    # hermes-aegis-net Docker network). Chromium on Linux uses BoringSSL + Chrome
    # Root Store and ignores system CA stores and env vars like SSL_CERT_FILE.
    # mitmproxy validates upstream certs before re-signing, so this is safe.
    # v0.7.0: upstream refactored cmd_parts to use cmd_prefix instead of browser_cmd.split()
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
            "    # Keep concrete executable paths intact, even when they contain spaces.\n"
            "    # Only the synthetic npx fallback needs to expand into multiple argv items.\n"
            "    cmd_prefix = [\"npx\", \"agent-browser\"] if browser_cmd == \"npx agent-browser\" else [browser_cmd]\n"
            "\n"
            "    cmd_parts = cmd_prefix + backend_args + [\n"
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
            "    # Keep concrete executable paths intact, even when they contain spaces.\n"
            "    # Only the synthetic npx fallback needs to expand into multiple argv items.\n"
            "    cmd_prefix = [\"npx\", \"agent-browser\"] if browser_cmd == \"npx agent-browser\" else [browser_cmd]\n"
            "\n"
            "    cmd_parts = cmd_prefix + backend_args + [\n"
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
            "        # Ensure subprocesses inherit the same browser-specific PATH fallbacks\n"
            "        # used during CLI discovery."
        ),
        after=(
            "        browser_env = {**os.environ}\n"
            "        # Aegis: strip proxy env vars so Chromium connects directly (_aegis_browser_strip_proxy)\n"
            "        # Routing browser traffic through mitmproxy breaks HTTPS because Chrome\n"
            "        # ignores Python/Node CA env vars. Browser/CDP is already TLS-secured.\n"
            "        for _k in (\"HTTP_PROXY\", \"HTTPS_PROXY\", \"http_proxy\", \"https_proxy\"):\n"
            "            browser_env.pop(_k, None)\n"
            "        # Aegis: also set env var for agent-browser to ignore HTTPS errors on reused sessions\n"
            "        if _aegis_mitm_active:\n"
            "            browser_env[\"AGENT_BROWSER_IGNORE_HTTPS_ERRORS\"] = \"1\"\n"
            "\n"
            "        # Ensure subprocesses inherit the same browser-specific PATH fallbacks\n"
            "        # used during CLI discovery."
        ),
        critical=False,
    ),

    # -- Patch 12: Update Aegis and re-apply patches after Hermes self-update
    # When the user runs `hermes update`, Hermes pulls a fresh copy of hermes-agent
    # from git, overwriting all our patches. This hook detects a hermes-aegis install,
    # updates hermes-aegis itself, and re-applies patches at the end of cmd_update()
    # so one `hermes update` keeps both projects current.
    FilePatch(
        name="hermes_update_aegis_repatch",
        file="hermes_cli/main.py",
        sentinel="# aegis: post-update-repatch",
        before=(
            "        print()\n"
            "        print(\"✓ Code updated!\")\n"
            "\n"
            "        # After git pull, source files on disk are newer than cached Python\n"
            "        # modules in this process.  Reload hermes_constants so that any lazy\n"
            "        # import executed below (skills sync, gateway restart) sees new\n"
            "        # attributes like display_hermes_home() added since the last release.\n"
            "        try:\n"
            "            import importlib\n"
            "            import hermes_constants as _hc\n"
            "\n"
            "            importlib.reload(_hc)\n"
            "        except Exception:\n"
            "            pass  # non-fatal — worst case a lazy import fails gracefully\n"
            "\n"
            "        # Sync bundled skills (copies new, updates changed, respects user deletions)"
        ),
        after=(
            "        print()\n"
            "        print(\"✓ Code updated!\")\n"
            "        \n"
            "        # aegis: post-update-repatch\n"
            "        if shutil.which(\"hermes-aegis\"):\n"
            "            print(\"→ Updating hermes-aegis and re-applying patches...\")\n"
            "            _aegis_result = subprocess.run([\"hermes-aegis\", \"update\"], check=False)\n"
            "            if _aegis_result.returncode != 0:\n"
            "                print(\"⚠ hermes-aegis update failed. Run: hermes-aegis update\")\n"
            "            else:\n"
            "                print(\"✓ Aegis updated and patches re-applied\")\n"
            "        \n"
            "        # After git pull, source files on disk are newer than cached Python\n"
            "        # modules in this process.  Reload hermes_constants so that any lazy\n"
            "        # import executed below (skills sync, gateway restart) sees new\n"
            "        # attributes like display_hermes_home() added since the last release.\n"
            "        try:\n"
            "            import importlib\n"
            "            import hermes_constants as _hc\n"
            "\n"
            "            importlib.reload(_hc)\n"
            "        except Exception:\n"
            "            pass  # non-fatal — worst case a lazy import fails gracefully\n"
            "\n"
            "        # Sync bundled skills (copies new, updates changed, respects user deletions)"
        ),
        critical=False,
    ),

    # --- Sandbox: GPU-safe local execution on macOS -------------------------
    FilePatch(
        name="local_sandbox_exec",
        file="tools/environments/local.py",
        sentinel="_aegis_sandbox_exec",
        before=(
            '        args = [bash, "-l", "-c", cmd_string] if login else [bash, "-c", cmd_string]\n'
            '        run_env = _make_run_env(self.env)'
        ),
        after=(
            '        args = [bash, "-l", "-c", cmd_string] if login else [bash, "-c", cmd_string]\n'
            '        # aegis: sandbox-exec wrapping for GPU-safe local isolation  # _aegis_sandbox_exec\n'
            '        if os.getenv("AEGIS_SANDBOX") == "1":\n'
            '            _sb_profile = os.getenv("AEGIS_SANDBOX_PROFILE", "")\n'
            '            if _sb_profile and os.path.isfile(_sb_profile):\n'
            '                _sb_params = []\n'
            '                for _key in ("WORK_DIR", "CACHE_DIR", "LOCAL_DIR"):\n'
            '                    _val = os.getenv(f"AEGIS_SANDBOX_{_key}", "")\n'
            '                    if _val:\n'
            '                        _sb_params.extend(["-D", f"{_key}={_val}"])\n'
            '                args = ["sandbox-exec"] + _sb_params + ["-f", _sb_profile] + args\n'
            '        run_env = _make_run_env(self.env)'
        ),
        critical=False,
    ),

    FilePatch(
        name="local_sandbox_path_preference",
        file="tools/environments/local.py",
        sentinel="_aegis_sandbox_path",
        before=(
            '        args = [bash, "-l", "-c", cmd_string] if login else [bash, "-c", cmd_string]'
        ),
        after=(
            '        # aegis: keep Homebrew Python ahead of /usr/local after shell snapshots  # _aegis_sandbox_path\n'
            '        if os.getenv("AEGIS_SANDBOX") == "1":\n'
            '            _aegis_home = os.path.expanduser("~")\n'
            '            _aegis_path_prefix = (\n'
            '                f"/opt/homebrew/bin:/opt/homebrew/sbin:"\n'
            '                f"{_aegis_home}/.local/bin:"\n'
            '                f"{_aegis_home}/Library/Python/3.14/bin"\n'
            '            )\n'
            '            _aegis_path_export = f\'export PATH="{_aegis_path_prefix}:$PATH"\'\n'
            '            if not login and cmd_string.startswith("source "):\n'
            '                _first_line, _sep, _rest = cmd_string.partition("\\n")\n'
            '                if _sep:\n'
            '                    cmd_string = f"{_first_line}\\n{_aegis_path_export}\\n{_rest}"\n'
            '                else:\n'
            '                    cmd_string = f"{_aegis_path_export}\\n{cmd_string}"\n'
            '            else:\n'
            '                cmd_string = f"{_aegis_path_export}\\n{cmd_string}"\n'
            '        args = [bash, "-l", "-c", cmd_string] if login else [bash, "-c", cmd_string]'
        ),
        critical=False,
    ),

    FilePatch(
        name="gateway_sandbox_startup_env",
        file="gateway/run.py",
        sentinel="_aegis_gateway_sandbox_startup",
        before=(
            "    except Exception:\n"
            "        pass  # Non-fatal; gateway can still run with .env values\n"
            "\n"
            "# Apply IPv4 preference if configured (before any HTTP clients are created)."
        ),
        after=(
            "    except Exception:\n"
            "        pass  # Non-fatal; gateway can still run with .env values\n"
            "\n"
            "# Aegis: activate macOS sandbox before GatewayRunner/tool state exists.  # _aegis_gateway_sandbox_startup\n"
            "def _aegis_activate_gateway_sandbox() -> None:\n"
            "    try:\n"
            "        import platform as _aegis_platform\n"
            "\n"
            "        if _aegis_platform.system() != \"Darwin\":\n"
            "            return\n"
            "\n"
            "        _aegis_dir = Path.home() / \".hermes-aegis\"\n"
            "        _cfg_path = _aegis_dir / \"config.json\"\n"
            "        _aegis_cfg = {}\n"
            "        if _cfg_path.exists():\n"
            "            try:\n"
            "                _aegis_cfg = json.loads(_cfg_path.read_text())\n"
            "            except Exception:\n"
            "                _aegis_cfg = {}\n"
            "\n"
            "        if not _aegis_cfg.get(\"gateway_sandbox\", True):\n"
            "            return\n"
            "\n"
            "        _profile = _aegis_dir / \"sandbox.sb\"\n"
            "        if not _profile.exists():\n"
            "            return\n"
            "\n"
            "        _work_dir = _aegis_cfg.get(\"sandbox_work_dir\", \"\")\n"
            "        if not _work_dir:\n"
            "            _work_dir = str(Path.home() / \"Projects\")\n"
            "        else:\n"
            "            _work_dir = str(Path(_work_dir).expanduser())\n"
            "\n"
            "        os.environ[\"TERMINAL_ENV\"] = \"local\"\n"
            "        os.environ[\"TERMINAL_CWD\"] = _work_dir\n"
            "        os.environ[\"AEGIS_SANDBOX\"] = \"1\"\n"
            "        os.environ[\"AEGIS_SANDBOX_PROFILE\"] = str(_profile)\n"
            "        os.environ[\"AEGIS_SANDBOX_WORK_DIR\"] = _work_dir\n"
            "        os.environ[\"AEGIS_SANDBOX_CACHE_DIR\"] = str(Path.home() / \".cache\")\n"
            "        os.environ[\"AEGIS_SANDBOX_LOCAL_DIR\"] = str(Path.home() / \".local\")\n"
            "        _preferred_path = [\n"
            "            \"/opt/homebrew/bin\",\n"
            "            \"/opt/homebrew/sbin\",\n"
            "            str(Path.home() / \".local\" / \"bin\"),\n"
            "            str(Path.home() / \"Library\" / \"Python\" / \"3.14\" / \"bin\"),\n"
            "        ]\n"
            "        _merged_path = []\n"
            "        for _entry in _preferred_path + os.environ.get(\"PATH\", \"\").split(\":\"):\n"
            "            if _entry and _entry not in _merged_path:\n"
            "                _merged_path.append(_entry)\n"
            "        os.environ[\"PATH\"] = \":\".join(_merged_path)\n"
            "    except Exception:\n"
            "        pass\n"
            "\n"
            "\n"
            "_aegis_activate_gateway_sandbox()\n"
            "\n"
            "# Apply IPv4 preference if configured (before any HTTP clients are created)."
        ),
        critical=False,
    ),

    FilePatch(
        name="cli_sandbox_terminal_override",
        file="cli.py",
        sentinel="_aegis_cli_sandbox_terminal_override",
        before=(
            "    for config_key, env_var in env_mappings.items():\n"
            "        if config_key in terminal_config:\n"
            "            if _file_has_terminal_config or env_var not in os.environ:\n"
            "                val = terminal_config[config_key]\n"
            "                if isinstance(val, list):\n"
            "                    os.environ[env_var] = json.dumps(val)\n"
            "                else:\n"
            "                    os.environ[env_var] = str(val)"
        ),
        after=(
            "    for config_key, env_var in env_mappings.items():\n"
            "        if config_key in terminal_config:\n"
            "            # aegis: preserve gateway macOS sandbox override during lazy cli imports  # _aegis_cli_sandbox_terminal_override\n"
            "            if os.getenv(\"AEGIS_SANDBOX\") == \"1\" and env_var in (\"TERMINAL_ENV\", \"TERMINAL_CWD\"):\n"
            "                continue\n"
            "            if _file_has_terminal_config or env_var not in os.environ:\n"
            "                val = terminal_config[config_key]\n"
            "                if isinstance(val, list):\n"
            "                    os.environ[env_var] = json.dumps(val)\n"
            "                else:\n"
            "                    os.environ[env_var] = str(val)"
        ),
        critical=False,
    ),

    # --- Sandbox: prevent session init from overwriting TERMINAL_ENV --------
    # hermes_base_env.py line 258-259 sets TERMINAL_ENV from config.yaml on
    # every session init, overwriting the hook's TERMINAL_ENV=local override.
    # When AEGIS_SANDBOX=1 is set, preserve the hook's value.
    FilePatch(
        name="base_env_sandbox_terminal_override",
        file="environments/hermes_base_env.py",
        sentinel="_aegis_sandbox_terminal_override",
        before=(
            '        if config.terminal_backend:\n'
            '            os.environ["TERMINAL_ENV"] = config.terminal_backend'
        ),
        after=(
            '        if config.terminal_backend:\n'
            '            # aegis: preserve sandbox TERMINAL_ENV override  # _aegis_sandbox_terminal_override\n'
            '            if os.getenv("AEGIS_SANDBOX") != "1":\n'
            '                os.environ["TERMINAL_ENV"] = config.terminal_backend'
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
