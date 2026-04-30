"""Hermes hook management and old setup migration."""
from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

HOOKS_DIR = Path.home() / ".hermes" / "hooks"
HOOK_NAME = "aegis-security"
HOOK_DIR = HOOKS_DIR / HOOK_NAME
HERMES_DIR = Path.home() / ".hermes"
HERMES_AGENT_DIR = HERMES_DIR / "hermes-agent"


def install_hook() -> Path:
    """Install Hermes event hook at ~/.hermes/hooks/aegis-security/.

    Returns the hook directory path.
    """
    HOOK_DIR.mkdir(parents=True, exist_ok=True)

    # Write HOOK.yaml
    hook_yaml = HOOK_DIR / "HOOK.yaml"
    hook_yaml.write_text(textwrap.dedent("""\
        name: aegis-security
        description: Start hermes-aegis proxy on gateway startup
        events:
          - gateway:startup
          - gateway:shutdown
    """))

    # Write handler.py — fully decoupled, no hermes_aegis imports
    handler_py = HOOK_DIR / "handler.py"
    handler_py.write_text(textwrap.dedent('''\
        """Hermes hook handler — starts aegis proxy on gateway startup."""
        import json
        import os
        import platform
        import socket
        import subprocess
        import time
        from pathlib import Path


        def _read_aegis_config() -> dict:
            """Read aegis config.json, returning {} on any error."""
            config_path = Path.home() / ".hermes-aegis" / "config.json"
            if not config_path.exists():
                return {}
            try:
                return json.loads(config_path.read_text())
            except Exception:
                return {}


        def _activate_sandbox_if_enabled() -> None:
            """Set sandbox env vars for gateway sessions when configured."""
            # --- Sandbox mode for gateway sessions (macOS GPU access) ---
            # This must run before proxy readiness checks: sandbox activation
            # only needs local config/profile state, and terminal sessions must
            # see TERMINAL_ENV=local before any agent session starts.
            aegis_cfg = _read_aegis_config()
            gateway_sandbox = aegis_cfg.get("gateway_sandbox", True)
            if not gateway_sandbox or platform.system() != "Darwin":
                return

            sandbox_profile = Path.home() / ".hermes-aegis" / "sandbox.sb"
            if not sandbox_profile.exists():
                return

            os.environ["TERMINAL_ENV"] = "local"
            os.environ["AEGIS_SANDBOX"] = "1"
            os.environ["AEGIS_SANDBOX_PROFILE"] = str(sandbox_profile)
            work_dir = aegis_cfg.get("sandbox_work_dir", "")
            if not work_dir:
                work_dir = str(Path.home() / "Projects")
            else:
                work_dir = str(Path(work_dir).expanduser())
            os.environ["TERMINAL_CWD"] = work_dir
            os.environ["AEGIS_SANDBOX_WORK_DIR"] = work_dir
            os.environ["AEGIS_SANDBOX_CACHE_DIR"] = str(Path.home() / ".cache")
            os.environ["AEGIS_SANDBOX_LOCAL_DIR"] = str(Path.home() / ".local")
            preferred_path = [
                "/opt/homebrew/bin",
                "/opt/homebrew/sbin",
                str(Path.home() / ".local" / "bin"),
                str(Path.home() / "Library" / "Python" / "3.14" / "bin"),
            ]
            merged_path = []
            for entry in preferred_path + os.environ.get("PATH", "").split(":"):
                if entry and entry not in merged_path:
                    merged_path.append(entry)
            os.environ["PATH"] = ":".join(merged_path)


        async def handle(event_type, context):
            if event_type == "gateway:startup":
                _activate_sandbox_if_enabled()

                # Start proxy via CLI (decoupled — no hermes_aegis imports needed)
                subprocess.Popen(
                    ["hermes-aegis", "start", "--quiet"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                # Poll for PID file (proxy needs time to start and bind port)
                pid_file = Path.home() / ".hermes-aegis" / "proxy.pid"
                for _ in range(10):
                    if pid_file.exists():
                        break
                    time.sleep(0.5)

                if not pid_file.exists():
                    return  # Proxy failed to start — don't set proxy env vars

                try:
                    pid_info = json.loads(pid_file.read_text())
                    pid = pid_info["pid"]
                    port = pid_info["port"]
                except (json.JSONDecodeError, KeyError):
                    return

                # Verify PID is alive AND port is listening (guards against PID reuse)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return  # Proxy died — don't set proxy env vars

                sock = socket.socket()
                try:
                    sock.settimeout(1.0)
                    sock.connect(("127.0.0.1", port))
                except OSError:
                    return  # Port not listening — don't set proxy env vars
                finally:
                    sock.close()

                proxy_url = f"http://127.0.0.1:{port}"
                os.environ["HTTP_PROXY"] = proxy_url
                os.environ["HTTPS_PROXY"] = proxy_url
                # Bypass proxy for local/LAN addresses — same list as hermes-aegis run
                os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1,*.local,192.168.0.0/16,10.0.0.0/8"
                ca_cert = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")
                os.environ["REQUESTS_CA_BUNDLE"] = ca_cert
                os.environ["SSL_CERT_FILE"] = ca_cert
                os.environ["GIT_SSL_CAINFO"] = ca_cert
                os.environ["NODE_EXTRA_CA_CERTS"] = ca_cert
                os.environ["CURL_CA_BUNDLE"] = ca_cert
                os.environ["PIP_CERT"] = ca_cert
                os.environ["AEGIS_ACTIVE"] = "1"
                # Tell hermes to forward proxy env vars into Docker exec calls.
                # Without this, TERMINAL_DOCKER_FORWARD_ENV defaults to [] and
                # the proxy URL / CA cert never reach containers.
                _forward_vars = [
                    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                    "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "GIT_SSL_CAINFO",
                    "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE", "PIP_CERT",
                    "AEGIS_ACTIVE",
                ]
                os.environ["TERMINAL_DOCKER_FORWARD_ENV"] = json.dumps(_forward_vars)

            elif event_type == "gateway:shutdown":
                # Stop proxy on Hermes exit
                subprocess.run(
                    ["hermes-aegis", "stop"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
    '''))

    return HOOK_DIR


def uninstall_hook() -> bool:
    """Remove the aegis-security hook directory. Returns True if removed."""
    if not HOOK_DIR.exists():
        return False
    shutil.rmtree(HOOK_DIR)
    return True


def is_hook_installed() -> bool:
    """Check if the aegis-security hook is installed."""
    return (HOOK_DIR / "HOOK.yaml").exists() and (HOOK_DIR / "handler.py").exists()


def clean_old_setup() -> list[str]:
    """Remove traces of the old invasive setup.

    Cleans:
    - sitecustomize.py Aegis loader entries
    - TERMINAL_ENV=aegis and PYTHONPATH lines from shell rc files
    - Old banner patch artifacts

    Returns list of actions taken.
    """
    actions: list[str] = []

    # Clean shell rc files
    for rc_name in [".zshrc", ".bashrc"]:
        rc_path = Path.home() / rc_name
        if not rc_path.exists():
            continue

        original = rc_path.read_text()
        lines = original.splitlines()
        cleaned = []
        skip_block = False

        for line in lines:
            # Skip the hermes-aegis block
            if "Hermes-Aegis Security Layer" in line:
                skip_block = True
                continue
            if skip_block:
                if line.strip().startswith("export PYTHONPATH") and "hermes-aegis" in line:
                    continue
                if line.strip().startswith("export TERMINAL_ENV") and "aegis" in line:
                    continue
                skip_block = False
            cleaned.append(line)

        new_text = "\n".join(cleaned)
        if new_text.rstrip("\n") != original.rstrip("\n"):
            rc_path.write_text(new_text)
            actions.append(f"Cleaned {rc_name}")

    # Clean sitecustomize.py entries
    import site
    import sys

    site_dirs = []
    # Check user site-packages
    try:
        site_dirs.append(Path(site.getusersitepackages()))
    except Exception:
        pass
    # Check venv site-packages
    if hasattr(sys, "prefix"):
        venv_sp = (
            Path(sys.prefix) / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
        if venv_sp.exists():
            site_dirs.append(venv_sp)

    for sp_dir in site_dirs:
        sc_path = sp_dir / "sitecustomize.py"
        if not sc_path.exists():
            continue

        content = sc_path.read_text()
        if "Hermes-Aegis Auto-Loader" not in content:
            continue

        lines = content.split("\n")
        new_lines = []
        skip = False
        for line in lines:
            if "Hermes-Aegis Auto-Loader" in line:
                skip = True
                continue
            if skip and line.strip() and not line.strip().startswith("#") and "aegis" not in line.lower():
                skip = False
            if not skip:
                new_lines.append(line)

        sc_path.write_text("\n".join(new_lines))
        actions.append(f"Cleaned sitecustomize.py in {sp_dir}")

    # Also clean sitecustomize.py in Hermes's own venv
    for venv_name in ["venv", ".venv"]:
        hermes_venv = HERMES_AGENT_DIR / venv_name
        if not hermes_venv.exists():
            continue
        for sc_path in hermes_venv.glob("lib/python*/site-packages/sitecustomize.py"):
            content = sc_path.read_text()
            if "hermes_aegis" not in content and "Hermes-Aegis" not in content:
                continue
            # Remove the entire file — it's an aegis-only loader
            sc_path.unlink()
            actions.append(f"Removed aegis sitecustomize.py from Hermes venv")

    # Clean aegis-managed placeholder keys from ~/.hermes/.env
    hermes_env = HERMES_DIR / ".env"
    if hermes_env.exists():
        try:
            lines = hermes_env.read_text().splitlines()
            new_lines = []
            cleaned_keys = []
            for line in lines:
                stripped = line.strip()
                if "=aegis-managed" in stripped:
                    key = stripped.split("=", 1)[0]
                    cleaned_keys.append(key)
                    continue
                new_lines.append(line)

            # Remove header if that's all that's left
            if all(l.strip().startswith("#") or not l.strip() for l in new_lines):
                new_lines = []

            if cleaned_keys:
                if new_lines:
                    hermes_env.write_text("\n".join(new_lines) + "\n")
                else:
                    hermes_env.unlink()
                actions.append(f"Removed aegis-managed placeholders from .env: {', '.join(cleaned_keys)}")
        except Exception:
            pass

    return actions
