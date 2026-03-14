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
        import socket
        import subprocess
        import time
        from pathlib import Path


        async def handle(event_type, context):
            if event_type == "gateway:startup":
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
                    return  # Proxy failed to start — don't set env vars

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
                    return  # Proxy died — don't set env vars

                sock = socket.socket()
                try:
                    sock.settimeout(1.0)
                    sock.connect(("127.0.0.1", port))
                except OSError:
                    return  # Port not listening — proxy not ready
                finally:
                    sock.close()

                os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
                os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{port}"
                ca_cert = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")
                os.environ["REQUESTS_CA_BUNDLE"] = ca_cert
                os.environ["SSL_CERT_FILE"] = ca_cert

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
