"""Proxy lifecycle management — start/stop mitmproxy as a subprocess."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from hermes_aegis.utils import find_available_port, wait_for_proxy_ready

AEGIS_DIR = Path.home() / ".hermes-aegis"
PID_FILE = AEGIS_DIR / "proxy.pid"
CONFIG_FILE = AEGIS_DIR / "proxy-config.json"


def _find_mitmdump() -> str:
    """Find the mitmdump binary, checking the current Python env first."""
    # Check PATH
    found = shutil.which("mitmdump")
    if found:
        return found

    # Check same bin directory as the current Python interpreter
    # (handles uv tool install where mitmdump is in the tool venv)
    bin_dir = Path(sys.executable).parent
    candidate = bin_dir / "mitmdump"
    if candidate.exists():
        return str(candidate)

    raise FileNotFoundError(
        "mitmdump not found. Install mitmproxy: pip install 'mitmproxy>=10.0'"
    )


def start_proxy_process(
    vault_secrets: dict[str, str],
    vault_values: list[str],
    audit_path: Path | None = None,
    listen_port: int | None = None,
    rate_limit_requests: int = 50,
    rate_limit_window: float = 1.0,
) -> int:
    """Start mitmproxy as a background subprocess. Returns PID."""
    if listen_port is None:
        listen_port = find_available_port()

    AEGIS_DIR.mkdir(parents=True, exist_ok=True)

    # Write proxy config with secrets (mode 0600)
    config = {
        "vault_secrets": vault_secrets,
        "vault_values": vault_values,
        "rate_limit_requests": rate_limit_requests,
        "rate_limit_window": rate_limit_window,
    }
    if audit_path is not None:
        config["audit_path"] = str(audit_path)

    CONFIG_FILE.write_text(json.dumps(config))
    os.chmod(CONFIG_FILE, 0o600)

    # Locate entry.py script
    entry_script = Path(__file__).parent / "entry.py"

    # Spawn mitmdump as background process, logging stderr
    mitmdump = _find_mitmdump()
    log_file = AEGIS_DIR / "proxy.log"
    log_handle = open(log_file, "a")
    os.chmod(log_file, 0o600)
    proc = subprocess.Popen(
        [
            mitmdump,
            "--listen-port", str(listen_port),
            "--ssl-insecure",
            "-s", str(entry_script),
        ],
        stdout=subprocess.DEVNULL,
        stderr=log_handle,
    )

    # Write PID file
    pid_info = {"pid": proc.pid, "port": listen_port}
    PID_FILE.write_text(json.dumps(pid_info))
    os.chmod(PID_FILE, 0o600)

    # Wait for proxy to be ready
    if not wait_for_proxy_ready(listen_port, timeout=5):
        # Clean up on failure
        proc.terminate()
        PID_FILE.unlink(missing_ok=True)
        CONFIG_FILE.unlink(missing_ok=True)
        raise RuntimeError(f"Proxy failed to start on port {listen_port}")

    return proc.pid


def stop_proxy(pid_file: Path = PID_FILE) -> bool:
    """Stop proxy via SIGTERM, then SIGKILL after 5s. Returns True if stopped."""
    if not pid_file.exists():
        return False

    try:
        pid_info = json.loads(pid_file.read_text())
        pid = pid_info["pid"]
    except (json.JSONDecodeError, KeyError):
        pid_file.unlink(missing_ok=True)
        return False

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return False

    # Wait up to 5s for graceful shutdown
    import time
    for _ in range(50):
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            pid_file.unlink(missing_ok=True)
            return True

    # Force kill
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    pid_file.unlink(missing_ok=True)
    return True


def is_proxy_running(pid_file: Path = PID_FILE) -> tuple[bool, int | None]:
    """Check if proxy is running via PID file + os.kill(pid, 0)."""
    if not pid_file.exists():
        return False, None

    try:
        pid_info = json.loads(pid_file.read_text())
        pid = pid_info["pid"]
    except (json.JSONDecodeError, KeyError):
        return False, None

    try:
        os.kill(pid, 0)
        return True, pid_info.get("port")
    except ProcessLookupError:
        # Stale PID file
        pid_file.unlink(missing_ok=True)
        return False, None
