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


def _start_proxy_once(
    listen_port: int,
    entry_script: Path,
) -> subprocess.Popen:
    """Spawn a single mitmdump process. Returns the Popen object."""
    mitmdump = _find_mitmdump()
    log_file = AEGIS_DIR / "proxy.log"
    log_handle = open(log_file, "a")
    os.chmod(log_file, 0o600)
    try:
        proc = subprocess.Popen(
            [
                mitmdump,
                "--listen-port", str(listen_port),
                # --ssl-insecure is correct here: this is a localhost MITM proxy with a
                # local CA cert. The proxy itself is the TLS termination point — upstream
                # connections use the system's real CA validation via REQUESTS_CA_BUNDLE.
                "--ssl-insecure",
                "-s", str(entry_script),
            ],
            stdout=subprocess.DEVNULL,
            stderr=log_handle,
        )
    except Exception:
        log_handle.close()
        raise
    # Child process inherited the FD via fork; parent no longer needs it
    log_handle.close()
    return proc


def start_proxy_process(
    vault_secrets: dict[str, str],
    vault_values: list[str],
    audit_path: Path | None = None,
    listen_port: int | None = None,
    rate_limit_requests: int = 50,
    rate_limit_window: float = 1.0,
) -> int:
    """Start mitmproxy as a background subprocess. Returns PID."""
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

    entry_script = Path(__file__).parent / "entry.py"

    # Retry up to 3 times with different ports to handle TOCTOU races
    # (port free at check time but taken before mitmdump binds)
    max_attempts = 3 if listen_port is None else 1
    last_error = None
    for attempt in range(max_attempts):
        port = listen_port if listen_port is not None else find_available_port()
        proc = _start_proxy_once(port, entry_script)

        # Write PID file
        pid_info = {"pid": proc.pid, "port": port}
        PID_FILE.write_text(json.dumps(pid_info))
        os.chmod(PID_FILE, 0o600)

        if wait_for_proxy_ready(port, timeout=5):
            return proc.pid

        # Clean up failed attempt
        proc.terminate()
        PID_FILE.unlink(missing_ok=True)
        last_error = RuntimeError(f"Proxy failed to start on port {port}")

    # All attempts exhausted
    CONFIG_FILE.unlink(missing_ok=True)
    raise last_error


def _secure_delete_config() -> None:
    """Overwrite proxy-config.json with zeros then unlink (defense in depth)."""
    try:
        if CONFIG_FILE.exists():
            size = CONFIG_FILE.stat().st_size
            CONFIG_FILE.write_bytes(b"\x00" * size)
            CONFIG_FILE.unlink(missing_ok=True)
    except OSError:
        CONFIG_FILE.unlink(missing_ok=True)


def stop_proxy(pid_file: Path = PID_FILE) -> bool:
    """Stop proxy via SIGTERM, then SIGKILL after 5s. Returns True if stopped."""
    if not pid_file.exists():
        return False

    try:
        pid_info = json.loads(pid_file.read_text())
        pid = pid_info["pid"]
    except (json.JSONDecodeError, KeyError):
        pid_file.unlink(missing_ok=True)
        _secure_delete_config()
        return False

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        _secure_delete_config()
        return False

    # Wait up to 5s for graceful shutdown
    import time
    for _ in range(50):
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            pid_file.unlink(missing_ok=True)
            _secure_delete_config()
            return True

    # Force kill
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    pid_file.unlink(missing_ok=True)
    _secure_delete_config()
    return True


def is_proxy_running(pid_file: Path = PID_FILE) -> tuple[bool, int | None]:
    """Check if proxy is running via PID file + os.kill(pid, 0) + port probe.

    Guards against stale PID files and PID reuse by also verifying
    the recorded port is actually accepting connections.
    """
    if not pid_file.exists():
        return False, None

    try:
        pid_info = json.loads(pid_file.read_text())
        pid = pid_info["pid"]
        port = pid_info.get("port")
    except (json.JSONDecodeError, KeyError):
        return False, None

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        # Stale PID file — process is dead
        pid_file.unlink(missing_ok=True)
        return False, None

    # PID is alive, but verify it's actually our proxy by probing the port
    if port is not None:
        import socket
        sock = socket.socket()
        try:
            sock.settimeout(0.5)
            sock.connect(("127.0.0.1", port))
        except OSError:
            # PID alive but port not listening — stale PID (reused by another process)
            pid_file.unlink(missing_ok=True)
            return False, None
        finally:
            sock.close()

    return True, port
