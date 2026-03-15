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


def _vault_hash(vault_secrets: dict) -> str:
    """Stable hash of vault secret keys+values for staleness detection."""
    import hashlib
    payload = json.dumps(vault_secrets, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


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
                # Do not intercept sigstore/TUF TLS — cosign uses its own certificate
                # bundle and rejects the mitmproxy CA, breaking Tirith's auto-install
                # and provenance verification. Pass these hosts through unmodified.
                "--ignore-hosts",
                r"(^|\.)(sigstore\.dev|tuf\.dev|rekor\.sigstore\.dev|fulcio\.sigstore\.dev|tuf-repo-cdn\.sigstore\.dev)$",
            ],
            # Capture both stdout and stderr — mitmdump prints crash tracebacks
            # and addon errors to stdout, not just stderr.
            stdout=log_handle,
            stderr=log_handle,
            # Isolate from parent process group so terminal SIGHUP/SIGINT
            # don't kill the proxy when hermes exits or user presses Ctrl+C.
            preexec_fn=os.setsid,
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

        # Write PID file — include a hash of vault secrets so callers can
        # detect when the proxy was started with stale/empty credentials.
        pid_info = {
            "pid": proc.pid,
            "port": port,
            "vault_hash": _vault_hash(vault_secrets),
        }
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


def _kill_pid(pid: int, timeout: float = 5.0) -> bool:
    """Send SIGTERM to pid, wait up to timeout seconds, then SIGKILL. Returns True if gone."""
    import time
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True  # Already gone

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            return True

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return True


def _find_all_aegis_proxy_pids() -> list[int]:
    """Find all mitmdump processes launched by hermes-aegis (running our entry.py).

    Uses pgrep to scan running processes without requiring psutil.
    Returns a list of PIDs (may be empty).
    """
    entry_script = str(Path(__file__).parent / "entry.py")
    pids: list[int] = []
    try:
        result = subprocess.run(
            ["pgrep", "-f", entry_script],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.strip().splitlines():
            try:
                pids.append(int(line.strip()))
            except ValueError:
                pass
    except FileNotFoundError:
        pass  # pgrep not available — skip
    return pids


def stop_proxy(pid_file: Path = PID_FILE) -> bool:
    """Stop all aegis proxy instances.

    Kills the PID recorded in the PID file first, then sweeps for any
    remaining mitmdump/entry.py processes that weren't in the PID file
    (e.g. from stale sessions or multiple concurrent starts).

    Returns True if at least one process was stopped.
    """
    import time

    stopped_any = False

    # Step 1: kill the PID-file proxy
    if pid_file.exists():
        try:
            pid_info = json.loads(pid_file.read_text())
            pid = pid_info["pid"]
            try:
                os.kill(pid, 0)  # Check process is alive before claiming we stopped it
                _kill_pid(pid)
                stopped_any = True
            except ProcessLookupError:
                pass  # Already dead — don't count as stopped
        except (json.JSONDecodeError, KeyError):
            pass
        pid_file.unlink(missing_ok=True)
        _secure_delete_config()

    # Step 2: kill any remaining aegis proxy processes not in the PID file
    remaining = _find_all_aegis_proxy_pids()
    for pid in remaining:
        try:
            _kill_pid(pid)
            stopped_any = True
        except ProcessLookupError:
            pass

    if not stopped_any and not pid_file.exists() and not remaining:
        return False

    return stopped_any


def is_proxy_running(pid_file: Path = PID_FILE) -> tuple[bool, int | None, str | None]:
    """Check if proxy is running via PID file + os.kill(pid, 0) + port probe.

    Guards against stale PID files and PID reuse by also verifying
    the recorded port is actually accepting connections.
    """
    if not pid_file.exists():
        return False, None, None

    try:
        pid_info = json.loads(pid_file.read_text())
        pid = pid_info["pid"]
        port = pid_info.get("port")
        vault_hash = pid_info.get("vault_hash")
    except (json.JSONDecodeError, KeyError):
        return False, None, None

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        # Stale PID file — process is dead
        pid_file.unlink(missing_ok=True)
        return False, None, None

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
            return False, None, None
        finally:
            sock.close()

    # Verify the PID belongs to our entry.py process (guards against PID reuse)
    our_pids = set(_find_all_aegis_proxy_pids())
    if our_pids and pid not in our_pids:
        pid_file.unlink(missing_ok=True)
        return False, None, None

    return True, port, vault_hash
