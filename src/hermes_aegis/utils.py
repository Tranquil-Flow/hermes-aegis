"""Shared utility functions for hermes-aegis."""
from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def find_available_port(start: int = 8443, end: int = 8500) -> int:
    """Find an available TCP port in the given range.

    Iterates from *start* to *end* (exclusive) and returns the first port
    that can be bound on localhost without raising an ``OSError``.

    Args:
        start: First port number to try (inclusive). Defaults to 8443.
        end: Upper bound of the port search range (exclusive). Defaults to 8500.

    Returns:
        An available port number in the range [start, end).

    Raises:
        RuntimeError: If no available port is found in the range.
    """
    for port in range(start, end):
        try:
            sock = socket.socket()
            sock.bind(("localhost", port))
            sock.close()
            return port
        except OSError:
            continue

    raise RuntimeError(f"No available port in range {start}-{end}")


def wait_for_proxy_ready(port: int, timeout: int = 5) -> bool:
    """Poll the local proxy port until it accepts connections or times out.

    Attempts a TCP connection to ``localhost:<port>`` in a tight loop, sleeping
    100 ms between attempts, until *timeout* seconds have elapsed.

    Args:
        port: TCP port to probe.
        timeout: Maximum seconds to wait before giving up. Defaults to 5.

    Returns:
        ``True`` if the proxy became reachable within *timeout* seconds,
        ``False`` otherwise.
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect(("localhost", port))
            sock.close()
            return True
        except OSError:
            time.sleep(0.1)

    return False


def ensure_mitmproxy_ca_cert() -> Path:
    """Ensure the mitmproxy CA certificate exists, generating it if necessary.

    If the certificate is not already present at ``~/.mitmproxy/mitmproxy-ca-cert.pem``,
    this function starts ``mitmdump`` briefly to trigger certificate generation,
    then terminates it.

    Returns:
        Path to the mitmproxy CA certificate PEM file.

    Raises:
        RuntimeError: If ``mitmdump`` is not installed or certificate generation fails.
    """
    cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    if cert_path.exists():
        return cert_path

    logger.info("Generating mitmproxy CA certificate...")

    try:
        proc = subprocess.Popen(
            ["mitmdump", "--set", "listen_port=0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except FileNotFoundError:
        raise RuntimeError("mitmdump not found - install mitmproxy")

    if not cert_path.exists():
        raise RuntimeError("Failed to generate mitmproxy CA certificate")

    return cert_path


def strip_secret_env_vars(env: dict) -> dict:
    """Return a copy of *env* with known secret variables removed.

    Drops any key that is an exact match for a hardcoded allowlist of common
    secret variable names (e.g. ``OPENAI_API_KEY``), and any key whose
    upper-cased name contains the substrings ``SECRET``, ``PASSWORD``,
    ``TOKEN``, ``KEY``, or ``PRIVATE``.

    Args:
        env: A ``{str: str}`` mapping representing an environment (e.g.
            ``os.environ`` or a subprocess ``env`` kwarg).

    Returns:
        A new dict with all secret-looking variables omitted.
    """
    secret_keys = [
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
        "GROQ_API_KEY", "TOGETHER_API_KEY", "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SLACK_TOKEN",
    ]

    clean = {}
    for k, v in env.items():
        if k in secret_keys:
            continue
        if any(word in k.upper() for word in ["SECRET", "PASSWORD", "TOKEN", "KEY", "PRIVATE"]):
            continue
        clean[k] = v

    return clean


def docker_available() -> bool:
    """Check if Docker daemon is running and accessible.

    Uses 'docker version' (lightweight metadata query) instead of
    'docker info' (heavy system scan) to avoid false negatives when
    Docker Desktop is busy on macOS.
    """
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _other_aegis_sessions_running() -> bool:
    """Check if other hermes-aegis run sessions are active.

    Uses pgrep to find hermes-aegis processes. Returns True if more than
    one 'hermes-aegis' process tree exists (the caller's own session).
    """
    try:
        result = subprocess.run(
            ["pgrep", "-f", "hermes-aegis run"],
            capture_output=True, text=True, timeout=5,
        )
        # Each line is a PID; our own process counts as one
        pids = [l for l in result.stdout.strip().splitlines() if l.strip()]
        return len(pids) > 1
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return True  # Assume yes if we can't check — safer to skip cleanup


def docker_post_run_cleanup() -> dict[str, str]:
    """Lightweight Docker cleanup after a hermes-aegis session.

    Safe for concurrent sessions: only removes exited containers,
    skips network/image cleanup when other sessions are active, and
    tolerates races where another session already cleaned the same resource.

    Returns a dict of what was cleaned (for logging/display), e.g.:
        {"containers": "2", "images": "3", "build_cache": "150MB"}
    """
    if not docker_available():
        return {}

    other_sessions = _other_aegis_sessions_running()
    results: dict[str, str] = {}

    # 1. Remove stopped containers with hermes name patterns.
    #    Only targets status=exited so running containers from other sessions
    #    are never touched. Uses --force to tolerate races where another
    #    session already removed the same container.
    try:
        stopped = subprocess.run(
            ["docker", "ps", "-a", "--filter", "status=exited",
             "--filter", "name=minisweagent-", "--format", "{{.ID}}"],
            capture_output=True, text=True, timeout=10,
        )
        container_ids = [
            cid for cid in stopped.stdout.strip().splitlines() if cid.strip()
        ]
        if container_ids:
            subprocess.run(
                ["docker", "rm", "--force"] + container_ids,
                capture_output=True, timeout=30,
            )
            results["containers"] = str(len(container_ids))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Skip image/cache/network cleanup when other sessions are active —
    # dangling images may be mid-build, and the network may be in use.
    if other_sessions:
        return results

    # 2. Remove dangling images (untagged layers from builds).
    #    Docker won't prune images referenced by running containers.
    try:
        prune = subprocess.run(
            ["docker", "image", "prune", "-f"],
            capture_output=True, text=True, timeout=30,
        )
        for line in prune.stdout.splitlines():
            if "reclaimed" in line.lower():
                results["dangling_images"] = line.strip()
                break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # 3. Remove build cache older than 7 days.
    try:
        prune = subprocess.run(
            ["docker", "builder", "prune", "-f", "--filter", "until=168h"],
            capture_output=True, text=True, timeout=30,
        )
        for line in prune.stdout.splitlines():
            if "reclaimed" in line.lower():
                results["build_cache"] = line.strip()
                break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # 4. Remove the aegis network if no containers are connected.
    #    Network rm fails atomically if a container attached between
    #    our inspect and rm — Docker rejects it, no harm done.
    try:
        from hermes_aegis.container.builder import AEGIS_NETWORK
        inspect = subprocess.run(
            ["docker", "network", "inspect", AEGIS_NETWORK,
             "--format", "{{len .Containers}}"],
            capture_output=True, text=True, timeout=10,
        )
        if inspect.returncode == 0 and inspect.stdout.strip() == "0":
            rm = subprocess.run(
                ["docker", "network", "rm", AEGIS_NETWORK],
                capture_output=True, timeout=10,
            )
            if rm.returncode == 0:
                results["network"] = AEGIS_NETWORK
    except (subprocess.TimeoutExpired, FileNotFoundError, ImportError):
        pass

    return results
