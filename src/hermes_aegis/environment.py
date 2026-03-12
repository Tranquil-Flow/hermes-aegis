"""AegisEnvironment - Hermes backend with proxy-based secret isolation.

Integrates with Hermes Agent as a terminal backend via TERMINAL_ENV=aegis.
Wraps DockerEnvironment and adds MITM proxy for transparent key injection.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Hermes imports are deferred to avoid triggering all tool dependencies
# They're only imported when actually creating an environment instance

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.proxy.runner import start_proxy
from hermes_aegis.vault.keyring_store import get_or_create_master_key
from hermes_aegis.vault.store import VaultStore

logger = logging.getLogger(__name__)

ARMOR_DIR = Path.home() / ".hermes-aegis"
VAULT_PATH = ARMOR_DIR / "vault.enc"
AUDIT_PATH = ARMOR_DIR / "audit.jsonl"


class AegisEnvironment:
    """Hermes execution backend with proxy-based secret isolation.

    Wraps DockerEnvironment. Starts MITM proxy before container,
    routes all container traffic through it. Secrets injected at
    HTTP layer — never in container env vars.
    
    Falls back to Tier 1 (LocalEnvironment + scanner) if Docker unavailable.
    """

    def __init__(self, image: str = "python:3.11-slim",
                 cwd: str = "/workspace",
                 timeout: int = 180,
                 env: dict = None,
                 **kwargs):
        self.cwd = cwd
        self.timeout = timeout
        self.env = env or {}

        self._tier = 2 if docker_available() else 1
        self._proxy_thread = None
        self._proxy_port = None
        self._vault = None
        self._audit_trail = AuditTrail(AUDIT_PATH)
        self._image = image
        self._kwargs = kwargs

        # Load vault
        if VAULT_PATH.exists():
            master_key = get_or_create_master_key()
            self._vault = VaultStore(VAULT_PATH, master_key)

        if self._tier == 1:
            # Fallback to Tier 1: local execution with scanner
            logger.warning(
                "Docker not available — falling back to Tier 1 "
                "(in-process scanning only). Install Docker for full isolation."
            )
            clean_env = env or {}
            # Defer LocalEnvironment import until needed
            self._inner = None  # Will be created on first execute

            # Install Tier 1 scanner if vault available
            if self._vault is not None:
                from hermes_aegis.tier1.scanner import install_scanner
                install_scanner(self._vault)
                logger.info("Tier 1 content scanner active")

        else:
            # Tier 2: Docker with proxy
            # Strip secrets from env before passing to DockerEnvironment
            self._clean_env = self._strip_secret_env_vars(env or {})

            # Add proxy routing (will be set when proxy starts)
            self._proxy_port = find_available_port()
            self._clean_env["HTTP_PROXY"] = f"http://host.docker.internal:{self._proxy_port}"
            self._clean_env["HTTPS_PROXY"] = f"http://host.docker.internal:{self._proxy_port}"
            self._clean_env["NO_PROXY"] = "localhost,127.0.0.1"

            # CA certificate env vars (cert mounted as volume)
            self._clean_env["REQUESTS_CA_BUNDLE"] = "/certs/mitmproxy-ca-cert.pem"
            self._clean_env["SSL_CERT_FILE"] = "/certs/mitmproxy-ca-cert.pem"

            # Defer DockerEnvironment creation until first execute
            self._inner = None

    def execute(self, command: str, cwd: str = "", *,
                timeout: int | None = None,
                stdin_data: str | None = None) -> dict:
        """Execute command in isolated environment (container or local)."""

        # Lazy initialization on first execute
        if self._inner is None:
            self._initialize_inner_environment()

        # Start proxy on first execute (lazy init for Tier 2)
        if self._tier == 2 and self._proxy_thread is None:
            self._start_proxy()

        # Delegate to inner environment
        return self._inner.execute(command, cwd, timeout=timeout, stdin_data=stdin_data)
    
    def _initialize_inner_environment(self):
        """Lazy initialization of inner environment (avoids import at module load)."""
        sys.path.insert(0, str(Path.home() / ".hermes" / "hermes-agent"))
        
        if self._tier == 1:
            from tools.environments.local import LocalEnvironment
            self._inner = LocalEnvironment(
                cwd=self.cwd,
                timeout=self.timeout,
                env=self.env
            )
        else:
            from tools.environments.docker import DockerEnvironment
            self._inner = DockerEnvironment(
                image=self._image,
                cwd=self.cwd,
                timeout=self.timeout,
                env=self._clean_env,
                **self._kwargs
            )

    def cleanup(self):
        """Release resources."""
        if hasattr(self, '_inner') and self._inner is not None:
            self._inner.cleanup()

        # Proxy thread is daemon — will die with process
        # But explicitly mark as None for clarity
        self._proxy_thread = None

    def _start_proxy(self):
        """Start MITM proxy for Tier 2."""
        if self._vault is None:
            logger.warning("No vault available - proxy will not inject keys")
            vault_secrets = {}
            vault_values = []
        else:
            # Build vault_secrets dict for LLM providers
            vault_secrets = {}
            for key_name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
                             "GROQ_API_KEY", "TOGETHER_API_KEY"]:
                value = self._vault.get(key_name)
                if value is not None:
                    vault_secrets[key_name] = value

            vault_values = self._vault.get_all_values()

        # Ensure CA cert exists
        cert_path = ensure_mitmproxy_ca_cert()
        logger.info(f"mitmproxy CA cert: {cert_path}")

        # Start proxy
        self._proxy_thread = start_proxy(
            vault_secrets=vault_secrets,
            vault_values=vault_values,
            audit_trail=self._audit_trail,
            listen_port=self._proxy_port
        )

        # Wait for proxy to be ready
        if not wait_for_proxy_ready(self._proxy_port, timeout=5):
            raise RuntimeError(f"Proxy failed to start on port {self._proxy_port}")

        logger.info(f"Proxy ready on port {self._proxy_port}")

    def _strip_secret_env_vars(self, env: dict) -> dict:
        """Remove secrets from environment dict."""
        secret_keys = [
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
            "GROQ_API_KEY", "TOGETHER_API_KEY", "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SLACK_TOKEN"
        ]

        clean = {}
        for k, v in env.items():
            # Skip known secret keys
            if k in secret_keys:
                continue
            # Skip anything that looks like a secret
            if any(word in k.upper() for word in ["SECRET", "PASSWORD", "TOKEN", "KEY", "PRIVATE"]):
                continue
            clean[k] = v

        return clean


def docker_available() -> bool:
    """Check if Docker is available."""
    if not shutil.which("docker"):
        return False

    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


def find_available_port(start: int = 8443, end: int = 8500) -> int:
    """Find an available port for the proxy."""
    import socket

    for port in range(start, end):
        try:
            sock = socket.socket()
            sock.bind(('localhost', port))
            sock.close()
            return port
        except OSError:
            continue

    raise RuntimeError(f"No available port in range {start}-{end}")


def wait_for_proxy_ready(port: int, timeout: int = 5) -> bool:
    """Poll until proxy is listening."""
    import socket
    import time

    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect(('localhost', port))
            sock.close()
            return True
        except OSError:
            time.sleep(0.1)

    return False


def ensure_mitmproxy_ca_cert() -> Path:
    """Ensure mitmproxy CA certificate exists."""
    import subprocess
    import time

    cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    if cert_path.exists():
        return cert_path

    # Generate by starting and immediately stopping mitmdump
    logger.info("Generating mitmproxy CA certificate...")

    try:
        proc = subprocess.Popen(
            ["mitmdump", "--set", "listen_port=0"],  # port 0 = OS picks
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)  # Wait for cert generation
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except FileNotFoundError:
        raise RuntimeError("mitmdump not found - install with: uv sync --extra tier2")

    if not cert_path.exists():
        raise RuntimeError("Failed to generate mitmproxy CA certificate")

    return cert_path
