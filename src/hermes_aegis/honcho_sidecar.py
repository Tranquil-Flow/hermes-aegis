"""Honcho sidecar management for hermes-aegis.

Manages a self-hosted Honcho instance via docker-compose in ~/Projects/honcho/.
The Honcho API runs at localhost:8000 on the host. The hermes-agent process
(run_agent.py) runs on the host and connects to it directly at localhost:8000.

The NO_PROXY setting in builder.py also lists host.docker.internal so that if
any tool code running inside a hermes-aegis Docker container needs to reach the
Honcho API (at http://host.docker.internal:8000 from inside a container), it
bypasses the MITM proxy.

Setup:
    hermes-aegis honcho setup      # clone + configure
    hermes-aegis honcho start      # docker compose up -d
    hermes-aegis honcho stop       # docker compose down
    hermes-aegis honcho status     # health check

Honcho config in ~/.honcho/config.json:
    {
      "apiKey": "local",
      "enabled": true,
      "hosts": {
        "hermes": {
          "workspace": "hermes",
          "memoryMode": "hybrid"
        }
      }
    }

Hermes config in ~/.hermes/config.yaml:
    honcho:
      base_url: http://localhost:8000
      enabled: true
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

HONCHO_REPO = "https://github.com/plastic-labs/honcho.git"
HONCHO_DIR = Path.home() / "Projects" / "honcho"
HONCHO_API_PORT = 8000
HONCHO_CONFIG_PATH = Path.home() / ".honcho" / "config.json"

# Where the Honcho API is reachable from the host
HOST_BASE_URL = f"http://localhost:{HONCHO_API_PORT}"

# Where the Honcho API is reachable from inside Docker containers
CONTAINER_BASE_URL = f"http://host.docker.internal:{HONCHO_API_PORT}"


def is_cloned() -> bool:
    """Check if Honcho has been cloned."""
    return (HONCHO_DIR / "docker-compose.yml").exists() or (HONCHO_DIR / "docker-compose.yml.example").exists()


def is_running() -> bool:
    """Check if the Honcho API is responding."""
    try:
        with urllib.request.urlopen(f"{HOST_BASE_URL}/health", timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_compose_file() -> Path | None:
    """Return the docker-compose.yml path, preferring the non-example version."""
    for name in ("docker-compose.yml", "docker-compose.yaml"):
        p = HONCHO_DIR / name
        if p.exists():
            return p
    return None


def clone() -> None:
    """Clone the Honcho repository into ~/Projects/honcho/."""
    HONCHO_DIR.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", HONCHO_REPO, str(HONCHO_DIR)], check=True)


def write_env_file(
    anthropic_key: str = "",
    gemini_key: str = "",
    openai_key: str = "",
) -> None:
    """Write a minimal .env file for Honcho (auth disabled, LLM keys optional).

    The Gemini key enables Honcho's deriver — the background worker that
    automatically builds cross-session user models from conversation history.
    Honcho defaults to gemini-2.5-flash-lite for the deriver, making it the
    most important key for full functionality.

    The Anthropic key enables the dialectic endpoint (honcho_context tool).
    Without LLM keys, basic store/recall still works.
    """
    env_path = HONCHO_DIR / ".env"

    # Preserve any existing keys the user may have manually set
    existing: dict[str, str] = {}
    if env_path.exists():
        for raw_line in env_path.read_text().splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip()

    def _line(key: str, value: str) -> str:
        return f"{key}={value}" if value else f"# {key}="

    lines = [
        "# Honcho self-hosted configuration",
        "AUTH_USE_AUTH=false",
        "SENTRY_ENABLED=false",
        "",
        "# Database (provided by docker-compose)",
        "DB_CONNECTION_URI=postgresql+psycopg://postgres:postgres@database:5432/postgres",
        "CACHE_URL=redis://redis:6379/0?suppress=true",
        "",
        "# LLM keys — Gemini enables deriver (cross-session user modeling)",
        "# Anthropic enables dialectic (honcho_context tool)",
        _line("LLM_GEMINI_API_KEY", gemini_key or existing.get("LLM_GEMINI_API_KEY", "")),
        _line("LLM_ANTHROPIC_API_KEY", anthropic_key or existing.get("LLM_ANTHROPIC_API_KEY", "")),
        _line("LLM_OPENAI_API_KEY", openai_key or existing.get("LLM_OPENAI_API_KEY", "")),
    ]
    env_path.write_text("\n".join(lines) + "\n")


def copy_compose_template() -> None:
    """Copy docker-compose.yml.example → docker-compose.yml if needed."""
    example = HONCHO_DIR / "docker-compose.yml.example"
    target = HONCHO_DIR / "docker-compose.yml"
    if not target.exists() and example.exists():
        target.write_text(example.read_text())


def start(detach: bool = True) -> subprocess.CompletedProcess:
    """Start Honcho via docker compose."""
    cmd = ["docker", "compose", "up"]
    if detach:
        cmd.append("-d")
    return subprocess.run(cmd, cwd=str(HONCHO_DIR), check=True)


def stop() -> subprocess.CompletedProcess:
    """Stop Honcho via docker compose."""
    return subprocess.run(["docker", "compose", "down"], cwd=str(HONCHO_DIR), check=True)


def write_honcho_client_config() -> None:
    """Write ~/.honcho/config.json configured for local self-hosted Honcho.

    Uses api_key="local" as a dummy value — Honcho's AUTH_USE_AUTH=false
    accepts any non-empty key (or no key at all). The client SDK still
    validates that the field is non-empty.
    """
    HONCHO_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Don't overwrite if the user has already configured it
    if HONCHO_CONFIG_PATH.exists():
        try:
            existing = json.loads(HONCHO_CONFIG_PATH.read_text())
            if existing.get("enabled"):
                return  # Already configured — leave it alone
        except (json.JSONDecodeError, OSError):
            pass

    config = {
        "apiKey": "local",
        "enabled": True,
        "hosts": {
            "hermes": {
                "workspace": "hermes",
                "memoryMode": "hybrid",
            }
        },
    }
    HONCHO_CONFIG_PATH.write_text(json.dumps(config, indent=2) + "\n")
