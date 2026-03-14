"""Mitmproxy addon entry script.

Loaded via: mitmdump -s entry.py
Reads config from ~/.hermes-aegis/proxy-config.json, instantiates AegisAddon,
then deletes secrets from the config file.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.proxy.addon import AegisAddon

AEGIS_DIR = Path.home() / ".hermes-aegis"
CONFIG_PATH = AEGIS_DIR / "proxy-config.json"


def _load_addon() -> AegisAddon:
    """Load AegisAddon from proxy config file."""
    if not CONFIG_PATH.exists():
        # No config — run with empty defaults
        return AegisAddon(vault_secrets={}, vault_values=[])

    try:
        config = json.loads(CONFIG_PATH.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        import sys
        print(f"[aegis] ERROR: Failed to load proxy config: {exc}", file=sys.stderr)
        return AegisAddon(vault_secrets={}, vault_values=[])

    # Set up audit trail if path provided
    audit_trail = None
    audit_path = config.get("audit_path")
    if audit_path:
        audit_trail = AuditTrail(Path(audit_path))

    try:
        addon = AegisAddon(
            vault_secrets=config.get("vault_secrets", {}),
            vault_values=config.get("vault_values", []),
            audit_trail=audit_trail,
            rate_limit_requests=config.get("rate_limit_requests", 50),
            rate_limit_window=config.get("rate_limit_window", 1.0),
        )
    except Exception as exc:
        import sys
        print(f"[aegis] ERROR: Failed to create addon: {exc}", file=sys.stderr)
        return AegisAddon(vault_secrets={}, vault_values=[])

    # Overwrite config file to remove secrets (keep non-secret fields)
    safe_config = {
        "rate_limit_requests": config.get("rate_limit_requests", 50),
        "rate_limit_window": config.get("rate_limit_window", 1.0),
        "started": True,
    }
    CONFIG_PATH.write_text(json.dumps(safe_config))
    os.chmod(CONFIG_PATH, 0o600)

    return addon


addons = [_load_addon()]
