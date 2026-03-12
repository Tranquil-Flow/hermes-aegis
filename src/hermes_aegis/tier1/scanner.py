"""Outbound HTTP content scanner for Tier 1.

Monkey-patches urllib3 to intercept outbound HTTP requests and scan for secrets.
This is best-effort protection - raw sockets and non-urllib3 libraries bypass this.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from hermes_aegis.patterns.secrets import scan_for_secrets
from hermes_aegis.vault.store import VaultStore


class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass


# Global state for scanner
_original_urlopen = None
_vault_values: list[str] = []


def install_scanner(vault: VaultStore) -> None:
    """Install the outbound content scanner.
    
    Args:
        vault: VaultStore instance to get secret values from
    """
    global _original_urlopen, _vault_values
    
    # Get all vault values for exact match scanning
    _vault_values = vault.get_all_values()
    
    # Import here to avoid issues if urllib3 isn't available
    import urllib3.connectionpool
    
    # Save original method
    _original_urlopen = urllib3.connectionpool.HTTPConnectionPool.urlopen
    
    # Replace with our scanning version
    urllib3.connectionpool.HTTPConnectionPool.urlopen = _scanning_urlopen


def uninstall_scanner() -> None:
    """Remove the outbound content scanner and restore original behavior."""
    global _original_urlopen
    
    if _original_urlopen is not None:
        import urllib3.connectionpool
        urllib3.connectionpool.HTTPConnectionPool.urlopen = _original_urlopen
        _original_urlopen = None


def _scanning_urlopen(self, method: str, url: str, body: Any = None, headers: Any = None, **kwargs) -> Any:
    """Intercept urllib3 urlopen and scan for secrets before sending."""
    # Scan request body
    if body is not None:
        body_str = _extract_string(body)
        if _contains_secret(body_str):
            raise SecurityError(f"Blocked outbound request to {url}: secret detected in body")
    
    # Scan headers
    if headers is not None:
        headers_str = _extract_string(headers)
        if _contains_secret(headers_str):
            raise SecurityError(f"Blocked outbound request to {url}: secret detected in headers")
    
    # Clean - pass through to original
    return _original_urlopen(self, method, url, body=body, headers=headers, **kwargs)


def _extract_string(data: Any) -> str:
    """Extract string representation from various data types."""
    if isinstance(data, str):
        return data
    elif isinstance(data, bytes):
        return data.decode('utf-8', errors='ignore')
    elif isinstance(data, dict):
        return json.dumps(data)
    else:
        return str(data)


def _contains_secret(text: str) -> bool:
    """Check if text contains any secrets (exact vault values or pattern matches)."""
    # Check exact vault value matches
    for secret in _vault_values:
        if secret in text:
            return True
        # Check base64-encoded version
        try:
            encoded = base64.b64encode(secret.encode()).decode()
            if encoded in text:
                return True
        except Exception:
            pass
    
    # Check pattern matches
    matches = scan_for_secrets(text)
    if matches:
        return True
    
    return False
