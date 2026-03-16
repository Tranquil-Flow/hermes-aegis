from __future__ import annotations

from hermes_aegis.patterns.crypto import scan_for_crypto_keys
from hermes_aegis.patterns.secrets import scan_for_secrets


class ContentScanner:
    """Scans outbound HTTP requests for secret material."""

    def __init__(self, vault_values: list[str] | None = None) -> None:
        self._vault_values = vault_values or []

    def update_vault_values(self, new_values: list[str]) -> None:
        """Replace the set of vault values used for secret scanning."""
        self._vault_values = new_values or []

    def scan_request(
        self,
        url: str,
        body: str,
        headers: dict,
    ) -> tuple[bool, str | None]:
        """Scan an HTTP request for secret patterns and cryptographic keys.

        Examines the request URL, body, and headers for leaked API keys,
        credentials, cryptographic keys, and other sensitive patterns.

        Args:
            url: The request URL to scan.
            body: The request body content to scan.
            headers: Dictionary of HTTP headers to scan.

        Returns:
            A tuple of (is_blocked, reason_message):
            - is_blocked: True if sensitive patterns were detected.
            - reason_message: Human-readable description of what was detected,
              or None if no patterns were found.
        """
        scannable = f"{url}\n{body}\n"
        for key, value in headers.items():
            scannable += f"{key}: {value}\n"

        matches = scan_for_secrets(scannable, exact_values=self._vault_values)
        matches.extend(scan_for_crypto_keys(scannable))
        if not matches:
            return False, None

        names = ", ".join(sorted({match.pattern_name for match in matches}))
        return True, f"Blocked: detected {names}"
