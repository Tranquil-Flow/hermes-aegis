from __future__ import annotations

from hermes_aegis.patterns.crypto import scan_for_crypto_keys
from hermes_aegis.patterns.secrets import scan_for_secrets


class ContentScanner:
    """Scans outbound HTTP requests for secret material."""

    def __init__(self, vault_values: list[str] | None = None) -> None:
        self._vault_values = vault_values or []

    def scan_request(
        self,
        url: str,
        body: str,
        headers: dict,
    ) -> tuple[bool, str | None]:
        scannable = f"{url}\n{body}\n"
        for key, value in headers.items():
            scannable += f"{key}: {value}\n"

        matches = scan_for_secrets(scannable, exact_values=self._vault_values)
        matches.extend(scan_for_crypto_keys(scannable))
        if not matches:
            return False, None

        names = ", ".join(sorted({match.pattern_name for match in matches}))
        return True, f"Blocked: detected {names}"
