from __future__ import annotations

from hermes_aegis.patterns.crypto import scan_for_crypto_keys
from hermes_aegis.patterns.secrets import scan_for_secrets
from hermes_aegis.detectors import default_registry
from hermes_aegis.detectors.base import DetectorMatch


class ContentScanner:
    """Scans outbound HTTP requests for secret material.

    Uses two layers:

    1. **Legacy patterns** (``scan_for_secrets`` + ``scan_for_crypto_keys``) for
       exact-value vault matching and established regex patterns.
    2. **Modular detector registry** for additional coverage: cloud credentials,
       webhooks, connection strings, private keys, and entropy analysis.

    Both layers run on every request and results are merged. The generic
    entropy detector can be skipped per-request via ``host_allowlisted=True``;
    targeted detectors (vault values, known patterns) always run as defense
    in depth even on allowlisted hosts.
    """

    # Detector names skipped when the destination host is allowlisted.
    # Generic entropy is the only one — it false-positives on legitimate
    # API keys embedded in request bodies (Tavily, Firecrawl, Exa, etc.).
    _ALLOWLIST_SKIP_DETECTORS: frozenset[str] = frozenset({"entropy"})

    def __init__(self, vault_values: list[str] | None = None) -> None:
        self._vault_values = vault_values or []
        self._registry = default_registry

    def update_vault_values(self, new_values: list[str]) -> None:
        """Replace the set of vault values used for secret scanning."""
        self._vault_values = new_values or []

    def scan_request(
        self,
        url: str,
        body: str,
        headers: dict,
        *,
        host_allowlisted: bool = False,
    ) -> tuple[bool, str | None]:
        """Scan an HTTP request for secret patterns and cryptographic keys.

        Examines the request URL, body, and headers for leaked API keys,
        credentials, cryptographic keys, and other sensitive patterns.

        Args:
            url: The request URL to scan.
            body: The request body content to scan.
            headers: Dictionary of HTTP headers to scan.
            host_allowlisted: If True, skip generic entropy detection
                (avoids false-positives on API keys destined for trusted
                hosts). Vault-value matches and known-pattern detectors
                still run.

        Returns:
            A tuple of (is_blocked, reason_message):
            - is_blocked: True if sensitive patterns were detected.
            - reason_message: Human-readable description of what was detected,
              or None if no patterns were found.
        """
        scannable = f"{url}\n{body}\n"
        for key, value in headers.items():
            scannable += f"{key}: {value}\n"

        # Layer 1: legacy pattern matching (exact values + established regexes)
        matches = scan_for_secrets(scannable, exact_values=self._vault_values)
        matches.extend(scan_for_crypto_keys(scannable))

        # Layer 2: modular detector registry. On allowlisted hosts, skip
        # the generic entropy detector by name — but still run every other
        # detector so cross-provider exfiltration is caught.
        skip = self._ALLOWLIST_SKIP_DETECTORS if host_allowlisted else frozenset()
        detector_matches: list[DetectorMatch] = self._scan_with_registry(
            scannable, skip_detector_names=skip,
        )

        # Collect all unique pattern names
        all_names: set[str] = {m.pattern_name for m in matches}
        all_names.update(m.pattern_name for m in detector_matches)

        if not all_names:
            return False, None

        names = ", ".join(sorted(all_names))
        return True, f"Blocked: detected {names}"

    def _scan_with_registry(
        self,
        text: str,
        *,
        skip_detector_names: frozenset[str] | set[str] = frozenset(),
    ) -> list[DetectorMatch]:
        """Run every registered detector except those whose name is in *skip*."""
        if not skip_detector_names:
            return self._registry.scan_all(text)
        results: list[DetectorMatch] = []
        for detector in self._registry.list_detectors():
            if detector.name in skip_detector_names:
                continue
            results.extend(detector.scan(text))
        return results
