from __future__ import annotations

from hermes_aegis.middleware.chain import CallContext, ToolMiddleware
from hermes_aegis.patterns.crypto import scan_for_crypto_keys
from hermes_aegis.patterns.secrets import scan_for_secrets


class SecretRedactionMiddleware(ToolMiddleware):
    """Scans tool results and replaces detected secrets with [REDACTED]."""

    def __init__(self, vault_values: list[str] | None = None) -> None:
        self._vault_values = vault_values or []

    async def post_dispatch(
        self,
        name: str,
        args: dict,
        result: str,
        ctx: CallContext,
    ) -> str:
        if not isinstance(result, str):
            return result

        matches = scan_for_secrets(result, exact_values=self._vault_values)
        matches.extend(scan_for_crypto_keys(result))
        if not matches:
            return result

        redacted = result
        for match in sorted(matches, key=lambda item: item.start, reverse=True):
            redacted = redacted[: match.start] + "[REDACTED]" + redacted[match.end :]

        return redacted
