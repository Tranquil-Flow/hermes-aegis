from __future__ import annotations

from hermes_aegis.middleware.chain import CallContext, ToolMiddleware
from hermes_aegis.patterns.crypto import scan_for_crypto_keys
from hermes_aegis.patterns.secrets import scan_for_secrets


class SecretRedactionMiddleware(ToolMiddleware):
    """Scans tool results and replaces detected secrets with [REDACTED].

    Runs as a post-dispatch middleware layer: after each tool call completes,
    the raw result string is scanned for secrets (API keys, tokens, private
    keys, etc.) using both the generic secrets pattern scanner and the crypto
    key scanner.  All detected spans are replaced with the literal string
    ``[REDACTED]`` so that sensitive values never reach the LLM context.

    Vault values (exact known secrets retrieved from the credential store) are
    passed in at construction time and are always redacted regardless of
    whether they match a pattern.
    """

    def __init__(self, vault_values: list[str] | None = None) -> None:
        """Initialise the middleware with optional explicit vault values.

        Args:
            vault_values: List of exact secret strings to always redact,
                typically retrieved from the Aegis vault at startup.  These
                are matched literally in addition to pattern-based scanning.
        """
        self._vault_values = vault_values or []

    async def post_dispatch(
        self,
        name: str,
        args: dict,
        result: str,
        ctx: CallContext,
    ) -> str:
        """Redact secrets from a tool result before it is returned to the LLM.

        Args:
            name: Name of the tool that was called.
            args: Arguments that were passed to the tool (not modified).
            result: Raw string result returned by the tool implementation.
            ctx: Shared call context carrying request metadata.

        Returns:
            The result string with all detected secret spans replaced by
            ``[REDACTED]``.  Non-string results are returned unchanged.
        """
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
