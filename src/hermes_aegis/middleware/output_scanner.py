"""Output secret scanner middleware for subprocess stdout/stderr."""
from __future__ import annotations

from typing import Any

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.chain import CallContext, ToolMiddleware
from hermes_aegis.patterns.secrets import scan_for_secrets


class OutputScannerMiddleware(ToolMiddleware):
    """Scans subprocess output for secrets and redacts them before returning to LLM."""

    def __init__(self, trail: AuditTrail | None = None, vault_values: list[str] | None = None) -> None:
        self._trail = trail
        self._vault_values = vault_values or []

    async def post_dispatch(
        self,
        name: str,
        args: dict,
        result: Any,
        ctx: CallContext,
    ) -> Any:
        """Scan and redact secrets in subprocess output."""
        # Handle dict results with "output" key (typical for subprocess tools)
        if isinstance(result, dict) and "output" in result:
            output = result.get("output", "")
            if isinstance(output, str):
                redacted_output, redaction_count = self._redact_secrets(output)
                if redaction_count > 0:
                    result = result.copy()
                    result["output"] = redacted_output
                    if self._trail:
                        self._trail.log(
                            tool_name=name,
                            args_redacted={"redactions": redaction_count},
                            decision="OUTPUT_REDACTED",
                            middleware=self.__class__.__name__,
                        )
        # Handle plain string results
        elif isinstance(result, str):
            redacted_result, redaction_count = self._redact_secrets(result)
            if redaction_count > 0:
                result = redacted_result
                if self._trail:
                    self._trail.log(
                        tool_name=name,
                        args_redacted={"redactions": redaction_count},
                        decision="OUTPUT_REDACTED",
                        middleware=self.__class__.__name__,
                    )
        
        return result

    def _redact_secrets(self, text: str) -> tuple[str, int]:
        """Scan text for secrets and redact them with pattern names.
        
        Returns:
            Tuple of (redacted_text, redaction_count)
        """
        matches = scan_for_secrets(text, exact_values=self._vault_values)
        if not matches:
            return text, 0

        # Sort matches by start position in reverse order for safe string replacement
        redacted = text
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            replacement = f"[REDACTED: {match.pattern_name}]"
            redacted = redacted[: match.start] + replacement + redacted[match.end :]

        return redacted, len(matches)
