from __future__ import annotations

import hashlib
from typing import Any

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.chain import CallContext, DispatchDecision, ToolMiddleware
from hermes_aegis.patterns.secrets import scan_for_secrets
from hermes_aegis.patterns.dangerous import detect_dangerous_command


class AuditTrailMiddleware(ToolMiddleware):
    """Logs tool calls to the audit trail with secret redaction."""

    def __init__(self, trail: AuditTrail) -> None:
        self._trail = trail

    async def pre_dispatch(
        self,
        name: str,
        args: dict,
        ctx: CallContext,
    ) -> DispatchDecision:
        # Check for dangerous command patterns (logging only, not blocking)
        decision = "INITIATED"
        redacted_args = _redact_args(args)
        
        if name == "terminal" and "command" in args:
            cmd = args.get("command", "")
            if isinstance(cmd, str):
                is_dangerous, pattern_key, description = detect_dangerous_command(cmd)
                if is_dangerous:
                    decision = "DANGEROUS_COMMAND"
                    # Store danger info in redacted args for audit trail
                    redacted_args["_danger_type"] = description
                    redacted_args["_danger_pattern"] = pattern_key
        
        self._trail.log(
            tool_name=name,
            args_redacted=redacted_args,
            decision=decision,
            middleware=self.__class__.__name__,
        )
        return DispatchDecision.ALLOW

    async def post_dispatch(
        self,
        name: str,
        args: dict,
        result: Any,
        ctx: CallContext,
    ) -> Any:
        result_hash = hashlib.sha256(str(result).encode()).hexdigest()[:16]
        self._trail.log(
            tool_name=name,
            args_redacted={},
            decision="COMPLETED",
            middleware=self.__class__.__name__,
            result_hash=result_hash,
        )
        return result


def _redact_args(args: dict) -> dict:
    """Replace arg values that match secret patterns with [REDACTED]."""
    redacted = {}
    for key, value in args.items():
        if isinstance(value, str):
            matches = scan_for_secrets(value)
            if matches:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        else:
            redacted[key] = value
    return redacted
