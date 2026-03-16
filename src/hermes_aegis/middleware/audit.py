from __future__ import annotations

import hashlib
from typing import Any

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.chain import CallContext, DispatchDecision, ToolMiddleware
from hermes_aegis.patterns.secrets import scan_for_secrets
from hermes_aegis.patterns.dangerous import detect_dangerous_command


class AuditTrailMiddleware(ToolMiddleware):
    """Logs tool calls to the audit trail with secret redaction.

    This middleware runs during both pre-dispatch and post-dispatch phases to provide
    comprehensive audit logging:

    - **Pre-dispatch**: Redacts all tool arguments and logs the invocation, including
      flagging dangerous commands (SSH, exfiltration patterns) for detection without
      blocking.
    - **Post-dispatch**: Logs the tool result hash (not the full result) and marks the
      tool call as completed.

    All secret values in arguments are automatically redacted using both pattern-based
    detection (API keys, tokens) and vault-managed exact value matching.
    """

    def __init__(self, trail: AuditTrail) -> None:
        """Initialize the audit trail middleware.

        Args:
            trail: The AuditTrail instance to write all log entries to.
        """
        self._trail = trail

    async def pre_dispatch(
        self,
        name: str,
        args: dict,
        ctx: CallContext,
    ) -> DispatchDecision:
        """Log a tool invocation before execution.

        Redacts sensitive arguments and performs special handling for terminal
        commands: checks for dangerous patterns (exfiltration, destructive operations)
        and annotates the log entry accordingly.

        Args:
            name: Name of the tool being invoked.
            args: Arguments passed to the tool.
            ctx: Shared call context for metadata exchange.

        Returns:
            Always returns ALLOW — this middleware never blocks, only logs.
        """
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
        """Log tool completion and result hash.

        Rather than logging the full result (which may be large or sensitive),
        this logs a SHA-256 hash of the result for integrity verification.

        Args:
            name: Name of the tool that was invoked.
            args: Arguments that were passed to the tool.
            result: The raw result returned by the tool handler.
            ctx: Shared call context for metadata exchange.

        Returns:
            The result unchanged (no transformation applied).
        """
        result_hash = hashlib.sha256(str(result).encode()).hexdigest()[:16]
        self._trail.log(
            tool_name=name,
            args_redacted={},
            decision="COMPLETED",
            middleware=self.__class__.__name__,
            result_hash=result_hash,
        )
        return result


def _redact_value(value):
    """Recursively redact secrets from a value at any nesting depth.

    Scans string values for secret patterns (API keys, tokens, cryptocurrency private
    keys) and replaces detected secrets with the literal string "[REDACTED]". For
    containers (dicts, lists, tuples), recursively processes each element.

    Args:
        value: Any value type — strings, dicts, lists, tuples, or scalars.

    Returns:
        The value with all detected secrets replaced by "[REDACTED]", maintaining
        the original structure (e.g., dicts remain dicts, lists remain lists).
    """
    if isinstance(value, str):
        return "[REDACTED]" if scan_for_secrets(value) else value
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


def _redact_args(args: dict) -> dict:
    """Replace arg values that match secret patterns with [REDACTED].

    Applies secret redaction to all values in the argument dictionary, preserving
    key names but replacing any detected secrets. This ensures tool arguments can
    be logged safely for audit trails without exposing API keys, tokens, or private
    keys.

    Args:
        args: Dictionary of tool arguments (e.g., {'api_key': 'sk-...', 'command': 'ls'})

    Returns:
        A new dictionary with the same structure where all secret values are
        replaced by "[REDACTED]".
    """
    return {k: _redact_value(v) for k, v in args.items()}
