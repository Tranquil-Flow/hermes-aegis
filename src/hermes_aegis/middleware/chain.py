from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable


class DispatchDecision(Enum):
    """Decision outcomes for middleware pre-dispatch checks.

    Attributes:
        ALLOW: Tool call is permitted to proceed.
        DENY: Tool call is blocked and execution is aborted.
        NEEDS_APPROVAL: Tool call requires external approval before proceeding.
    """
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


@dataclass
class CallContext:
    """Metadata bag passed through the middleware chain.

    Carries shared context about the current tool invocation, allowing middleware
    to communicate state (e.g., audit info, blocked reason, escalation level).

    Attributes:
        session_id: Unique identifier for the current session.
        metadata: Arbitrary key-value storage for middleware to share information.
    """

    session_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolMiddleware(ABC):
    """Base class for tool dispatch middleware.

    Middleware runs in a chain pattern around a tool handler:
    - **Pre-dispatch**: Runs before the tool handler, can block execution.
    - **Handler**: The actual tool implementation (outside middleware).
    - **Post-dispatch**: Runs after the handler, can transform the result.

    Subclasses should override ``pre_dispatch()`` and/or ``post_dispatch()`` to
    implement their security or transformation logic.
    """

    async def pre_dispatch(
        self,
        name: str,
        args: dict,
        ctx: CallContext,
    ) -> DispatchDecision:
        """Check tool invocation before execution.

        Args:
            name: Name of the tool being invoked.
            args: Arguments passed to the tool.
            ctx: Shared call context for metadata exchange.

        Returns:
            A DispatchDecision indicating whether to allow, deny, or request approval.
        """
        return DispatchDecision.ALLOW

    async def post_dispatch(
        self,
        name: str,
        args: dict,
        result: Any,
        ctx: CallContext,
    ) -> Any:
        """Transform or inspect the tool result after execution.

        Args:
            name: Name of the tool that was invoked.
            args: Arguments that were passed to the tool.
            result: The raw result returned by the tool handler.
            ctx: Shared call context for metadata exchange.

        Returns:
            The (possibly modified) result to pass to the next middleware or caller.
        """
        return result


class MiddlewareChain:
    """Executes a stack of middleware around a tool handler.

    Implements the middleware pattern: all pre-dispatch middleware runs first
    (in order), then the tool handler executes (if all pre-dispatch checks pass),
    then all post-dispatch middleware runs in reverse order.

    This layered approach enables security checks (dangerous commands, rate limits),
    output transformation (redaction, content scanning), and audit logging.
    """

    def __init__(self, middlewares: list[ToolMiddleware]) -> None:
        """Initialize the middleware chain.

        Args:
            middlewares: List of middleware instances to execute in order.
        """
        self.middlewares = middlewares

    async def execute(
        self,
        name: str,
        args: dict,
        handler: Callable[[dict], Awaitable[Any]],
        context: CallContext,
    ) -> Any:
        """Execute the middleware chain around a tool handler.

        Runs pre-dispatch middleware in order, skips to error return if any
        middleware denies the call. If all allow, executes the handler, then
        runs post-dispatch middleware in reverse order.

        Args:
            name: Name of the tool being invoked.
            args: Arguments to pass to the tool handler.
            handler: Async callable that invokes the actual tool.
            context: Shared call context for metadata exchange.

        Returns:
            The tool result (possibly modified by post-dispatch middleware),
            or an error dict if pre-dispatch blocked the call.
        """
        for middleware in self.middlewares:
            decision = await middleware.pre_dispatch(name, args, context)
            if decision == DispatchDecision.DENY:
                return {"error": f"Blocked by {middleware.__class__.__name__}"}
            if decision == DispatchDecision.NEEDS_APPROVAL:
                return {"error": "Needs approval"}

        result = await handler(args)

        for middleware in reversed(self.middlewares):
            result = await middleware.post_dispatch(name, args, result, context)

        return result


def create_default_chain(
    audit_trail: Any | None = None,
    vault_values: list[str] | None = None,
    dangerous_mode: str = "audit",
    tirith_mode: str = "detect",
) -> MiddlewareChain:
    """Create a default middleware chain with output scanner and dangerous blocker.
    
    Args:
        audit_trail: Optional audit trail for logging
        vault_values: Optional list of exact vault values to scan for
        dangerous_mode: Mode for dangerous command handling ("audit" or "block")
        tirith_mode: Mode for Tirith content scanning ("detect" or "block")
        
    Returns:
        MiddlewareChain with output scanner, Tirith scanner, dangerous blocker, and other middlewares
    """
    from hermes_aegis.middleware.output_scanner import OutputScannerMiddleware
    from hermes_aegis.middleware.dangerous_blocker import DangerousBlockerMiddleware
    from hermes_aegis.middleware.tirith_scanner import TirithScannerMiddleware
    
    middlewares: list[ToolMiddleware] = []
    
    # Dangerous blocker runs first (pre-dispatch)
    middlewares.append(DangerousBlockerMiddleware(mode=dangerous_mode, trail=audit_trail))
    
    # Output scanner is always active (on by default)
    middlewares.append(OutputScannerMiddleware(trail=audit_trail, vault_values=vault_values))
    
    # Tirith content scanner runs after output scanner (post-dispatch)
    middlewares.append(TirithScannerMiddleware(trail=audit_trail, mode=tirith_mode))
    
    return MiddlewareChain(middlewares)
