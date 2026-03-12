from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable


class DispatchDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


@dataclass
class CallContext:
    """Metadata bag passed through the middleware chain."""

    session_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolMiddleware(ABC):
    """Base class for tool dispatch middleware."""

    async def pre_dispatch(
        self,
        name: str,
        args: dict,
        ctx: CallContext,
    ) -> DispatchDecision:
        return DispatchDecision.ALLOW

    async def post_dispatch(
        self,
        name: str,
        args: dict,
        result: Any,
        ctx: CallContext,
    ) -> Any:
        return result


class MiddlewareChain:
    """Executes a stack of middleware around a tool handler."""

    def __init__(self, middlewares: list[ToolMiddleware]) -> None:
        self.middlewares = middlewares

    async def execute(
        self,
        name: str,
        args: dict,
        handler: Callable[[dict], Awaitable[Any]],
        context: CallContext,
    ) -> Any:
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
) -> MiddlewareChain:
    """Create a default middleware chain with output scanner and dangerous blocker.
    
    Args:
        audit_trail: Optional audit trail for logging
        vault_values: Optional list of exact vault values to scan for
        dangerous_mode: Mode for dangerous command handling ("audit" or "block")
        
    Returns:
        MiddlewareChain with output scanner, dangerous blocker, and other middlewares
    """
    from hermes_aegis.middleware.output_scanner import OutputScannerMiddleware
    from hermes_aegis.middleware.dangerous_blocker import DangerousBlockerMiddleware
    
    middlewares: list[ToolMiddleware] = []
    
    # Dangerous blocker runs first (pre-dispatch)
    middlewares.append(DangerousBlockerMiddleware(mode=dangerous_mode, trail=audit_trail))
    
    # Output scanner is always active (on by default)
    middlewares.append(OutputScannerMiddleware(trail=audit_trail, vault_values=vault_values))
    
    return MiddlewareChain(middlewares)
