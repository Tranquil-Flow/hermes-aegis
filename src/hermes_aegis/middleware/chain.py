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
                context.metadata["needs_approval"] = True

        result = await handler(args)

        for middleware in reversed(self.middlewares):
            result = await middleware.post_dispatch(name, args, result, context)

        return result
