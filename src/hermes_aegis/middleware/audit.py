from __future__ import annotations

import hashlib
from typing import Any

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.chain import CallContext, DispatchDecision, ToolMiddleware


class AuditTrailMiddleware(ToolMiddleware):
    """Logs tool calls to the audit trail."""

    def __init__(self, trail: AuditTrail) -> None:
        self._trail = trail

    async def pre_dispatch(
        self,
        name: str,
        args: dict,
        ctx: CallContext,
    ) -> DispatchDecision:
        self._trail.log(
            tool_name=name,
            args_redacted=args,
            decision="INITIATED",
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
            args_redacted=args,
            decision="COMPLETED",
            middleware=self.__class__.__name__,
            result_hash=result_hash,
        )
        return result
