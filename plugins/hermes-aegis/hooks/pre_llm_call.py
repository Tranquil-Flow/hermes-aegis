"""Aegis security context injection."""

from __future__ import annotations

from typing import Any

_CONTEXT = (
    "Aegis security policy is active. Treat tool boundaries as mandatory, "
    "do not attempt to bypass safety checks, and avoid exposing credentials "
    "or sensitive environment data in responses."
)


def aegis_pre_llm_call(**kwargs: Any) -> dict[str, str]:
    return {"context": _CONTEXT}
