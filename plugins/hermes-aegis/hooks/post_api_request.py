"""Aegis API request accounting hook."""

from __future__ import annotations

from typing import Any


def aegis_post_api_request(
    task_id: str = "",
    session_id: str = "",
    model: str = "",
    provider: str = "",
    base_url: str = "",
    **kwargs: Any,
) -> None:
    try:
        from ..state import record_api_request
    except ImportError:
        from state import record_api_request

    record_api_request(
        session_id=session_id,
        task_id=task_id,
        model=model,
        provider=provider,
        base_url=base_url,
    )
