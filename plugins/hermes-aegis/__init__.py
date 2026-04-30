"""Hermes Aegis plugin: tool-level security enforcement."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def register(ctx) -> None:
    """Register Aegis hooks with Hermes."""
    from .hooks.post_api_request import aegis_post_api_request
    from .hooks.post_tool_call import aegis_post_tool_call
    from .hooks.pre_llm_call import aegis_pre_llm_call
    from .hooks.pre_tool_call import aegis_pre_tool_call
    from .hooks.transforms import register_transforms

    ctx.register_hook("pre_tool_call", aegis_pre_tool_call)
    ctx.register_hook("post_tool_call", aegis_post_tool_call)
    register_transforms(ctx)
    ctx.register_hook("pre_llm_call", aegis_pre_llm_call)
    ctx.register_hook("post_api_request", aegis_post_api_request)
    logger.info("hermes-aegis plugin registered")
