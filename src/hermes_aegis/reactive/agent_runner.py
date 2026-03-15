"""Agent runner — spawns AIAgent with restricted config for security investigations.

Accepts an agent_factory callable for test injection.
"""
from __future__ import annotations

import json
import logging
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from hermes_aegis.reactive.rules import ReactiveRule
from hermes_aegis.reactive.templates import build_investigation_prompt, format_report

logger = logging.getLogger(__name__)

_path_lock = threading.Lock()
_path_added = False


def _ensure_hermes_path() -> None:
    """Thread-safe one-shot sys.path setup for hermes-agent imports."""
    global _path_added
    if _path_added:
        return
    with _path_lock:
        if _path_added:
            return
        hermes_agent_dir = str(Path.home() / ".hermes" / "hermes-agent")
        if hermes_agent_dir not in sys.path:
            sys.path.insert(0, hermes_agent_dir)
        _path_added = True


@dataclass
class AgentResult:
    """Result from a spawned investigation agent."""
    rule_name: str
    response: str = ""
    actions_requested: list[dict[str, Any]] = field(default_factory=list)
    report_path: Path | None = None
    error: str | None = None
    success: bool = True


def _default_agent_factory(
    model: str,
    prompt: str,
    max_iterations: int = 10,
) -> str:
    """Spawn a real AIAgent and return its response text."""
    _ensure_hermes_path()
    from run_agent import AIAgent

    agent = AIAgent(
        model=model,
        max_iterations=max_iterations,
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=True,
        platform="aegis-reactive",
        disabled_toolsets=["terminal", "cronjob", "browser", "code_execution"],
    )

    result = agent.run_conversation(prompt)
    if isinstance(result, dict):
        return result.get("content", str(result))
    return str(result)


def parse_action_blocks(response: str) -> list[dict[str, Any]]:
    """Extract action JSON blocks from agent response text."""
    actions: list[dict[str, Any]] = []

    # Match ```json ... ``` blocks
    for match in re.finditer(r"```json\s*\n(.*?)\n\s*```", response, re.DOTALL):
        try:
            data = json.loads(match.group(1))
            if isinstance(data, dict) and "action" in data:
                actions.append(data)
        except json.JSONDecodeError:
            continue

    return actions


def spawn_investigation_agent(
    rule: ReactiveRule,
    triggering_entries: list[dict[str, Any]],
    context_entries: list[dict[str, Any]],
    chain_valid: bool = True,
    agent_factory: Callable[..., str] | None = None,
) -> AgentResult:
    """Spawn an investigation agent and return the result.

    Args:
        rule: The reactive rule that triggered this investigation
        triggering_entries: Audit entries that caused the trigger
        context_entries: Additional context entries
        chain_valid: Whether the audit chain integrity check passed
        agent_factory: Optional callable for test injection. Signature:
            (model: str, prompt: str, max_iterations: int) -> str
    """
    factory = agent_factory or _default_agent_factory

    prompt = build_investigation_prompt(
        rule=rule,
        triggering_entries=triggering_entries,
        context_entries=context_entries,
        chain_valid=chain_valid,
        available_actions=rule.allowed_actions,
    )

    try:
        response = factory(
            model=rule.model,
            prompt=prompt,
            max_iterations=10,
        )
    except Exception as e:
        logger.exception("Agent spawn failed for rule '%s'", rule.name)
        return AgentResult(
            rule_name=rule.name,
            error=str(e),
            success=False,
        )

    # Parse action blocks from response
    actions = parse_action_blocks(response)

    # Generate and save report
    trigger_summary = f"{len(triggering_entries)} events matched rule '{rule.name}'"
    report_content = format_report(
        rule=rule,
        trigger_summary=trigger_summary,
        agent_response=response,
        actions_taken=actions if actions else None,
    )

    report_dir = rule.resolved_report_path
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_file = report_dir / f"{rule.name}_{timestamp}.md"
    report_file.write_text(report_content)

    return AgentResult(
        rule_name=rule.name,
        response=response,
        actions_requested=actions,
        report_path=report_file,
        success=True,
    )
