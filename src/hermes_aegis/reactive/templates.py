"""Structured report template and prompt construction for reactive agents."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from hermes_aegis.reactive.rules import ReactiveRule


REPORT_TEMPLATE = """\
# Security Incident Report — {rule_name}
**Generated**: {timestamp}
**Severity**: {severity}
**Triggered by**: {trigger_summary}

## Executive Summary
{executive_summary}

## Event Timeline
{event_timeline}

## Affected Resources
{affected_resources}

## Risk Assessment
{risk_assessment}

## Actions Taken
{actions_taken}

## Recommendations
{recommendations}
"""


def build_investigation_prompt(
    rule: ReactiveRule,
    triggering_entries: list[dict[str, Any]],
    context_entries: list[dict[str, Any]],
    chain_valid: bool,
    available_actions: list[str],
) -> str:
    """Build the system + user prompt for an investigation agent."""
    events_text = _format_events(triggering_entries)
    context_text = _format_events(context_entries[-50:]) if context_entries else "No additional context."

    chain_warning = ""
    if not chain_valid:
        chain_warning = (
            "\n\n**WARNING: The audit trail hash chain has been tampered with. "
            "Some entries may have been modified or deleted. Factor this into your analysis.**\n"
        )

    actions_text = "None — this is a report-only investigation."
    if available_actions:
        actions_text = (
            "You may request the following defensive actions by including a JSON block "
            "in your response:\n\n"
            "```json\n"
            '{"action": "<action_name>", "params": {...}, "justification": "..."}\n'
            "```\n\n"
            "Available actions:\n"
        )
        action_descriptions = {
            "kill_proxy": "Stop all outbound HTTP (reversal: hermes-aegis start)",
            "kill_hermes": "Terminate the running Hermes session",
            "lock_vault": "Block secret reads via sentinel file (reversal: hermes-aegis vault unlock)",
            "block_domain": "Add domain to blocklist (params: {\"domain\": \"evil.com\"})",
            "shrink_allowlist": "Remove domain from allowlist (params: {\"domain\": \"removed.com\"})",
            "tighten_rate_limit": "Lower rate threshold (params: {\"factor\": 0.5})",
        }
        for action in available_actions:
            desc = action_descriptions.get(action, action)
            actions_text += f"- `{action}`: {desc}\n"

    return f"""{rule.prompt}
{chain_warning}
## Triggering Events
{events_text}

## Audit Context (recent entries)
{context_text}

## Available Defensive Actions
{actions_text}

## Output Format
Write your analysis as a structured security report. Include:
1. Executive summary (2-3 sentences)
2. Event timeline (chronological)
3. Affected resources (hosts, domains, tools)
4. Risk assessment (severity, likelihood, blast radius)
5. Actions taken (if you requested any circuit breaker actions)
6. Recommendations (next steps for the human operator)
"""


def format_report(
    rule: ReactiveRule,
    trigger_summary: str,
    agent_response: str,
    actions_taken: list[dict[str, Any]] | None = None,
) -> str:
    """Format a completed investigation into the standard report template."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    actions_text = "No circuit breaker actions were executed."
    if actions_taken:
        lines = []
        for a in actions_taken:
            lines.append(f"- **{a['action']}**: {a.get('justification', 'N/A')}")
        actions_text = "\n".join(lines)

    return REPORT_TEMPLATE.format(
        rule_name=rule.name,
        timestamp=now,
        severity=rule.severity,
        trigger_summary=trigger_summary,
        executive_summary=agent_response,
        event_timeline="See agent analysis above.",
        affected_resources="See agent analysis above.",
        risk_assessment="See agent analysis above.",
        actions_taken=actions_text,
        recommendations="See agent analysis above.",
    )


def format_notify_message(
    rule: ReactiveRule,
    triggering_entries: list[dict[str, Any]],
) -> str:
    """Format a notification message using the rule's template."""
    template = rule.message_template or "Security event: {decision} on {host}"
    count = len(triggering_entries)

    # Extract common fields from triggering entries
    hosts = set()
    reasons = set()
    decisions = set()
    for e in triggering_entries:
        args = e.get("args_redacted", {})
        host = args.get("host", args.get("domain", "unknown"))
        hosts.add(str(host))
        reason = args.get("reason", e.get("middleware", ""))
        reasons.add(str(reason))
        decisions.add(e.get("decision", ""))

    from collections import defaultdict
    variables = defaultdict(lambda: "?", {
        "count": str(count),
        "host": ", ".join(sorted(hosts)) or "unknown",
        "reason": ", ".join(sorted(reasons)) or "unknown",
        "decision": ", ".join(sorted(decisions)) or "unknown",
    })
    try:
        return template.format_map(variables)
    except (KeyError, ValueError):
        return template


def _format_events(entries: list[dict[str, Any]]) -> str:
    """Format a list of audit entries into readable text."""
    if not entries:
        return "No events."

    lines = []
    for e in entries:
        ts = e.get("timestamp", 0)
        if isinstance(ts, (int, float)):
            ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
        else:
            ts_str = str(ts)
        tool = e.get("tool_name", "?")
        decision = e.get("decision", "?")
        middleware = e.get("middleware", "?")
        args = e.get("args_redacted", {})
        lines.append(f"- [{ts_str}] {tool} | {decision} | {middleware} | {args}")
    return "\n".join(lines)
