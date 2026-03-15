"""Scheduled report management — wraps hermes cron API for aegis reports."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from hermes_aegis.reports.generator import (
    build_report_prompt,
    get_last_report_time,
    set_last_report_time,
)

logger = logging.getLogger(__name__)

AEGIS_DIR = Path.home() / ".hermes-aegis"
AUDIT_PATH = AEGIS_DIR / "audit.jsonl"
JOB_PREFIX = "aegis-report-"


_path_added = False


def _ensure_cron_import():
    """Ensure hermes cron module is importable (one-shot)."""
    global _path_added
    if _path_added:
        return
    hermes_agent_dir = str(Path.home() / ".hermes" / "hermes-agent")
    if hermes_agent_dir not in sys.path:
        sys.path.insert(0, hermes_agent_dir)
    _path_added = True


def schedule_report(
    schedule: str,
    name: str | None = None,
    model: str = "anthropic/claude-sonnet-4-6",
    deliver: str | None = None,
) -> dict[str, Any]:
    """Create a hermes cron job for periodic audit reports.

    Args:
        schedule: Cron expression or interval (e.g. "24h", "0 9 * * 1")
        name: Optional friendly name (auto-generated if omitted)
        model: Model to use for report generation
        deliver: Delivery target (e.g. "telegram", "local")

    Returns:
        The created job dict
    """
    _ensure_cron_import()
    from cron.jobs import create_job

    job_name = name or f"{JOB_PREFIX}{schedule.replace(' ', '_')}"
    if not job_name.startswith(JOB_PREFIX):
        job_name = JOB_PREFIX + job_name

    # Use a meta-prompt that instructs the agent to read the audit trail fresh
    # at execution time, rather than baking stale statistics at schedule time.
    prompt = (
        "You are a security analyst for hermes-aegis. Generate a security digest report.\n"
        f"Read the audit trail at {AUDIT_PATH} and analyze events since the last report.\n"
        "Focus on BLOCKED, ANOMALY, and DANGEROUS_COMMAND events.\n"
        "Write a concise markdown report with: summary, event breakdown, blocked requests, "
        "anomalies, and recommendations."
    )

    job = create_job(
        prompt=prompt,
        schedule=schedule,
        name=job_name,
        deliver=deliver,
    )

    return job


def list_reports() -> list[dict[str, Any]]:
    """List all aegis report cron jobs."""
    _ensure_cron_import()
    from cron.jobs import list_jobs

    all_jobs = list_jobs(include_disabled=True)
    return [j for j in all_jobs if (j.get("name") or "").startswith(JOB_PREFIX)]


def cancel_report(job_id: str) -> bool:
    """Cancel (remove) a scheduled report by job ID."""
    _ensure_cron_import()
    from cron.jobs import remove_job

    return remove_job(job_id)


def run_report_now(
    model: str = "anthropic/claude-sonnet-4-6",
    deliver: str | None = None,
) -> dict[str, Any] | None:
    """Manually trigger a one-shot report immediately.

    Uses the agent runner directly instead of going through cron.
    """
    prompt = build_report_prompt(AUDIT_PATH, since=get_last_report_time())

    try:
        hermes_agent_dir = str(Path.home() / ".hermes" / "hermes-agent")
        if hermes_agent_dir not in sys.path:
            sys.path.insert(0, hermes_agent_dir)

        from run_agent import AIAgent

        agent = AIAgent(
            model=model,
            max_iterations=5,
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
            platform="aegis-report",
            disabled_toolsets=["terminal", "cronjob", "browser", "code_execution"],
        )

        result = agent.run_conversation(prompt)
        set_last_report_time()

        response = result if isinstance(result, str) else str(result)

        # Save report
        from datetime import datetime, timezone
        report_dir = AEGIS_DIR / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = report_dir / f"digest_{timestamp}.md"
        report_file.write_text(response)

        # Deliver if configured
        if deliver:
            try:
                from delivery.router import deliver as hermes_deliver
                hermes_deliver(response, target=deliver)
            except Exception:
                logger.exception("Failed to deliver report via '%s'", deliver)

        return {"report_path": str(report_file), "response": response}

    except Exception:
        logger.exception("Failed to generate manual report")
        return None
