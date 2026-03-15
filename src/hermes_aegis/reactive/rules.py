"""Rule and trigger dataclasses for reactive audit agents.

Handles JSON loading, trigger matching, duration parsing, and default rule generation.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def parse_duration(s: str) -> float:
    """Parse a human duration string (e.g. '5m', '2h', '60s') into seconds."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd])?", s.strip())
    if not m:
        raise ValueError(f"Invalid duration string: {s!r}")
    value = float(m.group(1))
    unit = m.group(2) or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


@dataclass
class Trigger:
    """Defines when a reactive rule should fire."""
    decision: str | None = None
    decision_in: list[str] | None = None
    middleware: str | None = None
    middleware_in: list[str] | None = None
    count: int | None = None
    window: str | None = None

    @property
    def window_seconds(self) -> float:
        if self.window is None:
            return 0.0
        return parse_duration(self.window)

    @property
    def is_threshold(self) -> bool:
        return self.count is not None and self.window is not None

    def matches_entry(self, decision: str, middleware: str) -> bool:
        """Check if a single audit entry matches this trigger's filters."""
        if self.decision is not None and decision != self.decision:
            return False
        if self.decision_in is not None and decision not in self.decision_in:
            return False
        if self.middleware is not None and middleware != self.middleware:
            return False
        if self.middleware_in is not None and middleware not in self.middleware_in:
            return False
        return True


@dataclass
class ReactiveRule:
    """A reactive agent rule loaded from configuration."""
    name: str
    enabled: bool = True
    severity: str = "medium"
    type: str = "notify"  # "investigate" or "notify"
    trigger: Trigger = field(default_factory=Trigger)
    cooldown: str = "5m"
    model: str = "anthropic/claude-sonnet-4-6"
    prompt: str = ""
    context: str = "recent"
    report_path: str = "~/.hermes-aegis/reports/"
    deliver: str | None = None
    allowed_actions: list[str] = field(default_factory=list)
    require_justification: bool = True
    message_template: str = ""

    @property
    def cooldown_seconds(self) -> float:
        return parse_duration(self.cooldown)

    @property
    def resolved_report_path(self) -> Path:
        return Path(self.report_path).expanduser()


VALID_DECISIONS = {
    "BLOCKED", "ANOMALY", "DANGEROUS_COMMAND", "OUTPUT_REDACTED",
    "INITIATED", "COMPLETED", "CHAIN_TAMPERED", "CIRCUIT_BREAKER",
}

VALID_MIDDLEWARES = {
    "ProxyContentScanner", "DomainAllowlist", "RateLimiter",
    "AuditTrailMiddleware", "DangerousBlockerMiddleware",
    "OutputScannerMiddleware",
}

VALID_ACTIONS = {
    "kill_proxy", "kill_hermes", "lock_vault",
    "block_domain", "shrink_allowlist", "tighten_rate_limit",
}


def _validate_rule(data: dict[str, Any]) -> list[str]:
    """Validate a rule dict and return a list of warnings."""
    warnings: list[str] = []
    name = data.get("name", "<unnamed>")

    if data.get("type") not in ("investigate", "notify"):
        warnings.append(f"Rule '{name}': invalid type '{data.get('type')}'")

    trigger = data.get("trigger", {})
    for d in (trigger.get("decision_in") or []):
        if d not in VALID_DECISIONS:
            warnings.append(f"Rule '{name}': unknown decision '{d}'")
    if trigger.get("decision") and trigger["decision"] not in VALID_DECISIONS:
        warnings.append(f"Rule '{name}': unknown decision '{trigger['decision']}'")

    for action in data.get("allowed_actions", []):
        if action not in VALID_ACTIONS:
            warnings.append(f"Rule '{name}': unknown action '{action}'")

    if data.get("allowed_actions") and data.get("severity") != "critical":
        warnings.append(f"Rule '{name}': allowed_actions requires severity='critical'")

    return warnings


def load_rules(path: Path | str) -> list[ReactiveRule]:
    """Load reactive rules from a JSON config file."""
    path = Path(path)
    if not path.exists():
        return []

    data = json.loads(path.read_text())
    rules_data = data.get("rules", [])
    result: list[ReactiveRule] = []

    for rd in rules_data:
        trigger_data = rd.get("trigger", {})
        trigger = Trigger(
            decision=trigger_data.get("decision"),
            decision_in=trigger_data.get("decision_in"),
            middleware=trigger_data.get("middleware"),
            middleware_in=trigger_data.get("middleware_in"),
            count=trigger_data.get("count"),
            window=trigger_data.get("window"),
        )
        rule = ReactiveRule(
            name=rd["name"],
            enabled=rd.get("enabled", True),
            severity=rd.get("severity", "medium"),
            type=rd.get("type", "notify"),
            trigger=trigger,
            cooldown=rd.get("cooldown", "5m"),
            model=rd.get("model", "anthropic/claude-sonnet-4-6"),
            prompt=rd.get("prompt", ""),
            context=rd.get("context", "recent"),
            report_path=rd.get("report_path", "~/.hermes-aegis/reports/"),
            deliver=rd.get("deliver"),
            allowed_actions=rd.get("allowed_actions", []),
            require_justification=rd.get("require_justification", True),
            message_template=rd.get("message_template", ""),
        )
        result.append(rule)

    return result


def save_rules(path: Path | str, rules: list[ReactiveRule]) -> None:
    """Save reactive rules to a JSON config file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rules_data = []
    for r in rules:
        rd: dict[str, Any] = {
            "name": r.name,
            "enabled": r.enabled,
            "severity": r.severity,
            "type": r.type,
            "trigger": {},
            "cooldown": r.cooldown,
        }
        t = r.trigger
        if t.decision is not None:
            rd["trigger"]["decision"] = t.decision
        if t.decision_in is not None:
            rd["trigger"]["decision_in"] = t.decision_in
        if t.middleware is not None:
            rd["trigger"]["middleware"] = t.middleware
        if t.middleware_in is not None:
            rd["trigger"]["middleware_in"] = t.middleware_in
        if t.count is not None:
            rd["trigger"]["count"] = t.count
        if t.window is not None:
            rd["trigger"]["window"] = t.window

        if r.type == "investigate":
            rd["model"] = r.model
            rd["prompt"] = r.prompt
            rd["context"] = r.context
            rd["report_path"] = r.report_path
            rd["require_justification"] = r.require_justification
            if r.allowed_actions:
                rd["allowed_actions"] = r.allowed_actions

        if r.type == "notify" and r.message_template:
            rd["message_template"] = r.message_template

        if r.deliver:
            rd["deliver"] = r.deliver

        rules_data.append(rd)

    path.write_text(json.dumps({"rules": rules_data}, indent=2))


def default_rules() -> list[ReactiveRule]:
    """Return the default set of reactive rules."""
    return [
        ReactiveRule(
            name="block-alert",
            enabled=True,
            severity="medium",
            type="notify",
            trigger=Trigger(decision="BLOCKED"),
            cooldown="2m",
            deliver="telegram",
            message_template="Aegis blocked {count} request(s) to {host}: {reason}",
        ),
        ReactiveRule(
            name="anomaly-reporter",
            enabled=True,
            severity="medium",
            type="investigate",
            trigger=Trigger(
                decision_in=["ANOMALY"],
                count=3,
                window="60s",
            ),
            cooldown="10m",
            model="anthropic/claude-sonnet-4-6",
            prompt=(
                "You are a security analyst for hermes-aegis. Investigate the following "
                "rate anomaly events. Determine if this represents a real exfiltration "
                "attempt or benign API usage. Write a concise report."
            ),
            context="recent",
        ),
        ReactiveRule(
            name="exfiltration-response",
            enabled=True,
            severity="critical",
            type="investigate",
            trigger=Trigger(
                decision_in=["BLOCKED"],
                middleware_in=["ProxyContentScanner"],
                count=5,
                window="120s",
            ),
            cooldown="15m",
            model="anthropic/claude-sonnet-4-6",
            prompt=(
                "You are a security analyst for hermes-aegis. Multiple outbound requests "
                "have been blocked for containing secrets or sensitive data. Investigate "
                "the pattern, assess the severity, and recommend defensive actions."
            ),
            context="recent",
            allowed_actions=["kill_proxy", "lock_vault", "block_domain"],
            require_justification=True,
        ),
    ]
