"""Reactive agent manager — evaluates rules, manages cooldowns, spawns agents.

Thread-safe. Called from the watcher thread.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.reactive.actions import CircuitBreakerExecutor
from hermes_aegis.reactive.agent_runner import AgentResult, spawn_investigation_agent
from hermes_aegis.reactive.rules import ReactiveRule, load_rules
from hermes_aegis.reactive.templates import format_notify_message

logger = logging.getLogger(__name__)

_hermes_path_lock = threading.Lock()
_hermes_path_added = False


def _ensure_hermes_path() -> None:
    """Thread-safe one-shot sys.path setup for hermes-agent imports."""
    global _hermes_path_added
    if _hermes_path_added:
        return
    with _hermes_path_lock:
        if _hermes_path_added:
            return
        import sys
        hermes_agent_dir = str(Path.home() / ".hermes" / "hermes-agent")
        if hermes_agent_dir not in sys.path:
            sys.path.insert(0, hermes_agent_dir)
        _hermes_path_added = True

MAX_SPAWNS_PER_HOUR = 5


class ReactiveAgentManager:
    """Evaluates audit entries against rules and takes action."""

    def __init__(
        self,
        rules_path: Path,
        audit_trail: AuditTrail,
        actions_executor: CircuitBreakerExecutor,
        agent_factory: Callable[..., str] | None = None,
    ) -> None:
        self._rules_path = rules_path
        self._audit = audit_trail
        self._actions = actions_executor
        self._agent_factory = agent_factory
        self._rules = load_rules(rules_path)

        self._lock = threading.Lock()

        # Per-rule sliding windows for threshold triggers: {rule_name: deque[float]}
        self._windows: dict[str, deque[float]] = {}
        # Per-rule last-fired timestamps
        self._cooldowns: dict[str, float] = {}
        # Global spawn rate limit
        self._spawn_times: deque[float] = deque(maxlen=MAX_SPAWNS_PER_HOUR)

        # Thread pool for concurrent agent spawning (max 2)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aegis-agent")

        # Accumulate triggering entries for threshold rules
        self._trigger_buffers: dict[str, list[dict[str, Any]]] = {}

    @property
    def rules(self) -> list[ReactiveRule]:
        return list(self._rules)

    def reload_rules(self) -> None:
        """Reload rules from disk."""
        with self._lock:
            self._rules = load_rules(self._rules_path)

    def evaluate(self, entry: dict[str, Any]) -> list[ReactiveRule]:
        """Evaluate an audit entry and return rules that should fire.

        Also triggers side effects (notify, agent spawn) for firing rules.
        """
        decision = entry.get("decision", "")
        middleware = entry.get("middleware", "")
        now = time.time()
        fired: list[ReactiveRule] = []
        # Collect side effects to execute OUTSIDE the lock — avoid blocking
        # the watcher thread on I/O (network delivery, file reads, agent spawn).
        to_execute: list[tuple[ReactiveRule, list[dict[str, Any]]]] = []

        with self._lock:
            for rule in self._rules:
                if not rule.enabled:
                    continue

                if not rule.trigger.matches_entry(decision, middleware):
                    continue

                if rule.trigger.is_threshold:
                    # Sliding window tracking
                    if rule.name not in self._windows:
                        self._windows[rule.name] = deque()
                        self._trigger_buffers[rule.name] = []

                    window = self._windows[rule.name]
                    buffer = self._trigger_buffers[rule.name]
                    cutoff = now - rule.trigger.window_seconds
                    while window and window[0] < cutoff:
                        window.popleft()
                        buffer.pop(0)

                    window.append(now)
                    buffer.append(entry)

                    if len(window) < rule.trigger.count:
                        continue

                    # Threshold reached — check cooldown
                    triggering_entries = list(buffer)
                    # Reset window after firing
                    window.clear()
                    buffer.clear()
                else:
                    triggering_entries = [entry]

                # Cooldown check
                last_fired = self._cooldowns.get(rule.name, 0)
                if now - last_fired < rule.cooldown_seconds:
                    continue

                self._cooldowns[rule.name] = now
                fired.append(rule)
                to_execute.append((rule, triggering_entries))

        # Execute side effects outside the lock
        for rule, entries in to_execute:
            try:
                if rule.type == "notify":
                    self._handle_notify(rule, entries)
                elif rule.type == "investigate":
                    self._handle_investigate(rule, entries)
            except Exception:
                logger.exception("Side effect failed for rule '%s'", rule.name)

        return fired

    def _handle_notify(
        self, rule: ReactiveRule, entries: list[dict[str, Any]]
    ) -> None:
        """Handle a notify-type rule — format and deliver message."""
        message = format_notify_message(rule, entries)
        logger.info("Reactive notify [%s]: %s", rule.name, message)

        if rule.deliver:
            self._deliver_message(rule.deliver, message)

    def _handle_investigate(
        self, rule: ReactiveRule, entries: list[dict[str, Any]]
    ) -> None:
        """Handle an investigate-type rule — spawn agent in thread pool."""
        # Global spawn rate check
        now = time.time()
        if len(self._spawn_times) >= MAX_SPAWNS_PER_HOUR:
            oldest = self._spawn_times[0]
            if now - oldest < 3600:
                logger.warning(
                    "Global spawn rate limit reached (%d/hr), skipping rule '%s'",
                    MAX_SPAWNS_PER_HOUR, rule.name,
                )
                return

        self._spawn_times.append(now)

        # Verify chain integrity before investigation
        chain_valid = self._audit.verify_chain()
        if not chain_valid:
            logger.warning("Audit chain integrity check FAILED — logging CHAIN_TAMPERED")
            self._audit.log(
                tool_name="chain_verification",
                args_redacted={"rule": rule.name},
                decision="CHAIN_TAMPERED",
                middleware="ReactiveAgentManager",
            )

        # Get context entries
        context = self._audit.read_all()

        # Submit to thread pool
        try:
            self._executor.submit(
                self._run_investigation,
                rule, entries, context, chain_valid,
            )
        except RuntimeError:
            logger.warning("Thread pool rejected investigation for rule '%s'", rule.name)

    def _run_investigation(
        self,
        rule: ReactiveRule,
        triggering_entries: list[dict[str, Any]],
        context_entries: list[dict[str, Any]],
        chain_valid: bool,
    ) -> None:
        """Run investigation agent (in thread pool thread)."""
        # Convert AuditEntry objects to dicts if needed
        context_dicts = []
        for e in context_entries:
            if isinstance(e, dict):
                context_dicts.append(e)
            else:
                context_dicts.append({
                    "timestamp": e.timestamp,
                    "tool_name": e.tool_name,
                    "args_redacted": e.args_redacted,
                    "decision": e.decision,
                    "middleware": e.middleware,
                })

        result = spawn_investigation_agent(
            rule=rule,
            triggering_entries=triggering_entries,
            context_entries=context_dicts,
            chain_valid=chain_valid,
            agent_factory=self._agent_factory,
        )

        if not result.success:
            logger.error(
                "Investigation failed for rule '%s': %s",
                rule.name, result.error,
            )
            return

        logger.info(
            "Investigation complete for rule '%s'. Report: %s",
            rule.name, result.report_path,
        )

        # Execute any requested actions
        for action_req in result.actions_requested:
            action_name = action_req.get("action", "")
            params = action_req.get("params", {})
            justification = action_req.get("justification", "Agent recommendation")

            self._actions.execute(
                action_name=action_name,
                params=params,
                justification=justification,
                rule_name=rule.name,
                allowed_actions=rule.allowed_actions,
            )

        # Deliver report if configured
        if rule.deliver and result.report_path:
            report_text = result.report_path.read_text()
            self._deliver_message(rule.deliver, report_text)

    def _deliver_message(self, deliver: str, message: str) -> None:
        """Deliver a message via the hermes delivery system."""
        try:
            _ensure_hermes_path()
            from delivery.router import deliver as hermes_deliver
            hermes_deliver(message, target=deliver)
        except Exception:
            logger.exception("Failed to deliver message via '%s'", deliver)

    def shutdown(self) -> None:
        """Shut down the thread pool, waiting for running investigations to finish."""
        self._executor.shutdown(wait=True, cancel_futures=True)
