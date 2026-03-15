"""Circuit breaker actions — defensive responses to security events.

All actions reduce capability only — never expand. Worst case is DoS,
which is preferable to data exfiltration.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any

from hermes_aegis.audit.trail import AuditTrail

logger = logging.getLogger(__name__)

AEGIS_DIR = Path.home() / ".hermes-aegis"
VAULT_LOCK_FILE = AEGIS_DIR / "vault.lock"
BLOCKLIST_FILE = AEGIS_DIR / "domain-blocklist.json"

VALID_ACTIONS = {
    "kill_proxy", "kill_hermes", "lock_vault",
    "block_domain", "shrink_allowlist", "tighten_rate_limit",
}


class CircuitBreakerExecutor:
    """Validates and executes defensive actions, logging each to the audit trail."""

    def __init__(
        self,
        audit_trail: AuditTrail,
        hermes_pid: int | None = None,
    ) -> None:
        self._audit = audit_trail
        self._hermes_pid = hermes_pid

    def execute(
        self,
        action_name: str,
        params: dict[str, Any],
        justification: str,
        rule_name: str,
        allowed_actions: list[str],
    ) -> bool:
        """Validate and execute a circuit breaker action.

        Returns True if the action was executed successfully.
        """
        if action_name not in VALID_ACTIONS:
            logger.warning("Unknown action: %s", action_name)
            return False

        if action_name not in allowed_actions:
            logger.warning(
                "Action '%s' not in allowed_actions for rule '%s'",
                action_name, rule_name,
            )
            return False

        try:
            method = getattr(self, f"_action_{action_name}")
            method(params)
        except Exception:
            logger.exception("Circuit breaker action '%s' failed", action_name)
            self._log_action(action_name, params, justification, rule_name, success=False)
            return False

        self._log_action(action_name, params, justification, rule_name, success=True)
        return True

    def _log_action(
        self,
        action_name: str,
        params: dict[str, Any],
        justification: str,
        rule_name: str,
        success: bool,
    ) -> None:
        self._audit.log(
            tool_name="circuit_breaker",
            args_redacted={
                "action": action_name,
                "params": params,
                "justification": justification,
                "rule": rule_name,
                "success": success,
            },
            decision="CIRCUIT_BREAKER",
            middleware="ReactiveAgentManager",
        )

    def _action_kill_proxy(self, params: dict[str, Any]) -> None:
        from hermes_aegis.proxy.runner import stop_proxy
        stop_proxy()
        logger.info("Circuit breaker: proxy killed")

    def _action_kill_hermes(self, params: dict[str, Any]) -> None:
        if self._hermes_pid is None:
            logger.warning("Cannot kill hermes: no PID available")
            return
        try:
            os.kill(self._hermes_pid, signal.SIGTERM)
            logger.info("Circuit breaker: hermes (PID %d) terminated", self._hermes_pid)
        except ProcessLookupError:
            logger.info("Hermes process already gone (PID %d)", self._hermes_pid)

    def _action_lock_vault(self, params: dict[str, Any]) -> None:
        VAULT_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        VAULT_LOCK_FILE.write_text(json.dumps({
            "locked_at": time.time(),
            "reason": params.get("reason", "circuit breaker"),
        }))
        logger.info("Circuit breaker: vault locked")

    def _action_block_domain(self, params: dict[str, Any]) -> None:
        domain = params.get("domain", "")
        if not domain:
            logger.warning("block_domain: no domain specified")
            return

        blocklist: list[str] = []
        if BLOCKLIST_FILE.exists():
            try:
                blocklist = json.loads(BLOCKLIST_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        if domain not in blocklist:
            blocklist.append(domain)
            BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
            BLOCKLIST_FILE.write_text(json.dumps(blocklist, indent=2))
        logger.info("Circuit breaker: domain '%s' blocked", domain)

    def _action_shrink_allowlist(self, params: dict[str, Any]) -> None:
        domain = params.get("domain", "")
        if not domain:
            logger.warning("shrink_allowlist: no domain specified")
            return

        from hermes_aegis.config.allowlist import DomainAllowlist
        allowlist_path = AEGIS_DIR / "domain-allowlist.json"
        al = DomainAllowlist(allowlist_path)
        al.remove(domain)
        logger.info("Circuit breaker: domain '%s' removed from allowlist", domain)

    def _action_tighten_rate_limit(self, params: dict[str, Any]) -> None:
        from hermes_aegis.config.settings import Settings
        config_path = AEGIS_DIR / "config.json"
        settings = Settings(config_path)
        factor = params.get("factor", 0.5)
        current = int(settings.get("rate_limit_requests", 50))
        new_limit = max(1, int(current * factor))
        settings.set("rate_limit_requests", new_limit)
        logger.info(
            "Circuit breaker: rate limit tightened from %d to %d",
            current, new_limit,
        )
