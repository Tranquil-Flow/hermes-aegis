"""Dangerous command blocking middleware.

Upgrades dangerous command detection from audit-only to configurable blocking.
Based on patterns in patterns/dangerous.py with configurable enforcement.
"""
from __future__ import annotations

import logging
from typing import Any

from hermes_aegis.middleware.chain import CallContext, DispatchDecision, ToolMiddleware
from hermes_aegis.patterns.dangerous import detect_dangerous_command

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a dangerous command is blocked."""
    pass


class DangerousBlockerMiddleware(ToolMiddleware):
    """Block or audit dangerous commands based on configuration.
    
    This middleware checks terminal commands for dangerous patterns
    (rm -rf, curl | sh, etc.) and either blocks them or logs them
    depending on the configured mode.
    
    Modes:
        - "audit" (default): Log dangerous commands but allow execution
        - "block": Raise SecurityError to prevent execution
    """

    def __init__(self, mode: str = "audit", trail: Any = None):
        """Initialize dangerous blocker middleware.
        
        Args:
            mode: Either "audit" (log only) or "block" (prevent execution)
            trail: Optional audit trail for logging
        """
        self.mode = mode.lower()
        self.trail = trail
        
        if self.mode not in ("audit", "block"):
            logger.warning(f"Invalid mode '{mode}', defaulting to 'audit'")
            self.mode = "audit"

    async def pre_dispatch(
        self,
        name: str,
        args: dict,
        ctx: CallContext,
    ) -> DispatchDecision:
        """Check for dangerous commands before execution.
        
        Args:
            name: Tool name being invoked
            args: Tool arguments
            ctx: Call context
            
        Returns:
            DispatchDecision.DENY if blocking mode and dangerous pattern found,
            DispatchDecision.ALLOW otherwise
            
        Raises:
            SecurityError: If mode is "block" and dangerous pattern detected
        """
        # Only check terminal/shell commands
        if name not in ("terminal", "shell", "execute_command"):
            return DispatchDecision.ALLOW
        
        # Extract command from args
        command = self._extract_command(args)
        if not command:
            return DispatchDecision.ALLOW
        
        # Check for dangerous patterns
        is_dangerous, pattern_key, description = detect_dangerous_command(command)
        
        if is_dangerous:
            message = f"Dangerous command detected: {description}"
            
            # Log to audit trail if available
            if self.trail:
                try:
                    # Add danger metadata to args for audit
                    args_with_metadata = args.copy()
                    args_with_metadata["_danger_pattern"] = pattern_key
                    args_with_metadata["_danger_type"] = description
                    
                    self.trail.log(
                        tool_name=name,
                        args_redacted=args_with_metadata,
                        decision="BLOCKED" if self.mode == "block" else "AUDIT",
                        middleware="DangerousBlockerMiddleware",
                    )
                except Exception as e:
                    logger.warning(f"Failed to log to audit trail: {e}")
            
            if self.mode == "block":
                logger.warning(f"BLOCKED: {message} (pattern: {pattern_key})")
                # Store error in context metadata for better error reporting
                ctx.metadata["blocked_reason"] = message
                ctx.metadata["pattern"] = pattern_key
                raise SecurityError(message)
            else:
                # Audit mode: log but allow
                logger.info(f"AUDIT: {message} (pattern: {pattern_key})")
        
        return DispatchDecision.ALLOW

    def _extract_command(self, args: dict) -> str:
        """Extract command string from tool arguments.
        
        Args:
            args: Tool arguments dictionary
            
        Returns:
            Command string or empty string if not found
        """
        # Try various common parameter names
        for key in ("command", "cmd", "script", "code"):
            if key in args and isinstance(args[key], str):
                return args[key]
        
        # Check for array-style command (e.g., ["rm", "-rf", "/"])
        if "command" in args and isinstance(args["command"], list):
            return " ".join(str(x) for x in args["command"])
        
        return ""
