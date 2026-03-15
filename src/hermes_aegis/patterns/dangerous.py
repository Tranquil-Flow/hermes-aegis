"""Dangerous command patterns for audit logging.

These patterns are copied from Hermes Agent's tools/approval.py to enable
audit trail logging of dangerous commands without importing the full tools module.

Note: We LOG these for awareness, we don't BLOCK them (Hermes terminal tool does that).
"""
import re
from typing import Optional, Tuple


# Dangerous command patterns from Hermes Agent tools/approval.py
DANGEROUS_PATTERNS = [
    (r'\brm\s+(-[^\s]*\s+)*/', "delete in root path"),
    (r'\brm\s+-[^\s]*r', "recursive delete"),
    (r'\brm\s+--recursive\b', "recursive delete (long flag)"),
    (r'\bchmod\s+(-[^\s]*\s+)*777\b', "world-writable permissions"),
    (r'\bchmod\s+--recursive\b.*777', "recursive world-writable (long flag)"),
    (r'\bchown\s+(-[^\s]*)?R\s+root', "recursive chown to root"),
    (r'\bchown\s+--recursive\b.*root', "recursive chown to root (long flag)"),
    (r'\bmkfs\b', "format filesystem"),
    (r'\bdd\s+.*if=', "disk copy"),
    (r'>\s*/dev/sd', "write to block device"),
    (r'\bDROP\s+(TABLE|DATABASE)\b', "SQL DROP"),
    (r'\bDELETE\s+FROM\b(?!.*\bWHERE\b)', "SQL DELETE without WHERE"),
    (r'\bTRUNCATE\s+(TABLE)?\s*\w', "SQL TRUNCATE"),
    (r'>\s*/etc/', "overwrite system config"),
    (r'\bsystemctl\s+(stop|disable|mask)\b', "stop/disable system service"),
    (r'\bkill\s+-9\s+-1\b', "kill all processes"),
    (r'\bpkill\s+-9\b', "force kill processes"),
    (r':()\s*{\s*:\s*\|\s*:&\s*}\s*;:', "fork bomb"),
    (r'\b(bash|sh|zsh)\s+-c\s+', "shell command via -c flag"),
    (r'\b(python[23]?|perl|ruby|node)\s+-[ec]\s+', "script execution via -e/-c flag"),
    (r'\b(curl|wget)\b.*\|\s*(ba)?sh\b', "pipe remote content to shell"),
    (r'\b(bash|sh|zsh|ksh)\s+<\s*<?\s*\(\s*(curl|wget)\b', "execute remote script via process substitution"),
    (r'\btee\b.*(/etc/|/dev/sd|\.ssh/|\.hermes/\.env)', "overwrite system file via tee"),
    (r'\bxargs\s+.*\brm\b', "xargs with rm"),
    (r'\bfind\b.*-exec\s+(/\S*/)?rm\b', "find -exec rm"),
    (r'\bfind\b.*-delete\b', "find -delete"),
    # SSH / non-HTTP exfiltration patterns
    # Match ssh/scp/sftp as command invocations (start of line, after pipe/semicolon, or after &&/||)
    # Excludes references in strings/paths like .ssh/ or "use ssh keys"
    (r'(?:^|[;&|]\s*)\bssh\s+\S', "SSH connection"),
    (r'(?:^|[;&|]\s*)\bscp\s+\S', "SCP file transfer"),
    (r'(?:^|[;&|]\s*)\bsftp\s+\S', "SFTP file transfer"),
    (r'\brsync\b.*-e\s+ssh', "rsync over SSH"),
    (r'\b(nc|netcat|ncat)\b', "netcat connection"),
    (r'\bsocat\b', "socat connection"),
    (r'\bgit\s+(push|fetch|pull|clone)\s+git@', "git SSH remote operation"),
    (r'\bgit\s+remote\s+add\s+\S+\s+git@', "add git SSH remote"),
]


def detect_dangerous_command(command: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Check if a command matches any dangerous patterns.
    
    Args:
        command: The shell command to check
        
    Returns:
        Tuple of (is_dangerous, pattern_key, description)
        - is_dangerous: True if dangerous pattern matched
        - pattern_key: Short identifier for the pattern (for deduplication)
        - description: Human-readable description of why it's dangerous
        
    Example:
        >>> detect_dangerous_command("rm -rf /")
        (True, "rm", "delete in root path")
        >>> detect_dangerous_command("ls -la")
        (False, None, None)
    """
    command_lower = command.lower()
    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, command_lower, re.IGNORECASE | re.DOTALL):
            # Extract a clean pattern key for deduplication
            pattern_key = pattern.split(r'\b')[1] if r'\b' in pattern else pattern[:20]
            return (True, pattern_key, description)
    return (False, None, None)
