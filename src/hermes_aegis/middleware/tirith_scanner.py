"""Tirith content scanner middleware.

Scans LLM response bodies for:
  1. Homograph / confusable URLs (punycode, Cyrillic/Greek lookalikes, mixed-script)
  2. Code injection patterns (eval, exec, subprocess, obfuscated variants)
  3. Terminal injection (ANSI escapes, raw control characters)
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.middleware.chain import CallContext, ToolMiddleware


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class TirithCategory(str, Enum):
    HOMOGRAPH_URL = "homograph_url"
    CODE_INJECTION = "code_injection"
    TERMINAL_INJECTION = "terminal_injection"


class TirithSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TirithFinding:
    category: TirithCategory
    severity: TirithSeverity
    description: str
    matched_text: str


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

# Characters that look like ASCII Latin but come from other scripts.
# Map: confusable char -> ASCII equivalent
_CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0445": "x",  # х
    "\u0443": "y",  # у
    "\u0456": "i",  # і
    "\u0455": "s",  # ѕ
    "\u04bb": "h",  # һ
    "\u0501": "d",  # ԁ
    "\u051b": "q",  # ԛ
    # Greek
    "\u03bf": "o",  # ο
    "\u03b1": "a",  # α  (close enough in many fonts)
    "\u03c1": "p",  # ρ
    "\u03b5": "e",  # ε  (in some fonts)
}

_CONFUSABLE_CHARS = set(_CONFUSABLE_MAP.keys())

# URL regex (simplified but effective)
_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)

# Code injection patterns
_CODE_INJECTION_PATTERNS: list[tuple[re.Pattern, str, TirithSeverity]] = [
    (re.compile(r"\beval\s*\(", re.IGNORECASE), "eval() call", TirithSeverity.HIGH),
    (re.compile(r"\bexec\s*\(", re.IGNORECASE), "exec() call", TirithSeverity.HIGH),
    (re.compile(r"\b__import__\s*\("), "__import__() call", TirithSeverity.CRITICAL),
    (re.compile(r"\bsubprocess\s*\.\s*(call|Popen|run|check_output|check_call)\s*\("),
     "subprocess execution", TirithSeverity.HIGH),
    (re.compile(r"\bos\s*\.\s*(system|popen)\s*\("), "os.system/popen call", TirithSeverity.HIGH),
    (re.compile(r"\bcompile\s*\(.*\bexec\b"), "compile() with exec", TirithSeverity.HIGH),
    # Obfuscated variants
    (re.compile(r"getattr\s*\(\s*__builtins__"), "getattr on builtins", TirithSeverity.CRITICAL),
    (re.compile(r"b(?:ase)?64[._]?(?:de|b64de)code\s*\(.*?\)\s*\)?\s*\)?\s*\.?\s*(?:decode)?\s*\(?\)?\s*\)?\s*$",
     re.MULTILINE), "base64-decoded execution", TirithSeverity.CRITICAL),
    (re.compile(r"""(?:eval|exec)\s*\(\s*(?:["'][^"']*["']\s*\+\s*)+["'][^"']*["']\s*\)"""),
     "string concatenation eval/exec", TirithSeverity.CRITICAL),
    (re.compile(r"""(?:eval|exec)\s*\(\s*.*b(?:ase)?64.*decode""", re.IGNORECASE | re.DOTALL),
     "eval/exec with base64 decode", TirithSeverity.CRITICAL),
]

# Terminal injection patterns
_TERMINAL_INJECTION_PATTERNS: list[tuple[re.Pattern, str, TirithSeverity]] = [
    # ANSI escape sequences (both \x1b[ and \033[ forms)
    (re.compile(r"(?:\x1b|\033)\[[\d;]*[A-Za-z]"), "ANSI escape sequence", TirithSeverity.MEDIUM),
    # Literal string representations of escapes in text
    (re.compile(r"\\x1b\[[\d;]*[A-Za-z]"), "ANSI escape (string literal)", TirithSeverity.MEDIUM),
    (re.compile(r"\\033\[[\d;]*[A-Za-z]"), "ANSI escape (octal literal)", TirithSeverity.MEDIUM),
    # OSC sequences (title setting, etc.)
    (re.compile(r"(?:\x1b|\033)\][\d;]*[^\x07\x1b]*(?:\x07|(?:\x1b|\033)\\)"),
     "OSC terminal title/command", TirithSeverity.HIGH),
    # Raw control characters (excluding common whitespace \t \n \r)
    (re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]"),
     "raw control character", TirithSeverity.MEDIUM),
]

_REDACT_PLACEHOLDER = "[TIRITH_REDACTED]"


def _get_scripts(text: str) -> set[str]:
    """Return the set of Unicode script names present in *text*."""
    scripts: set[str] = set()
    for ch in text:
        if ch.isascii():
            if ch.isalpha():
                scripts.add("LATIN")
        else:
            try:
                name = unicodedata.name(ch, "")
                # Script is typically the first word of the Unicode name
                if name:
                    for script in ("CYRILLIC", "GREEK", "ARABIC", "HEBREW",
                                   "CJK", "HANGUL", "HIRAGANA", "KATAKANA"):
                        if script in name:
                            scripts.add(script)
                            break
            except ValueError:
                pass
    return scripts


def scan_homograph_urls(text: str) -> list[TirithFinding]:
    """Detect homograph / confusable URLs in *text*."""
    findings: list[TirithFinding] = []

    for m in _URL_RE.finditer(text):
        url = m.group(0)
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            continue

        # Check 1: punycode (xn--)
        if "xn--" in domain.lower():
            findings.append(TirithFinding(
                category=TirithCategory.HOMOGRAPH_URL,
                severity=TirithSeverity.HIGH,
                description=f"Punycode domain detected: {domain}",
                matched_text=url,
            ))
            continue

        # Check 2: confusable characters
        confusables_found = [ch for ch in domain if ch in _CONFUSABLE_CHARS]
        if confusables_found:
            findings.append(TirithFinding(
                category=TirithCategory.HOMOGRAPH_URL,
                severity=TirithSeverity.CRITICAL,
                description=(
                    f"Confusable characters in domain: "
                    f"{', '.join(repr(c) for c in confusables_found)}"
                ),
                matched_text=url,
            ))
            continue

        # Check 3: mixed-script domain
        scripts = _get_scripts(domain)
        if len(scripts) > 1:
            findings.append(TirithFinding(
                category=TirithCategory.HOMOGRAPH_URL,
                severity=TirithSeverity.HIGH,
                description=f"Mixed-script domain ({', '.join(sorted(scripts))}): {domain}",
                matched_text=url,
            ))

    return findings


def scan_code_injection(text: str) -> list[TirithFinding]:
    """Detect code injection patterns in *text*."""
    findings: list[TirithFinding] = []
    for pattern, desc, severity in _CODE_INJECTION_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(TirithFinding(
                category=TirithCategory.CODE_INJECTION,
                severity=severity,
                description=desc,
                matched_text=m.group(0),
            ))
    return findings


def scan_terminal_injection(text: str) -> list[TirithFinding]:
    """Detect terminal injection patterns in *text*."""
    findings: list[TirithFinding] = []
    for pattern, desc, severity in _TERMINAL_INJECTION_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(TirithFinding(
                category=TirithCategory.TERMINAL_INJECTION,
                severity=severity,
                description=desc,
                matched_text=m.group(0),
            ))
    return findings


def scan_all(text: str) -> list[TirithFinding]:
    """Run all Tirith scanners on *text*."""
    findings: list[TirithFinding] = []
    findings.extend(scan_homograph_urls(text))
    findings.extend(scan_code_injection(text))
    findings.extend(scan_terminal_injection(text))
    return findings


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class TirithScannerMiddleware(ToolMiddleware):
    """Scans tool output for homograph URLs, code injection, and terminal injection.

    Args:
        trail: Optional audit trail for logging findings.
        mode: ``"detect"`` logs findings only; ``"block"`` also redacts matched text.
    """

    def __init__(
        self,
        trail: AuditTrail | None = None,
        mode: str = "detect",
    ) -> None:
        if mode not in ("detect", "block"):
            raise ValueError(f"Invalid mode {mode!r}; expected 'detect' or 'block'")
        self._trail = trail
        self._mode = mode

    # -- helpers --------------------------------------------------------

    def _extract_text(self, result: Any) -> str | None:
        """Pull a scannable string out of *result*."""
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            # Common shapes: {"output": ...}, {"content": ...}, {"text": ...}
            for key in ("output", "content", "text", "result"):
                val = result.get(key)
                if isinstance(val, str):
                    return val
        return None

    def _redact(self, text: str, findings: list[TirithFinding]) -> str:
        """Replace every matched span with a redaction placeholder."""
        redacted = text
        # Replace longest matches first to avoid index drift issues
        for finding in sorted(findings, key=lambda f: len(f.matched_text), reverse=True):
            redacted = redacted.replace(finding.matched_text, _REDACT_PLACEHOLDER)
        return redacted

    def _apply_redaction(self, result: Any, original_text: str, redacted_text: str) -> Any:
        """Return a copy of *result* with the original text swapped for redacted."""
        if isinstance(result, str):
            return redacted_text
        if isinstance(result, dict):
            result = result.copy()
            for key in ("output", "content", "text", "result"):
                if key in result and isinstance(result[key], str) and result[key] == original_text:
                    result[key] = redacted_text
                    break
            return result
        return result

    def _log_findings(self, name: str, findings: list[TirithFinding]) -> None:
        if not self._trail:
            return
        for finding in findings:
            self._trail.log(
                tool_name=name,
                args_redacted={
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "description": finding.description,
                    "matched_text": finding.matched_text[:120],
                },
                decision="TIRITH_DETECT",
                middleware=self.__class__.__name__,
            )

    # -- middleware interface -------------------------------------------

    async def post_dispatch(
        self,
        name: str,
        args: dict,
        result: Any,
        ctx: CallContext,
    ) -> Any:
        text = self._extract_text(result)
        if text is None:
            return result

        findings = scan_all(text)
        if not findings:
            return result

        self._log_findings(name, findings)

        if self._mode == "block":
            redacted = self._redact(text, findings)
            return self._apply_redaction(result, text, redacted)

        # detect mode: log only, return unmodified result
        return result
