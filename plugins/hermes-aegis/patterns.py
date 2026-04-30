"""Dangerous command and secret pattern adapters."""

from __future__ import annotations

from dataclasses import dataclass

try:
    from ._deps import ensure_local_dependency_paths
except ImportError:
    from _deps import ensure_local_dependency_paths

ensure_local_dependency_paths()


@dataclass(frozen=True)
class SecretMatch:
    name: str
    start: int
    end: int


def check_command(command: str) -> str | None:
    """Return a human-readable reason when a shell command is dangerous."""
    try:
        from hermes_aegis.patterns.dangerous import detect_dangerous_command

        is_dangerous, _pattern_key, description = detect_dangerous_command(command)
        return description if is_dangerous else None
    except Exception:
        from aegis_core.middleware.dangerous_cmd import detect_dangerous_command

        is_dangerous, _pattern_key, description = detect_dangerous_command(command)
        return description if is_dangerous else None


def scan_secrets(text: str) -> list[SecretMatch]:
    """Return secret spans detected by the canonical scanner."""
    extra_patterns = []
    try:
        from hermes_aegis.patterns.secrets import (
            AWS_ACCESS_KEY,
            GITHUB_TOKEN,
            GOOGLE_API_KEY,
            scan_for_secrets,
        )

        extra_patterns = [
            ("aws_access_key", AWS_ACCESS_KEY),
            ("github_token", GITHUB_TOKEN),
            ("google_api_key", GOOGLE_API_KEY),
        ]
    except Exception:
        from aegis_core.middleware.secret_scanner import scan_for_secrets

    matches: list[SecretMatch] = []
    for match in scan_for_secrets(text):
        name = getattr(match, "pattern_name", "secret")
        matches.append(SecretMatch(name=name, start=match.start, end=match.end))
    for name, pattern in extra_patterns:
        for match in pattern.finditer(text):
            matches.append(SecretMatch(name=name, start=match.start(), end=match.end()))
    return _dedupe_matches(matches)


def _dedupe_matches(matches: list[SecretMatch]) -> list[SecretMatch]:
    seen: set[tuple[int, int, str]] = set()
    deduped: list[SecretMatch] = []
    for match in sorted(matches, key=lambda item: (item.start, item.end, item.name)):
        key = (match.start, match.end, match.name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return deduped
