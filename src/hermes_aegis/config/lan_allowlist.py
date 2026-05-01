"""LAN allowlist for sandbox network-outbound rules.

Mirrors :class:`hermes_aegis.config.allowlist.DomainAllowlist` but operates
on `host:port` pairs (IPv4 host + numeric port) and feeds the macOS
sandbox profile rather than the HTTP proxy.

Entries become `(allow network-outbound (remote tcp "*:port"))` lines in
`~/.hermes-aegis/sandbox.sb` so gateway sessions can reach LAN hosts
(e.g. a remote Ollama or training worker on the local network).

**Important constraint of the macOS sandbox-exec DSL:** `(remote tcp ...)`
only accepts `*` or `localhost` as the host — literal IPs are rejected
at profile-load time with `host must be * or localhost in network
address`. So the sandbox cannot pin by destination IP; it can only filter
by *port*. We render `*:port` rules, deduped by port. The IPv4 host the
user supplies is preserved in the JSON file as **intent / documentation**
(so `lan list` is meaningful), but is not enforced at the kernel level.

An empty / missing allowlist means **no LAN access** — the sandbox falls
back to localhost-only. This is the inverse of DomainAllowlist's
allow-all-when-empty behaviour: domain-allowlist defaults to permissive
because the proxy can still log/inspect, but the sandbox has no such
visibility, so we default to deny.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

# host:port — IPv4 dotted quad + numeric port (1-65535).
# Wildcard ports are intentionally NOT supported: with sandbox-exec only
# allowing `*` or `localhost` as the host, a wildcard port would compile
# to `*:*` (allow all outbound TCP), which silently undoes the sandbox.
_ENTRY_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$"
)


def _validate_entry(entry: str) -> str:
    """Return the canonical form of `entry` or raise ValueError.

    Accepts `IPv4:port`. Each octet must be 0-255. Port must be 1-65535.
    """
    entry = entry.strip()
    m = _ENTRY_RE.match(entry)
    if not m:
        raise ValueError(
            f"invalid LAN entry {entry!r}: expected 'IPv4:port' "
            "(e.g. 192.168.1.112:22). Wildcard ports are not supported."
        )
    host, port = m.group(1), m.group(2)
    for octet in host.split("."):
        if not 0 <= int(octet) <= 255:
            raise ValueError(f"invalid IPv4 octet in {entry!r}")
    port_n = int(port)
    if not 1 <= port_n <= 65535:
        raise ValueError(f"invalid port in {entry!r}: must be 1-65535")
    return f"{host}:{port}"


class LanAllowlist:
    """Manage LAN host:port allowlist for sandbox network-outbound rules."""

    def __init__(self, config_path: Path | None):
        """Initialise allowlist manager.

        Args:
            config_path: Path to lan-allowlist.json. None creates an
                in-memory empty allowlist (no LAN access).
        """
        self.config_path = config_path
        self._entries: List[str] = []
        self._mtime: float = 0.0
        self.load()

    def load(self) -> None:
        """Load entries from JSON file. Missing file = empty list."""
        if self.config_path is None or not self.config_path.exists():
            self._entries = []
            return

        try:
            with open(self.config_path, "r") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    raise ValueError("LAN allowlist must be a JSON array")
                # Drop invalid entries rather than raising — keep the
                # subsystem permissive about disk state but loud about it.
                clean: List[str] = []
                for raw in data:
                    try:
                        clean.append(_validate_entry(str(raw)))
                    except ValueError as e:
                        logger.warning(
                            "Skipping invalid LAN allowlist entry: %s", e
                        )
                self._entries = clean
            try:
                self._mtime = self.config_path.stat().st_mtime
            except OSError:
                pass
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(
                "Corrupted LAN allowlist at %s (%s) — falling back to empty",
                self.config_path, e,
            )
            self._entries = []

    def save(self) -> None:
        """Save entries to JSON file."""
        if self.config_path is None:
            return
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump(sorted(self._entries), f, indent=2)

    def add(self, entry: str) -> str:
        """Add a host:port entry. Returns canonical form. Raises ValueError on bad input."""
        canon = _validate_entry(entry)
        if canon not in self._entries:
            self._entries.append(canon)
            self.save()
        return canon

    def remove(self, entry: str) -> bool:
        """Remove a host:port entry. Returns True if removed."""
        try:
            canon = _validate_entry(entry)
        except ValueError:
            canon = entry.strip()
        if canon in self._entries:
            self._entries.remove(canon)
            self.save()
            return True
        return False

    def list(self) -> List[str]:
        """Return sorted copy of allowlist entries."""
        return sorted(self._entries.copy())

    def ports(self) -> List[int]:
        """Return the unique sorted list of ports across all entries."""
        seen: set[int] = set()
        for e in self._entries:
            seen.add(int(e.split(":", 1)[1]))
        return sorted(seen)

    def render_sandbox_rules(self) -> str:
        """Render entries as sandbox-exec `network-outbound` rules.

        Emits one `(allow network-outbound (remote tcp "*:PORT"))` rule
        per **unique port** in the allowlist. The host portion is dropped
        because macOS sandbox-exec rejects literal IPs in `(remote tcp …)`
        — see module docstring. Multiple entries on the same port collapse
        to a single rule. Returns "" when the allowlist is empty.

        A leading comment line annotates each rule with the IP(s) the
        user actually intended, so the rendered profile remains readable.
        """
        if not self._entries:
            return ""

        # Group entries by port for the annotation comment
        by_port: dict[int, list[str]] = {}
        for e in sorted(self._entries):
            host, port_s = e.split(":", 1)
            by_port.setdefault(int(port_s), []).append(host)

        lines: List[str] = []
        for port in sorted(by_port):
            hosts = ", ".join(by_port[port])
            lines.append(f";; intent: {hosts}")
            lines.append(f'(allow network-outbound (remote tcp "*:{port}"))')
        return "\n".join(lines)
