"""Persistent state helpers for the Aegis plugin and dashboard."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

_audit_lock = threading.Lock()
_stats_lock = threading.Lock()
_audit_entries: list[dict[str, Any]] = []
_session_stats: dict[str, dict[str, Any]] = {}


def aegis_state_dir() -> Path:
    try:
        from hermes_constants import get_hermes_home

        return get_hermes_home() / "aegis"
    except Exception:
        return Path.home() / ".hermes" / "aegis"


def audit_log_path() -> Path:
    return aegis_state_dir() / "audit.jsonl"


def stats_path() -> Path:
    return aegis_state_dir() / "stats.json"


def record_audit_entry(entry: dict[str, Any]) -> None:
    """Append an audit entry in memory and to the dashboard-readable JSONL log."""
    payload = dict(entry)
    payload.setdefault("timestamp", time.time())
    with _audit_lock:
        _audit_entries.append(payload)
        path = audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True, default=str))
            fh.write("\n")


def record_api_request(
    *,
    session_id: str = "",
    task_id: str = "",
    model: str = "",
    provider: str = "",
    base_url: str = "",
) -> None:
    key = session_id or task_id or "default"
    with _stats_lock:
        stats = _session_stats.setdefault(
            key,
            {
                "call_count": 0,
                "models": set(),
                "providers": set(),
                "base_urls": set(),
                "started_at": time.time(),
                "last_seen_at": 0.0,
            },
        )
        stats["call_count"] += 1
        stats["last_seen_at"] = time.time()
        if model:
            stats["models"].add(model)
        if provider:
            stats["providers"].add(provider)
        if base_url:
            stats["base_urls"].add(base_url)
        _write_stats_locked()


def read_audit_entries(limit: int | None = None) -> list[dict[str, Any]]:
    """Read persisted audit entries, falling back to in-memory state."""
    path = audit_log_path()
    entries: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                entries.append(item)
    else:
        entries = list(_audit_entries)
    if limit is not None:
        return entries[-limit:]
    return entries


def read_session_stats() -> dict[str, dict[str, Any]]:
    path = stats_path()
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = {}
        if isinstance(loaded, dict):
            return {str(key): value for key, value in loaded.items() if isinstance(value, dict)}

    with _stats_lock:
        return {
            key: _serialize_stats(value)
            for key, value in _session_stats.items()
        }


def reset_state_for_tests() -> None:
    with _audit_lock:
        _audit_entries.clear()
    with _stats_lock:
        _session_stats.clear()
    for path in (audit_log_path(), stats_path()):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _write_stats_locked() -> None:
    path = stats_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {key: _serialize_stats(value) for key, value in _session_stats.items()},
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )


def _serialize_stats(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "call_count": value.get("call_count", 0),
        "models": sorted(value.get("models", [])),
        "providers": sorted(value.get("providers", [])),
        "base_urls": sorted(value.get("base_urls", [])),
        "started_at": value.get("started_at", 0.0),
        "last_seen_at": value.get("last_seen_at", 0.0),
    }
