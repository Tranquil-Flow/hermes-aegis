"""FastAPI backend for the Aegis dashboard tab."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from fastapi import APIRouter, Query
except ImportError:  # pragma: no cover - exercised by plugin-only test environments
    class APIRouter:  # minimal no-op shim for direct function tests without FastAPI installed
        def get(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

    def Query(default, **kwargs):
        return default

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

router = APIRouter()


@router.get("/audit")
async def get_audit(page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200)):
    from state import read_audit_entries

    start = (page - 1) * limit
    entries = list(reversed(read_audit_entries()))
    return {"entries": entries[start : start + limit], "total": len(entries), "page": page}


@router.get("/violations")
async def get_violations():
    from state import read_audit_entries

    blocked = [entry for entry in read_audit_entries() if entry.get("decision") == "BLOCKED"]
    return {"violations": list(reversed(blocked))}


@router.get("/stats")
async def get_stats():
    from state import read_audit_entries, read_session_stats

    entries = read_audit_entries()
    return {
        "total_tool_calls": len(entries),
        "total_blocks": sum(1 for entry in entries if entry.get("decision") == "BLOCKED"),
        "sessions": read_session_stats(),
    }
