"""Persistent approval cache — stores approval decisions across sessions.

Decisions are stored encrypted in the aegis vault alongside API keys,
keyed with the prefix 'approval_cache:'.
"""
from __future__ import annotations

import json
import time
import logging
from dataclasses import dataclass, asdict
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class CachedApproval:
    pattern: str           # command pattern or domain glob
    decision: str          # "allow" or "deny"
    reason: str = ""       # why this was cached
    created_at: float = 0.0
    expires_at: float = 0.0  # 0 = never expires
    created_by: str = ""   # who created this entry
    
    @property
    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> CachedApproval:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class ApprovalCache:
    """Persistent approval decision cache.
    
    Uses a JSON file for storage (simpler than vault for structured data).
    Located at ~/.hermes-aegis/approval-cache.json
    """
    
    def __init__(self, cache_path: Path | None = None):
        if cache_path is None:
            cache_path = Path.home() / ".hermes-aegis" / "approval-cache.json"
        self._path = cache_path
        self._entries: list[CachedApproval] = []
        self._load()
    
    def _load(self) -> None:
        if not self._path.exists():
            self._entries = []
            return
        try:
            data = json.loads(self._path.read_text())
            self._entries = [CachedApproval.from_dict(e) for e in data]
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
            logger.warning("Corrupted approval cache at %s — starting fresh", self._path)
            self._entries = []
    
    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(
            [e.to_dict() for e in self._entries],
            indent=2,
        ))
    
    def add(
        self,
        pattern: str,
        decision: str,
        reason: str = "",
        ttl_seconds: float = 0,
        created_by: str = "user",
    ) -> CachedApproval:
        # Remove existing entry for this pattern
        self._entries = [e for e in self._entries if e.pattern != pattern]
        
        entry = CachedApproval(
            pattern=pattern,
            decision=decision,
            reason=reason,
            created_at=time.time(),
            expires_at=time.time() + ttl_seconds if ttl_seconds > 0 else 0,
            created_by=created_by,
        )
        self._entries.append(entry)
        self._save()
        return entry
    
    def check(self, command: str) -> CachedApproval | None:
        """Check if command matches any cached approval.
        
        Uses simple substring matching and fnmatch for glob patterns.
        Returns the first matching non-expired entry, or None.
        """
        import fnmatch
        
        self._cleanup_expired()
        
        for entry in self._entries:
            if entry.is_expired:
                continue
            # Try exact match first
            if entry.pattern == command:
                return entry
            # Try glob/fnmatch
            if fnmatch.fnmatch(command, entry.pattern):
                return entry
            # Try substring match for simple patterns
            if '*' not in entry.pattern and '?' not in entry.pattern:
                if entry.pattern in command:
                    return entry
        return None
    
    def remove(self, pattern: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.pattern != pattern]
        if len(self._entries) < before:
            self._save()
            return True
        return False
    
    def list_all(self) -> list[CachedApproval]:
        self._cleanup_expired()
        return list(self._entries)
    
    def clear(self) -> int:
        count = len(self._entries)
        self._entries = []
        self._save()
        return count
    
    def _cleanup_expired(self) -> None:
        before = len(self._entries)
        self._entries = [e for e in self._entries if not e.is_expired]
        if len(self._entries) < before:
            self._save()
