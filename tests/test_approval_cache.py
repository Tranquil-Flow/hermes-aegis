"""Tests for the persistent approval cache."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from hermes_aegis.approval.cache import ApprovalCache, CachedApproval


# ---------------------------------------------------------------------------
# CachedApproval dataclass tests
# ---------------------------------------------------------------------------

class TestCachedApproval:
    def test_not_expired_when_no_expiry(self):
        entry = CachedApproval(pattern="rm *", decision="deny", expires_at=0)
        assert not entry.is_expired

    def test_not_expired_when_future(self):
        entry = CachedApproval(pattern="rm *", decision="deny", expires_at=time.time() + 3600)
        assert not entry.is_expired

    def test_expired_when_past(self):
        entry = CachedApproval(pattern="rm *", decision="deny", expires_at=time.time() - 1)
        assert entry.is_expired

    def test_to_dict(self):
        entry = CachedApproval(
            pattern="curl *",
            decision="allow",
            reason="safe",
            created_at=1000.0,
            expires_at=2000.0,
            created_by="admin",
        )
        d = entry.to_dict()
        assert d == {
            "pattern": "curl *",
            "decision": "allow",
            "reason": "safe",
            "created_at": 1000.0,
            "expires_at": 2000.0,
            "created_by": "admin",
        }

    def test_from_dict(self):
        d = {"pattern": "git push", "decision": "allow", "reason": "ok", "created_at": 1.0, "expires_at": 0, "created_by": "user"}
        entry = CachedApproval.from_dict(d)
        assert entry.pattern == "git push"
        assert entry.decision == "allow"
        assert entry.reason == "ok"

    def test_from_dict_ignores_extra_keys(self):
        d = {"pattern": "ls", "decision": "allow", "extra_field": "ignored"}
        entry = CachedApproval.from_dict(d)
        assert entry.pattern == "ls"
        assert not hasattr(entry, "extra_field")

    def test_roundtrip(self):
        original = CachedApproval(pattern="npm *", decision="deny", reason="risky", created_at=5.0, expires_at=10.0, created_by="bot")
        restored = CachedApproval.from_dict(original.to_dict())
        assert restored == original


# ---------------------------------------------------------------------------
# ApprovalCache tests
# ---------------------------------------------------------------------------

@pytest.fixture
def cache_path(tmp_path: Path) -> Path:
    return tmp_path / "approval-cache.json"


@pytest.fixture
def cache(cache_path: Path) -> ApprovalCache:
    return ApprovalCache(cache_path)


class TestApprovalCacheAddAndCheck:
    def test_add_and_check_exact(self, cache: ApprovalCache):
        cache.add("git push", "allow")
        result = cache.check("git push")
        assert result is not None
        assert result.decision == "allow"

    def test_check_miss(self, cache: ApprovalCache):
        assert cache.check("unknown command") is None

    def test_add_replaces_existing(self, cache: ApprovalCache):
        cache.add("rm -rf /", "deny")
        cache.add("rm -rf /", "allow", reason="changed mind")
        entries = cache.list_all()
        assert len(entries) == 1
        assert entries[0].decision == "allow"
        assert entries[0].reason == "changed mind"


class TestApprovalCacheGlobMatching:
    def test_glob_star(self, cache: ApprovalCache):
        cache.add("curl *", "allow")
        assert cache.check("curl https://example.com") is not None

    def test_glob_question_mark(self, cache: ApprovalCache):
        cache.add("ls -?", "allow")
        assert cache.check("ls -l") is not None
        assert cache.check("ls -la") is None  # too long

    def test_glob_no_match(self, cache: ApprovalCache):
        cache.add("docker *", "deny")
        assert cache.check("podman run") is None


class TestApprovalCacheSubstringMatching:
    def test_substring_match(self, cache: ApprovalCache):
        cache.add("sudo", "deny")
        assert cache.check("sudo rm -rf /") is not None

    def test_substring_no_match(self, cache: ApprovalCache):
        cache.add("sudo", "deny")
        assert cache.check("echo hello") is None


class TestApprovalCacheExactMatchPriority:
    def test_exact_match_before_glob(self, cache: ApprovalCache):
        """Exact match entry should be returned even if a glob also matches."""
        cache.add("git push origin main", "deny", reason="exact")
        cache.add("git push *", "allow", reason="glob")
        result = cache.check("git push origin main")
        assert result is not None
        # The first matching entry wins — exact match is first in the iteration
        assert result.reason == "exact"


class TestApprovalCacheRemove:
    def test_remove_existing(self, cache: ApprovalCache):
        cache.add("rm *", "deny")
        assert cache.remove("rm *") is True
        assert cache.check("rm foo") is None

    def test_remove_nonexistent(self, cache: ApprovalCache):
        assert cache.remove("nonexistent") is False


class TestApprovalCacheListAndClear:
    def test_list_all(self, cache: ApprovalCache):
        cache.add("a", "allow")
        cache.add("b", "deny")
        entries = cache.list_all()
        assert len(entries) == 2
        patterns = {e.pattern for e in entries}
        assert patterns == {"a", "b"}

    def test_clear(self, cache: ApprovalCache):
        cache.add("a", "allow")
        cache.add("b", "deny")
        count = cache.clear()
        assert count == 2
        assert cache.list_all() == []


class TestApprovalCacheTTL:
    def test_ttl_not_expired(self, cache: ApprovalCache):
        cache.add("pip install *", "allow", ttl_seconds=3600)
        result = cache.check("pip install requests")
        assert result is not None
        assert result.expires_at > 0

    def test_ttl_expired(self, cache: ApprovalCache, cache_path: Path):
        cache.add("pip install *", "allow", ttl_seconds=1)
        # Manually set expires_at to the past
        data = json.loads(cache_path.read_text())
        data[0]["expires_at"] = time.time() - 10
        cache_path.write_text(json.dumps(data))
        # Reload
        cache2 = ApprovalCache(cache_path)
        assert cache2.check("pip install requests") is None

    def test_cleanup_removes_expired(self, cache: ApprovalCache, cache_path: Path):
        cache.add("a", "allow", ttl_seconds=1)
        cache.add("b", "deny")  # no expiry
        # Expire entry "a"
        data = json.loads(cache_path.read_text())
        for item in data:
            if item["pattern"] == "a":
                item["expires_at"] = time.time() - 10
        cache_path.write_text(json.dumps(data))
        # Reload and list — expired entry should be cleaned up
        cache2 = ApprovalCache(cache_path)
        entries = cache2.list_all()
        assert len(entries) == 1
        assert entries[0].pattern == "b"


class TestApprovalCachePersistence:
    def test_persists_across_instances(self, cache_path: Path):
        cache1 = ApprovalCache(cache_path)
        cache1.add("docker run *", "deny", reason="dangerous")

        cache2 = ApprovalCache(cache_path)
        result = cache2.check("docker run ubuntu")
        assert result is not None
        assert result.decision == "deny"
        assert result.reason == "dangerous"

    def test_file_created_on_save(self, cache_path: Path):
        assert not cache_path.exists()
        cache = ApprovalCache(cache_path)
        cache.add("test", "allow")
        assert cache_path.exists()


class TestApprovalCacheCorruptedFile:
    def test_corrupted_json(self, cache_path: Path):
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("not valid json {{{")
        cache = ApprovalCache(cache_path)
        assert cache.list_all() == []
        # Should still be usable
        cache.add("test", "allow")
        assert len(cache.list_all()) == 1

    def test_invalid_structure(self, cache_path: Path):
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"not": "a list"}))
        cache = ApprovalCache(cache_path)
        assert cache.list_all() == []

    def test_empty_file(self, cache_path: Path):
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("")
        cache = ApprovalCache(cache_path)
        assert cache.list_all() == []
