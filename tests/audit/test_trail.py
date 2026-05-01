import pytest
from hermes_aegis.audit.trail import AuditTrail

class TestAuditTrail:
    def test_initial_state(self):
        trail = AuditTrail()
        assert trail.chain == []

    def test_add_single_entry(self):
        trail = AuditTrail()
        trail.add("test entry")
        assert len(trail.chain) == 1
        assert trail.chain[0].data == "test entry"

    def test_chain_integrity(self):
        trail = AuditTrail()
        trail.add("entry1")
        trail.add("entry2")
        assert trail.chain[1].prev_hash == trail.chain[0].hash

    def test_verification_failure_on_modification(self):
        trail = AuditTrail()
        trail.add("original")
        trail.add("secondary")
        trail.chain[0].data = "modified"
        assert not trail.verify()


class TestFileBackedHashCache:
    """log() caches the tail hash so writes stay O(1) and the chain stays
    intact across successive writes (third-reviewer round-5 P2)."""

    def test_log_does_not_reread_file_on_each_write(self, tmp_path, monkeypatch):
        """After the first write seeds the cache, subsequent writes must not
        re-scan the file."""
        path = tmp_path / "audit.jsonl"
        trail = AuditTrail(path)

        trail.log("t1", {"a": 1}, "ALLOW", "bench")

        original_read = type(path).read_text
        calls = {"n": 0}

        def _tracked_read(self, *args, **kwargs):
            calls["n"] += 1
            return original_read(self, *args, **kwargs)

        monkeypatch.setattr(type(path), "read_text", _tracked_read)

        for i in range(50):
            trail.log("t", {"i": i}, "ALLOW", "bench")

        assert calls["n"] == 0, "log() re-read the file on a hot cache"

    def test_chain_stays_intact_with_cache(self, tmp_path):
        """50 writes through the cache produce a chain that verify_chain accepts."""
        path = tmp_path / "audit.jsonl"
        trail = AuditTrail(path)
        for i in range(50):
            trail.log("t", {"i": i}, "ALLOW", "bench")
        assert trail.verify_chain() is True

    def test_independent_reader_sees_committed_tail(self, tmp_path):
        """An independent reader (e.g. the reactive watcher) sees the same
        committed tail that the cache stores."""
        path = tmp_path / "audit.jsonl"
        writer = AuditTrail(path)
        for i in range(5):
            writer.log("t", {"i": i}, "ALLOW", "bench")

        reader = AuditTrail(path)  # fresh instance, cold cache
        assert reader.verify_chain() is True
        assert reader._get_last_hash() == writer._last_hash_cache

    def test_two_writers_on_same_file_keep_chain_intact(self, tmp_path):
        """Two AuditTrail instances writing to the same audit.jsonl must
        not corrupt the hash chain via stale per-instance caches.

        Reproduces the third-reviewer round-6 P1: hermes-aegis production
        creates one AuditTrail in the proxy (proxy/entry.py) and another
        in the reactive/circuit-breaker path (cli.py); both append to
        ``~/.hermes-aegis/audit.jsonl``. With a naive single-writer cache,
        the second proxy.log() call after a reactive.log() interleave
        wrote prev_hash from its stale cache and broke verify_chain().
        """
        path = tmp_path / "audit.jsonl"
        proxy_writer = AuditTrail(path)
        reactive_writer = AuditTrail(path)

        proxy_writer.log("proxy.req", {"i": 1}, "ALLOW", "ProxyContentScanner")
        reactive_writer.log("reactive.note", {"i": 2}, "AUDIT", "ReactiveAgentManager")
        proxy_writer.log("proxy.req", {"i": 3}, "ALLOW", "ProxyContentScanner")

        # Hash chain must be intact even though two writers interleaved.
        assert proxy_writer.verify_chain() is True
        assert reactive_writer.verify_chain() is True

    def test_external_append_invalidates_cache(self, tmp_path):
        """When another writer appends between calls, the next write picks
        up the new tail rather than reusing the stale cached hash."""
        path = tmp_path / "audit.jsonl"
        writer_a = AuditTrail(path)
        writer_b = AuditTrail(path)

        writer_a.log("a1", {}, "ALLOW", "src")
        writer_b.log("b1", {}, "ALLOW", "src")

        # writer_a's cache is now stale (it remembers a1's tail, but b1
        # is on disk). The next a-side write must chain to b1, not a1.
        writer_a.log("a2", {}, "ALLOW", "src")

        entries = AuditTrail(path).read_all()
        assert [e.tool_name for e in entries] == ["a1", "b1", "a2"]
        # a2.prev_hash must equal b1's hash (the actual tail when a wrote).
        assert entries[2].prev_hash == entries[1].entry_hash