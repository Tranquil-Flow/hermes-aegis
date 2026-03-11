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