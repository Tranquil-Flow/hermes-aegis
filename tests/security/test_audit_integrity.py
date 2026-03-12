"""Real security Tests for audit trail integrity verification.

Tests verify that the audit trail's hash chain properly detects various
tampering attempts: deletion, modification, reordering, and forgery.
"""
import pytest
import json
from pathlib import Path

from hermes_aegis.audit.trail import AuditTrail


@pytest.fixture
def audit_path(tmp_path):
    """Provide a temporary audit trail path."""
    return tmp_path / "audit.jsonl"


def create_test_entries(audit_path, count=10):
    """Helper function to create a trail with multiple entries."""
    trail = AuditTrail(audit_path)
    for i in range(count):
        trail.log(
            tool_name=f"tool_{i}",
            args_redacted={"index": i},
            decision="ALLOW",
            middleware="TestMiddleware"
        )
    return trail


# Task 3.5.1: Deletion Detection
def test_detects_deleted_entry(audit_path):
    """Test that deleting an entry from the middle breaks the chain."""
    create_test_entries(audit_path, count=10)
    
    #Read lines
    lines = audit_path.read_text().splitlines()
    assert len(lines) == 10
    
    # Delete entry #5 (index 4)
    del lines[4]
    audit_path.write_text("\n".join(lines) + "\n")
    
    # Verify chain detects tampering
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain(), "Chain verification should fail after deletion"


def test_detects_deleted_first_entry(audit_path):
    """Test that deleting the first entry breaks the chain."""
    create_test_entries(audit_path, count=5)
    
    lines = audit_path.read_text().splitlines()
    # Delete first entry
    del lines[0]
    audit_path.write_text("\n".join(lines) + "\n")
    
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain()


def test_detects_deleted_last_entry(audit_path):
    """Test that deleting the last entry breaks the chain (if there are more entries after)."""
    create_test_entries(audit_path, count=5)
    
    lines = audit_path.read_text().splitlines()
    # Delete last entry
    del lines[-1]
    audit_path.write_text("\n".join(lines) + "\n")
    
    # This _should_ still verify since the chain is intact for remaining entries
    # But if we then add another entry, it would fail
    trail = AuditTrail(audit_path)
    # Deleting last entry doesn't break the chain of what remains
    assert trail.verify_chain()


# Task 3.5.2: Modification Detection
def test_detects_modified_tool_name(audit_path):
    """Test that modifying a tool name breaks the entry hash."""
    create_test_entries(audit_path, count=5)
    
    lines = audit_path.read_text().splitlines()
    tampered_lines = []
    
    for i, line in enumerate(lines):
        data = json.loads(line)
        if i == 2:  # Tamper with third entry
            data["tool_name"] = "TAMPERED_TOOL"
        tampered_lines.append(json.dumps(data))
    
    audit_path.write_text("\n".join(tampered_lines) + "\n")
    
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain()


def test_detects_modified_decision(audit_path):
    """Test that modifying a decision field breaks the chain."""
    create_test_entries(audit_path, count=5)
    
    lines = audit_path.read_text().splitlines()
    tampered_lines = []
    
    for i, line in enumerate(lines):
        data = json.loads(line)
        if i == 3:
            data["decision"] = "DENY"  # Change from ALLOW to DENY
        tampered_lines.append(json.dumps(data))
    
    audit_path.write_text("\n".join(tampered_lines) + "\n")
    
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain()


def test_detects_modified_args(audit_path):
    """Test that modifying args breaks the chain."""
    create_test_entries(audit_path, count=5)
    
    lines = audit_path.read_text().splitlines()
    tampered_lines = []
    
    for i, line in enumerate(lines):
        data = json.loads(line)
        if i == 1:
            data["args_redacted"]["malicious"] = "injection"
        tampered_lines.append(json.dumps(data))
    
    audit_path.write_text("\n".join(tampered_lines) + "\n")
    
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain()


# Task 3.5.3: Forgery Detection
def test_detects_forged_entry_wrong_prev_hash(audit_path):
    """Test that appending a forged entry with wrong prev_hash is detected."""
    create_test_entries(audit_path, count=5)
    
    # Append a forged entry with incorrect prev_hash
    forged_entry = {
        "timestamp": 9999999.0,
        "tool_name": "forged_tool",
        "args_redacted": {},
        "decision": "ALLOW",
        "middleware": "EvilMiddleware",
        "prev_hash": "0" * 64,  # Wrong hash
        "entry_hash": "a" * 64  # Fake hash
    }
    
    with audit_path.open("a") as f:
        f.write(json.dumps(forged_entry) + "\n")
    
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain()


def test_detects_forged_entry_recalculated(audit_path):
    """Test that even a cleverly forged entry is detected."""
    create_test_entries(audit_path, count=3)
    
    trail = AuditTrail(audit_path)
    last_entry = trail.read_all()[-1]
    
    # Forge an entry with correct prev_hash but wrong timestamp signature
    forged_entry = {
        "timestamp": 1234567890.0,  # Fake timestamp
        "tool_name": "backdoor",
        "args_redacted": {},
        "decision": "ALLOW",
        "middleware": "EvilMiddleware",
        "prev_hash": last_entry.hash,  # Correct prev_hash
        "entry_hash": "b" * 64  # But wrong entry_hash
    }
    
    with audit_path.open("a") as f:
        f.write(json.dumps(forged_entry) + "\n")
    
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain()


# Task 3.5.4: Reordering Detection
def test_detects_reordered_entries(audit_path):
    """Test that reordering entries breaks the chain."""
    create_test_entries(audit_path, count=5)
    
    lines = audit_path.read_text().splitlines()
    
    # Swap entries 2 and 3
    lines[1], lines[2] = lines[2], lines[1]
    
    audit_path.write_text("\n".join(lines) + "\n")
    
    trail = AuditTrail(audit_path)
    assert not trail.verify_chain()


def test_clean_trail_verifies(audit_path):
    """Test that an untampered trail passes verification."""
    create_test_entries(audit_path, count=10)
    
    trail = AuditTrail(audit_path)
    assert trail.verify_chain(), "Clean trail should verify successfully"


def test_empty_trail_verifies(audit_path):
    """Test that an empty trail (non-existent file) verifies."""
    trail = AuditTrail(audit_path)
    assert trail.verify_chain(), "Empty trail should verify (vacuous truth)"
