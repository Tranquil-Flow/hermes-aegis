"""Tests for domain allowlist functionality."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_aegis.config.allowlist import DomainAllowlist


@pytest.fixture
def allowlist_path(tmp_path):
    """Provide a temporary path for allowlist testing."""
    return tmp_path / "domain-allowlist.json"


@pytest.fixture
def allowlist(allowlist_path):
    """Create a DomainAllowlist instance."""
    return DomainAllowlist(allowlist_path)


class TestDomainAllowlist:
    """Test suite for DomainAllowlist class."""

    def test_initialization_creates_empty_list(self, allowlist):
        """Test that initialization creates an empty list."""
        assert allowlist.list() == []

    def test_add_single_domain(self, allowlist):
        """Test adding a single domain."""
        allowlist.add("example.com")
        assert "example.com" in allowlist.list()

    def test_add_multiple_domains(self, allowlist):
        """Test adding multiple domains."""
        allowlist.add("example.com")
        allowlist.add("github.com")
        allowlist.add("api.openai.com")
        
        domains = allowlist.list()
        assert len(domains) == 3
        assert "example.com" in domains
        assert "github.com" in domains
        assert "api.openai.com" in domains

    def test_add_duplicate_domain_ignored(self, allowlist):
        """Test that adding duplicate domain doesn't create duplicates."""
        allowlist.add("example.com")
        allowlist.add("example.com")
        assert allowlist.list().count("example.com") == 1

    def test_add_normalizes_case(self, allowlist):
        """Test that domains are normalized to lowercase."""
        allowlist.add("EXAMPLE.COM")
        allowlist.add("Example.Com")
        assert allowlist.list() == ["example.com"]

    def test_add_strips_whitespace(self, allowlist):
        """Test that whitespace is stripped from domains."""
        allowlist.add("  example.com  ")
        assert allowlist.list() == ["example.com"]

    def test_remove_existing_domain(self, allowlist):
        """Test removing an existing domain."""
        allowlist.add("example.com")
        allowlist.add("github.com")
        
        result = allowlist.remove("example.com")
        assert result is True
        assert "example.com" not in allowlist.list()
        assert "github.com" in allowlist.list()

    def test_remove_nonexistent_domain(self, allowlist):
        """Test removing a domain that doesn't exist."""
        allowlist.add("example.com")
        result = allowlist.remove("github.com")
        assert result is False
        assert "example.com" in allowlist.list()

    def test_remove_normalizes_case(self, allowlist):
        """Test that remove works with normalized case."""
        allowlist.add("example.com")
        result = allowlist.remove("EXAMPLE.COM")
        assert result is True
        assert allowlist.list() == []

    def test_is_allowed_empty_list_allows_all(self, allowlist):
        """Test that empty allowlist allows all domains."""
        assert allowlist.is_allowed("example.com")
        assert allowlist.is_allowed("github.com")
        assert allowlist.is_allowed("any-random-domain.com")

    def test_is_allowed_exact_match(self, allowlist):
        """Test that exact domain match is allowed."""
        allowlist.add("example.com")
        assert allowlist.is_allowed("example.com")

    def test_is_allowed_subdomain_match(self, allowlist):
        """Test that subdomains of allowed domains are allowed."""
        allowlist.add("example.com")
        assert allowlist.is_allowed("api.example.com")
        assert allowlist.is_allowed("www.example.com")
        assert allowlist.is_allowed("deep.nested.example.com")

    def test_is_allowed_blocks_unlisted_domain(self, allowlist):
        """Test that unlisted domains are blocked when list is non-empty."""
        allowlist.add("example.com")
        assert not allowlist.is_allowed("github.com")
        assert not allowlist.is_allowed("evil.com")

    def test_is_allowed_blocks_similar_domain(self, allowlist):
        """Test that similar but different domains are blocked."""
        allowlist.add("example.com")
        assert not allowlist.is_allowed("example.org")
        assert not allowlist.is_allowed("notexample.com")
        assert not allowlist.is_allowed("example.com.evil.com")

    def test_is_allowed_strips_port(self, allowlist):
        """Test that port numbers are stripped from host check."""
        allowlist.add("example.com")
        assert allowlist.is_allowed("example.com:8080")
        assert allowlist.is_allowed("api.example.com:443")

    def test_is_allowed_case_insensitive(self, allowlist):
        """Test that host checking is case-insensitive."""
        allowlist.add("example.com")
        assert allowlist.is_allowed("EXAMPLE.COM")
        assert allowlist.is_allowed("Example.Com")
        assert allowlist.is_allowed("API.EXAMPLE.COM")

    def test_persistence_across_instances(self, allowlist_path):
        """Test that allowlist persists across different instances."""
        # Add domains with first instance
        allowlist1 = DomainAllowlist(allowlist_path)
        allowlist1.add("example.com")
        allowlist1.add("github.com")
        
        # Load with second instance and verify
        allowlist2 = DomainAllowlist(allowlist_path)
        domains = allowlist2.list()
        assert "example.com" in domains
        assert "github.com" in domains

    def test_list_returns_sorted_copy(self, allowlist):
        """Test that list() returns sorted list."""
        allowlist.add("zebra.com")
        allowlist.add("apple.com")
        allowlist.add("microsoft.com")
        
        domains = allowlist.list()
        assert domains == ["apple.com", "microsoft.com", "zebra.com"]
        
        # Verify it's a copy (modifying doesn't affect original)
        domains.append("new.com")
        assert "new.com" not in allowlist.list()

    def test_json_file_format(self, allowlist_path, allowlist):
        """Test that JSON file has correct format."""
        allowlist.add("example.com")
        allowlist.add("github.com")
        
        # Read raw JSON and verify it's a sorted array
        with open(allowlist_path, 'r') as f:
            data = json.load(f)
        
        assert isinstance(data, list)
        assert data == ["example.com", "github.com"]

    def test_load_handles_corrupted_file(self, allowlist_path):
        """Test that corrupted JSON file is handled gracefully."""
        # Write invalid JSON
        with open(allowlist_path, 'w') as f:
            f.write("invalid json {]")
        
        # Should not raise, but start with empty list
        allowlist = DomainAllowlist(allowlist_path)
        assert allowlist.list() == []

    def test_load_handles_invalid_format(self, allowlist_path):
        """Test that non-array JSON is handled gracefully."""
        # Write valid JSON but wrong format (object instead of array)
        with open(allowlist_path, 'w') as f:
            json.dump({"domains": ["example.com"]}, f)
        
        # Should not raise, but start with empty list
        allowlist = DomainAllowlist(allowlist_path)
        assert allowlist.list() == []

    def test_save_creates_parent_directory(self, tmp_path):
        """Test that save creates parent directories if needed."""
        nested_path = tmp_path / "nested" / "dir" / "allowlist.json"
        allowlist = DomainAllowlist(nested_path)
        allowlist.add("example.com")
        
        assert nested_path.exists()
        assert nested_path.parent.is_dir()

    def test_multiple_overlapping_domains(self, allowlist):
        """Test behavior with overlapping domain rules."""
        allowlist.add("example.com")
        allowlist.add("api.example.com")  # More specific subdomain
        
        # Both should work
        assert allowlist.is_allowed("example.com")
        assert allowlist.is_allowed("api.example.com")
        assert allowlist.is_allowed("other.api.example.com")
        assert allowlist.is_allowed("www.example.com")

    def test_empty_domain_not_added(self, allowlist):
        """Test that empty strings are not added."""
        allowlist.add("")
        allowlist.add("   ")
        assert allowlist.list() == []

    def test_real_world_scenario(self, allowlist):
        """Test a realistic usage scenario."""
        # Add approved API endpoints
        allowlist.add("api.openai.com")
        allowlist.add("api.anthropic.com")
        allowlist.add("api.github.com")
        
        # These should be allowed
        assert allowlist.is_allowed("api.openai.com")
        assert allowlist.is_allowed("api.anthropic.com")
        assert allowlist.is_allowed("api.github.com")
        
        # These should be blocked (not in allowlist)
        assert not allowlist.is_allowed("evil-exfil.com")
        assert not allowlist.is_allowed("api.attacker.com")
        assert not allowlist.is_allowed("data-leak.io")
        
        # Remove one domain
        allowlist.remove("api.github.com")
        assert not allowlist.is_allowed("api.github.com")
        
        # Others still allowed
        assert allowlist.is_allowed("api.openai.com")
        assert allowlist.is_allowed("api.anthropic.com")
