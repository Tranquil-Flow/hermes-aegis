"""Domain allowlist management for network filtering."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


class DomainAllowlist:
    """Manage domain allowlist for outbound network requests."""

    def __init__(self, config_path: Path):
        """Initialize allowlist manager.
        
        Args:
            config_path: Path to domain-allowlist.json file
        """
        self.config_path = config_path
        self._domains: List[str] = []
        self.load()

    def load(self) -> None:
        """Load domains from JSON file. Creates empty list if file doesn't exist."""
        if not self.config_path.exists():
            self._domains = []
            return
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
                if not isinstance(data, list):
                    raise ValueError("Allowlist must be a JSON array")
                self._domains = [str(d) for d in data]
        except (json.JSONDecodeError, ValueError) as e:
            # If file is corrupted, start fresh with empty list
            logger.warning(
                "Corrupted allowlist at %s (%s) — falling back to empty (allow-all)",
                self.config_path, e,
            )
            self._domains = []

    def save(self) -> None:
        """Save domains to JSON file."""
        # Ensure parent directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            json.dump(sorted(self._domains), f, indent=2)

    def add(self, domain: str) -> None:
        """Add a domain to the allowlist.
        
        Args:
            domain: Domain name (e.g., "example.com" or "api.github.com")
        """
        domain = domain.strip().lower()
        if domain and domain not in self._domains:
            self._domains.append(domain)
            self.save()

    def remove(self, domain: str) -> bool:
        """Remove a domain from the allowlist.
        
        Args:
            domain: Domain name to remove
            
        Returns:
            True if domain was removed, False if it wasn't in the list
        """
        domain = domain.strip().lower()
        if domain in self._domains:
            self._domains.remove(domain)
            self.save()
            return True
        return False

    def is_allowed(self, host: str) -> bool:
        """Check if a host is allowed by the allowlist.
        
        Args:
            host: Hostname to check (e.g., "api.example.com")
            
        Returns:
            True if allowed (empty list allows all, or host is in list)
        """
        # Empty allowlist means allow all (no breakage)
        if not self._domains:
            return True
        
        host = host.strip().lower()
        
        # Strip port if present
        if ':' in host:
            host = host.split(':', 1)[0]
        
        # Check exact match
        if host in self._domains:
            return True
        
        # Check if host is subdomain of any allowed domain
        for domain in self._domains:
            if host.endswith('.' + domain):
                return True
        
        return False

    def list(self) -> List[str]:
        """Get current list of allowed domains.
        
        Returns:
            List of domain strings
        """
        return sorted(self._domains.copy())
