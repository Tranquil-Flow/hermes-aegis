"""Audit trail module for logging and tracking all proxy operations.

The audit module provides tamper-proof logging of proxy requests, responses,
blocked operations, and state changes using JSONL format with SHA256 hash chains.
"""
from hermes_aegis.audit.trail import AuditTrail

__all__ = ["AuditTrail"]
