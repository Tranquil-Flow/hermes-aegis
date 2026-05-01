"""Modular secret detection framework.

Each detector specializes in a category of secrets:
- api_keys: OpenAI, Anthropic, GitHub, generic bearer/API key patterns
- cloud: AWS, GCP, Azure credential formats
- webhooks: Slack, Discord, Stripe, GitHub webhook URLs
- connection_strings: PostgreSQL, MySQL, MongoDB, Redis, AMQP URIs
- private_keys: RSA, EC, DSA, OpenSSH, PGP private key blocks
- entropy: high-entropy strings that don't match known formats

Usage::

    from hermes_aegis.detectors import default_registry

    matches = default_registry.scan_all(text)
    for m in matches:
        print(f"[{m.severity}] {m.detector_name}/{m.pattern_name}: {m.matched_text!r}")
"""
from __future__ import annotations

from hermes_aegis.detectors.registry import DetectorRegistry
from hermes_aegis.detectors.api_keys import ApiKeysDetector
from hermes_aegis.detectors.cloud import CloudDetector
from hermes_aegis.detectors.webhooks import WebhooksDetector
from hermes_aegis.detectors.connection_strings import ConnectionStringsDetector
from hermes_aegis.detectors.private_keys import PrivateKeysDetector
from hermes_aegis.detectors.entropy import EntropyDetector

__all__ = [
    "DetectorRegistry",
    "ApiKeysDetector",
    "CloudDetector",
    "WebhooksDetector",
    "ConnectionStringsDetector",
    "PrivateKeysDetector",
    "EntropyDetector",
    "default_registry",
]

# Pre-built registry with all built-in detectors
default_registry = DetectorRegistry()
default_registry.register(ApiKeysDetector())
default_registry.register(CloudDetector())
default_registry.register(WebhooksDetector())
default_registry.register(ConnectionStringsDetector())
default_registry.register(PrivateKeysDetector())
default_registry.register(EntropyDetector())
