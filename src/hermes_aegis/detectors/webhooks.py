"""Webhooks detector — Slack, Discord, Stripe, GitHub webhook signatures."""
from __future__ import annotations

import re

from hermes_aegis.detectors.base import Detector, DetectorMatch

_WEBHOOK_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # Slack webhook URL
    ("slack_webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
     "high"),
    # Discord webhook URL
    ("discord_webhook",
     re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
     "high"),
    # Stripe secret key (sk_live_ or sk_test_)
    ("stripe_secret_key",
     re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}"),
     "critical"),
    # Stripe publishable key (pk_live_ or pk_test_)
    ("stripe_publishable_key",
     re.compile(r"pk_(?:live|test)_[A-Za-z0-9]{20,}"),
     "medium"),
    # Stripe restricted key
    ("stripe_restricted_key",
     re.compile(r"rk_(?:live|test)_[A-Za-z0-9]{20,}"),
     "critical"),
    # GitHub webhook secret (whsec_ prefix)
    ("github_webhook_secret",
     re.compile(r"whsec_[A-Za-z0-9]{20,}"),
     "high"),
    # Shopify webhook signature
    ("shopify_webhook_secret",
     re.compile(r"shpss_[A-Za-z0-9]{20,}"),
     "high"),
    # Twilio webhook/auth token
    ("twilio_auth_token",
     re.compile(r"SK[0-9a-fA-F]{32}"),
     "high"),
    # SendGrid API key
    ("sendgrid_api_key",
     re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
     "high"),
]


class WebhooksDetector(Detector):
    """Detects webhook URLs and integration secrets."""

    def __init__(self) -> None:
        super().__init__(
            name="webhooks",
            description="Webhook and integration secrets: Slack, Discord, Stripe, GitHub, SendGrid",
        )

    def scan(self, text: str) -> list[DetectorMatch]:
        matches: list[DetectorMatch] = []
        for pattern_name, pattern, severity in _WEBHOOK_PATTERNS:
            for m in pattern.finditer(text):
                matches.append(DetectorMatch(
                    detector_name=self.name,
                    pattern_name=pattern_name,
                    matched_text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    severity=severity,
                ))
        return matches
