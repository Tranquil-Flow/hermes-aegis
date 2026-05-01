"""Cloud credentials detector — AWS, GCP, Azure."""
from __future__ import annotations

import base64
import re

from hermes_aegis.detectors.base import Detector, DetectorMatch

_CLOUD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # AWS Access Key ID: AKIA + 16 uppercase alphanumeric
    ("aws_access_key_id",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "high"),
    # AWS Secret Access Key (label + value)
    ("aws_secret_key",
     re.compile(
         r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"
     ),
     "critical"),
    # AWS Secret Access Key (value alone, lookbehind)
    ("aws_secret_value",
     re.compile(r"(?<=AWS_SECRET_ACCESS_KEY[=: ])[A-Za-z0-9/+=]{40}"),
     "critical"),
    # Azure storage account key in connection string
    ("azure_storage_connection_string",
     re.compile(
         r"DefaultEndpointsProtocol=https?;[^;]*;AccountKey=[A-Za-z0-9+/=]{60,};"
     ),
     "critical"),
    # Azure SAS token. The query string starts with sv=YYYY-MM-DD (the
    # storage service version) and always carries a sig=<url-encoded-base64>
    # parameter — that signature is the actual secret. The previous pattern
    # had a stray ``^`` between ``=`` and ``[&\s]`` which made it impossible
    # to match anywhere except the start of the string, so SAS tokens
    # silently passed through. This pattern anchors on the sv= prefix,
    # walks across the intermediate non-whitespace parameters, and requires
    # a signature of at least 20 URL-encoded base64 characters.
    ("azure_sas_token",
     re.compile(
         r"\?sv=\d{4}-\d{2}-\d{2}&[^\s]*?sig=[A-Za-z0-9%/+=]{20,}"
     ),
     "high"),
    # Google Cloud API key (39 chars)
    ("gcp_api_key",
     re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
     "high"),
    # GCP OAuth access token (ya29.)
    ("gcp_oauth_token",
     re.compile(r"ya29\.[0-9A-Za-z_\-]+"),
     "high"),
]


class CloudDetector(Detector):
    """Detects AWS, GCP, and Azure credential patterns."""

    def __init__(self) -> None:
        super().__init__(
            name="cloud",
            description="Cloud credential patterns: AWS, GCP, Azure",
        )

    def scan(self, text: str) -> list[DetectorMatch]:
        matches: list[DetectorMatch] = []
        for pattern_name, pattern, severity in _CLOUD_PATTERNS:
            for m in pattern.finditer(text):
                matches.append(DetectorMatch(
                    detector_name=self.name,
                    pattern_name=pattern_name,
                    matched_text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    severity=severity,
                ))

        # GCP service account key: base64-encoded JSON starting with ey (base64 of {")
        for m in re.compile(r"ey[A-Za-z0-9+/=]{40,}").finditer(text):
            try:
                decoded = base64.b64decode(m.group() + "==").decode("utf-8", errors="ignore")
                if '"type"' in decoded and ("service_account" in decoded or '"project_id"' in decoded):
                    matches.append(DetectorMatch(
                        detector_name=self.name,
                        pattern_name="gcp_service_account_key",
                        matched_text=m.group(),
                        start=m.start(),
                        end=m.end(),
                        severity="critical",
                    ))
            except Exception:
                pass

        return matches
