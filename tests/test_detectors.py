"""Tests for the modular detector framework (Phase 4).

Tests are written FIRST (TDD red-green):
1. Base types (DetectorMatch, Detector base class)
2. DetectorRegistry (register, scan_all, list)
3. Individual detectors: api_keys, cloud, webhooks, connection_strings,
   private_keys, entropy
4. Integration: ContentScanner wired through registry
"""
from __future__ import annotations

import math

import pytest

from hermes_aegis.detectors.base import DetectorMatch, Detector


# ---------------------------------------------------------------------------
# Base types
# ---------------------------------------------------------------------------

class TestDetectorMatch:
    """DetectorMatch dataclass structure."""

    def test_fields(self):
        m = DetectorMatch(
            detector_name="api_keys",
            pattern_name="openai_api_key",
            matched_text="sk-proj-abc123",
            start=10,
            end=24,
            severity="high",
        )
        assert m.detector_name == "api_keys"
        assert m.pattern_name == "openai_api_key"
        assert m.matched_text == "sk-proj-abc123"
        assert m.start == 10
        assert m.end == 24
        assert m.severity == "high"

    def test_default_severity_is_medium(self):
        m = DetectorMatch(
            detector_name="x",
            pattern_name="y",
            matched_text="z",
            start=0,
            end=1,
        )
        assert m.severity == "medium"


class TestDetectorBase:
    """Detector base class contract."""

    def test_subclass_must_implement_scan(self):
        d = Detector(name="test", description="test detector")
        with pytest.raises(NotImplementedError):
            d.scan("some text")

    def test_subclass_scan_works(self):
        import re

        class FakeDetector(Detector):
            def scan(self, text: str) -> list[DetectorMatch]:
                results = []
                for m in re.compile(r"sk-[a-z]+").finditer(text):
                    results.append(
                        DetectorMatch(
                            detector_name=self.name,
                            pattern_name="fake_pattern",
                            matched_text=m.group(),
                            start=m.start(),
                            end=m.end(),
                        )
                    )
                return results

        d = FakeDetector(name="fake", description="fake detector")
        matches = d.scan("key=sk-abc and sk-xyz")
        assert len(matches) == 2
        assert matches[0].matched_text == "sk-abc"
        assert matches[1].matched_text == "sk-xyz"

    def test_name_and_description(self):
        d = Detector(name="mydetector", description="Does things")
        assert d.name == "mydetector"
        assert d.description == "Does things"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestDetectorRegistry:
    """DetectorRegistry: register, scan_all, list, get."""

    def test_register_and_list(self):
        from hermes_aegis.detectors.registry import DetectorRegistry
        import re

        class Det(Detector):
            def scan(self, text: str) -> list[DetectorMatch]:
                return []

        reg = DetectorRegistry()
        d = Det(name="test_det", description="test")
        reg.register(d)
        assert "test_det" in [x.name for x in reg.list_detectors()]

    def test_scan_all_runs_all_detectors(self):
        from hermes_aegis.detectors.registry import DetectorRegistry
        import re

        class DetA(Detector):
            def scan(self, text: str) -> list[DetectorMatch]:
                m = re.search(r"AAAA", text)
                if m:
                    return [DetectorMatch(
                        detector_name=self.name, pattern_name="a",
                        matched_text=m.group(), start=m.start(), end=m.end(),
                    )]
                return []

        class DetB(Detector):
            def scan(self, text: str) -> list[DetectorMatch]:
                m = re.search(r"BBBB", text)
                if m:
                    return [DetectorMatch(
                        detector_name=self.name, pattern_name="b",
                        matched_text=m.group(), start=m.start(), end=m.end(),
                    )]
                return []

        reg = DetectorRegistry()
        reg.register(DetA(name="a", description="a"))
        reg.register(DetB(name="b", description="b"))
        matches = reg.scan_all("AAAA and BBBB")
        assert len(matches) == 2
        names = {m.detector_name for m in matches}
        assert names == {"a", "b"}

    def test_get_by_name(self):
        from hermes_aegis.detectors.registry import DetectorRegistry

        class Det(Detector):
            def scan(self, text: str) -> list[DetectorMatch]:
                return []

        reg = DetectorRegistry()
        d = Det(name="lookup_me", description="findable")
        reg.register(d)
        assert reg.get("lookup_me") is d
        assert reg.get("nonexistent") is None

    def test_scan_all_empty_registry(self):
        from hermes_aegis.detectors.registry import DetectorRegistry
        reg = DetectorRegistry()
        assert reg.scan_all("sk-proj-test1234567890") == []


# ---------------------------------------------------------------------------
# API Keys detector
# ---------------------------------------------------------------------------

class TestApiKeyDetector:
    """ApiKeysDetector: OpenAI, Anthropic, GitHub, generic bearer, generic api_key, RPC URLs."""

    @pytest.fixture
    def det(self):
        from hermes_aegis.detectors.api_keys import ApiKeysDetector
        return ApiKeysDetector()

    def test_openai_key(self, det):
        matches = det.scan("key=sk-proj-abc123def456ghi789jkl012mno345")
        assert len(matches) >= 1
        assert any(m.pattern_name == "openai_api_key" for m in matches)

    def test_anthropic_key(self, det):
        matches = det.scan("key=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678")
        assert len(matches) >= 1
        assert any(m.pattern_name == "anthropic_api_key" for m in matches)

    def test_github_token(self, det):
        matches = det.scan("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert len(matches) >= 1
        assert any("github" in m.pattern_name for m in matches)

    def test_generic_bearer(self, det):
        matches = det.scan("Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890ABCD")
        assert len(matches) >= 1
        assert any(m.pattern_name == "generic_bearer" for m in matches)

    def test_generic_api_key(self, det):
        matches = det.scan("api_key=abcdefghijklmnopqrstuvwxyz1234567890")
        assert len(matches) >= 1
        assert any(m.pattern_name == "generic_api_key" for m in matches)

    def test_rpc_url_alchemy(self, det):
        matches = det.scan("url=https://eth-mainnet.g.alchemy.com/v2/abc123def456ghi789jkl012mno")
        assert len(matches) >= 1
        assert any(m.pattern_name == "rpc_url_with_key" for m in matches)

    def test_no_false_positive_normal_text(self, det):
        matches = det.scan("Hello world, this is a normal sentence about API design.")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Cloud credentials detector
# ---------------------------------------------------------------------------

class TestCloudDetector:
    """CloudDetector: AWS access keys, GCP service accounts, Azure credentials."""

    @pytest.fixture
    def det(self):
        from hermes_aegis.detectors.cloud import CloudDetector
        return CloudDetector()

    def test_aws_access_key_id(self, det):
        matches = det.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert len(matches) >= 1
        assert any(m.pattern_name == "aws_access_key_id" for m in matches)

    def test_aws_secret_key(self, det):
        matches = det.scan("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        assert len(matches) >= 1
        assert any("aws_secret" in m.pattern_name for m in matches)

    def test_gcp_service_account_key(self, det):
        # GCP SA keys are base64 JSON starting with eyI (base64 of {")
        import base64
        sa_json = '{"type":"service_account","project_id":"test"}'
        b64 = base64.b64encode(sa_json.encode()).decode()
        matches = det.scan(f"GOOGLE_CREDENTIALS={b64}")
        assert len(matches) >= 1
        assert any("gcp" in m.pattern_name for m in matches)

    def test_azure_connection_string(self, det):
        matches = det.scan("DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=" + "A" * 66 + "==;EndpointSuffix=core.windows.net")
        assert len(matches) >= 1
        assert any("azure" in m.pattern_name for m in matches)

    def test_azure_sas_token(self, det):
        """Real Azure SAS token shape — sv=YYYY-MM-DD ... sig=<base64>.

        Regression: the original pattern had a stray ``^`` that made it
        impossible to match mid-string, so SAS tokens silently passed
        through the detector.
        """
        url = (
            "https://myacc.blob.core.windows.net/cnt/blob"
            "?sv=2023-01-03&ss=b&srt=co&sp=rwdlacx"
            "&se=2024-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https"
            "&sig=AbCdEf%2FgHiJkLmNoPqRsTuVwXyZ123456789AB%3D"
        )
        matches = det.scan(url)
        assert any(m.pattern_name == "azure_sas_token" for m in matches), (
            f"azure_sas_token did not fire on a real SAS token: {[m.pattern_name for m in matches]}"
        )

    def test_azure_sas_no_false_positive_on_partial_query(self, det):
        """A bare sv= without the required sig= must not fire."""
        matches = det.scan("?sv=2023-01-03&just=some&random=params")
        assert not any(m.pattern_name == "azure_sas_token" for m in matches)

    def test_no_false_positive(self, det):
        matches = det.scan("The cloud is cloudy today, no keys here.")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Webhooks detector
# ---------------------------------------------------------------------------

class TestWebhooksDetector:
    """WebhooksDetector: Slack, Discord, Stripe, GitHub webhook signatures."""

    @pytest.fixture
    def det(self):
        from hermes_aegis.detectors.webhooks import WebhooksDetector
        return WebhooksDetector()

    def test_slack_webhook(self, det):
        matches = det.scan("https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")
        assert len(matches) >= 1
        assert any("slack" in m.pattern_name for m in matches)

    def test_discord_webhook(self, det):
        matches = det.scan("https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwx")
        assert len(matches) >= 1
        assert any("discord" in m.pattern_name for m in matches)

    def test_stripe_key(self, det):
        matches = det.scan("STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx123456789")
        assert len(matches) >= 1
        assert any("stripe" in m.pattern_name for m in matches)

    def test_github_webhook_secret(self, det):
        matches = det.scan("GITHUB_WEBHOOK_SECRET=whsec_abcdefghijklmnop1234567890")
        assert len(matches) >= 1
        assert any("github" in m.pattern_name for m in matches)

    def test_no_false_positive(self, det):
        matches = det.scan("Check out https://example.com/api/data for info")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Connection strings detector
# ---------------------------------------------------------------------------

class TestConnectionStringsDetector:
    """ConnectionStringsDetector: PostgreSQL, MySQL, MongoDB, Redis, AMQP."""

    @pytest.fixture
    def det(self):
        from hermes_aegis.detectors.connection_strings import ConnectionStringsDetector
        return ConnectionStringsDetector()

    def test_postgres_connection_string(self, det):
        matches = det.scan("DATABASE_URL=postgresql://user:secretpassword@db.example.com:5432/mydb")
        assert len(matches) >= 1
        assert any("postgres" in m.pattern_name or "database" in m.pattern_name for m in matches)

    def test_mysql_connection_string(self, det):
        matches = det.scan("DB_URL=mysql://admin:hunter2@localhost:3306/production")
        assert len(matches) >= 1
        assert any("mysql" in m.pattern_name or "database" in m.pattern_name for m in matches)

    def test_mongodb_connection_string(self, det):
        matches = det.scan("MONGO_URI=mongodb+srv://user:p@ssw0rd@cluster.mongodb.net/mydb")
        assert len(matches) >= 1
        assert any("mongo" in m.pattern_name or "database" in m.pattern_name for m in matches)

    def test_redis_url(self, det):
        matches = det.scan("REDIS_URL=redis://:mypassword@redis.example.com:6379/0")
        assert len(matches) >= 1
        assert any("redis" in m.pattern_name for m in matches)

    def test_amqp_connection_string(self, det):
        matches = det.scan("AMQP_URL=amqp://guest:guest@rabbitmq.example.com:5672/vhost")
        assert len(matches) >= 1
        assert any("amqp" in m.pattern_name for m in matches)

    def test_no_false_positive_url_without_password(self, det):
        matches = det.scan("Visit https://example.com/path for details")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Private keys detector
# ---------------------------------------------------------------------------

class TestPrivateKeysDetector:
    """PrivateKeysDetector: RSA, EC, DSA, OpenSSH, PGP private key blocks."""

    @pytest.fixture
    def det(self):
        from hermes_aegis.detectors.private_keys import PrivateKeysDetector
        return PrivateKeysDetector()

    def test_rsa_private_key(self, det):
        matches = det.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")
        assert len(matches) >= 1
        assert any("rsa" in m.pattern_name or "private_key" in m.pattern_name for m in matches)

    def test_openssh_private_key(self, det):
        matches = det.scan("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...\n-----END OPENSSH PRIVATE KEY-----")
        assert len(matches) >= 1
        assert any("openssh" in m.pattern_name or "private_key" in m.pattern_name for m in matches)

    def test_ec_private_key(self, det):
        matches = det.scan("-----BEGIN EC PRIVATE KEY-----\nMHQ...\n-----END EC PRIVATE KEY-----")
        assert len(matches) >= 1
        assert any("ec" in m.pattern_name or "private_key" in m.pattern_name for m in matches)

    def test_pgp_private_key(self, det):
        matches = det.scan("-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQI...\n-----END PGP PRIVATE KEY BLOCK-----")
        assert len(matches) >= 1
        assert any("pgp" in m.pattern_name or "private_key" in m.pattern_name for m in matches)

    def test_no_false_positive_public_key(self, det):
        matches = det.scan("-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----")
        # Public keys should NOT be flagged as private keys
        assert len(matches) == 0

    def test_no_false_positive_cert(self, det):
        matches = det.scan("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Entropy detector
# ---------------------------------------------------------------------------

class TestEntropyDetector:
    """EntropyDetector: flags high-entropy strings (likely secrets with no known format)."""

    @pytest.fixture
    def det(self):
        from hermes_aegis.detectors.entropy import EntropyDetector
        return EntropyDetector()

    def test_high_entropy_base64(self, det):
        # 40+ chars of high-entropy base64
        text = "token=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
        matches = det.scan(text)
        assert len(matches) >= 1
        assert any("high_entropy" in m.pattern_name for m in matches)

    def test_high_entropy_hex(self, det):
        text = "key=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"
        matches = det.scan(text)
        assert len(matches) >= 1

    def test_low_entropy_normal_text_not_flagged(self, det):
        text = "Hello world this is a normal sentence with words"
        matches = det.scan(text)
        assert len(matches) == 0

    def test_short_high_entropy_not_flagged(self, det):
        # Too short to be meaningful — under the min_length threshold
        text = "x=Ab3dF"
        matches = det.scan(text)
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Integration: built-in registry
# ---------------------------------------------------------------------------

class TestBuiltinRegistry:
    """The default registry auto-registers all built-in detectors."""

    def test_default_registry_has_all_detectors(self):
        from hermes_aegis.detectors import default_registry
        names = {d.name for d in default_registry.list_detectors()}
        expected = {"api_keys", "cloud", "webhooks", "connection_strings",
                    "private_keys", "entropy"}
        assert expected.issubset(names), f"Missing: {expected - names}"

    def test_default_registry_scan_finds_openai_key(self):
        from hermes_aegis.detectors import default_registry
        matches = default_registry.scan_all("key=sk-proj-abc123def456ghi789jkl012mno345")
        assert len(matches) >= 1
        assert any(m.detector_name == "api_keys" for m in matches)

    def test_default_registry_scan_finds_private_key(self):
        from hermes_aegis.detectors import default_registry
        matches = default_registry.scan_all("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert len(matches) >= 1
        assert any(m.detector_name == "private_keys" for m in matches)
