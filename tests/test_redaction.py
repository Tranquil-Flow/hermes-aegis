import asyncio

import pytest

from hermes_aegis.middleware.chain import CallContext, DispatchDecision
from hermes_aegis.middleware.redaction import SecretRedactionMiddleware


@pytest.fixture
def vault_values():
    return ["sk-test-secret-key-1234567890", "my-anthropic-key-67890"]


@pytest.fixture
def middleware(vault_values):
    return SecretRedactionMiddleware(vault_values=vault_values)


class TestSecretRedaction:
    def test_redacts_exact_vault_value(self, middleware):
        result = "The API returned: sk-test-secret-key-1234567890 successfully"
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("tool", {}, result, ctx))

        assert "sk-test-secret-key-1234567890" not in redacted
        assert "[REDACTED]" in redacted

    def test_redacts_pattern_match(self, middleware):
        result = "Found key: sk-proj-abcdefghijklmnopqrstuvwxyz123456"
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("tool", {}, result, ctx))

        assert "sk-proj-abcdefghijklmnopqrstuvwxyz123456" not in redacted
        assert "[REDACTED]" in redacted

    def test_preserves_normal_text(self, middleware):
        result = "This is a normal tool output with no secrets."
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("tool", {}, result, ctx))

        assert redacted == result

    def test_overlapping_exact_and_pattern_matches_redact_cleanly(self):
        secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        middleware = SecretRedactionMiddleware(vault_values=[secret])
        ctx = CallContext()

        redacted = asyncio.run(middleware.post_dispatch("tool", {}, f"Leaked: {secret}", ctx))

        assert redacted == "Leaked: [REDACTED]"

    def test_redacts_repeated_exact_vault_values(self):
        secret = "my-anthropic-key-67890"
        middleware = SecretRedactionMiddleware(vault_values=[secret])
        ctx = CallContext()

        redacted = asyncio.run(
            middleware.post_dispatch("tool", {}, f"first={secret} second={secret}", ctx)
        )

        assert redacted == "first=[REDACTED] second=[REDACTED]"

    def test_pre_dispatch_always_allows(self, middleware):
        ctx = CallContext()

        decision = asyncio.run(middleware.pre_dispatch("tool", {}, ctx))

        assert decision == DispatchDecision.ALLOW
