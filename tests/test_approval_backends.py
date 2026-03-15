"""Tests for approval backends."""
import hashlib
import hmac
import json
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from hermes_aegis.approval.backends import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    BlockBackend,
    CachedBackend,
    LogOnlyBackend,
    WebhookBackend,
    get_backend,
)
from hermes_aegis.approval.cache import ApprovalCache


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_request():
    return ApprovalRequest(
        command="rm -rf /",
        pattern_key="destructive_rm",
        description="Recursive force delete",
        timestamp=1700000000.0,
        session_id="test-session-123",
    )


def _make_mock_requests(post_return=None, post_side_effect=None):
    """Create a mock requests module with Timeout exception class."""
    mock_mod = MagicMock()

    class MockTimeout(Exception):
        pass

    mock_mod.Timeout = MockTimeout
    if post_side_effect:
        mock_mod.post.side_effect = post_side_effect
    elif post_return:
        mock_mod.post.return_value = post_return
    return mock_mod


def _call_webhook(backend, request, mock_requests):
    """Call request_approval with a mocked requests module."""
    with patch.dict(sys.modules, {"requests": mock_requests}):
        return backend.request_approval(request)


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------

class TestApprovalRequest:
    def test_fields(self):
        req = ApprovalRequest(
            command="whoami",
            pattern_key="info_gathering",
            description="User enumeration",
            timestamp=123.0,
        )
        assert req.command == "whoami"
        assert req.pattern_key == "info_gathering"
        assert req.description == "User enumeration"
        assert req.timestamp == 123.0
        assert req.session_id == ""  # default

    def test_session_id_default(self):
        req = ApprovalRequest(
            command="ls", pattern_key="k", description="d", timestamp=0.0,
        )
        assert req.session_id == ""

    def test_session_id_set(self):
        req = ApprovalRequest(
            command="ls", pattern_key="k", description="d",
            timestamp=0.0, session_id="abc",
        )
        assert req.session_id == "abc"


class TestApprovalResponse:
    def test_fields(self):
        resp = ApprovalResponse(
            decision=ApprovalDecision.APPROVED,
            reason="ok",
            responder="test",
            response_time=1.5,
        )
        assert resp.decision == ApprovalDecision.APPROVED
        assert resp.reason == "ok"
        assert resp.responder == "test"
        assert resp.response_time == 1.5

    def test_defaults(self):
        resp = ApprovalResponse(decision=ApprovalDecision.DENIED)
        assert resp.reason == ""
        assert resp.responder == ""
        assert resp.response_time == 0.0


# ---------------------------------------------------------------------------
# BlockBackend
# ---------------------------------------------------------------------------

class TestBlockBackend:
    def test_name(self):
        assert BlockBackend().name == "block"

    def test_always_denies(self, sample_request):
        backend = BlockBackend()
        resp = backend.request_approval(sample_request)
        assert resp.decision == ApprovalDecision.DENIED
        assert "Blocked by policy" in resp.reason
        assert resp.responder == "block_backend"

    def test_includes_description(self, sample_request):
        resp = BlockBackend().request_approval(sample_request)
        assert sample_request.description in resp.reason

    def test_is_approval_backend(self):
        assert isinstance(BlockBackend(), ApprovalBackend)


# ---------------------------------------------------------------------------
# LogOnlyBackend
# ---------------------------------------------------------------------------

class TestLogOnlyBackend:
    def test_name(self):
        assert LogOnlyBackend().name == "log_only"

    def test_always_approves(self, sample_request):
        backend = LogOnlyBackend()
        resp = backend.request_approval(sample_request)
        assert resp.decision == ApprovalDecision.APPROVED
        assert resp.responder == "log_only_backend"

    def test_logs_warning(self, sample_request):
        backend = LogOnlyBackend()
        with patch("hermes_aegis.approval.backends.logger") as mock_logger:
            backend.request_approval(sample_request)
            mock_logger.warning.assert_called_once()
            args = mock_logger.warning.call_args[0]
            assert "log_only" in args[0]

    def test_is_approval_backend(self):
        assert isinstance(LogOnlyBackend(), ApprovalBackend)


# ---------------------------------------------------------------------------
# WebhookBackend
# ---------------------------------------------------------------------------

class TestWebhookBackend:
    def test_name(self):
        assert WebhookBackend(url="http://example.com").name == "webhook"

    def test_is_approval_backend(self):
        assert isinstance(WebhookBackend(url="http://example.com"), ApprovalBackend)

    def test_approved(self, sample_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "approved": True,
            "reason": "Looks safe",
            "responder": "admin",
        }
        mock_requests = _make_mock_requests(post_return=mock_resp)

        backend = WebhookBackend(url="http://webhook.example.com/approve")
        resp = _call_webhook(backend, sample_request, mock_requests)

        assert resp.decision == ApprovalDecision.APPROVED
        assert resp.reason == "Looks safe"
        assert resp.responder == "admin"

    def test_denied(self, sample_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"approved": False, "reason": "Too risky"}
        mock_requests = _make_mock_requests(post_return=mock_resp)

        backend = WebhookBackend(url="http://webhook.example.com/approve")
        resp = _call_webhook(backend, sample_request, mock_requests)

        assert resp.decision == ApprovalDecision.DENIED
        assert resp.reason == "Too risky"

    def test_non_200_status(self, sample_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_requests = _make_mock_requests(post_return=mock_resp)

        backend = WebhookBackend(url="http://webhook.example.com/approve")
        resp = _call_webhook(backend, sample_request, mock_requests)

        assert resp.decision == ApprovalDecision.DENIED
        assert "500" in resp.reason

    def test_timeout(self, sample_request):
        mock_requests = _make_mock_requests()

        # Make post raise the Timeout from our mock module
        mock_requests.post.side_effect = mock_requests.Timeout("timed out")

        backend = WebhookBackend(url="http://webhook.example.com/approve", timeout=5.0)
        resp = _call_webhook(backend, sample_request, mock_requests)

        assert resp.decision == ApprovalDecision.TIMEOUT
        assert "5.0" in resp.reason

    def test_error(self, sample_request):
        mock_requests = _make_mock_requests(
            post_side_effect=ConnectionError("refused"),
        )

        backend = WebhookBackend(url="http://webhook.example.com/approve")
        resp = _call_webhook(backend, sample_request, mock_requests)

        assert resp.decision == ApprovalDecision.ERROR
        assert "refused" in resp.reason

    def test_hmac_signature(self, sample_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"approved": True}
        mock_requests = _make_mock_requests(post_return=mock_resp)

        secret = "my-secret-key"
        backend = WebhookBackend(
            url="http://webhook.example.com/approve",
            secret=secret,
        )
        _call_webhook(backend, sample_request, mock_requests)

        # Verify the call was made with the HMAC signature header
        call_args = mock_requests.post.call_args
        headers = call_args.kwargs.get("headers", {})
        assert "X-Aegis-Signature" in headers

        # Verify the signature is correct
        payload = {
            "command": sample_request.command[:500],
            "pattern_key": sample_request.pattern_key,
            "description": sample_request.description,
            "timestamp": sample_request.timestamp,
            "session_id": sample_request.session_id,
        }
        expected_sig = hmac.new(
            secret.encode(),
            json.dumps(payload, sort_keys=True).encode(),
            hashlib.sha256,
        ).hexdigest()
        assert headers["X-Aegis-Signature"] == expected_sig

    def test_no_signature_without_secret(self, sample_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"approved": True}
        mock_requests = _make_mock_requests(post_return=mock_resp)

        backend = WebhookBackend(url="http://webhook.example.com/approve")
        _call_webhook(backend, sample_request, mock_requests)

        call_args = mock_requests.post.call_args
        headers = call_args.kwargs.get("headers", {})
        assert "X-Aegis-Signature" not in headers

    def test_command_truncated_in_payload(self, sample_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"approved": True}
        mock_requests = _make_mock_requests(post_return=mock_resp)

        sample_request.command = "x" * 1000
        backend = WebhookBackend(url="http://webhook.example.com/approve")
        _call_webhook(backend, sample_request, mock_requests)

        call_args = mock_requests.post.call_args
        sent_json = call_args.kwargs.get("json", {})
        assert len(sent_json["command"]) == 500


# ---------------------------------------------------------------------------
# get_backend factory
# ---------------------------------------------------------------------------

class TestGetBackend:
    def test_default_is_block(self):
        backend = get_backend({})
        assert isinstance(backend, BlockBackend)
        assert backend.name == "block"

    def test_explicit_block(self):
        backend = get_backend({"approval_backend": "block"})
        assert isinstance(backend, BlockBackend)

    def test_log_only(self):
        backend = get_backend({"approval_backend": "log_only"})
        assert isinstance(backend, LogOnlyBackend)

    def test_webhook(self):
        backend = get_backend({
            "approval_backend": "webhook",
            "approval_webhook_url": "http://example.com/approve",
        })
        assert isinstance(backend, WebhookBackend)

    def test_webhook_with_options(self):
        backend = get_backend({
            "approval_backend": "webhook",
            "approval_webhook_url": "http://example.com/approve",
            "approval_webhook_timeout": 60,
            "approval_webhook_secret": "secret123",
        })
        assert isinstance(backend, WebhookBackend)
        assert backend._timeout == 60.0
        assert backend._secret == "secret123"

    def test_webhook_missing_url_falls_back_to_block(self):
        backend = get_backend({"approval_backend": "webhook"})
        assert isinstance(backend, BlockBackend)

    def test_webhook_empty_url_falls_back_to_block(self):
        backend = get_backend({
            "approval_backend": "webhook",
            "approval_webhook_url": "",
        })
        assert isinstance(backend, BlockBackend)

    def test_unknown_backend_falls_back_to_block(self):
        backend = get_backend({"approval_backend": "nonexistent"})
        assert isinstance(backend, BlockBackend)


# ---------------------------------------------------------------------------
# ApprovalDecision enum
# ---------------------------------------------------------------------------

class TestApprovalDecision:
    def test_values(self):
        assert ApprovalDecision.APPROVED.value == "approved"
        assert ApprovalDecision.DENIED.value == "denied"
        assert ApprovalDecision.TIMEOUT.value == "timeout"
        assert ApprovalDecision.ERROR.value == "error"

    def test_members(self):
        assert len(ApprovalDecision) == 4


# ---------------------------------------------------------------------------
# CachedBackend
# ---------------------------------------------------------------------------

class TestCachedBackend:
    @pytest.fixture
    def cache(self, tmp_path):
        return ApprovalCache(tmp_path / "test-cache.json")

    @pytest.fixture
    def allow_backend(self):
        backend = MagicMock(spec=ApprovalBackend)
        backend.name = "log_only"
        backend.request_approval.return_value = ApprovalResponse(
            decision=ApprovalDecision.APPROVED,
            reason="Allowed by log_only policy",
            responder="log_only_backend",
        )
        return backend

    @pytest.fixture
    def deny_backend(self):
        backend = MagicMock(spec=ApprovalBackend)
        backend.name = "block"
        backend.request_approval.return_value = ApprovalResponse(
            decision=ApprovalDecision.DENIED,
            reason="Blocked by policy",
            responder="block_backend",
        )
        return backend

    def test_name_property(self, allow_backend, cache):
        cb = CachedBackend(allow_backend, cache)
        assert cb.name == "cached_log_only"

    def test_allow_cached_on_second_call(self, allow_backend, cache, sample_request):
        cb = CachedBackend(allow_backend, cache)

        # First call: cache miss, asks inner backend
        resp1 = cb.request_approval(sample_request)
        assert resp1.decision == ApprovalDecision.APPROVED
        assert allow_backend.request_approval.call_count == 1

        # Second call: should hit cache, inner backend NOT called again
        resp2 = cb.request_approval(sample_request)
        assert resp2.decision == ApprovalDecision.APPROVED
        assert "Cached approval" in resp2.reason
        assert allow_backend.request_approval.call_count == 1  # still 1

    def test_deny_not_cached(self, deny_backend, cache, sample_request):
        cb = CachedBackend(deny_backend, cache)

        # First call
        resp1 = cb.request_approval(sample_request)
        assert resp1.decision == ApprovalDecision.DENIED
        assert deny_backend.request_approval.call_count == 1

        # Second call: denial NOT cached, inner backend called again
        resp2 = cb.request_approval(sample_request)
        assert resp2.decision == ApprovalDecision.DENIED
        assert deny_backend.request_approval.call_count == 2

    def test_cache_ttl_expiration(self, allow_backend, cache, sample_request):
        cb = CachedBackend(allow_backend, cache, default_ttl=0.1)

        # First call caches the approval
        resp1 = cb.request_approval(sample_request)
        assert resp1.decision == ApprovalDecision.APPROVED
        assert allow_backend.request_approval.call_count == 1

        # Wait for TTL to expire
        time.sleep(0.15)

        # Second call: cache expired, inner backend called again
        resp2 = cb.request_approval(sample_request)
        assert resp2.decision == ApprovalDecision.APPROVED
        assert allow_backend.request_approval.call_count == 2

    def test_is_approval_backend(self, allow_backend, cache):
        cb = CachedBackend(allow_backend, cache)
        assert isinstance(cb, ApprovalBackend)

    def test_get_backend_with_cache_enabled(self, tmp_path):
        config = {
            "approval_backend": "log_only",
            "approval_cache_enabled": True,
            "approval_cache_ttl": 7200,
        }
        mock_cache = MagicMock()
        with patch(
            "hermes_aegis.approval.cache.ApprovalCache",
            return_value=mock_cache,
        ):
            backend = get_backend(config)
            assert isinstance(backend, CachedBackend)
            assert backend.name == "cached_log_only"
            assert backend._default_ttl == 7200.0
