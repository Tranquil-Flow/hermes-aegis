"""Tests for the Tirith content scanner middleware."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, call

import pytest

from hermes_aegis.middleware.chain import CallContext
from hermes_aegis.middleware.tirith_scanner import (
    TirithCategory,
    TirithFinding,
    TirithScannerMiddleware,
    TirithSeverity,
    scan_all,
    scan_code_injection,
    scan_homograph_urls,
    scan_terminal_injection,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _ctx() -> CallContext:
    return CallContext(session_id="test-session")


def _make_trail() -> MagicMock:
    trail = MagicMock()
    trail.log = MagicMock()
    return trail


# ---------------------------------------------------------------------------
# 1. Homograph URL detection
# ---------------------------------------------------------------------------

class TestHomographURLs:
    def test_punycode_domain(self):
        text = "Visit https://xn--pple-43d.com/login for details."
        findings = scan_homograph_urls(text)
        assert len(findings) >= 1
        assert findings[0].category == TirithCategory.HOMOGRAPH_URL
        assert "punycode" in findings[0].description.lower() or "Punycode" in findings[0].description

    def test_cyrillic_lookalike_domain(self):
        # Domain with Cyrillic 'а' and 'е' instead of Latin
        text = "Go to https://\u0430ppl\u0435.com/page"
        findings = scan_homograph_urls(text)
        assert len(findings) >= 1
        assert findings[0].category == TirithCategory.HOMOGRAPH_URL
        assert findings[0].severity == TirithSeverity.CRITICAL

    def test_greek_lookalike(self):
        text = "Check https://g\u03bfogle.com/search"
        findings = scan_homograph_urls(text)
        assert len(findings) >= 1
        assert findings[0].category == TirithCategory.HOMOGRAPH_URL

    def test_mixed_script_domain(self):
        # Mix of Latin and Cyrillic in domain
        text = "See https://exam\u043fle.com"
        findings = scan_homograph_urls(text)
        assert len(findings) >= 1

    def test_clean_urls_pass(self):
        text = "Visit https://www.google.com and https://example.org/path?q=1"
        findings = scan_homograph_urls(text)
        assert len(findings) == 0

    def test_clean_url_with_path(self):
        text = "https://api.github.com/repos/owner/repo/pulls"
        findings = scan_homograph_urls(text)
        assert len(findings) == 0

    def test_multiple_urls_mixed(self):
        text = (
            "Safe: https://example.com "
            "Bad: https://xn--exmple-cua.com "
            "Also safe: https://python.org"
        )
        findings = scan_homograph_urls(text)
        assert len(findings) == 1
        assert "xn--" in findings[0].matched_text


# ---------------------------------------------------------------------------
# 2. Code injection detection
# ---------------------------------------------------------------------------

class TestCodeInjection:
    def test_eval_call(self):
        text = 'result = eval("2+2")'
        findings = scan_code_injection(text)
        assert len(findings) >= 1
        assert findings[0].category == TirithCategory.CODE_INJECTION

    def test_exec_call(self):
        text = 'exec("import os; os.system(\'rm -rf /\')")'
        findings = scan_code_injection(text)
        assert len(findings) >= 1

    def test_subprocess_popen(self):
        text = 'p = subprocess.Popen(["ls", "-la"])'
        findings = scan_code_injection(text)
        assert len(findings) >= 1

    def test_subprocess_run(self):
        text = 'subprocess.run(["curl", url], capture_output=True)'
        findings = scan_code_injection(text)
        assert len(findings) >= 1

    def test_os_system(self):
        text = 'os.system("whoami")'
        findings = scan_code_injection(text)
        assert len(findings) >= 1

    def test_dunder_import(self):
        text = '__import__("os").system("id")'
        findings = scan_code_injection(text)
        assert len(findings) >= 1
        assert any(f.severity == TirithSeverity.CRITICAL for f in findings)

    def test_obfuscated_base64_eval(self):
        text = 'eval(base64.b64decode("aW1wb3J0IG9z").decode())'
        findings = scan_code_injection(text)
        assert len(findings) >= 1

    def test_string_concat_eval(self):
        text = """eval("__imp" + "ort__" + "('os')")"""
        findings = scan_code_injection(text)
        assert len(findings) >= 1

    def test_safe_code_passes(self):
        text = 'x = sum([1, 2, 3])\nprint(x)\nresult = len("hello")'
        findings = scan_code_injection(text)
        assert len(findings) == 0

    def test_getattr_builtins(self):
        text = 'getattr(__builtins__, "eval")("print(1)")'
        findings = scan_code_injection(text)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# 3. Terminal injection detection
# ---------------------------------------------------------------------------

class TestTerminalInjection:
    def test_ansi_escape_literal(self):
        text = "Normal text \x1b[2J\x1b[H hidden"
        findings = scan_terminal_injection(text)
        assert len(findings) >= 1
        assert findings[0].category == TirithCategory.TERMINAL_INJECTION

    def test_ansi_color_codes(self):
        text = "Some \x1b[31mred\x1b[0m text"
        findings = scan_terminal_injection(text)
        assert len(findings) >= 1

    def test_ansi_escape_string_literal(self):
        text = r"Run this: echo -e '\x1b[2J\x1b[H'"
        findings = scan_terminal_injection(text)
        assert len(findings) >= 1

    def test_octal_escape_string_literal(self):
        text = r"Try: printf '\033[2J\033[H'"
        findings = scan_terminal_injection(text)
        assert len(findings) >= 1

    def test_raw_control_character(self):
        text = "Hidden \x00 null and \x7f delete"
        findings = scan_terminal_injection(text)
        assert len(findings) >= 1

    def test_clean_text_passes(self):
        text = "This is perfectly normal text with\nnewlines and\ttabs."
        findings = scan_terminal_injection(text)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# 4. Middleware mode=detect (log only, no modification)
# ---------------------------------------------------------------------------

class TestDetectMode:
    def test_detect_logs_but_doesnt_modify(self):
        trail = _make_trail()
        mw = TirithScannerMiddleware(trail=trail, mode="detect")
        text = 'eval("bad code")'
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        # Result unchanged
        assert result == text
        # But trail was called
        trail.log.assert_called()

    def test_detect_homograph_logs(self):
        trail = _make_trail()
        mw = TirithScannerMiddleware(trail=trail, mode="detect")
        text = "Visit https://xn--pple-43d.com"
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert result == text
        trail.log.assert_called()
        log_args = trail.log.call_args
        assert log_args.kwargs["decision"] == "TIRITH_DETECT"

    def test_clean_text_no_logging(self):
        trail = _make_trail()
        mw = TirithScannerMiddleware(trail=trail, mode="detect")
        text = "Normal safe text"
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert result == text
        trail.log.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Middleware mode=block (redact findings)
# ---------------------------------------------------------------------------

class TestBlockMode:
    def test_block_redacts_eval(self):
        mw = TirithScannerMiddleware(mode="block")
        text = 'Run this: eval("payload")'
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert "eval(" not in result
        assert "[TIRITH_REDACTED]" in result

    def test_block_redacts_url(self):
        mw = TirithScannerMiddleware(mode="block")
        text = "Click https://xn--pple-43d.com/login to continue"
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert "xn--" not in result
        assert "[TIRITH_REDACTED]" in result

    def test_block_redacts_ansi(self):
        mw = TirithScannerMiddleware(mode="block")
        text = "Output: \x1b[31mred\x1b[0m"
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert "\x1b[" not in result

    def test_block_handles_dict_result(self):
        mw = TirithScannerMiddleware(mode="block")
        result_dict = {"output": 'eval("bad")', "status": "ok"}
        result = _run(mw.post_dispatch("tool", {}, result_dict, _ctx()))
        assert isinstance(result, dict)
        assert "eval(" not in result["output"]
        assert result["status"] == "ok"

    def test_block_preserves_clean_text(self):
        mw = TirithScannerMiddleware(mode="block")
        text = "Perfectly safe output"
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert result == text


# ---------------------------------------------------------------------------
# 6. Audit trail integration
# ---------------------------------------------------------------------------

class TestAuditTrailIntegration:
    def test_finding_logged_with_category(self):
        trail = _make_trail()
        mw = TirithScannerMiddleware(trail=trail, mode="detect")
        text = 'exec("bad")'
        _run(mw.post_dispatch("terminal", {}, text, _ctx()))
        trail.log.assert_called()
        kwargs = trail.log.call_args.kwargs
        assert kwargs["decision"] == "TIRITH_DETECT"
        assert kwargs["middleware"] == "TirithScannerMiddleware"
        assert kwargs["args_redacted"]["category"] == "code_injection"

    def test_no_trail_doesnt_crash(self):
        mw = TirithScannerMiddleware(trail=None, mode="detect")
        text = 'eval("bad")'
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert result == text  # No crash, result unchanged


# ---------------------------------------------------------------------------
# 7. Multiple findings in same text
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    def test_code_and_url_findings(self):
        text = (
            "Download from https://xn--pple-43d.com and run: "
            'eval("import os")'
        )
        findings = scan_all(text)
        categories = {f.category for f in findings}
        assert TirithCategory.HOMOGRAPH_URL in categories
        assert TirithCategory.CODE_INJECTION in categories

    def test_all_three_categories(self):
        text = (
            "Visit https://xn--test-cua.com, then run "
            'exec("os.system(\'id\')") and see \x1b[2Joutput'
        )
        findings = scan_all(text)
        categories = {f.category for f in findings}
        assert TirithCategory.HOMOGRAPH_URL in categories
        assert TirithCategory.CODE_INJECTION in categories
        assert TirithCategory.TERMINAL_INJECTION in categories

    def test_block_redacts_all_findings(self):
        mw = TirithScannerMiddleware(mode="block")
        text = 'eval("bad") and https://xn--test-cua.com'
        result = _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert "eval(" not in result
        assert "xn--" not in result

    def test_multiple_findings_all_logged(self):
        trail = _make_trail()
        mw = TirithScannerMiddleware(trail=trail, mode="detect")
        text = 'eval("x") and exec("y")'
        _run(mw.post_dispatch("tool", {}, text, _ctx()))
        assert trail.log.call_count >= 2


# ---------------------------------------------------------------------------
# 8. Edge cases and invalid mode
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="Invalid mode"):
            TirithScannerMiddleware(mode="invalid")

    def test_non_text_result_passthrough(self):
        mw = TirithScannerMiddleware(mode="block")
        result = _run(mw.post_dispatch("tool", {}, 42, _ctx()))
        assert result == 42

    def test_none_result_passthrough(self):
        mw = TirithScannerMiddleware(mode="block")
        result = _run(mw.post_dispatch("tool", {}, None, _ctx()))
        assert result is None

    def test_dict_without_text_keys_passthrough(self):
        mw = TirithScannerMiddleware(mode="block")
        result = _run(mw.post_dispatch("tool", {}, {"code": 0}, _ctx()))
        assert result == {"code": 0}
