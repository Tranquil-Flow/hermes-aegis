"""Tests for Phase 5: Seccomp profiles + Reactive sequences.

Covers:
1. Seccomp profile generation (container/seccomp.py)
2. Container builder seccomp wiring
3. SequenceTrigger (reactive/sequences.py)
4. ReactiveAgentManager sequence evaluation
5. Updated default rules with sequences
6. Save/load round-trip serialization
7. Sequence rule validation
"""
from __future__ import annotations

import json
import time

import pytest

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.container.seccomp import (
    SECCOMP_PROFILE_PATH,
    generate_seccomp_profile,
)
from hermes_aegis.reactive.actions import CircuitBreakerExecutor
from hermes_aegis.reactive.manager import ReactiveAgentManager
from hermes_aegis.reactive.rules import (
    Trigger,
    ReactiveRule,
    default_rules,
    load_rules,
    save_rules,
)
from hermes_aegis.reactive.sequences import SequenceTrigger, Step


def _make_test_sequence() -> SequenceTrigger:
    """Helper: create a simple test SequenceTrigger."""
    return SequenceTrigger(
        steps=[
            Step(decision="BLOCKED", middleware="ProxyContentScanner"),
            Step(decision="DANGEROUS_COMMAND"),
        ],
        window="60s",
    )


import contextlib  # noqa: E402
import logging  # noqa: E402


@contextlib.contextmanager
def _capture_rules_warnings():
    """Capture WARNING records from hermes_aegis.reactive.rules.

    The reactive package's __init__.py installs a FileHandler on
    ``hermes_aegis.reactive`` and disables propagation, so pytest's caplog
    fixture cannot see records from this subtree. This helper attaches a
    list-collecting handler directly to the rules logger.
    """
    captured: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record.getMessage())

    h = _Capture(level=logging.WARNING)
    log = logging.getLogger("hermes_aegis.reactive.rules")
    prev_level = log.level
    log.setLevel(logging.WARNING)
    log.addHandler(h)
    try:
        yield captured
    finally:
        log.removeHandler(h)
        log.setLevel(prev_level)


def _collect_syscall_names(profile: dict) -> list[str]:
    """Extract blocked syscall names from a seccomp profile."""
    names = []
    for entry in profile.get("syscalls", []):
        if entry.get("action") == "SCMP_ACT_ERRNO":
            names.extend(entry.get("names", []))
    return names


# ---------------------------------------------------------------------------
# Seccomp profile
# ---------------------------------------------------------------------------

class TestSeccompProfile:
    """container/seccomp.py: generate_seccomp_profile() produces valid JSON."""

    def test_generates_valid_json(self):
        profile = generate_seccomp_profile()
        parsed = json.loads(profile)
        assert isinstance(parsed, dict)

    def test_has_required_fields(self):
        parsed = json.loads(generate_seccomp_profile())
        # Block-list: default is ALLOW, dangerous syscalls are explicitly blocked
        assert parsed["defaultAction"] == "SCMP_ACT_ALLOW"
        assert "syscalls" in parsed
        assert isinstance(parsed["syscalls"], list)

    def test_blocks_io_uring(self):
        names = _collect_syscall_names(json.loads(generate_seccomp_profile()))
        io_uring = [n for n in names if "io_uring" in n]
        assert len(io_uring) >= 2, f"Expected io_uring syscalls, got: {names}"

    def test_blocks_ptrace(self):
        names = _collect_syscall_names(json.loads(generate_seccomp_profile()))
        assert "ptrace" in names, f"ptrace not blocked: {names}"

    def test_blocks_bpf(self):
        names = _collect_syscall_names(json.loads(generate_seccomp_profile()))
        assert "bpf" in names, f"bpf not blocked: {names}"

    def test_blocks_keyring(self):
        names = _collect_syscall_names(json.loads(generate_seccomp_profile()))
        assert "keyctl" in names, f"keyctl not blocked: {names}"

    def test_block_list_default_allow(self):
        """Block-list profile: only blocked syscalls are listed, everything else is allowed."""
        parsed = json.loads(generate_seccomp_profile())
        assert len(parsed["syscalls"]) == 1
        assert parsed["syscalls"][0]["action"] == "SCMP_ACT_ERRNO"
        blocked = parsed["syscalls"][0]["names"]
        assert "read" not in blocked
        assert "write" not in blocked
        assert "openat" not in blocked

    def test_blocks_kernel_breakout_syscalls(self):
        """High-risk syscalls associated with container breakout / kernel exploits are blocked."""
        names = set(_collect_syscall_names(json.loads(generate_seccomp_profile())))
        for syscall in (
            "kexec_load",
            "kexec_file_load",
            "userfaultfd",
            "process_vm_readv",
            "process_vm_writev",
            "open_by_handle_at",
            "name_to_handle_at",
            "create_module",
            "umount",
        ):
            assert syscall in names, f"{syscall} should be blocked"

    def test_profile_is_deterministic(self):
        assert generate_seccomp_profile() == generate_seccomp_profile()

    def test_seccomp_file_path(self):
        assert "seccomp-aegis.json" in str(SECCOMP_PROFILE_PATH)

    def test_write_to_custom_path(self, tmp_path):
        """write_seccomp_profile writes to a custom path."""
        from hermes_aegis.container.seccomp import write_seccomp_profile
        custom = tmp_path / "custom-seccomp.json"
        result = write_seccomp_profile(custom)
        assert result == custom
        assert custom.exists()
        parsed = json.loads(custom.read_text())
        assert parsed["defaultAction"] == "SCMP_ACT_ALLOW"


# ---------------------------------------------------------------------------
# Container builder seccomp wiring
# ---------------------------------------------------------------------------

class TestContainerBuilderSeccomp:
    """Container builder applies seccomp when caller provides a profile path."""

    def test_build_run_args_includes_seccomp_when_path_given(self, tmp_path):
        from hermes_aegis.container.builder import build_run_args, ContainerConfig
        from hermes_aegis.container.seccomp import write_seccomp_profile
        config = ContainerConfig(workspace_path="/tmp/test")
        profile = write_seccomp_profile(tmp_path / "seccomp.json")
        args = build_run_args(config, seccomp_profile_path=profile)
        assert "security_opt" in args
        has_seccomp = any("seccomp" in opt for opt in args["security_opt"])
        assert has_seccomp, f"seccomp not in security_opt: {args['security_opt']}"

    def test_runner_materializes_profile_before_calling_build_run_args(self, tmp_path, monkeypatch):
        """ContainerRunner.start should be the side-effecting boundary, not build_run_args."""
        from hermes_aegis.container import seccomp as seccomp_mod
        target = tmp_path / "seccomp-aegis.json"
        monkeypatch.setattr(seccomp_mod, "SECCOMP_PROFILE_PATH", target)

        # Just exercise ensure_seccomp_profile directly — verifies the helper
        # writes only when missing and is idempotent on re-call.
        assert not target.exists()
        result = seccomp_mod.ensure_seccomp_profile()
        assert result == target
        assert target.exists()
        mtime = target.stat().st_mtime
        seccomp_mod.ensure_seccomp_profile()
        assert target.stat().st_mtime == mtime  # not rewritten


# ---------------------------------------------------------------------------
# SequenceTrigger
# ---------------------------------------------------------------------------

class TestSequenceTrigger:
    """reactive/sequences.py: SequenceTrigger matches ordered sequences."""

    def test_matches_simple_sequence(self):
        seq = SequenceTrigger(
            steps=[
                Step(decision="BLOCKED", middleware="ProxyContentScanner"),
                Step(decision="BLOCKED", middleware="ProxyContentScanner"),
            ],
            window="120s",
        )
        now = time.time()
        entries = [
            {"decision": "BLOCKED", "middleware": "ProxyContentScanner", "timestamp": now},
            {"decision": "BLOCKED", "middleware": "ProxyContentScanner", "timestamp": now + 0.1},
        ]
        assert seq.check(entries) is True

    def test_does_not_match_out_of_order(self):
        seq = SequenceTrigger(
            steps=[
                Step(decision="BLOCKED", middleware="ProxyContentScanner"),
                Step(decision="ANOMALY", middleware="RateLimiter"),
            ],
            window="120s",
        )
        now = time.time()
        entries = [
            {"decision": "ANOMALY", "middleware": "RateLimiter", "timestamp": now},
            {"decision": "BLOCKED", "middleware": "ProxyContentScanner", "timestamp": now + 0.1},
        ]
        assert seq.check(entries) is False

    def test_does_not_match_expired_window(self):
        seq = SequenceTrigger(
            steps=[
                Step(decision="BLOCKED", middleware="ProxyContentScanner"),
                Step(decision="BLOCKED", middleware="ProxyContentScanner"),
            ],
            window="2s",
        )
        now = time.time()
        entries = [
            {"decision": "BLOCKED", "middleware": "ProxyContentScanner", "timestamp": now - 10},
            {"decision": "BLOCKED", "middleware": "ProxyContentScanner", "timestamp": now},
        ]
        assert seq.check(entries) is False

    def test_matches_with_intervening_noise(self):
        seq = SequenceTrigger(
            steps=[
                Step(decision="BLOCKED", middleware="ProxyContentScanner"),
                Step(decision="ANOMALY", middleware="RateLimiter"),
            ],
            window="120s",
        )
        now = time.time()
        entries = [
            {"decision": "BLOCKED", "middleware": "ProxyContentScanner", "timestamp": now - 3},
            {"decision": "COMPLETED", "middleware": "AuditTrailMiddleware", "timestamp": now - 2},
            {"decision": "ANOMALY", "middleware": "RateLimiter", "timestamp": now},
        ]
        assert seq.check(entries) is True

    def test_partial_sequence_does_not_match(self):
        seq = SequenceTrigger(
            steps=[
                Step(decision="BLOCKED", middleware="ProxyContentScanner"),
                Step(decision="ANOMALY", middleware="RateLimiter"),
                Step(decision="DANGEROUS_COMMAND", middleware="DangerousBlockerMiddleware"),
            ],
            window="120s",
        )
        now = time.time()
        entries = [
            {"decision": "BLOCKED", "middleware": "ProxyContentScanner", "timestamp": now - 2},
            {"decision": "ANOMALY", "middleware": "RateLimiter", "timestamp": now},
        ]
        assert seq.check(entries) is False

    def test_window_seconds_property(self):
        seq = SequenceTrigger(steps=[], window="60s")
        assert seq.window_seconds == 60.0

    def test_step_matching_with_decision_in(self):
        seq = SequenceTrigger(
            steps=[
                Step(decision_in=["BLOCKED", "ANOMALY"]),
                Step(decision="DANGEROUS_COMMAND"),
            ],
            window="120s",
        )
        now = time.time()
        entries = [
            {"decision": "ANOMALY", "middleware": "RateLimiter", "timestamp": now - 2},
            {"decision": "DANGEROUS_COMMAND", "middleware": "DangerousBlockerMiddleware", "timestamp": now},
        ]
        assert seq.check(entries) is True

    def test_step_matching_with_middleware_in(self):
        seq = SequenceTrigger(
            steps=[
                Step(decision="BLOCKED", middleware_in=["ProxyContentScanner", "DomainAllowlist"]),
            ],
            window="120s",
        )
        now = time.time()
        entries = [
            {"decision": "BLOCKED", "middleware": "DomainAllowlist", "timestamp": now},
        ]
        assert seq.check(entries) is True

    def test_empty_entries_no_match(self):
        seq = SequenceTrigger(steps=[Step(decision="BLOCKED")], window="120s")
        assert seq.check([]) is False

    def test_empty_steps_no_match(self):
        seq = SequenceTrigger(steps=[], window="120s")
        assert seq.check([{"decision": "BLOCKED", "timestamp": time.time()}]) is False

    def test_step_with_no_filters_never_matches(self):
        """A step with all-None filters should never match."""
        step = Step()  # all None
        assert step.matches({"decision": "BLOCKED", "middleware": "test"}) is False

    def test_out_of_window_early_match_does_not_shadow_later_sequence(self):
        """An early step-0 match whose completion is out of window must not
        starve a later in-window sequence."""
        seq = SequenceTrigger(
            steps=[Step(decision="A"), Step(decision="B")],
            window="100s",
        )
        entries = [
            {"decision": "A", "middleware": "m", "timestamp": 0.0},
            {"decision": "X", "middleware": "m", "timestamp": 50.0},
            {"decision": "A", "middleware": "m", "timestamp": 200.0},
            {"decision": "B", "middleware": "m", "timestamp": 250.0},
        ]
        assert seq.check(entries) is True

    def test_repeated_step0_within_window_does_not_block_completion(self):
        """Multiple step-0 matches inside the window must still complete."""
        seq = SequenceTrigger(
            steps=[Step(decision="A"), Step(decision="B")],
            window="100s",
        )
        entries = [
            {"decision": "A", "middleware": "m", "timestamp": 0.0},
            {"decision": "A", "middleware": "m", "timestamp": 10.0},
            {"decision": "B", "middleware": "m", "timestamp": 20.0},
        ]
        assert seq.check(entries) is True

    def test_no_valid_completion_returns_false(self):
        """If no in-window completion exists, return False even with multiple starts."""
        seq = SequenceTrigger(
            steps=[Step(decision="A"), Step(decision="B")],
            window="50s",
        )
        entries = [
            {"decision": "A", "middleware": "m", "timestamp": 0.0},
            {"decision": "A", "middleware": "m", "timestamp": 100.0},
            {"decision": "B", "middleware": "m", "timestamp": 200.0},
        ]
        assert seq.check(entries) is False


# ---------------------------------------------------------------------------
# Default rules with sequences
# ---------------------------------------------------------------------------

class TestDefaultRulesSequences:
    """Default rules include sequence-based rules."""

    def test_default_rules_include_exfiltration_sequence(self):
        rules = default_rules()
        names = [r.name for r in rules]
        assert "exfiltration-sequence" in names

    def test_sequence_rule_has_sequence_trigger(self):
        rules = default_rules()
        seq_rule = next(r for r in rules if r.name == "exfiltration-sequence")
        assert seq_rule.sequence is not None
        assert isinstance(seq_rule.sequence, SequenceTrigger)
        assert len(seq_rule.sequence.steps) == 2

    def test_exfiltration_sequence_steps(self):
        rules = default_rules()
        seq_rule = next(r for r in rules if r.name == "exfiltration-sequence")
        seq = seq_rule.sequence
        assert seq.steps[0].decision == "BLOCKED"
        assert seq.steps[0].middleware == "ProxyContentScanner"
        assert seq.steps[1].decision == "DANGEROUS_COMMAND"


# ---------------------------------------------------------------------------
# Manager sequence evaluation (integration)
# ---------------------------------------------------------------------------

@pytest.fixture
def make_manager(tmp_path):
    """Create a ReactiveAgentManager with test infrastructure."""
    rules_path = tmp_path / "rules.json"
    audit_path = tmp_path / "audit.jsonl"

    def _make(rules: list[ReactiveRule]) -> tuple[ReactiveAgentManager, AuditTrail]:
        save_rules(rules_path, rules)
        audit_trail = AuditTrail(audit_path)
        executor = CircuitBreakerExecutor(audit_trail, hermes_pid=None)
        manager = ReactiveAgentManager(
            rules_path=rules_path,
            audit_trail=audit_trail,
            actions_executor=executor,
            agent_factory=lambda model, prompt, max_iterations: "Mock agent response",
        )
        return manager, audit_trail

    return _make


class TestManagerSequenceEvaluation:
    """ReactiveAgentManager.evaluate() fires sequence-based rules."""

    def test_sequence_rule_fires_on_matching_pattern(self, make_manager):
        """Sequence rule fires when entries match the ordered pattern."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                severity="critical",
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="BLOCKED"), Step(decision="DANGEROUS_COMMAND")],
                    window="120s",
                ),
                cooldown="0s",
                message_template="Sequence detected!",
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        fired = manager.evaluate({
            "decision": "BLOCKED", "middleware": "test", "timestamp": now - 1,
        })
        assert len(fired) == 0

        fired = manager.evaluate({
            "decision": "DANGEROUS_COMMAND", "middleware": "test", "timestamp": now,
        })
        assert len(fired) == 1
        assert fired[0].name == "test-sequence"

    def test_sequence_rule_respects_cooldown(self, make_manager):
        """Sequence rule does not re-fire within cooldown period."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                severity="critical",
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B")],
                    window="120s",
                ),
                cooldown="60s",
                message_template="Sequence detected!",
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now - 1})
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now})
        assert len(fired) == 1

        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now + 1})
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now + 2})
        assert len(fired) == 0

    def test_sequence_rule_does_not_fire_on_partial_match(self, make_manager):
        """Sequence rule does not fire if only first steps match."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B"), Step(decision="C")],
                    window="120s",
                ),
                cooldown="0s",
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now - 2})
        manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now - 1})
        fired = manager.evaluate({"decision": "X", "middleware": "t", "timestamp": now})
        assert len(fired) == 0

    def test_sequence_buffer_retains_entries_across_noise(self, make_manager):
        """Sequence buffer retains past entries for pattern matching."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B")],
                    window="120s",
                ),
                cooldown="0s",
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now - 5})
        manager.evaluate({"decision": "NOISE", "middleware": "t", "timestamp": now - 4})
        manager.evaluate({"decision": "NOISE", "middleware": "t", "timestamp": now - 3})
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now})
        assert len(fired) == 1

    def test_simple_and_sequence_rules_coexist(self, make_manager):
        """Simple trigger rules and sequence rules can fire on the same entry."""
        rules = [
            ReactiveRule(
                name="simple-rule",
                enabled=True,
                type="notify",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="0s",
                message_template="Simple: {decision}",
            ),
            ReactiveRule(
                name="seq-rule",
                enabled=True,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="BLOCKED"), Step(decision="ANOMALY")],
                    window="120s",
                ),
                cooldown="0s",
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        fired = manager.evaluate({
            "decision": "BLOCKED", "middleware": "t", "timestamp": now - 1,
        })
        assert len(fired) == 1
        assert fired[0].name == "simple-rule"

        fired = manager.evaluate({
            "decision": "ANOMALY", "middleware": "t", "timestamp": now,
        })
        seq_fired = [r for r in fired if r.name == "seq-rule"]
        assert len(seq_fired) == 1

    def test_timestamp_added_if_missing(self, make_manager):
        """Manager adds timestamp to entries that lack one."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B")],
                    window="120s",
                ),
                cooldown="0s",
            ),
        ]
        manager, _ = make_manager(rules)

        fired = manager.evaluate({"decision": "A", "middleware": "t"})
        assert len(fired) == 0
        fired = manager.evaluate({"decision": "B", "middleware": "t"})
        assert len(fired) == 1

    def test_disabled_sequence_rule_does_not_fire(self, make_manager):
        """Disabled sequence rule is skipped."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=False,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B")],
                    window="120s",
                ),
                cooldown="0s",
            ),
        ]
        manager, _ = make_manager(rules)

        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": time.time()})
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": time.time()})
        assert len(fired) == 0

    def test_matched_sequence_does_not_refire_on_unrelated_entry(self, make_manager):
        """Once a sequence has matched, later unrelated entries must not
        re-trigger the same already-consumed match (third-reviewer P1)."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B")],
                    window="120s",
                ),
                cooldown="0s",  # cooldown does NOT mask the bug
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        # First A — no match yet.
        fired = manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now})
        assert len(fired) == 0
        # First B — sequence completes, fires once.
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now + 1})
        assert len(fired) == 1
        # Unrelated NOISE — must NOT cause the buffer's [A, B] shape to refire.
        fired = manager.evaluate({"decision": "NOISE", "middleware": "t", "timestamp": now + 2})
        assert len(fired) == 0

    def test_fresh_sequence_after_match_does_fire(self, make_manager):
        """A genuinely new A→B (after the previous match was consumed) still fires."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B")],
                    window="120s",
                ),
                cooldown="0s",
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now})
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now + 1})
        assert len(fired) == 1

        # Fresh A then B — new events with later timestamps — should fire.
        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now + 10})
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now + 11})
        assert len(fired) == 1

    def test_cooldown_still_suppresses_but_consumes_buffer(self, make_manager):
        """When cooldown blocks side effects, the match is still consumed so
        the same shape will not fire again on later noise."""
        rules = [
            ReactiveRule(
                name="test-sequence",
                enabled=True,
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="A"), Step(decision="B")],
                    window="120s",
                ),
                cooldown="60s",
            ),
        ]
        manager, _ = make_manager(rules)

        now = time.time()
        # Pre-fire to install a cooldown.
        manager._cooldowns["test-sequence"] = now

        manager.evaluate({"decision": "A", "middleware": "t", "timestamp": now + 1})
        fired = manager.evaluate({"decision": "B", "middleware": "t", "timestamp": now + 2})
        assert len(fired) == 0  # suppressed by cooldown
        # Cooldown suppressed but the [A, B] shape was consumed. NOISE must
        # not retrigger it once the cooldown lapses.
        manager._cooldowns["test-sequence"] = now - 1000  # cooldown expired
        fired = manager.evaluate({"decision": "NOISE", "middleware": "t", "timestamp": now + 3})
        assert len(fired) == 0


# ---------------------------------------------------------------------------
# Save / load round-trip with sequences
# ---------------------------------------------------------------------------

class TestSequenceRuleSerialization:
    """Sequence rules survive save/load round-trip."""

    def test_save_load_round_trip(self, tmp_path):
        rules_path = tmp_path / "rules.json"
        rules = [
            ReactiveRule(
                name="seq-rule",
                type="investigate",
                trigger=Trigger(),
                sequence=_make_test_sequence(),
                cooldown="30m",
                severity="critical",
                model="anthropic/claude-sonnet-4-6",
                prompt="Investigate sequence",
                context="recent",
                allowed_actions=["kill_proxy"],
                require_justification=True,
            ),
        ]
        save_rules(rules_path, rules)
        loaded = load_rules(rules_path)

        assert len(loaded) == 1
        r = loaded[0]
        assert r.name == "seq-rule"
        assert r.sequence is not None
        assert isinstance(r.sequence, SequenceTrigger)
        assert len(r.sequence.steps) == 2
        assert r.sequence.window == "60s"
        assert r.sequence.steps[0].decision == "BLOCKED"
        assert r.sequence.steps[0].middleware == "ProxyContentScanner"
        assert r.sequence.steps[1].decision == "DANGEROUS_COMMAND"

    def test_save_load_preserves_decision_in(self, tmp_path):
        rules_path = tmp_path / "rules.json"
        rules = [
            ReactiveRule(
                name="multi-decision-seq",
                type="notify",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[
                        Step(decision_in=["BLOCKED", "ANOMALY"]),
                        Step(middleware_in=["RateLimiter", "DomainAllowlist"]),
                    ],
                    window="300s",
                ),
                cooldown="0s",
            ),
        ]
        save_rules(rules_path, rules)
        loaded = load_rules(rules_path)

        seq = loaded[0].sequence
        assert seq.steps[0].decision_in == ["BLOCKED", "ANOMALY"]
        assert seq.steps[1].middleware_in == ["RateLimiter", "DomainAllowlist"]

    def test_save_load_mixed_rules(self, tmp_path):
        """Mix of simple, threshold, and sequence rules round-trip correctly."""
        rules_path = tmp_path / "rules.json"
        rules = [
            ReactiveRule(
                name="simple-rule",
                type="notify",
                trigger=Trigger(decision="BLOCKED"),
                cooldown="2m",
            ),
            ReactiveRule(
                name="threshold-rule",
                type="investigate",
                trigger=Trigger(decision="ANOMALY", count=3, window="60s"),
                cooldown="10m",
                prompt="Investigate anomalies",
            ),
            ReactiveRule(
                name="sequence-rule",
                type="investigate",
                trigger=Trigger(),
                sequence=SequenceTrigger(
                    steps=[Step(decision="BLOCKED"), Step(decision="DANGEROUS_COMMAND")],
                    window="120s",
                ),
                cooldown="15m",
                severity="critical",
                prompt="Investigate sequence",
                allowed_actions=["kill_proxy"],
            ),
        ]
        save_rules(rules_path, rules)
        loaded = load_rules(rules_path)

        assert len(loaded) == 3
        assert loaded[0].sequence is None
        assert loaded[1].sequence is None
        assert loaded[2].sequence is not None
        assert loaded[1].trigger.is_threshold

    def test_default_rules_round_trip(self, tmp_path):
        """Default rules (including exfiltration-sequence) round-trip correctly."""
        rules_path = tmp_path / "rules.json"
        rules = default_rules()
        save_rules(rules_path, rules)
        loaded = load_rules(rules_path)

        assert len(loaded) == 4
        names = [r.name for r in loaded]
        assert "exfiltration-sequence" in names

        seq_rule = next(r for r in loaded if r.name == "exfiltration-sequence")
        assert seq_rule.sequence is not None
        assert len(seq_rule.sequence.steps) == 2
        assert seq_rule.severity == "critical"


# ---------------------------------------------------------------------------
# Sequence rule validation
# ---------------------------------------------------------------------------

class TestSequenceValidation:
    """_validate_rule catches sequence configuration errors."""

    def test_warns_on_empty_steps(self):
        from hermes_aegis.reactive.rules import _validate_rule
        warnings = _validate_rule({
            "name": "bad-seq",
            "type": "notify",
            "sequence": {"steps": [], "window": "120s"},
        })
        assert any("no steps" in w for w in warnings)

    def test_warns_on_step_with_no_filters(self):
        from hermes_aegis.reactive.rules import _validate_rule
        warnings = _validate_rule({
            "name": "bad-seq",
            "type": "notify",
            "sequence": {
                "steps": [{"decision": "BLOCKED"}, {}],
                "window": "120s",
            },
        })
        assert any("step 1 has no filters" in w for w in warnings)

    def test_warns_on_invalid_window(self):
        from hermes_aegis.reactive.rules import _validate_rule
        warnings = _validate_rule({
            "name": "bad-seq",
            "type": "notify",
            "sequence": {
                "steps": [{"decision": "BLOCKED"}],
                "window": "not_a_duration",
            },
        })
        assert any("invalid sequence window" in w for w in warnings)

    def test_no_warnings_on_valid_sequence(self):
        from hermes_aegis.reactive.rules import _validate_rule
        warnings = _validate_rule({
            "name": "good-seq",
            "type": "investigate",
            "severity": "critical",
            "sequence": {
                "steps": [
                    {"decision": "BLOCKED", "middleware": "ProxyContentScanner"},
                    {"decision": "DANGEROUS_COMMAND"},
                ],
                "window": "300s",
            },
            "allowed_actions": ["kill_proxy"],
        })
        assert len(warnings) == 0

    def test_warns_on_invalid_cooldown(self):
        from hermes_aegis.reactive.rules import _validate_rule
        warnings = _validate_rule({
            "name": "bad-cooldown",
            "type": "notify",
            "trigger": {"decision": "BLOCKED"},
            "cooldown": "wat",
        })
        assert any("invalid cooldown" in w for w in warnings)

    def test_warns_on_empty_trigger_without_sequence(self):
        from hermes_aegis.reactive.rules import _validate_rule
        warnings = _validate_rule({
            "name": "no-filters",
            "type": "notify",
            "trigger": {},
        })
        assert any("trigger has no filters" in w for w in warnings)

    def test_no_warning_on_empty_trigger_with_sequence(self):
        from hermes_aegis.reactive.rules import _validate_rule
        warnings = _validate_rule({
            "name": "seq-only",
            "type": "investigate",
            "severity": "critical",
            "trigger": {},
            "sequence": {
                "steps": [{"decision": "BLOCKED"}, {"decision": "DANGEROUS_COMMAND"}],
                "window": "120s",
            },
            "allowed_actions": ["kill_proxy"],
        })
        assert not any("trigger has no filters" in w for w in warnings)

    def test_load_rules_skips_invalid_cooldown(self, tmp_path):
        """A rule with an unparseable cooldown is skipped by load_rules so
        ReactiveAgentManager.evaluate cannot crash on it later (third-reviewer P1)."""
        import json as _json
        from hermes_aegis.reactive.rules import load_rules

        path = tmp_path / "rules.json"
        path.write_text(_json.dumps({"rules": [
            {"name": "bad", "type": "notify", "trigger": {"decision": "BLOCKED"}, "cooldown": "wat"},
            {"name": "good", "type": "notify", "trigger": {"decision": "BLOCKED"}, "cooldown": "5m"},
        ]}))

        with _capture_rules_warnings() as messages:
            loaded = load_rules(path)

        assert [r.name for r in loaded] == ["good"]
        assert any("invalid cooldown" in m for m in messages)

    def test_load_rules_skips_empty_trigger_without_sequence(self, tmp_path):
        """A non-sequence rule with no trigger filters fires on every audit
        entry — load_rules drops it (third-reviewer P1)."""
        import json as _json
        from hermes_aegis.reactive.rules import load_rules

        path = tmp_path / "rules.json"
        path.write_text(_json.dumps({"rules": [
            {"name": "no-filters", "type": "notify", "trigger": {}},
            {"name": "good", "type": "notify", "trigger": {"decision": "BLOCKED"}},
        ]}))

        with _capture_rules_warnings() as messages:
            loaded = load_rules(path)

        assert [r.name for r in loaded] == ["good"]
        assert any("trigger has no filters" in m for m in messages)

    def test_load_rules_accepts_legacy_rule_without_explicit_type(self, tmp_path):
        """A rule that omits 'type' must inherit the 'notify' default rather
        than being rejected as invalid (third-reviewer round-5 P2)."""
        import json as _json
        from hermes_aegis.reactive.rules import load_rules

        path = tmp_path / "rules.json"
        path.write_text(_json.dumps({"rules": [
            {"name": "legacy-notify", "trigger": {"decision": "BLOCKED"}},
        ]}))

        with _capture_rules_warnings() as messages:
            loaded = load_rules(path)

        assert [r.name for r in loaded] == ["legacy-notify"]
        assert loaded[0].type == "notify"
        assert not messages  # no warnings

    def test_validate_rule_still_rejects_bogus_explicit_type(self):
        """An explicit nonsense type still produces a warning."""
        from hermes_aegis.reactive.rules import _validate_rule

        warnings = _validate_rule({
            "name": "bogus",
            "type": "weird",
            "trigger": {"decision": "BLOCKED"},
        })
        assert any("invalid type 'weird'" in w for w in warnings)
