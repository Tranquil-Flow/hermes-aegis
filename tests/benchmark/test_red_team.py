"""Pytest wrapper for red-team benchmark scenarios.

Allows the benchmark to run as part of CI via ``pytest tests/benchmark/``.
"""
from __future__ import annotations

import pytest

from tests.benchmark.red_team import (
    ALL_SCENARIOS,
    ScenarioResult,
    compute_scores,
    run_all_scenarios,
)


# Build a list of (id, callable) for parametrize
_SCENARIO_IDS = [fn.__name__.removeprefix("scenario_") for fn in ALL_SCENARIOS]


@pytest.mark.parametrize("scenario_fn", ALL_SCENARIOS, ids=_SCENARIO_IDS)
def test_scenario_blocks(scenario_fn):
    """Each individual scenario must be blocked by Aegis."""
    result: ScenarioResult = scenario_fn()
    assert result.aegis_result == "blocked", (
        f"Scenario '{result.name}' was NOT blocked by Aegis. "
        f"Details: {result.details}"
    )


def test_all_scenarios_aggregate():
    """Aggregate: 100% of red-team scenarios must be blocked."""
    results = run_all_scenarios()
    scores = compute_scores(results)
    failed = [r.name for r in results if r.aegis_result != "blocked"]
    assert scores["aegis_block_rate"] == 1.0, (
        f"Aegis block rate is {scores['aegis_block_rate']*100:.0f}%, "
        f"expected 100%. Failed scenarios: {failed}"
    )


def test_bare_has_no_protection():
    """Sanity check: bare (no protection) should leak everything."""
    results = run_all_scenarios()
    scores = compute_scores(results)
    assert scores["bare_block_rate"] == 0.0, (
        "Expected bare (no protection) to block nothing."
    )
