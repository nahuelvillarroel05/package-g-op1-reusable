"""Frozen I2 machine and resource-law regression tests."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.i2_contract import (
    I2ContractError, RUN_MACHINE, SESSION_MACHINE, frozen_document,
    replay_budget,
)
from package_g.op1_reusable.identity import generate_id


def budget(**overrides):
    value = {
        "http_transactions": 4,
        "tcp_calibrations": 0,
        "udp_calibrations": 0,
        "pktmon_starts": 0,
        "channel_e_starts": 0,
        "job_starts": 0,
        "output_bytes": 400,
        "cpu_ms": 100,
        "elapsed_ms": 100,
        "memory_peak_bytes": 20,
        "max_concurrent_runs": 2,
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize("machine,legal,forbidden", [
    (SESSION_MACHINE, 6, 19),
    (RUN_MACHINE, 20, 205),
])
def test_exhaustive_frozen_state_pairs(machine, legal, forbidden):
    accepted = rejected = 0
    for previous in machine.states:
        for requested in machine.states:
            if (previous, requested) in machine.edges:
                machine.require(previous, requested)
                accepted += 1
            else:
                with pytest.raises(I2ContractError):
                    machine.require(previous, requested)
                rejected += 1
    assert (accepted, rejected) == (legal, forbidden)
    assert all(source not in machine.terminal_states for source, _ in machine.edges)


def test_frozen_claim_and_continuation_policy_are_present():
    assert frozen_document("OP1_RUN_CLAIM_POLICY.json")["claim_consumed_closes_run"] is True
    assert frozen_document("OP1_RUN_CLAIM_POLICY.json")["claim_consumed_does_not_automatically_terminate_session"] is True
    assert frozen_document("OP1_SESSION_CONTINUATION_POLICY.json")["quarantine_or_terminate"]["authority_integrity_failure"] == "QUARANTINE"


def test_budget_cumulative_and_active_reconstruct_without_refund():
    first, second = generate_id("RUN"), generate_id("RUN")
    reserve_first = {"kind": "RESERVE", "event_id": generate_id("EVENT"), "run_id": first,
                     "budget": budget(http_transactions=2, output_bytes=200, cpu_ms=50, elapsed_ms=50, memory_peak_bytes=12)}
    reserve_second = {"kind": "RESERVE", "event_id": generate_id("EVENT"), "run_id": second,
                      "budget": budget(http_transactions=2, output_bytes=200, cpu_ms=50, elapsed_ms=50, memory_peak_bytes=8)}
    close_first = {"kind": "RELEASE", "event_id": generate_id("EVENT"), "run_id": first,
                   "durable_terminal_event_id": generate_id("EVENT"), "cleanup_proven": True}
    view = replay_budget(budget(), 2, [reserve_first, reserve_second, close_first])
    assert view.runs_reserved == 2
    assert view.cumulative["http_transactions"] == 4
    assert view.cumulative["output_bytes"] == 400
    assert (view.active_memory, view.active_runs) == (8, 1)
    with pytest.raises(I2ContractError, match="max_runs"):
        replay_budget(budget(), 2, [reserve_first, reserve_second, close_first,
                                     {"kind": "RESERVE", "event_id": generate_id("EVENT"),
                                      "run_id": generate_id("RUN"), "budget": budget()}])


def test_unknown_consumption_and_cleanup_do_not_refund_without_proof():
    run_id = generate_id("RUN")
    reservation = {"kind": "RESERVE", "event_id": generate_id("EVENT"), "run_id": run_id,
                   "budget": budget(memory_peak_bytes=20)}
    view = replay_budget(budget(), 1, [reservation])
    assert (view.active_memory, view.active_runs) == (20, 1)
    with pytest.raises(I2ContractError, match="durable closure"):
        replay_budget(budget(), 1, [reservation,
            {"kind": "RELEASE", "event_id": generate_id("EVENT"), "run_id": run_id,
             "durable_terminal_event_id": generate_id("EVENT"), "cleanup_proven": False}])


def test_budget_race_projection_rejects_overcommit_and_reuse():
    first, second = generate_id("RUN"), generate_id("RUN")
    one = {"kind": "RESERVE", "event_id": generate_id("EVENT"), "run_id": first,
           "budget": budget(http_transactions=3, memory_peak_bytes=15)}
    over = {"kind": "RESERVE", "event_id": generate_id("EVENT"), "run_id": second,
            "budget": budget(http_transactions=2, memory_peak_bytes=6)}
    with pytest.raises(I2ContractError, match="cumulative"):
        replay_budget(budget(), 2, [one, over])
    with pytest.raises(I2ContractError, match="duplicate"):
        replay_budget(budget(), 2, [one, {**one, "event_id": generate_id("EVENT")}])


def test_schema_rejects_negative_or_unbounded_budget():
    run_id = generate_id("RUN")
    for malformed in (budget(output_bytes=-1), {**budget(), "extra": 1}):
        with pytest.raises(I2ContractError, match="schema rejected"):
            replay_budget(budget(), 1, [{"kind": "RESERVE", "event_id": generate_id("EVENT"),
                                         "run_id": run_id, "budget": malformed}])
