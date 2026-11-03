import json
from pathlib import Path

import pytest

from runtime.candidate.run_framework.resources import (
    MAX_SCALE_BYTES,
    ResourceGuard,
    ResourceLimitStop,
    STOP_RECORD,
)


def test_budget_admits_whole_transaction_and_accounts_actual_files(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    guard = ResourceGuard(root, max_bytes=256, stop_reserve_bytes=128)
    receipt = root / "receipt.json"
    journal = root / "journal.jsonl"
    guard.before_publication(128)
    receipt.write_bytes(b"r" * 30)
    guard.account_write(receipt, 30)
    journal.write_bytes(b"j" * 10)
    guard.account_write(journal, 10)
    guard.finish_publication()
    assert guard.actual_bytes == 40
    assert guard.remaining_bytes == 88


def test_insufficient_transaction_budget_stops_before_any_publication(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    guard = ResourceGuard(root, max_bytes=256, stop_reserve_bytes=128)
    with pytest.raises(ResourceLimitStop) as stopped:
        guard.before_publication(129)
    assert stopped.value.reason == "BYTE_BUDGET_EXHAUSTED"
    assert list(root.iterdir()) == [root / STOP_RECORD]
    assert json.loads((root / STOP_RECORD).read_bytes())["reason"] == stopped.value.reason
    with pytest.raises(ResourceLimitStop) as stopped_again:
        guard.before_publication(1)
    assert stopped_again.value.reason == "BYTE_BUDGET_EXHAUSTED"


def test_actual_size_overrun_stops_and_retains_integrity_evidence(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    guard = ResourceGuard(root, max_bytes=256, stop_reserve_bytes=128)
    target = root / "oversized.tmp"
    guard.before_publication(20)
    target.write_bytes(b"x" * 20)
    with pytest.raises(ResourceLimitStop) as stopped:
        guard.account_write(target, 10)
    assert stopped.value.reason == "INTEGRITY_FAILURE"
    assert (root / STOP_RECORD).exists()


def test_duration_unit_error_and_explicit_stop_reasons(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    now = [10.0]
    guard = ResourceGuard(root, max_bytes=256, max_seconds=2, stop_reserve_bytes=128,
                          clock=lambda: now[0])
    now[0] = 12.0
    with pytest.raises(ResourceLimitStop) as stopped:
        guard.check_limits()
    assert stopped.value.reason == "DURATION_LIMIT_REACHED"

    another = tmp_path / "another"
    another.mkdir()
    units = ResourceGuard(another, max_bytes=256, max_units=3, stop_reserve_bytes=128)
    with pytest.raises(ResourceLimitStop) as stopped:
        units.check_limits(unit_count=3)
    assert stopped.value.reason == "UNIT_LIMIT_REACHED"

    third = tmp_path / "third"
    third.mkdir()
    errors = ResourceGuard(third, max_bytes=256, max_errors=1, stop_reserve_bytes=128)
    with pytest.raises(ResourceLimitStop) as stopped:
        errors.check_limits(error_count=1)
    assert stopped.value.reason == "ERROR_LIMIT_REACHED"

    fourth = tmp_path / "fourth"
    fourth.mkdir()
    explicit = ResourceGuard(fourth, max_bytes=256, stop_reserve_bytes=128)
    with pytest.raises(ResourceLimitStop) as stopped:
        explicit.request_stop("EXTERNAL_INTERRUPTION", {"source": "test"})
    assert stopped.value.reason == "EXTERNAL_INTERRUPTION"
    assert json.loads((fourth / STOP_RECORD).read_bytes())["details"] == {"source": "test"}


def test_scale_cap_and_malformed_limits_are_rejected(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    with pytest.raises(ValueError, match="20 GiB"):
        ResourceGuard(root, max_bytes=MAX_SCALE_BYTES + 1)
    with pytest.raises(ValueError, match="positive integer"):
        ResourceGuard(root, max_units=True)
    with pytest.raises(ValueError, match="positive number"):
        ResourceGuard(root, max_seconds=float("nan"))


def test_reparse_entries_are_integrity_stop(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"x")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ResourceLimitStop) as stopped:
        ResourceGuard(root, max_bytes=1024, stop_reserve_bytes=128)
    assert stopped.value.reason == "INTEGRITY_FAILURE"


def test_explicit_registry_path_is_included_and_recovered_read_only(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    registry = tmp_path / "registry"
    registry.mkdir()
    marker = registry / "attempt.json"
    marker.write_bytes(b"marker")
    guard = ResourceGuard(root, max_bytes=1024, stop_reserve_bytes=128,
                          accounted_paths=[registry])
    assert guard.actual_bytes == 6
    before = marker.read_bytes()
    recovered = ResourceGuard(root, max_bytes=1024, stop_reserve_bytes=128,
                              accounted_paths=[registry])
    assert recovered.actual_bytes == 6
    assert marker.read_bytes() == before


def test_persisted_stop_is_honored_and_read_only_refresh_never_writes(tmp_path):
    root = tmp_path / "campaign"
    root.mkdir()
    stopped = ResourceGuard(root, max_bytes=1024, stop_reserve_bytes=128)
    with pytest.raises(ResourceLimitStop):
        stopped.request_stop("EXTERNAL_INTERRUPTION", {"source": "external"})
    stop_bytes = (root / STOP_RECORD).read_bytes()
    resumed = ResourceGuard(root, max_bytes=1024, stop_reserve_bytes=128)
    with pytest.raises(ResourceLimitStop) as blocked:
        resumed.before_publication(1)
    assert blocked.value.reason == "EXTERNAL_INTERRUPTION"
    assert (root / STOP_RECORD).read_bytes() == stop_bytes

    large = tmp_path / "read-only"
    large.mkdir()
    (large / "existing.bin").write_bytes(b"x" * 10)
    recovery = ResourceGuard(large, max_bytes=200, stop_reserve_bytes=128, read_only=True)
    assert recovery.refresh_usage() == 10
    assert not (large / STOP_RECORD).exists()
    with pytest.raises(ResourceLimitStop, match="read-only"):
        recovery.before_publication(1)
