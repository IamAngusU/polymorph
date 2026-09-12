from __future__ import annotations

from datetime import UTC, datetime

import pytest

from polymorph.sync_state import (
    CheckpointConflict,
    CommitReceipt,
    RunLeaseBusy,
    SchedulePolicy,
    SyncStateError,
    SyncStateStore,
)


def _receipt(run_id: str, records: int = 2) -> CommitReceipt:
    return CommitReceipt(run_id, records, "2026-09-12T12:00:00Z")


def test_checkpoint_advances_only_with_compare_and_swap_and_is_idempotent(tmp_path) -> None:
    store = SyncStateStore(tmp_path / "sync.sqlite3")
    first = store.advance(
        "invoices-v1", expected_generation=0, next_cursor={"page": 2}, receipt=_receipt("run-1")
    )
    repeated = store.advance(
        "invoices-v1", expected_generation=0, next_cursor={"page": 2}, receipt=_receipt("run-1")
    )
    assert first == repeated
    assert first.generation == 1
    assert first.committed_records == 2

    with pytest.raises(CheckpointConflict, match="generation"):
        store.advance(
            "invoices-v1",
            expected_generation=0,
            next_cursor={"page": 3},
            receipt=_receipt("run-2"),
        )


def test_non_completed_result_cannot_create_commit_receipt() -> None:
    with pytest.raises(SyncStateError, match="non-completed"):
        CommitReceipt.from_result({"status": "unknown", "records_written": 1})


def test_run_lease_is_fenced_and_cursor_is_redacted_by_default(tmp_path) -> None:
    store = SyncStateStore(tmp_path / "sync.sqlite3")
    lease = store.claim("route")
    with pytest.raises(RunLeaseBusy):
        store.claim("route")
    store.release(lease)
    store.advance(
        "route", expected_generation=0, next_cursor={"token": "sensitive"}, receipt=_receipt("run")
    )
    payload = store.get("route").to_dict()  # type: ignore[union-attr]
    assert "cursor" not in payload
    assert "sensitive" not in str(payload)


def test_schedule_policy_uses_stable_route_jitter() -> None:
    policy = SchedulePolicy(3600, 120)
    previous = datetime(2026, 9, 12, tzinfo=UTC)
    assert policy.next_due("route-a", previous) == policy.next_due("route-a", previous)
