from __future__ import annotations

import io
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from polymorph.errors import IntegrityError
from polymorph.observability import EventStream, OperationalEvent
from polymorph.workflow_benchmark import run_workflow_benchmark

_RUN_A = "01" * 16
_RUN_B = "02" * 16
_NOW = datetime(2026, 9, 10, 12, 30, tzinfo=UTC)


def test_event_stream_round_trip_is_bounded_and_payload_free(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    stream = EventStream(path, run_id=_RUN_A, clock=lambda: _NOW)
    correlation_id = stream.correlation_id("private-record-reference")

    first = stream.emit(
        component="destination_runtime",
        event_type="delivery",
        status="quarantined",
        correlation_id=correlation_id,
        reason_code="write_outcome_unknown",
        duration_ms=1.25,
        item_count=1,
    )
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_completed",
        status="failed",
        correlation_id=stream.correlation_id("workflow"),
        reason_code="write_outcome_unknown",
        item_count=0,
    )

    reopened = EventStream(path, run_id=_RUN_A)
    events = reopened.read()
    assert events[0] == first
    assert len(events) == 2
    assert correlation_id == stream.correlation_id("private-record-reference")
    summary = reopened.summary(run_id=_RUN_A).as_dict()
    assert summary == {
        "run_id": _RUN_A,
        "events": 2,
        "components": {"destination_runtime": 1, "workflow_benchmark": 1},
        "event_types": {"delivery": 1, "workflow_completed": 1},
        "statuses": {"failed": 1, "quarantined": 1},
        "reasons": {"write_outcome_unknown": 2},
        "first_timestamp": _NOW.isoformat(),
        "last_timestamp": _NOW.isoformat(),
        "first_event_type": "delivery",
        "last_event_type": "workflow_completed",
        "workflow_lifecycle_valid": False,
        "event_ids_unique": True,
        "duplicate_event_ids": 0,
        "event_contract_valid": True,
        "workflow_counts_valid": None,
    }
    raw = path.read_text(encoding="utf-8")
    assert "private-record-reference" not in raw
    assert all(len(line.encode("utf-8")) <= 4096 for line in raw.splitlines())
    assert path.read_bytes().endswith(b"\n")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("component", "Destination Runtime"),
        ("event_type", "delivery.ok"),
        ("status", ""),
        ("reason_code", "raw exception: customer@example.test"),
        ("duration_ms", float("inf")),
        ("item_count", -1),
    ],
)
def test_event_stream_rejects_unbounded_or_non_machine_fields(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    stream = EventStream(tmp_path / "events.jsonl", run_id=_RUN_A, clock=lambda: _NOW)
    arguments: dict[str, object] = {
        "component": "runtime",
        "event_type": "delivery",
        "status": "passed",
        "reason_code": None,
        "duration_ms": 1.0,
        "item_count": 1,
    }
    arguments[field] = value

    with pytest.raises(ValueError):
        stream.emit(**arguments)  # type: ignore[arg-type]

    assert not stream.path.exists()


def test_event_reader_rejects_extra_fields(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    stream = EventStream(path, run_id=_RUN_A, clock=lambda: _NOW)
    event = stream.emit(component="runtime", event_type="delivery", status="passed")
    payload = event.as_dict()
    payload["payload"] = "must-never-be-accepted"

    with pytest.raises(IntegrityError, match="field set"):
        OperationalEvent.from_dict(payload)


def test_event_reader_rejects_duplicate_json_fields(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
    stream = EventStream(path, run_id=_RUN_A)

    with pytest.raises(IntegrityError, match="duplicate field"):
        stream.read()
    with pytest.raises(IntegrityError, match="duplicate field"):
        stream.emit(component="runtime", event_type="delivery", status="passed")


def test_event_reader_wraps_excessive_json_nesting(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"[" * 1100 + b"0" + b"]" * 1100 + b"\n")
    stream = EventStream(path, run_id=_RUN_A)

    with pytest.raises(IntegrityError, match="line 1 is invalid JSON"):
        stream.read()


def test_event_reader_wraps_timestamp_normalization_overflow() -> None:
    event = OperationalEvent(
        event_id="03" * 16,
        run_id=_RUN_A,
        correlation_id="04" * 16,
        timestamp=_NOW,
        component="workflow_benchmark",
        event_type="workflow_started",
        status="started",
        item_count=0,
    ).as_dict()
    event["timestamp"] = "9999-12-31T23:59:59-23:59"

    with pytest.raises(IntegrityError, match="field validation failed"):
        OperationalEvent.from_dict(event)


def test_incomplete_tail_is_neither_accepted_nor_extended(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    incomplete = b'{"schema_version":1'
    path.write_bytes(incomplete)
    stream = EventStream(path, run_id=_RUN_A, clock=lambda: _NOW)

    with pytest.raises(IntegrityError, match="incomplete tail"):
        stream.read()
    with pytest.raises(IntegrityError, match="incomplete tail"):
        stream.emit(component="runtime", event_type="delivery", status="passed")

    assert path.read_bytes() == incomplete


@pytest.mark.parametrize("terminated", [False, True])
def test_event_reader_rejects_oversized_records_without_unbounded_reads(
    tmp_path: Path,
    terminated: bool,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"x" * (1024 * 1024) + (b"\n" if terminated else b""))
    stream = EventStream(path, run_id=_RUN_A)

    with pytest.raises(IntegrityError, match="line 1 exceeds the size limit"):
        stream.read()


def test_event_parser_caps_the_underlying_line_read() -> None:
    class GuardedBytesIO(io.BytesIO):
        requested_sizes: list[int]

        def __init__(self, value: bytes) -> None:
            super().__init__(value)
            self.requested_sizes = []

        def readline(self, size: int = -1, /) -> bytes:
            self.requested_sizes.append(size)
            if size < 0 or size > 4097:
                raise AssertionError("event parser attempted an unbounded read")
            return super().readline(size)

    handle = GuardedBytesIO(b"x" * (1024 * 1024))

    with pytest.raises(IntegrityError, match="line 1 exceeds the size limit"):
        tuple(EventStream._iter_handle(handle))

    assert handle.requested_sizes == [4097]


def test_writer_revalidates_after_detected_in_place_change(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    stream = EventStream(path, run_id=_RUN_A, clock=lambda: _NOW)
    stream.emit(component="runtime", event_type="delivery", status="passed")
    original = path.read_bytes()
    before = path.stat()
    path.write_bytes(b"[" + original[1:])
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))

    with pytest.raises(IntegrityError, match="invalid JSON"):
        stream.emit(component="runtime", event_type="delivery", status="passed")

    assert path.read_bytes() == b"[" + original[1:]


def test_cooperative_thread_writers_produce_complete_json_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    first = EventStream(path, run_id=_RUN_A, clock=lambda: _NOW)
    second = EventStream(path, run_id=_RUN_B, clock=lambda: _NOW)

    def write_events(stream: EventStream) -> None:
        for index in range(12):
            stream.emit(
                component="worker",
                event_type="record_observed",
                status="passed",
                correlation_id=stream.correlation_id(f"record:{index}"),
                item_count=1,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write_events, stream) for stream in (first, second)]
        for future in futures:
            future.result()

    assert len(first.read()) == 24
    assert first.summary(run_id=_RUN_A).events == 12
    assert first.summary(run_id=_RUN_B).events == 12


def test_workflow_persists_correlated_operational_history(tmp_path: Path) -> None:
    work_dir = tmp_path / "workflow"
    report, _ = run_workflow_benchmark(records=2, batch_size=1, work_dir=work_dir)

    assert report.success
    observability = report.observability
    assert observability["stream_valid"] is True
    assert observability["run_closed"] is True
    assert observability["workflow_lifecycle_valid"] is True
    assert observability["event_ids_unique"] is True
    assert observability["duplicate_event_ids"] == 0
    assert observability["event_contract_valid"] is True
    assert observability["workflow_counts_valid"] is True
    assert observability["durable_appends"] is True
    assert observability["failure_reason_code"] is None
    assert observability["event_types"]["workflow_started"] == 1
    assert observability["event_types"]["workflow_completed"] == 1
    assert observability["event_types"]["batch_completed"] == 2
    assert observability["event_types"]["delivery"] == 2
    assert observability["components"]["destination_runtime"] == 2
    assert report.final_state["storage_bytes"]["operational_events"] > 0

    path = work_dir / "operational-events.jsonl"
    events = EventStream(path, run_id=str(observability["run_id"])).read()
    assert {event.run_id for event in events} == {observability["run_id"]}
    workflow_events = [event for event in events if event.component == "workflow_benchmark"]
    lifecycle = [
        event
        for event in workflow_events
        if event.event_type in {"workflow_started", "workflow_completed"}
    ]
    assert len(lifecycle) == 2
    assert lifecycle[0].correlation_id == lifecycle[1].correlation_id
    delivery_events = [event for event in events if event.event_type == "delivery"]
    assert len({event.correlation_id for event in delivery_events}) == 2
    raw = path.read_text(encoding="utf-8")
    assert "polymorph-canary-customer-001@example.test" not in raw
    assert str(work_dir.resolve()) not in raw


def test_unknown_workflow_stage_component_invalidates_event_contract(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    stream = EventStream(path, run_id=_RUN_A, clock=lambda: _NOW)
    workflow_id = stream.correlation_id("workflow")
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_started",
        status="started",
        correlation_id=workflow_id,
        item_count=0,
    )
    stream.emit(
        component="totally_made_up_stage",
        event_type="stage_summary",
        status="passed",
        correlation_id=stream.correlation_id("stage:fake"),
        duration_ms=0,
        item_count=0,
    )
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_completed",
        status="passed",
        correlation_id=workflow_id,
        item_count=0,
    )

    assert stream.summary(run_id=_RUN_A).event_contract_valid is False


def test_workflow_reports_a_delivery_event_gap_without_retrying_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_emit = EventStream.emit

    def fail_delivery_event(self: EventStream, **arguments: object) -> OperationalEvent:
        if arguments.get("component") == "destination_runtime":
            raise OSError("private event sink failure")
        return original_emit(self, **arguments)  # type: ignore[arg-type]

    monkeypatch.setattr(EventStream, "emit", fail_delivery_event)
    report, resources = run_workflow_benchmark(
        records=1,
        batch_size=1,
        work_dir=tmp_path / "event-failure",
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "destination_operational_event_check"
    assert report.failure.reason_code == "destination_operational_event_status_unexpected"
    assert report.records_delivered == 1
    assert report.records_acknowledged == 1
    assert resources.result_count == 1
    assert report.final_state["destination_rows"] == 1
    assert report.final_state["ledger_committed"] == 1
    assert report.observability["stream_valid"] is True
    assert report.observability["run_closed"] is False
    assert (
        report.observability["failure_reason_code"]
        == "destination_operational_event_status_unexpected"
    )
    assert "private event sink failure" not in json.dumps(report.as_dict(), sort_keys=True)


def test_workflow_detects_silent_destination_event_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_append = EventStream.append

    def drop_destination_event(self: EventStream, event: OperationalEvent) -> None:
        if event.component != "destination_runtime":
            original_append(self, event)

    monkeypatch.setattr(EventStream, "append", drop_destination_event)
    report, resources = run_workflow_benchmark(
        records=1,
        batch_size=1,
        work_dir=tmp_path / "silent-event-loss",
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.reason_code == "observability_event_count_mismatch"
    assert report.records_delivered == 1
    assert report.final_state["destination_rows"] == 1
    assert report.final_state["ledger_committed"] == 1
    assert report.observability["stream_valid"] is True
    assert report.observability["workflow_lifecycle_valid"] is True
    assert report.observability["workflow_counts_valid"] is False
    assert report.observability["run_closed"] is False
    assert resources.result_count == 1
