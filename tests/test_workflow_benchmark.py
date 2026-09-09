from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import pytest

import polymorph.workflow_benchmark as workflow_benchmark
from polymorph.audit import AuditEvent, AuditLog
from polymorph.cli import build_parser
from polymorph.connectors.base import DeliveryContext
from polymorph.connectors.csv_file import CsvConnector
from polymorph.connectors.database import DatabaseConnector
from polymorph.content import ContentInspector
from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.mapping import MappingDecision
from polymorph.models.schema import SchemaDescriptor
from polymorph.workflow_benchmark import run_workflow_benchmark


def _stage_names(payload: dict[str, object]) -> list[str]:
    stages = payload["stages"]
    assert isinstance(stages, list)
    return [str(stage["name"]) for stage in stages if isinstance(stage, dict)]


def test_real_workflow_benchmark_crosses_every_durable_boundary(tmp_path: Path) -> None:
    work_dir = tmp_path / "workflow"
    report, resources = run_workflow_benchmark(
        records=4,
        batch_size=2,
        work_dir=work_dir,
    )

    payload = report.as_dict()
    assert report.success
    assert report.records_delivered == 4
    assert report.records_acknowledged == 4
    assert report.batches_completed == 2
    assert payload["mapping"] == {
        "source_fields": 5,
        "target_fields": 6,
        "auto": 5,
        "review": 0,
        "blocked": 0,
    }
    assert payload["preflight"] == {
        "records_checked": 4,
        "complete_scan": True,
        "promotable": True,
        "blocking_findings": 0,
        "review_findings": 0,
    }
    final_state = payload["final_state"]
    expected_state = {
        "destination_rows": 4,
        "content_verified": True,
        "mismatch_count": 0,
        "ledger_committed": 4,
        "outbox_depth": 0,
        "relay_depth": 0,
        "quarantine_depth": 0,
        "audit_events": 4,
        "audit_signatures_verified": True,
        "known_plaintext_canaries_absent": True,
    }
    assert {key: final_state[key] for key in expected_state} == expected_state
    storage = final_state["storage_bytes"]
    assert storage["source_fixture"] > 0
    assert storage["destination"] > 0
    assert storage["audit"] > 0
    assert storage["total"] == sum(value for key, value in storage.items() if key != "total")
    durability = final_state["sqlite_durability"]
    assert durability["destination"]["journal_mode"] in {"delete", "wal"}
    assert durability["destination"]["synchronous"] == 2
    assert set(durability["blind_state_journal_modes"]) <= {"delete", "wal"}
    assert durability["blind_state_synchronous_levels"] == [2]
    assert payload["artifacts"] == {"retained": True, "work_directory": None}
    assert _stage_names(payload) == [
        "fixture_generation",
        "destination_setup",
        "content_inspection",
        "source_schema_inspection",
        "target_schema_inspection",
        "mapping_and_plan",
        "full_preflight",
        "security_and_state_setup",
        "source_record_read",
        "source_seal_and_outbox_stage",
        "outbox_reload_and_relay_enqueue",
        "relay_lease",
        "destination_delivery",
        "acknowledgements",
        "destination_audit_outcome_check",
        "end_to_end_verification",
    ]
    assert all(stage["status"] == "passed" for stage in payload["stages"])
    assert all(stage["latency_sample_count"] <= 10_000 for stage in payload["stages"])
    stages = {stage["name"]: stage for stage in payload["stages"]}
    assert stages["fixture_generation"]["call_latency_p95_ms"] is None
    assert stages["destination_delivery"]["call_latency_p95_ms"] is not None
    assert resources.python_allocation_tracing is False
    assert resources.peak_python_bytes is None
    assert resources.result_count == 4
    assert resources.throughput_per_second is not None

    connection = sqlite3.connect(work_dir / "destination.sqlite")
    try:
        rows = connection.execute(
            """
            SELECT order_reference, customer_email, region, order_status, api_token
            FROM delivered_records
            ORDER BY id
            """
        ).fetchall()
    finally:
        connection.close()
    assert rows == [
        (
            "polymorph-canary-order-00000001",
            "polymorph-canary-customer-001@example.test",
            "polymorph-canary-region-eu-west",
            "polymorph-canary-status-paid",
            "polymorph-canary-token-00000001-01",
        ),
        ("ORD-00000002", "customer-002@example.test", "us-east", "packed", "tok-00000002-02"),
        ("ORD-00000003", "customer-003@example.test", "ap-south", "shipped", "tok-00000003-03"),
        ("ORD-00000004", "customer-004@example.test", "eu-central", "created", "tok-00000004-04"),
    ]

    serialized = json.dumps(payload, sort_keys=True)
    assert "polymorph-canary-customer-001@example.test" not in serialized
    assert "polymorph-canary-token-00000001-01" not in serialized
    assert str(work_dir.resolve()) not in serialized


def test_destination_content_check_does_not_assume_relay_delivery_order(tmp_path: Path) -> None:
    destination = tmp_path / "reordered.sqlite"
    workflow_benchmark._create_destination(destination)
    with sqlite3.connect(destination) as connection:
        connection.executemany(
            """
            INSERT INTO delivered_records (
                order_reference, customer_email, region, order_status, api_token
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                workflow_benchmark._fixture_values(2),
                workflow_benchmark._fixture_values(1),
            ],
        )

    assert workflow_benchmark._destination_content_result(destination, 2) == (2, 0)


def test_workflow_benchmark_can_disable_destination_audit(tmp_path: Path) -> None:
    report, _ = run_workflow_benchmark(
        records=2,
        batch_size=1,
        work_dir=tmp_path / "without-audit",
        signed_audit=False,
    )

    assert report.success
    assert report.final_state["audit_events"] == 0
    assert report.final_state["audit_signatures_verified"] is False
    assert not (tmp_path / "without-audit" / "audit.sqlite").exists()


def test_workflow_failure_reports_stage_without_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "tok-value-that-must-not-reach-results"

    def fail_inspection(self: ContentInspector, path: str | Path) -> None:
        del self, path
        raise RuntimeError(secret)

    monkeypatch.setattr(ContentInspector, "inspect", fail_inspection)
    report, resources = run_workflow_benchmark(
        records=2,
        batch_size=1,
        work_dir=tmp_path / "failed",
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "content_inspection"
    assert report.failure.reason_code == "workflow_stage_failed"
    assert report.failure.error_type == "RuntimeError"
    assert report.records_delivered == 0
    assert resources.result_count == 0
    serialized = json.dumps(report.as_dict(), sort_keys=True)
    assert secret not in serialized
    assert _stage_names(report.as_dict()) == [
        "fixture_generation",
        "destination_setup",
        "content_inspection",
    ]


def test_workflow_rejects_a_fixture_mapping_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_propose = HybridMatcher.propose

    def swapped_propose(
        self: HybridMatcher,
        source_schema: SchemaDescriptor,
        target_schema: SchemaDescriptor,
    ) -> list[MappingDecision]:
        decisions = original_propose(self, source_schema, target_schema)
        swapped_targets = {"c3": "order_status", "c4": "region"}
        return [
            replace(
                decision,
                target_field_id=swapped_targets.get(
                    decision.source_field_id,
                    decision.target_field_id,
                ),
            )
            for decision in decisions
        ]

    monkeypatch.setattr(HybridMatcher, "propose", swapped_propose)
    report, resources = run_workflow_benchmark(
        records=2,
        batch_size=2,
        work_dir=tmp_path / "mapping-swap",
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "mapping_and_plan"
    assert report.failure.reason_code == "mapping_fixture_mismatch"
    assert resources.result_count == 0
    stages = {stage.name: stage for stage in report.stages}
    assert stages["mapping_and_plan"].status == "failed"


def test_workflow_detects_destination_value_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_write = DatabaseConnector.write_records
    corrupt_value = "corrupted-value-that-must-not-reach-report@example.test"

    def corrupt_write(
        self: DatabaseConnector,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        rows = [dict(record) for record in records]
        for row in rows:
            row["customer_email"] = corrupt_value
        return original_write(self, rows, context=context)

    monkeypatch.setattr(DatabaseConnector, "write_records", corrupt_write)
    report, resources = run_workflow_benchmark(
        records=2,
        batch_size=2,
        work_dir=tmp_path / "corrupt-destination",
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "end_to_end_verification"
    assert report.failure.reason_code == "destination_content_mismatch"
    assert report.records_delivered == 2
    assert report.records_acknowledged == 2
    assert resources.result_count == 2
    assert report.final_state["destination_rows"] == 2
    assert report.final_state["content_verified"] is False
    assert report.final_state["mismatch_count"] == 2
    assert corrupt_value not in json.dumps(report.as_dict(), sort_keys=True)


def test_workflow_sanitizes_a_second_source_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_iter_records = CsvConnector.iter_records
    secret = "second-pass-secret-must-not-reach-report"
    calls = 0

    def flaky_iter_records(
        self: CsvConnector,
    ) -> Iterable[Mapping[str, object]]:
        nonlocal calls
        calls += 1
        source = iter(original_iter_records(self))
        if calls == 1:
            return source

        def broken_second_pass() -> Iterator[Mapping[str, object]]:
            try:
                yield next(source)
                raise RuntimeError(secret)
            finally:
                close_source = getattr(source, "close", None)
                if callable(close_source):
                    close_source()

        return broken_second_pass()

    monkeypatch.setattr(CsvConnector, "iter_records", flaky_iter_records)
    private_temp_parent = tmp_path / "private-second-read-path"
    private_temp_parent.mkdir()
    monkeypatch.setattr(workflow_benchmark.tempfile, "tempdir", str(private_temp_parent))
    report, resources = run_workflow_benchmark(
        records=2,
        batch_size=2,
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "source_record_read"
    assert report.failure.reason_code == "workflow_stage_failed"
    assert report.failure.error_type == "RuntimeError"
    assert report.records_read == 1
    assert resources.result_count == 0
    stages = {stage.name: stage for stage in report.stages}
    assert stages["source_record_read"].status == "failed"
    serialized = json.dumps(report.as_dict(), sort_keys=True)
    assert secret not in serialized
    assert str(private_temp_parent.resolve()) not in serialized


def test_audit_append_failure_preserves_commit_and_ack_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "audit-secret-must-not-reach-report"

    def fail_append(self: AuditLog, event: AuditEvent) -> NoReturn:
        del self, event
        raise RuntimeError(secret)

    monkeypatch.setattr(AuditLog, "append", fail_append)
    report, resources = run_workflow_benchmark(
        records=1,
        batch_size=1,
        work_dir=tmp_path / "audit-failure",
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "destination_audit_outcome_check"
    assert report.failure.reason_code == "destination_audit_status_unexpected"
    assert report.records_delivered == 1
    assert report.records_acknowledged == 1
    assert resources.result_count == 1
    assert report.final_state["destination_rows"] == 1
    assert report.final_state["ledger_committed"] == 1
    assert report.final_state["outbox_depth"] == 0
    assert report.final_state["relay_depth"] == 0
    assert report.final_state["content_verified"] is True
    assert report.final_state["mismatch_count"] == 0
    assert report.final_state["audit_events"] == 0
    stages = {stage.name: stage for stage in report.stages}
    assert stages["destination_delivery"].status == "passed"
    assert stages["acknowledgements"].status == "passed"
    assert stages["destination_audit_outcome_check"].status == "failed"
    assert secret not in json.dumps(report.as_dict(), sort_keys=True)


def test_source_count_mismatch_marks_read_stage_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_write_fixture = workflow_benchmark._write_fixture

    def write_fewer_records(path: Path, records: int) -> None:
        original_write_fixture(path, records - 1)

    monkeypatch.setattr(workflow_benchmark, "_write_fixture", write_fewer_records)
    report, resources = run_workflow_benchmark(
        records=3,
        batch_size=2,
        work_dir=tmp_path / "short-source",
    )

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "source_record_read"
    assert report.failure.reason_code == "source_record_count_mismatch"
    assert report.records_read == 2
    assert report.records_delivered == 2
    assert resources.result_count == 2
    assert report.final_state["destination_rows"] == 2
    assert report.final_state["content_verified"] is False
    assert report.final_state["mismatch_count"] == 1
    stages = {stage.name: stage for stage in report.stages}
    assert stages["source_record_read"].status == "failed"


def test_standard_report_omits_retained_absolute_work_directory(tmp_path: Path) -> None:
    work_dir = tmp_path / "private-customer-name" / "workflow"
    report, _ = run_workflow_benchmark(
        records=1,
        batch_size=1,
        work_dir=work_dir,
        signed_audit=False,
    )

    assert report.success
    assert report.work_directory == str(work_dir.resolve())
    payload = report.as_dict()
    assert payload["artifacts"] == {"retained": True, "work_directory": None}
    assert str(work_dir.resolve()) not in json.dumps(payload, sort_keys=True)


def test_workflow_cli_writes_machine_readable_json(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    args = build_parser().parse_args(
        [
            "benchmark",
            "workflow",
            "--records",
            "2",
            "--batch-size",
            "2",
            "--work-dir",
            str(tmp_path / "cli-work"),
            "--no-audit",
            "--output",
            str(output),
        ]
    )

    args.func(args)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["benchmark"] == "workflow"
    assert payload["version"] == 1
    assert payload["measurement"]["mode"] == "standard"
    assert "pid" not in payload["resources"]
    assert payload["environment"]["product_version"]
    assert payload["environment"]["python_version"]
    assert payload["environment"]["sqlite_version"]
    assert payload["workflow"]["success"] is True
    assert payload["workflow"]["configuration"]["signed_audit"] is False
    assert str((tmp_path / "cli-work").resolve()) not in json.dumps(payload, sort_keys=True)


def test_workflow_benchmark_rejects_nonempty_work_directory(tmp_path: Path) -> None:
    work_dir = tmp_path / "existing"
    work_dir.mkdir()
    (work_dir / "keep.txt").write_text("do not overwrite", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        run_workflow_benchmark(records=1, work_dir=work_dir)

    assert (work_dir / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"


def test_temporary_cleanup_failure_is_structured_and_payload_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "temporary-workflow"
    root.mkdir()
    secret = "private-cleanup-path-and-message"

    class FailingTemporaryDirectory:
        def cleanup(self) -> None:
            raise RuntimeError(secret)

    def fake_workspace(
        work_dir: str | Path | None,
        *,
        keep_work_dir: bool,
    ) -> tuple[Path, bool, FailingTemporaryDirectory]:
        assert work_dir is None
        assert keep_work_dir is False
        return root, False, FailingTemporaryDirectory()

    monkeypatch.setattr(workflow_benchmark, "_prepare_workspace", fake_workspace)
    report, resources = run_workflow_benchmark(records=1, batch_size=1)

    assert not report.success
    assert report.failure is not None
    assert report.failure.stage == "resource_cleanup"
    assert report.failure.reason_code == "workflow_stage_failed"
    assert report.failure.error_type == "RuntimeError"
    assert report.records_delivered == 1
    assert resources.result_count == 1
    assert report.stages[-1].name == "resource_cleanup"
    assert report.stages[-1].status == "failed"
    assert secret not in json.dumps(report.as_dict(), sort_keys=True)
