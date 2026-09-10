from __future__ import annotations

import csv
import re
import sqlite3
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import NoReturn, TypeVar

from .agents import BlindDestinationAgent, BlindSourceAgent, BlindTransportRecord
from .audit import AuditLog
from .benchmark import BenchmarkResult, benchmark_call
from .connectors.csv_file import CsvConnector
from .connectors.database import DATABASE_ATOMIC_BATCH_MAX_RECORDS, DatabaseConnector
from .content import ContentInspector, ContentKind, FileInspection
from .crypto import RecipientKeyPair
from .ledger import DeliveryLedger
from .matching.hybrid import HybridMatcher
from .models.mapping import MappingDecision, MappingPlan, MappingStatus
from .models.schema import SchemaDescriptor
from .observability import (
    DEFAULT_EVENT_STREAM_BYTES,
    MAX_COMPACT_EVENT_BYTES,
    MAX_EVENT_STREAM_BYTES,
    MIN_EVENT_STREAM_BYTES,
    WORKFLOW_STAGE_COMPONENTS,
    EventStream,
    EventWriteStatus,
)
from .outbox import SourceOutbox
from .planning import build_plan
from .preflight import PreflightReport, PreflightRunner
from .recipient_auth import RecipientKeyCertificate, RecipientKeyTrustStore
from .relay import LeasedRecord, RelayPolicy, RouteBinding, SealedRelayQueue
from .runtime import (
    AuditWriteStatus,
    DeliveryBatchInterrupted,
    DeliveryReceipt,
    DeliveryStatus,
    DestinationRuntime,
)
from .signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey, signing_key_id
from .spool import SealedSpool

T = TypeVar("T")

_DESTINATION_CONNECTOR = "workflow-sqlite-destination"
_TABLE_NAME = "delivered_records"
_SAFE_ERROR_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_ORDER_REFERENCE = re.compile(r"^ORD-([0-9]{8})$")
_EXPECTED_MAPPING = {
    "c1": "order_reference",
    "c2": "customer_email",
    "c3": "region",
    "c4": "order_status",
    "c5": "api_token",
}
_BLIND_STATE_DATABASES = (
    "source-outbox.sqlite",
    "relay.sqlite",
    "delivery-ledger.sqlite",
    "sealed-spool.sqlite",
    "audit.sqlite",
)
_SQLITE_FILE_SUFFIXES = ("", "-wal", "-journal", "-shm")
_SCAN_CHUNK_BYTES = 64 * 1024
_MAX_LATENCY_SAMPLES = 10_000
_STAGE_ORDER = WORKFLOW_STAGE_COMPONENTS


def _required_event_stream_bytes(records: int, batch_size: int) -> int:
    maximum_batches = (records + batch_size - 1) // batch_size
    full_outer_batches, remainder = divmod(records, batch_size)
    atomic_batches_per_full_outer = (
        batch_size + DATABASE_ATOMIC_BATCH_MAX_RECORDS - 1
    ) // DATABASE_ATOMIC_BATCH_MAX_RECORDS
    remainder_atomic_batches = (
        remainder + DATABASE_ATOMIC_BATCH_MAX_RECORDS - 1
    ) // DATABASE_ATOMIC_BATCH_MAX_RECORDS
    maximum_atomic_batches = (
        0
        if batch_size == 1
        else full_outer_batches * atomic_batches_per_full_outer + remainder_atomic_batches
    )
    maximum_events = (
        records + maximum_batches + maximum_atomic_batches + len(WORKFLOW_STAGE_COMPONENTS) + 2
    )
    return maximum_events * MAX_COMPACT_EVENT_BYTES


def _validate_event_stream_capacity(records: int, batch_size: int, maximum_bytes: int) -> int:
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int):
        raise TypeError("workflow event stream size limit must be an integer")
    if not MIN_EVENT_STREAM_BYTES <= maximum_bytes <= MAX_EVENT_STREAM_BYTES:
        raise ValueError(
            "workflow event stream size limit must be between "
            f"{MIN_EVENT_STREAM_BYTES} and {MAX_EVENT_STREAM_BYTES} bytes"
        )
    required = _required_event_stream_bytes(records, batch_size)
    if required > maximum_bytes:
        raise ValueError(
            "workflow event stream capacity is too small: "
            f"the run reserves {required} bytes but only {maximum_bytes} are configured; "
            "increase --event-stream-max-mib, reduce --records, or increase --batch-size"
        )
    return required


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


@dataclass(frozen=True, slots=True)
class WorkflowStageResult:
    name: str
    status: str
    wall_ms: float
    cpu_ms: float
    calls: int
    items_processed: int
    item_unit: str
    throughput_per_second: float | None
    latency_sample_count: int
    call_latency_p50_ms: float | None
    call_latency_p95_ms: float | None
    reason_code: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "wall_ms": self.wall_ms,
            "cpu_ms": self.cpu_ms,
            "calls": self.calls,
            "items_processed": self.items_processed,
            "item_unit": self.item_unit,
            "throughput_per_second": self.throughput_per_second,
            "latency_sample_count": self.latency_sample_count,
            "call_latency_p50_ms": self.call_latency_p50_ms,
            "call_latency_p95_ms": self.call_latency_p95_ms,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class WorkflowFailure:
    stage: str
    reason_code: str
    error_type: str

    def as_dict(self) -> dict[str, str]:
        return {
            "stage": self.stage,
            "reason_code": self.reason_code,
            "error_type": self.error_type,
        }


@dataclass(frozen=True, slots=True)
class WorkflowBenchmarkReport:
    success: bool
    records_requested: int
    batch_size: int
    signed_audit_enabled: bool
    artifacts_retained: bool
    work_directory: str | None
    batches_completed: int
    records_read: int
    records_staged: int
    records_relayed: int
    records_leased: int
    records_delivered: int
    records_acknowledged: int
    mapping: dict[str, int]
    preflight: dict[str, object]
    final_state: dict[str, object]
    observability: dict[str, object]
    stages: tuple[WorkflowStageResult, ...]
    failure: WorkflowFailure | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "configuration": {
                "records": self.records_requested,
                "batch_size": self.batch_size,
                "signed_audit": self.signed_audit_enabled,
                "event_stream_max_bytes": self.observability.get("max_stream_bytes"),
                "event_stream_reserved_bytes": self.observability.get("reserved_stream_bytes"),
            },
            "artifacts": {
                "retained": self.artifacts_retained,
                # The API object retains this for the local caller, but the standard
                # machine-readable report must be safe to publish without path scrubbing.
                "work_directory": None,
            },
            "progress": {
                "batches_completed": self.batches_completed,
                "records_read": self.records_read,
                "records_staged": self.records_staged,
                "records_relayed": self.records_relayed,
                "records_leased": self.records_leased,
                "records_delivered": self.records_delivered,
                "records_acknowledged": self.records_acknowledged,
            },
            "mapping": self.mapping,
            "preflight": self.preflight,
            "final_state": self.final_state,
            "observability": self.observability,
            "stages": [stage.as_dict() for stage in self.stages],
            "failure": self.failure.as_dict() if self.failure is not None else None,
        }


@dataclass(slots=True)
class _StageAccumulator:
    name: str
    item_unit: str
    wall_ms: float = 0.0
    cpu_ms: float = 0.0
    calls: int = 0
    items_processed: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    failed: bool = False
    failure_reason_code: str | None = None

    def observe_latency(self, wall_ms: float) -> None:
        """Keep a bounded deterministic reservoir so measurement does not scale with input."""

        observation = self.calls
        if len(self.latencies_ms) < _MAX_LATENCY_SAMPLES:
            self.latencies_ms.append(wall_ms)
            return
        mixed = (observation * 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        slot = mixed % observation
        if slot < _MAX_LATENCY_SAMPLES:
            self.latencies_ms[slot] = wall_ms

    def result(self) -> WorkflowStageResult:
        throughput = None
        if self.items_processed > 0 and self.wall_ms > 0:
            throughput = self.items_processed / (self.wall_ms / 1000.0)
        return WorkflowStageResult(
            name=self.name,
            status="failed" if self.failed else "passed",
            wall_ms=self.wall_ms,
            cpu_ms=self.cpu_ms,
            calls=self.calls,
            items_processed=self.items_processed,
            item_unit=self.item_unit,
            throughput_per_second=throughput,
            latency_sample_count=len(self.latencies_ms),
            call_latency_p50_ms=(_percentile(self.latencies_ms, 0.50) if self.calls >= 2 else None),
            call_latency_p95_ms=(_percentile(self.latencies_ms, 0.95) if self.calls >= 2 else None),
            reason_code=self.failure_reason_code,
        )


class _BenchmarkCheckFailed(Exception):
    def __init__(self, reason_code: str, *, items_processed: int = 0) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.items_processed = items_processed


class _WorkflowStopped(Exception):
    def __init__(self, failure: WorkflowFailure) -> None:
        super().__init__(failure.reason_code)
        self.failure = failure


class _OperationalEventAppendFailed(Exception):
    def __init__(self, error_type: str) -> None:
        super().__init__("observability_append_failed")
        self.error_type = error_type


class _StageBook:
    def __init__(self) -> None:
        self._stages: dict[str, _StageAccumulator] = {}

    def measure(
        self,
        name: str,
        item_unit: str,
        operation: Callable[[], T],
        *,
        items: int | Callable[[T], int] = 1,
    ) -> T:
        stage = self._stages.setdefault(name, _StageAccumulator(name, item_unit))
        if stage.item_unit != item_unit:
            raise RuntimeError("workflow benchmark stage unit changed")
        wall_started = time.perf_counter_ns()
        cpu_started = time.process_time_ns()
        try:
            result = operation()
            count = items(result) if callable(items) else items
        except Exception as exc:
            wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
            cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
            stage.wall_ms += wall_ms
            stage.cpu_ms += cpu_ms
            stage.calls += 1
            stage.observe_latency(wall_ms)
            stage.failed = True
            if isinstance(exc, _BenchmarkCheckFailed):
                stage.items_processed += exc.items_processed
                failure = self.mark_failed(
                    name,
                    item_unit,
                    exc.reason_code,
                    error_type="benchmark_assertion",
                )
            else:
                failure = self.mark_failed(
                    name,
                    item_unit,
                    "workflow_stage_failed",
                    error_type=_safe_error_type(exc),
                )
            raise _WorkflowStopped(failure) from exc
        wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
        cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
        stage.wall_ms += wall_ms
        stage.cpu_ms += cpu_ms
        stage.calls += 1
        stage.items_processed += count
        stage.observe_latency(wall_ms)
        return result

    def mark_failed(
        self,
        name: str,
        item_unit: str,
        reason_code: str,
        *,
        error_type: str = "benchmark_assertion",
    ) -> WorkflowFailure:
        stage = self._stages.setdefault(name, _StageAccumulator(name, item_unit))
        if stage.item_unit != item_unit:
            raise RuntimeError("workflow benchmark stage unit changed")
        stage.failed = True
        stage.failure_reason_code = reason_code
        return WorkflowFailure(name, reason_code, error_type)

    def stop(
        self,
        name: str,
        item_unit: str,
        reason_code: str,
        *,
        error_type: str = "benchmark_assertion",
    ) -> NoReturn:
        raise _WorkflowStopped(
            self.mark_failed(name, item_unit, reason_code, error_type=error_type)
        )

    def results(self) -> tuple[WorkflowStageResult, ...]:
        return tuple(self._stages[name].result() for name in _STAGE_ORDER if name in self._stages)


def _safe_error_type(exc: Exception) -> str:
    candidate = type(exc).__name__
    return candidate if _SAFE_ERROR_TYPE.fullmatch(candidate) else "Exception"


@dataclass(slots=True)
class _Progress:
    batches_completed: int = 0
    records_read: int = 0
    records_staged: int = 0
    records_relayed: int = 0
    records_leased: int = 0
    records_delivered: int = 0
    records_acknowledged: int = 0


def _write_fixture(path: Path, records: int) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            ("order_reference", "customer_email", "region", "order_status", "api_token")
        )
        for index in range(1, records + 1):
            writer.writerow(_fixture_values(index))


def _fixture_values(index: int) -> tuple[str, str, str, str, str]:
    if index == 1:
        return (
            "polymorph-canary-order-00000001",
            "polymorph-canary-customer-001@example.test",
            "polymorph-canary-region-eu-west",
            "polymorph-canary-status-paid",
            "polymorph-canary-token-00000001-01",
        )
    regions = ("eu-central", "eu-west", "us-east", "ap-south")
    statuses = ("created", "paid", "packed", "shipped")
    return (
        f"ORD-{index:08d}",
        f"customer-{index % 997:03d}@example.test",
        regions[index % len(regions)],
        statuses[index % len(statuses)],
        f"tok-{index:08d}-{index % 97:02d}",
    )


def _create_destination(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f"""
            CREATE TABLE {_TABLE_NAME} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_reference TEXT NOT NULL UNIQUE,
                customer_email TEXT NOT NULL,
                region TEXT NOT NULL,
                order_status TEXT NOT NULL,
                api_token TEXT NOT NULL
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def _sqlite_url(path: Path) -> str:
    return f"sqlite:///{path.resolve().as_posix()}"


def _checked_inspection(path: Path) -> FileInspection:
    report = ContentInspector().inspect(path)
    if not report.safe:
        raise _BenchmarkCheckFailed("source_content_unsafe")
    if report.kind not in {ContentKind.DELIMITED_TEXT, ContentKind.TEXT}:
        raise _BenchmarkCheckFailed("source_content_not_delimited_text")
    return report


def _checked_mapping(
    source_schema: SchemaDescriptor,
    target_schema: SchemaDescriptor,
) -> tuple[list[MappingDecision], MappingPlan, dict[str, int]]:
    decisions = HybridMatcher().propose(source_schema, target_schema)
    summary = {
        "source_fields": len(source_schema.fields),
        "target_fields": len(target_schema.fields),
        "auto": sum(item.status is MappingStatus.AUTO for item in decisions),
        "review": sum(item.status is MappingStatus.REVIEW for item in decisions),
        "blocked": sum(item.status is MappingStatus.BLOCKED for item in decisions),
    }
    if summary["auto"] != len(source_schema.fields):
        raise _BenchmarkCheckFailed("mapping_not_fully_automatic")
    by_source = {item.source_field_id: item for item in decisions}
    if set(by_source) != set(_EXPECTED_MAPPING) or any(
        by_source[source_id].target_field_id != target_id
        for source_id, target_id in _EXPECTED_MAPPING.items()
    ):
        raise _BenchmarkCheckFailed("mapping_fixture_mismatch")
    plan = build_plan(source_schema, target_schema, decisions)
    if len(plan.rules) != len(source_schema.fields):
        raise _BenchmarkCheckFailed("mapping_plan_incomplete")
    return decisions, plan, summary


def _checked_preflight(
    source: CsvConnector,
    source_schema: SchemaDescriptor,
    target_schema: SchemaDescriptor,
    plan: MappingPlan,
) -> PreflightReport:
    report = PreflightRunner().run(
        source.iter_records(),
        source_schema,
        target_schema,
        plan,
    )
    if not report.promotable:
        raise _BenchmarkCheckFailed("preflight_not_promotable")
    return report


@dataclass(slots=True)
class _TransportRuntime:
    source_agent: BlindSourceAgent
    outbox: SourceOutbox
    relay: SealedRelayQueue
    runtime: DestinationRuntime
    ledger: DeliveryLedger
    spool: SealedSpool
    audit: AuditLog | None
    audit_public_key: bytes | None


def _make_transport_runtime(
    root: Path,
    source_schema: SchemaDescriptor,
    target_schema: SchemaDescriptor,
    plan: MappingPlan,
    destination: DatabaseConnector,
    events: EventStream,
    *,
    signed_audit: bool,
) -> _TransportRuntime:
    recipient = RecipientKeyPair.generate()
    recipient_identity = SigningKeyPair.generate()
    recipient_identity_public_key = recipient_identity.public_bytes()
    recipient_trust_state_path = root / "recipient-trust-state.json"
    recipient_trust = RecipientKeyTrustStore(
        identity_public_key=recipient_identity_public_key,
        tenant="workflow-benchmark",
        destination_connector=_DESTINATION_CONNECTOR,
        state_path=recipient_trust_state_path,
    )
    certificate_time = datetime.now(UTC)
    recipient_trust.accept(
        RecipientKeyCertificate.issue(
            tenant="workflow-benchmark",
            destination_connector=_DESTINATION_CONNECTOR,
            public_key=recipient.public_bytes(),
            generation=1,
            previous_key_id=None,
            identity_signer=recipient_identity,
            issued_at=certificate_time,
            not_before=certificate_time,
            not_after=certificate_time + timedelta(days=1),
        ),
        now=certificate_time,
    )
    # Force the measured source path to reload and verify the durable checkpoint instead of
    # continuing with the in-memory object that performed the initial acceptance.
    recipient_trust = RecipientKeyTrustStore(
        identity_public_key=recipient_identity_public_key,
        tenant="workflow-benchmark",
        destination_connector=_DESTINATION_CONNECTOR,
        state_path=recipient_trust_state_path,
    )
    recipient_trust.current(now=certificate_time)
    source_signer = SigningKeyPair.generate()
    source_key_id = signing_key_id(source_signer.public_bytes())
    trust = SourceTrustStore(
        [TrustedSourceKey(source_signer.public_bytes(), "workflow-benchmark", source_schema.id)]
    )
    source_agent = BlindSourceAgent(
        tenant="workflow-benchmark",
        source_connector_id=source_schema.id,
        destination_connector_id=_DESTINATION_CONNECTOR,
        source_schema=source_schema,
        target_schema=target_schema,
        plan=plan,
        destination_public_key=None,
        signing_key=source_signer,
        recipient_key_trust_store=recipient_trust,
    )
    outbox = SourceOutbox(root / "source-outbox.sqlite")
    relay = SealedRelayQueue(
        root / "relay.sqlite",
        RelayPolicy(
            (
                RouteBinding(
                    "workflow-benchmark",
                    source_schema.id,
                    _DESTINATION_CONNECTOR,
                    allowed_plan_digests=frozenset({plan.digest()}),
                    allowed_source_key_ids=frozenset({source_key_id}),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    ledger = DeliveryLedger(root / "delivery-ledger.sqlite")
    spool = SealedSpool(root / "sealed-spool.sqlite")
    audit_signer = SigningKeyPair.generate() if signed_audit else None
    audit = AuditLog(root / "audit.sqlite", signer=audit_signer) if audit_signer else None
    runtime = DestinationRuntime(
        connector_id=_DESTINATION_CONNECTOR,
        agent=BlindDestinationAgent(
            recipient.private_key,
            expected_tenant="workflow-benchmark",
            expected_connector_id=_DESTINATION_CONNECTOR,
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=destination,
        ledger=ledger,
        spool=spool,
        plan=plan,
        target_schema=target_schema,
        audit=audit,
        events=events,
        actor_id="workflow-benchmark-destination",
    )
    return _TransportRuntime(
        source_agent,
        outbox,
        relay,
        runtime,
        ledger,
        spool,
        audit,
        audit_signer.public_bytes() if audit_signer else None,
    )


def _seal_and_stage_batch(
    transport: _TransportRuntime,
    records: Sequence[dict[str, object]],
    *,
    first_record_number: int,
    transfer_id: str,
) -> tuple[BlindTransportRecord, ...]:
    sealed_records = transport.source_agent.prepare_records(
        records,
        record_ids=tuple(f"row-{first_record_number + offset}" for offset in range(len(records))),
        transfer_id=transfer_id,
    )
    if any(sealed.authentication is None for sealed in sealed_records):
        raise _BenchmarkCheckFailed("source_record_not_signed")
    receipts = transport.outbox.stage_many(sealed_records)
    if len(receipts) != len(sealed_records):
        raise _BenchmarkCheckFailed("source_outbox_stage_count_mismatch")
    return tuple(sealed_records)


def _reload_and_enqueue(
    transport: _TransportRuntime,
    expected: int,
    progress: _Progress,
) -> tuple[BlindTransportRecord, ...]:
    pending = transport.outbox.pending(limit=expected)
    if len(pending) != expected:
        raise _BenchmarkCheckFailed("outbox_pending_count_mismatch")
    records: list[BlindTransportRecord] = []
    records.extend(item.record for item in pending)
    receipts = transport.relay.enqueue_many(records)
    if len(receipts) != expected:
        raise _BenchmarkCheckFailed("relay_enqueue_count_mismatch")
    progress.records_relayed += len(receipts)
    return tuple(records)


def _lease_batch(
    transport: _TransportRuntime,
    expected: int,
    batch_number: int,
    progress: _Progress,
) -> tuple[LeasedRecord, ...]:
    leased = transport.relay.lease(
        destination_connector=_DESTINATION_CONNECTOR,
        lease_owner=f"workflow-worker-{batch_number}",
        limit=expected,
    )
    progress.records_leased += len(leased)
    if len(leased) != expected:
        raise _BenchmarkCheckFailed("relay_lease_count_mismatch")
    return leased


def _deliver_batch(
    transport: _TransportRuntime,
    records: Sequence[BlindTransportRecord],
    progress: _Progress,
) -> tuple[DeliveryReceipt, ...]:
    try:
        receipts = transport.runtime.deliver_many(records)
    except DeliveryBatchInterrupted as exc:
        completed = exc.completed_receipts
        progress.records_delivered += sum(
            receipt.status is DeliveryStatus.DELIVERED for receipt in completed
        )
        raise _BenchmarkCheckFailed(
            "destination_delivery_interrupted",
            items_processed=len(completed),
        ) from exc
    if len(receipts) != len(records):
        raise _BenchmarkCheckFailed("destination_delivery_count_mismatch")
    progress.records_delivered += sum(
        receipt.status is DeliveryStatus.DELIVERED for receipt in receipts
    )
    for receipt in receipts:
        if receipt.status is not DeliveryStatus.DELIVERED:
            raise _BenchmarkCheckFailed(
                receipt.reason_code or "destination_delivery_not_delivered",
                items_processed=len(receipts),
            )
    return receipts


def _check_audit_outcome(
    transport: _TransportRuntime,
    receipt: DeliveryReceipt,
) -> None:
    expected_audit = (
        AuditWriteStatus.RECORDED if transport.audit is not None else AuditWriteStatus.DISABLED
    )
    if receipt.audit_status is not expected_audit:
        raise _BenchmarkCheckFailed("destination_audit_status_unexpected")


def _check_operational_event_outcome(receipt: DeliveryReceipt) -> None:
    if receipt.operational_event_status is not EventWriteStatus.RECORDED:
        raise _BenchmarkCheckFailed("destination_operational_event_status_unexpected")
    if not receipt.run_id or not receipt.correlation_id:
        raise _BenchmarkCheckFailed("destination_operational_event_context_missing")


def _ack_batch(
    transport: _TransportRuntime,
    leased: Sequence[LeasedRecord],
    lease_owner: str,
) -> None:
    acknowledgements = tuple((item.record.digest(), item.lease_id) for item in leased)
    transport.relay.ack_many(acknowledgements, lease_owner=lease_owner)
    removed = transport.outbox.ack_many(digest for digest, _ in acknowledgements)
    if len(removed) != len(acknowledgements) or not all(removed):
        raise _BenchmarkCheckFailed("source_outbox_ack_missing")


def _check_audit_outcomes(
    transport: _TransportRuntime,
    receipts: Sequence[DeliveryReceipt],
) -> None:
    for receipt in receipts:
        _check_audit_outcome(transport, receipt)


def _check_operational_event_outcomes(
    receipts: Sequence[DeliveryReceipt],
) -> None:
    for receipt in receipts:
        _check_operational_event_outcome(receipt)


def _read_source_record(
    iterator: Iterator[Mapping[str, object]],
) -> dict[str, object] | None:
    try:
        return dict(next(iterator))
    except StopIteration:
        return None


def _count_rows(path: Path, statement: str, parameters: tuple[object, ...] = ()) -> int:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(statement, parameters).fetchone()
    finally:
        connection.close()
    if row is None:
        raise _BenchmarkCheckFailed("verification_query_returned_no_row")
    return int(row[0])


def _destination_content_result(path: Path, expected: int) -> tuple[int, int]:
    connection = sqlite3.connect(path)
    rows_seen = 0
    mismatches = 0
    matched_indexes: set[int] = set()
    try:
        cursor = connection.execute(
            f"""
            SELECT order_reference, customer_email, region, order_status, api_token
            FROM {_TABLE_NAME}
            ORDER BY id
            """
        )
        for row in cursor:
            rows_seen += 1
            order_reference = str(row[0])
            if order_reference == _fixture_values(1)[0]:
                fixture_index = 1
            else:
                match = _ORDER_REFERENCE.fullmatch(order_reference)
                fixture_index = int(match.group(1)) if match is not None else 0
            if fixture_index < 1 or fixture_index > expected or fixture_index in matched_indexes:
                mismatches += 1
                continue
            matched_indexes.add(fixture_index)
            if tuple(row) != _fixture_values(fixture_index):
                mismatches += 1
    finally:
        connection.close()
    if rows_seen < expected:
        mismatches += expected - rows_seen
    return rows_seen, mismatches


def _file_contains_any(path: Path, needles: tuple[bytes, ...]) -> bool:
    overlap = max(len(item) for item in needles) - 1
    previous = b""
    with path.open("rb") as handle:
        while chunk := handle.read(_SCAN_CHUNK_BYTES):
            window = previous + chunk
            if any(item in window for item in needles):
                return True
            previous = window[-overlap:] if overlap else b""
    return False


def _sqlite_family_paths(root: Path, database_name: str) -> tuple[Path, ...]:
    base_path = root / database_name
    return tuple(
        state_path
        for suffix in _SQLITE_FILE_SUFFIXES
        if (state_path := Path(f"{base_path}{suffix}")).is_file()
    )


def _known_plaintext_canaries_absent(root: Path) -> bool:
    canaries = tuple(value.encode("utf-8") for value in _fixture_values(1))
    for database_name in _BLIND_STATE_DATABASES:
        for state_path in _sqlite_family_paths(root, database_name):
            if _file_contains_any(state_path, canaries):
                return False
    recipient_trust_state = root / "recipient-trust-state.json"
    if recipient_trust_state.is_file() and _file_contains_any(recipient_trust_state, canaries):
        return False
    event_path = root / "operational-events.jsonl"
    return not (event_path.is_file() and _file_contains_any(event_path, canaries))


def _artifact_storage_bytes(root: Path) -> dict[str, int]:
    groups = {
        "source_fixture": (root / "source.csv",),
        "destination": _sqlite_family_paths(root, "destination.sqlite"),
        "source_outbox": _sqlite_family_paths(root, "source-outbox.sqlite"),
        "relay": _sqlite_family_paths(root, "relay.sqlite"),
        "delivery_ledger": _sqlite_family_paths(root, "delivery-ledger.sqlite"),
        "sealed_spool": _sqlite_family_paths(root, "sealed-spool.sqlite"),
        "audit": _sqlite_family_paths(root, "audit.sqlite"),
        "recipient_trust": (root / "recipient-trust-state.json",),
        "operational_events": (root / "operational-events.jsonl",),
    }
    storage = {
        name: sum(path.stat().st_size for path in paths if path.is_file())
        for name, paths in groups.items()
    }
    storage["total"] = sum(storage.values())
    return storage


def _sqlite_settings(path: Path) -> dict[str, str | int | None]:
    connection = sqlite3.connect(path)
    try:
        journal_row = connection.execute("PRAGMA journal_mode").fetchone()
        synchronous_row = connection.execute("PRAGMA synchronous").fetchone()
    finally:
        connection.close()
    return {
        "journal_mode": str(journal_row[0]).casefold() if journal_row is not None else "unknown",
        "synchronous": int(synchronous_row[0]) if synchronous_row is not None else None,
    }


def _sqlite_durability_summary(root: Path) -> dict[str, object]:
    blind_settings = [
        _sqlite_settings(root / database_name)
        for database_name in _BLIND_STATE_DATABASES
        if (root / database_name).is_file()
    ]
    return {
        "destination": _sqlite_settings(root / "destination.sqlite"),
        "blind_state_journal_modes": sorted(
            {str(settings["journal_mode"]) for settings in blind_settings}
        ),
        "blind_state_synchronous_levels": sorted(
            {
                value
                for settings in blind_settings
                if isinstance((value := settings["synchronous"]), int)
            }
        ),
    }


@dataclass(frozen=True, slots=True)
class _FinalVerification:
    state: dict[str, object]
    reason_code: str | None
    destination_rows: int


def _verify_final_state(
    root: Path,
    transport: _TransportRuntime,
    expected: int,
) -> _FinalVerification:
    destination_rows, content_mismatches = _destination_content_result(
        root / "destination.sqlite", expected
    )
    ledger_committed = _count_rows(
        root / "delivery-ledger.sqlite",
        "SELECT COUNT(*) FROM deliveries WHERE state = ?",
        ("committed",),
    )
    outbox_depth = transport.outbox.depth()
    relay_depth = transport.relay.depth()
    quarantine_depth = _count_rows(
        root / "sealed-spool.sqlite", "SELECT COUNT(*) FROM sealed_quarantine"
    )
    audit_events = 0
    audit_signatures_verified = False
    if transport.audit is not None:
        if transport.audit_public_key is None:
            raise _BenchmarkCheckFailed("audit_public_key_missing")
        audit_events = transport.audit.verify(trusted_public_key=transport.audit_public_key)
        audit_signatures_verified = True

    canaries_absent = _known_plaintext_canaries_absent(root)
    state: dict[str, object] = {
        "destination_rows": destination_rows,
        "content_verified": content_mismatches == 0,
        "mismatch_count": content_mismatches,
        "ledger_committed": ledger_committed,
        "outbox_depth": outbox_depth,
        "relay_depth": relay_depth,
        "quarantine_depth": quarantine_depth,
        "audit_events": audit_events,
        "audit_signatures_verified": audit_signatures_verified,
        "known_plaintext_canaries_absent": canaries_absent,
        "storage_bytes": _artifact_storage_bytes(root),
        "sqlite_durability": _sqlite_durability_summary(root),
    }
    checks = (
        (destination_rows != expected, "destination_row_count_mismatch"),
        (content_mismatches != 0, "destination_content_mismatch"),
        (ledger_committed != expected, "ledger_commit_count_mismatch"),
        (outbox_depth != 0, "source_outbox_not_empty"),
        (relay_depth != 0, "relay_not_empty"),
        (quarantine_depth != 0, "quarantine_not_empty"),
        (
            transport.audit is not None and audit_events != expected,
            "audit_event_count_mismatch",
        ),
        (not canaries_absent, "known_plaintext_canary_found_in_blind_state"),
    )
    reason_code = next((reason for failed, reason in checks if failed), None)
    return _FinalVerification(state, reason_code, destination_rows)


def _preflight_payload(report: PreflightReport | None) -> dict[str, object]:
    if report is None:
        return {
            "records_checked": 0,
            "complete_scan": False,
            "promotable": False,
            "blocking_findings": 0,
            "review_findings": 0,
        }
    return {
        "records_checked": report.records_checked,
        "complete_scan": report.complete_scan,
        "promotable": report.promotable,
        "blocking_findings": sum(
            item.severity.value == "blocking" for item in report.plan_validation.findings
        )
        + sum(item.severity.value == "blocking" for item in report.findings),
        "review_findings": sum(
            item.severity.value == "review" for item in report.plan_validation.findings
        )
        + sum(item.severity.value == "review" for item in report.findings),
    }


def _emit_required_event(
    events: EventStream,
    *,
    component: str,
    event_type: str,
    status: str,
    correlation_id: str,
    reason_code: str | None = None,
    item_count: int | None = None,
) -> None:
    try:
        events.emit(
            component=component,
            event_type=event_type,
            status=status,
            correlation_id=correlation_id,
            reason_code=reason_code,
            item_count=item_count,
        )
    except Exception as exc:
        raise _OperationalEventAppendFailed(_safe_error_type(exc)) from exc


def _finalize_observability(
    events: EventStream,
    stages: _StageBook,
    workflow_correlation_id: str,
    progress: _Progress,
    failure: WorkflowFailure | None,
) -> tuple[WorkflowFailure | None, dict[str, object]]:
    append_complete = True
    stream_valid = False
    observability_failure = (
        failure.reason_code
        if failure is not None
        and failure.reason_code
        in {
            "destination_operational_event_status_unexpected",
            "observability_append_failed",
            "observability_event_contract_invalid",
            "observability_event_count_mismatch",
            "observability_lifecycle_invalid",
            "observability_stream_invalid",
        }
        else None
    )
    try:
        for stage in stages.results():
            events.emit(
                component=stage.name,
                event_type="stage_summary",
                status=stage.status,
                correlation_id=events.correlation_id(f"stage:{stage.name}"),
                reason_code=stage.reason_code,
                duration_ms=stage.wall_ms,
                item_count=stage.items_processed,
            )
        events.emit(
            component="workflow_benchmark",
            event_type="workflow_completed",
            status="passed" if failure is None else "failed",
            correlation_id=workflow_correlation_id,
            reason_code=failure.reason_code if failure is not None else None,
            item_count=progress.records_delivered,
        )
    except Exception as exc:
        append_complete = False
        observability_failure = "observability_append_failed"
        if failure is None:
            failure = stages.mark_failed(
                "workflow_internal",
                "operations",
                observability_failure,
                error_type=_safe_error_type(exc),
            )

    try:
        summary = events.summary(run_id=events.run_id).as_dict()
        stream_valid = bool(summary["event_contract_valid"])
        if summary["event_contract_valid"] is not True:
            observability_failure = observability_failure or "observability_event_contract_invalid"
            if failure is None:
                failure = stages.mark_failed(
                    "workflow_internal",
                    "operations",
                    observability_failure,
                )
        elif summary["workflow_lifecycle_valid"] is not True:
            observability_failure = observability_failure or "observability_lifecycle_invalid"
            if failure is None:
                failure = stages.mark_failed(
                    "workflow_internal",
                    "operations",
                    observability_failure,
                )
        elif summary["workflow_counts_valid"] is not True:
            observability_failure = observability_failure or "observability_event_count_mismatch"
            if failure is None:
                failure = stages.mark_failed(
                    "workflow_internal",
                    "operations",
                    observability_failure,
                )
    except Exception as exc:
        summary = {
            "run_id": events.run_id,
            "events": None,
            "components": {},
            "event_types": {},
            "statuses": {},
            "reasons": {},
            "first_timestamp": None,
            "last_timestamp": None,
            "first_event_type": None,
            "last_event_type": None,
            "workflow_lifecycle_valid": False,
            "event_ids_unique": False,
            "duplicate_event_ids": None,
            "event_contract_valid": False,
            "workflow_counts_valid": None,
        }
        observability_failure = observability_failure or "observability_stream_invalid"
        if failure is None:
            failure = stages.mark_failed(
                "workflow_internal",
                "operations",
                observability_failure,
                error_type=_safe_error_type(exc),
            )
    summary.update(
        {
            "format": "jsonl",
            "schema_version": 1,
            "durable_appends": True,
            "stream_valid": stream_valid,
            "run_closed": append_complete and stream_valid and observability_failure is None,
            "failure_reason_code": observability_failure,
        }
    )
    return failure, summary


def _execute_workflow(
    root: Path,
    *,
    records: int,
    batch_size: int,
    event_stream_max_bytes: int,
    event_stream_reserved_bytes: int,
    signed_audit: bool,
    artifacts_retained: bool,
) -> WorkflowBenchmarkReport:
    stages = _StageBook()
    progress = _Progress()
    events = EventStream(
        root / "operational-events.jsonl",
        max_stream_bytes=event_stream_max_bytes,
    )
    workflow_correlation_id = events.correlation_id("workflow")
    mapping_summary = {
        "source_fields": 0,
        "target_fields": 0,
        "auto": 0,
        "review": 0,
        "blocked": 0,
    }
    preflight: PreflightReport | None = None
    final_state: dict[str, object] = {}
    failure: WorkflowFailure | None = None
    destination: DatabaseConnector | None = None
    transport: _TransportRuntime | None = None
    iterator: Iterator[Mapping[str, object]] | None = None
    source_path = root / "source.csv"
    destination_path = root / "destination.sqlite"

    try:
        _emit_required_event(
            events,
            component="workflow_benchmark",
            event_type="workflow_started",
            status="started",
            correlation_id=workflow_correlation_id,
            item_count=records,
        )
        stages.measure(
            "fixture_generation",
            "records",
            lambda: _write_fixture(source_path, records),
            items=records,
        )
        stages.measure(
            "destination_setup",
            "tables",
            lambda: _create_destination(destination_path),
        )
        inspection = stages.measure(
            "content_inspection",
            "files",
            lambda: _checked_inspection(source_path),
        )
        source = CsvConnector(source_path, expected_source_identity=inspection.identity)
        source_schema = stages.measure(
            "source_schema_inspection",
            "fields",
            source.inspect_schema,
            items=lambda result: len(result.fields),
        )

        def inspect_destination() -> SchemaDescriptor:
            nonlocal destination
            destination = DatabaseConnector(_sqlite_url(destination_path), _TABLE_NAME)
            return destination.inspect_schema()

        target_schema = stages.measure(
            "target_schema_inspection",
            "fields",
            inspect_destination,
            items=lambda result: len(result.fields),
        )
        mapping_result = stages.measure(
            "mapping_and_plan",
            "fields",
            lambda: _checked_mapping(source_schema, target_schema),
            items=lambda result: len(result[0]),
        )
        _, plan, mapping_summary = mapping_result
        preflight = stages.measure(
            "full_preflight",
            "records",
            lambda: _checked_preflight(source, source_schema, target_schema, plan),
            items=lambda result: result.records_checked,
        )
        if destination is None:
            raise RuntimeError("destination connector was not created")
        transport = stages.measure(
            "security_and_state_setup",
            "components",
            lambda: _make_transport_runtime(
                root,
                source_schema,
                target_schema,
                plan,
                destination,
                events,
                signed_audit=signed_audit,
            ),
            items=6 if signed_audit else 5,
        )

        iterator = iter(source.iter_records())
        record_number = 0
        batch_number = 0
        source_exhausted = False
        while record_number < records and not source_exhausted:
            batch: list[dict[str, object]] = []
            while len(batch) < batch_size:
                raw_record = stages.measure(
                    "source_record_read",
                    "records",
                    partial(_read_source_record, iterator),
                    items=lambda result: 0 if result is None else 1,
                )
                if raw_record is None:
                    source_exhausted = True
                    break
                batch.append(raw_record)
                progress.records_read += 1
            if not batch:
                break
            batch_number += 1
            transfer_id = f"workflow-batch-{batch_number}"
            current_batch_size = len(batch)
            sealed = stages.measure(
                "source_seal_and_outbox_stage",
                "records",
                partial(
                    _seal_and_stage_batch,
                    transport,
                    batch,
                    first_record_number=record_number + 1,
                    transfer_id=transfer_id,
                ),
                items=current_batch_size,
            )
            record_number += current_batch_size
            progress.records_staged += len(sealed)
            stages.measure(
                "outbox_reload_and_relay_enqueue",
                "records",
                partial(_reload_and_enqueue, transport, current_batch_size, progress),
                items=current_batch_size,
            )
            lease_owner = f"workflow-worker-{batch_number}"
            leased = stages.measure(
                "relay_lease",
                "records",
                partial(_lease_batch, transport, current_batch_size, batch_number, progress),
                items=current_batch_size,
            )
            receipts = stages.measure(
                "destination_delivery",
                "records",
                partial(
                    _deliver_batch,
                    transport,
                    tuple(item.record for item in leased),
                    progress,
                ),
                items=current_batch_size,
            )
            stages.measure(
                "acknowledgements",
                "records",
                partial(_ack_batch, transport, leased, lease_owner),
                items=current_batch_size,
            )
            progress.records_acknowledged += current_batch_size
            stages.measure(
                "destination_audit_outcome_check",
                "events",
                partial(_check_audit_outcomes, transport, receipts),
                items=current_batch_size if transport.audit is not None else 0,
            )
            stages.measure(
                "destination_operational_event_check",
                "events",
                partial(_check_operational_event_outcomes, receipts),
                items=current_batch_size,
            )
            progress.batches_completed += 1
            _emit_required_event(
                events,
                component="workflow_benchmark",
                event_type="batch_completed",
                status="passed",
                correlation_id=events.correlation_id(f"batch:{batch_number}"),
                item_count=current_batch_size,
            )

        if not source_exhausted and progress.records_read == records:
            extra_record = stages.measure(
                "source_record_read",
                "records",
                partial(_read_source_record, iterator),
                items=lambda result: 0 if result is None else 1,
            )
            if extra_record is not None:
                progress.records_read += 1
        if progress.records_read != records:
            raise _WorkflowStopped(
                stages.mark_failed(
                    "source_record_read",
                    "records",
                    "source_record_count_mismatch",
                )
            )
    except _WorkflowStopped as exc:
        failure = exc.failure
    except _OperationalEventAppendFailed as exc:
        failure = stages.mark_failed(
            "workflow_internal",
            "operations",
            "observability_append_failed",
            error_type=exc.error_type,
        )
    except Exception as exc:
        failure = stages.mark_failed(
            "workflow_internal",
            "operations",
            "workflow_stage_failed",
            error_type=_safe_error_type(exc),
        )
    finally:
        if iterator is not None:
            close_iterator = getattr(iterator, "close", None)
            if callable(close_iterator):
                try:
                    close_iterator()
                except Exception as exc:
                    close_failure = stages.mark_failed(
                        "source_record_read",
                        "records",
                        "workflow_stage_failed",
                        error_type=_safe_error_type(exc),
                    )
                    if failure is None:
                        failure = close_failure

    if transport is not None:
        try:
            verification = stages.measure(
                "end_to_end_verification",
                "records",
                lambda: _verify_final_state(root, transport, records),
                items=lambda result: result.destination_rows,
            )
        except _WorkflowStopped as exc:
            if failure is None:
                failure = exc.failure
        else:
            final_state = verification.state
            if verification.reason_code is not None:
                verification_failure = stages.mark_failed(
                    "end_to_end_verification",
                    "records",
                    verification.reason_code,
                )
                if failure is None:
                    failure = verification_failure

    if destination is not None:
        try:
            destination.close()
        except Exception as exc:
            cleanup_failure = stages.mark_failed(
                "resource_cleanup",
                "resources",
                "workflow_stage_failed",
                error_type=_safe_error_type(exc),
            )
            if failure is None:
                failure = cleanup_failure

    failure, observability = _finalize_observability(
        events,
        stages,
        workflow_correlation_id,
        progress,
        failure,
    )
    observability["max_stream_bytes"] = event_stream_max_bytes
    observability["reserved_stream_bytes"] = event_stream_reserved_bytes
    if final_state:
        final_state["storage_bytes"] = _artifact_storage_bytes(root)

    return WorkflowBenchmarkReport(
        success=failure is None,
        records_requested=records,
        batch_size=batch_size,
        signed_audit_enabled=signed_audit,
        artifacts_retained=artifacts_retained,
        work_directory=str(root) if artifacts_retained else None,
        batches_completed=progress.batches_completed,
        records_read=progress.records_read,
        records_staged=progress.records_staged,
        records_relayed=progress.records_relayed,
        records_leased=progress.records_leased,
        records_delivered=progress.records_delivered,
        records_acknowledged=progress.records_acknowledged,
        mapping=mapping_summary,
        preflight=_preflight_payload(preflight),
        final_state=final_state,
        observability=observability,
        stages=stages.results(),
        failure=failure,
    )


def _prepare_workspace(
    work_dir: str | Path | None,
    *,
    keep_work_dir: bool,
) -> tuple[Path, bool, tempfile.TemporaryDirectory[str] | None]:
    if work_dir is not None:
        root = Path(work_dir).expanduser().resolve()
        if root.exists():
            if not root.is_dir():
                raise ValueError("workflow benchmark work path is not a directory")
            if any(root.iterdir()):
                raise ValueError("workflow benchmark work directory must be empty")
        else:
            root.mkdir(parents=True)
        return root, True, None
    if keep_work_dir:
        return Path(tempfile.mkdtemp(prefix="polymorph-workflow-")), True, None
    temporary = tempfile.TemporaryDirectory(prefix="polymorph-workflow-")
    return Path(temporary.name), False, temporary


def run_workflow_benchmark(
    *,
    records: int = 1000,
    batch_size: int = 100,
    work_dir: str | Path | None = None,
    keep_work_dir: bool = False,
    signed_audit: bool = True,
    trace_python_allocations: bool = False,
    event_stream_max_bytes: int = DEFAULT_EVENT_STREAM_BYTES,
) -> tuple[WorkflowBenchmarkReport, BenchmarkResult]:
    """Run the real local data path and return payload-free timing and state evidence."""

    if isinstance(records, bool) or not isinstance(records, int) or not 1 <= records <= 1_000_000:
        raise ValueError("workflow benchmark records must be between 1 and 1000000")
    if (
        isinstance(batch_size, bool)
        or not isinstance(batch_size, int)
        or not 1 <= batch_size <= 10_000
    ):
        raise ValueError("workflow benchmark batch size must be between 1 and 10000")
    event_stream_reserved_bytes = _validate_event_stream_capacity(
        records,
        batch_size,
        event_stream_max_bytes,
    )
    root, retained, temporary = _prepare_workspace(work_dir, keep_work_dir=keep_work_dir)
    report, resources = benchmark_call(
        "workflow_end_to_end",
        lambda: _execute_workflow(
            root,
            records=records,
            batch_size=batch_size,
            event_stream_max_bytes=event_stream_max_bytes,
            event_stream_reserved_bytes=event_stream_reserved_bytes,
            signed_audit=signed_audit,
            artifacts_retained=retained,
        ),
        result_count=lambda result: result.records_delivered,
        trace_python_allocations=trace_python_allocations,
    )
    if temporary is not None:
        wall_started = time.perf_counter_ns()
        cpu_started = time.process_time_ns()
        try:
            temporary.cleanup()
        except Exception as exc:
            wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
            cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
            cleanup_failure = WorkflowFailure(
                "resource_cleanup",
                "workflow_stage_failed",
                _safe_error_type(exc),
            )
            cleanup_stage = WorkflowStageResult(
                name="resource_cleanup",
                status="failed",
                wall_ms=wall_ms,
                cpu_ms=cpu_ms,
                calls=1,
                items_processed=0,
                item_unit="resources",
                throughput_per_second=None,
                latency_sample_count=1,
                call_latency_p50_ms=None,
                call_latency_p95_ms=None,
                reason_code="workflow_stage_failed",
            )
            report = replace(
                report,
                success=False,
                failure=report.failure or cleanup_failure,
                stages=(*report.stages, cleanup_stage),
            )
    return report, resources
