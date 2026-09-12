from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path

from polymorph.cli import build_parser
from polymorph.conformance import check_connector_conformance
from polymorph.connector_registry import (
    ConnectorSpec,
    EndpointRole,
    default_connector_registry,
)
from polymorph.connectors.base import ConnectorCapabilities, DeliveryContext
from polymorph.domain_events import (
    AsyncQueueEventSink,
    CallbackEventSink,
    EventDispatcher,
    EventScope,
    EventSeverity,
    PolymorphEvent,
    PresentationHint,
    RetryPolicy,
)
from polymorph.embed import MoveSession, RouteStatus
from polymorph.errors import PartialConnectorWriteError, WriteOutcome
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType


class _MemoryDestination:
    capabilities = ConnectorCapabilities(read_schema=True, write_records=True)

    def __init__(self, schema: SchemaDescriptor) -> None:
        self.schema = schema
        self.rows: list[dict[str, object]] = []

    def inspect_schema(self) -> SchemaDescriptor:
        return self.schema

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        del context
        written = 0
        for record in records:
            self.rows.append(dict(record))
            written += 1
        return written


class _PartialDestination(_MemoryDestination):
    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        del context
        first = next(iter(records))
        self.rows.append(dict(first))
        raise PartialConnectorWriteError(
            "synthetic committed prefix",
            committed_count=1,
            next_record_outcome=WriteOutcome.NOT_COMMITTED,
        )


class _MemorySource:
    capabilities = ConnectorCapabilities(read_schema=True, read_records=True)

    def __init__(self, schema: SchemaDescriptor) -> None:
        self.schema = schema

    def inspect_schema(self) -> SchemaDescriptor:
        return self.schema

    def iter_records(self) -> Iterable[Mapping[str, object]]:
        yield {"customer_id": "C-1"}


def _target_schema() -> SchemaDescriptor:
    return SchemaDescriptor(
        "target",
        (FieldDescriptor("customer_id", "Customer ID", DataType.STRING, nullable=False),),
    )


def _json_source(path: Path) -> None:
    path.write_text(
        '[{"customer_id":"C-1"},{"customer_id":"C-2"}]',
        encoding="utf-8",
    )


def test_domain_event_localization_and_payload_contract() -> None:
    event = PolymorphEvent.create(
        "mapping.review_required",
        severity=EventSeverity.REVIEW,
        default_message="Review is required.",
        next_action="Review the proposed field.",
        retry_policy=RetryPolicy.AFTER_REVIEW,
        presentation_hint=PresentationHint.DIALOG,
        run_id="run-1",
        correlation_id="route-1",
        scope=EventScope("mapping", source_field_id="legacy_customer"),
        reason_code="mapping_review_required",
        parameters={"review_fields": 1},
    )

    payload = event.as_dict()

    assert payload["schema_version"] == 1
    assert payload["retry_policy"] == "after_review"
    assert "explizite Entscheidung" in event.localized_message("de")
    assert "record" not in payload


def test_event_consumers_cannot_interrupt_each_other() -> None:
    delivered: list[PolymorphEvent] = []

    def fail(_event: PolymorphEvent) -> None:
        raise RuntimeError("consumer-local failure")

    dispatcher = EventDispatcher([CallbackEventSink(fail), CallbackEventSink(delivered.append)])
    event = PolymorphEvent.create(
        "run.started",
        severity=EventSeverity.INFO,
        default_message="Run started.",
        next_action="Wait.",
        retry_policy=RetryPolicy.NOT_APPLICABLE,
        presentation_hint=PresentationHint.BACKGROUND,
        run_id="run-1",
        correlation_id="route-1",
        scope=EventScope("run"),
    )

    dispatcher.emit(event)

    assert delivered == [event]
    assert dispatcher.failure_count == 1
    assert dispatcher.failures[0].error_type == "RuntimeError"


def test_async_event_queue_is_bounded() -> None:
    queue = AsyncQueueEventSink(maxsize=1)
    event = PolymorphEvent.create(
        "run.started",
        severity=EventSeverity.INFO,
        default_message="Run started.",
        next_action="Wait.",
        retry_policy=RetryPolicy.NOT_APPLICABLE,
        presentation_hint=PresentationHint.BACKGROUND,
        run_id="run-1",
        correlation_id="route-1",
        scope=EventScope("run"),
    )

    queue.emit(event)

    assert queue.pending == 1
    assert queue.get_nowait() is event


def test_registry_resolves_source_from_content_and_hides_configuration(tmp_path) -> None:
    source = tmp_path / "payload.unknown"
    _json_source(source)
    registry = default_connector_registry()

    resolved = registry.resolve_file_source(source)
    secret_spec = ConnectorSpec.destination(
        "database",
        url="postgresql://user:secret@example.invalid/database",
        table="customers",
    )

    assert resolved.manifest.connector_id == "json"
    assert resolved.connector.inspect_schema().fields[0].id == "customer_id"
    assert "secret" not in repr(secret_spec)
    assert {item.connector_id for item in registry.manifests()} == {
        "csv",
        "database",
        "excel",
        "http-json",
        "json",
        "parquet",
    }


def test_connector_conformance_is_non_invasive() -> None:
    destination = _MemoryDestination(_target_schema())

    report = check_connector_conformance(destination, EndpointRole.DESTINATION)

    assert report.passed
    assert destination.rows == []


def test_embedded_move_prepares_then_streams_only_after_execute(tmp_path) -> None:
    source = tmp_path / "customers.upload"
    _json_source(source)
    destination = _MemoryDestination(_target_schema())
    observed: list[str] = []
    session = MoveSession(source, destination, progress_interval=1)
    session.on("*", lambda event: observed.append(event.event_type))

    preparation = session.prepare()

    assert preparation.status is RouteStatus.READY
    assert preparation.source_snapshot_proven
    assert destination.rows == []

    result = session.execute()

    assert result.status is RouteStatus.COMPLETED
    assert result.records_written == 2
    assert destination.rows == [{"customer_id": "C-1"}, {"customer_id": "C-2"}]
    assert "run.progress" in observed
    assert observed[-1] == "run.completed"


def test_embedded_move_preserves_partial_write_evidence(tmp_path) -> None:
    source = tmp_path / "customers.data"
    _json_source(source)
    destination = _PartialDestination(_target_schema())
    session = MoveSession(source, destination)

    result = session.execute()

    assert result.status is RouteStatus.PARTIAL
    assert result.records_written == 1
    assert result.retry_policy is RetryPolicy.NEVER_BLIND
    assert "committed prefix of 1" in result.destination_evidence


def test_embedded_move_refuses_unproven_mutable_source() -> None:
    schema = _target_schema()
    destination = _MemoryDestination(schema)
    session = MoveSession(_MemorySource(schema), destination)

    assert session.prepare().status is RouteStatus.READY
    result = session.execute()

    assert result.status is RouteStatus.BLOCKED
    assert result.reason_code == "source_snapshot_unproven"
    assert destination.rows == []


def test_connector_and_demo_cli_are_local_and_machine_usable(tmp_path, capsys) -> None:
    connector_args = build_parser().parse_args(["connectors"])
    connector_args.func(connector_args)
    connectors = json.loads(capsys.readouterr().out)
    assert connectors["third_party_loading"] == "disabled"
    assert len(connectors["connectors"]) == 6

    output = tmp_path / "demo.html"
    demo_args = build_parser().parse_args(["demo", "--locale", "de", "--output", str(output)])
    demo_args.func(demo_args)
    summary = json.loads(capsys.readouterr().out)

    rendered = output.read_text(encoding="utf-8")
    assert summary["destination_write_called"] is False
    assert summary["network_used"] is False
    assert summary["route_status"] == "ready"
    assert "LOCAL PRODUCT DEMO" not in rendered
    assert "LOKALE PRODUKT-DEMO" in rendered
    assert "https://" not in rendered
    assert "<svg" in rendered
