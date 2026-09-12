from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TypeAlias, cast

from .conformance import assert_connector_conformant
from .connector_registry import (
    ConnectorRegistry,
    ConnectorResolutionError,
    ConnectorSpec,
    EndpointRole,
    default_connector_registry,
)
from .connectors.base import (
    ConnectorCapabilities,
    DestinationConnector,
    SourceConnector,
)
from .content import FileInspection
from .domain_events import (
    EventDispatcher,
    EventHandler,
    EventParameter,
    EventScope,
    EventSeverity,
    EventSink,
    PolymorphEvent,
    PresentationHint,
    RetryPolicy,
    message_for,
)
from .errors import ConnectorWriteError, PartialConnectorWriteError, WriteOutcome
from .execution import DataPlaneExecutor
from .matching import HybridMatcher
from .models.mapping import MappingDecision, MappingPlan, MappingStatus
from .models.schema import SchemaDescriptor
from .planning import build_plan
from .preflight import ForeignKeyResolver, PreflightReport, PreflightRunner
from .serialization import plan_to_dict, schema_to_dict

SourceInput: TypeAlias = str | Path | SourceConnector | ConnectorSpec
DestinationInput: TypeAlias = DestinationConnector | ConnectorSpec

_EVENT_ALIASES = {
    "review_required": "mapping.review_required",
    "blocked": "run.blocked",
    "progress": "run.progress",
    "completed": "run.completed",
}


class RouteStatus(StrEnum):
    READY = "ready"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    NOT_COMMITTED = "not_committed"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ReviewedMapping:
    source_field_id: str
    target_field_id: str
    reviewed_by: str

    def __post_init__(self) -> None:
        for label, value in (
            ("source field id", self.source_field_id),
            ("target field id", self.target_field_id),
            ("reviewer", self.reviewed_by),
        ):
            if not value or len(value) > 128 or not value.isprintable() or value != value.strip():
                raise ValueError(f"{label} must be bounded printable text")

    def as_dict(self) -> dict[str, str]:
        return {
            "source_field_id": self.source_field_id,
            "target_field_id": self.target_field_id,
            "reviewed_by": self.reviewed_by,
        }


def _decision_dict(decision: MappingDecision) -> dict[str, object]:
    return {
        "source_field_id": decision.source_field_id,
        "target_field_id": decision.target_field_id,
        "status": decision.status.value,
        "score": decision.score,
        "margin": decision.margin,
        "reasons": list(decision.reasons),
    }


@dataclass(frozen=True, slots=True)
class RoutePreparation:
    run_id: str
    status: RouteStatus
    source_connector_id: str
    destination_connector_id: str
    source_schema: SchemaDescriptor
    destination_schema: SchemaDescriptor
    decisions: tuple[MappingDecision, ...]
    reviewed_mappings: tuple[ReviewedMapping, ...]
    source_snapshot_proven: bool
    plan: MappingPlan | None = None
    preflight: PreflightReport | None = None
    content: FileInspection | None = None
    reason_codes: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return self.status is RouteStatus.READY

    def as_dict(self) -> dict[str, object]:
        return {
            "contract_version": 1,
            "run_id": self.run_id,
            "status": self.status.value,
            "ready": self.ready,
            "source_connector_id": self.source_connector_id,
            "destination_connector_id": self.destination_connector_id,
            "source_snapshot_proven": self.source_snapshot_proven,
            "content": self.content.as_dict() if self.content is not None else None,
            "source_schema": schema_to_dict(self.source_schema),
            "destination_schema": schema_to_dict(self.destination_schema),
            "decisions": [_decision_dict(item) for item in self.decisions],
            "reviewed_mappings": [item.as_dict() for item in self.reviewed_mappings],
            "plan": plan_to_dict(self.plan) if self.plan is not None else None,
            "preflight": self.preflight.as_dict() if self.preflight is not None else None,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class MoveResult:
    run_id: str
    status: RouteStatus
    records_written: int | None
    reason_code: str | None
    next_action: str
    retry_policy: RetryPolicy
    destination_evidence: str
    event_delivery_failures: int

    @property
    def completed(self) -> bool:
        return self.status is RouteStatus.COMPLETED

    def as_dict(self) -> dict[str, object]:
        return {
            "contract_version": 1,
            "run_id": self.run_id,
            "status": self.status.value,
            "completed": self.completed,
            "records_written": self.records_written,
            "reason_code": self.reason_code,
            "next_action": self.next_action,
            "retry_policy": self.retry_policy.value,
            "destination_evidence": self.destination_evidence,
            "event_delivery_failures": self.event_delivery_failures,
        }


class MoveSession:
    """Explicit prepare-then-execute API for an embedded local bridge."""

    def __init__(
        self,
        source: SourceInput,
        destination: DestinationInput,
        *,
        registry: ConnectorRegistry | None = None,
        matcher: HybridMatcher | None = None,
        events: EventDispatcher | None = None,
        max_input_records: int = 100_000,
        progress_interval: int = 100,
    ) -> None:
        for name, value in (
            ("max_input_records", max_input_records),
            ("progress_interval", progress_interval),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._source_input = source
        self._destination_input = destination
        self._registry = registry or default_connector_registry()
        self._matcher = matcher or HybridMatcher()
        self._events = events or EventDispatcher()
        self._max_input_records = max_input_records
        self._progress_interval = progress_interval
        self._run_id = uuid.uuid4().hex
        self._correlation_id = uuid.uuid4().hex
        self._source: SourceConnector | None = None
        self._destination: DestinationConnector | None = None
        self._source_connector_id = "embedded-source"
        self._destination_connector_id = "embedded-destination"
        self._inspection: FileInspection | None = None
        self._reviews: dict[str, ReviewedMapping] = {}
        self._preparation: RoutePreparation | None = None
        self._destination_capabilities: ConnectorCapabilities | None = None

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def event_dispatcher(self) -> EventDispatcher:
        return self._events

    def on(self, event_type: str, handler: EventHandler) -> MoveSession:
        self._events.on(_EVENT_ALIASES.get(event_type, event_type), handler)
        return self

    def add_event_sink(self, sink: EventSink) -> MoveSession:
        self._events.add_sink(sink)
        return self

    def review_mapping(
        self,
        source_field_id: str,
        target_field_id: str,
        *,
        reviewed_by: str,
    ) -> MoveSession:
        reviewed = ReviewedMapping(source_field_id, target_field_id, reviewed_by)
        self._reviews[source_field_id] = reviewed
        self._preparation = None
        return self

    def _emit(
        self,
        event_type: str,
        *,
        severity: EventSeverity,
        stage: str,
        next_action: str,
        retry_policy: RetryPolicy,
        presentation_hint: PresentationHint,
        reason_code: str | None = None,
        connector_id: str | None = None,
        parameters: Mapping[str, EventParameter] | None = None,
    ) -> PolymorphEvent:
        event = PolymorphEvent.create(
            event_type,
            severity=severity,
            default_message=message_for(event_type),
            next_action=next_action,
            retry_policy=retry_policy,
            presentation_hint=presentation_hint,
            run_id=self._run_id,
            correlation_id=self._correlation_id,
            scope=EventScope(stage=stage, connector_id=connector_id),
            reason_code=reason_code,
            parameters=parameters,
        )
        self._events.emit(event)
        return event

    def _resolve_source(self) -> SourceConnector:
        if self._source is not None:
            return self._source
        if isinstance(self._source_input, (str, Path)):
            resolved = self._registry.resolve_file_source(self._source_input)
            self._source = resolved.connector
            self._source_connector_id = resolved.manifest.connector_id
            self._inspection = resolved.inspection
        elif isinstance(self._source_input, ConnectorSpec):
            self._source = self._registry.create_source(self._source_input)
            self._source_connector_id = self._source_input.connector_id
        else:
            assert_connector_conformant(self._source_input, EndpointRole.SOURCE)
            self._source = self._source_input
        return self._source

    def _resolve_destination(self) -> DestinationConnector:
        if self._destination is not None:
            return self._destination
        if isinstance(self._destination_input, ConnectorSpec):
            self._destination = self._registry.create_destination(self._destination_input)
            self._destination_connector_id = self._destination_input.connector_id
        elif isinstance(self._destination_input, (str, Path)):
            raise ConnectorResolutionError(
                "destination inference is forbidden; pass a destination connector or "
                "ConnectorSpec.destination(...)"
            )
        else:
            assert_connector_conformant(self._destination_input, EndpointRole.DESTINATION)
            self._destination = self._destination_input
        return self._destination

    def prepare(self) -> RoutePreparation:
        if self._preparation is not None:
            return self._preparation
        self._emit(
            "run.started",
            severity=EventSeverity.INFO,
            stage="run",
            next_action="Wait for inspection, mapping and preflight to finish.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.BACKGROUND,
        )
        self._emit(
            "source.inspecting",
            severity=EventSeverity.INFO,
            stage="source",
            next_action="Wait for the content and schema trust gates.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.INLINE,
        )
        source = self._resolve_source()
        destination = self._resolve_destination()
        source_schema = source.inspect_schema()
        destination_schema = destination.inspect_schema()
        self._destination_capabilities = destination.capabilities
        self._emit(
            "source.accepted",
            severity=EventSeverity.INFO,
            stage="source",
            next_action="Continue to deterministic schema matching.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.INLINE,
            connector_id=self._source_connector_id,
            parameters={
                "fields": len(source_schema.fields),
                "snapshot_proven": self._inspection is not None,
            },
        )
        self._emit(
            "mapping.started",
            severity=EventSeverity.INFO,
            stage="mapping",
            next_action="Wait for policy-constrained mapping decisions.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.BACKGROUND,
        )
        proposed = self._matcher.propose(source_schema, destination_schema)
        proposed_source_ids = {item.source_field_id for item in proposed}
        unknown_reviews = sorted(set(self._reviews) - proposed_source_ids)
        if unknown_reviews:
            raise ValueError(f"review references unknown source field: {unknown_reviews[0]}")
        destination_fields = destination_schema.by_id()
        decisions: list[MappingDecision] = []
        unresolved_reviews = 0
        blocked = 0
        reviewed_mappings: list[ReviewedMapping] = []
        for decision in proposed:
            reviewed = self._reviews.get(decision.source_field_id)
            if reviewed is not None:
                if reviewed.target_field_id not in destination_fields:
                    raise ValueError(
                        f"review references unknown target field: {reviewed.target_field_id}"
                    )
                if decision.status is MappingStatus.BLOCKED:
                    blocked += 1
                    decisions.append(decision)
                    continue
                decision = MappingDecision(
                    source_field_id=decision.source_field_id,
                    target_field_id=reviewed.target_field_id,
                    status=MappingStatus.REVIEW,
                    score=decision.score,
                    margin=decision.margin,
                    reasons=(*decision.reasons, "explicit_operator_review"),
                )
                reviewed_mappings.append(reviewed)
            elif decision.status is MappingStatus.REVIEW:
                unresolved_reviews += 1
            elif decision.status is MappingStatus.BLOCKED:
                blocked += 1
            decisions.append(decision)

        def assembled_preparation(
            status: RouteStatus,
            *,
            plan: MappingPlan | None = None,
            preflight: PreflightReport | None = None,
            reason_codes: tuple[str, ...] = (),
        ) -> RoutePreparation:
            return RoutePreparation(
                run_id=self._run_id,
                status=status,
                source_connector_id=self._source_connector_id,
                destination_connector_id=self._destination_connector_id,
                source_schema=source_schema,
                destination_schema=destination_schema,
                decisions=tuple(decisions),
                reviewed_mappings=tuple(reviewed_mappings),
                source_snapshot_proven=self._inspection is not None,
                plan=plan,
                preflight=preflight,
                content=self._inspection,
                reason_codes=reason_codes,
            )

        if blocked:
            self._preparation = assembled_preparation(
                RouteStatus.BLOCKED,
                reason_codes=("mapping_blocked",),
            )
            self._emit(
                "mapping.blocked",
                severity=EventSeverity.ERROR,
                stage="mapping",
                next_action="Inspect blocked fields and policy evidence before creating a route.",
                retry_policy=RetryPolicy.AFTER_REVIEW,
                presentation_hint=PresentationHint.DIALOG,
                reason_code="mapping_blocked",
                parameters={"blocked_fields": blocked},
            )
            self._emit(
                "run.blocked",
                severity=EventSeverity.ERROR,
                stage="run",
                next_action="Resolve the mapping block; no destination write was called.",
                retry_policy=RetryPolicy.AFTER_REVIEW,
                presentation_hint=PresentationHint.BANNER,
                reason_code="mapping_blocked",
            )
            return self._preparation
        if unresolved_reviews:
            self._preparation = assembled_preparation(
                RouteStatus.REVIEW_REQUIRED,
                reason_codes=("mapping_review_required",),
            )
            self._emit(
                "mapping.review_required",
                severity=EventSeverity.REVIEW,
                stage="mapping",
                next_action="Review each unresolved suggestion and call review_mapping explicitly.",
                retry_policy=RetryPolicy.AFTER_REVIEW,
                presentation_hint=PresentationHint.DIALOG,
                reason_code="mapping_review_required",
                parameters={"review_fields": unresolved_reviews},
            )
            return self._preparation

        plan = build_plan(
            source_schema,
            destination_schema,
            decisions,
            allow_review=bool(reviewed_mappings),
        )
        self._emit(
            "mapping.ready",
            severity=EventSeverity.INFO,
            stage="mapping",
            next_action="Run a complete no-write preflight.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.INLINE,
            parameters={"rules": len(plan.rules), "reviewed_rules": len(reviewed_mappings)},
        )
        self._emit(
            "preflight.started",
            severity=EventSeverity.INFO,
            stage="preflight",
            next_action="Wait for every source record to be checked without destination writes.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.BACKGROUND,
        )
        foreign_key_resolver = (
            cast(ForeignKeyResolver, destination)
            if callable(getattr(destination, "resolve_foreign_key", None))
            else None
        )
        preflight = PreflightRunner().run(
            source.iter_records(),
            source_schema,
            destination_schema,
            plan,
            max_input_records=self._max_input_records,
            foreign_key_resolver=foreign_key_resolver,
        )
        reason_codes = tuple(
            dict.fromkeys(
                [item.code for item in preflight.plan_validation.findings]
                + [item.code for item in preflight.findings]
            )
        )
        self._emit(
            "preflight.completed",
            severity=EventSeverity.INFO if preflight.promotable else EventSeverity.WARNING,
            stage="preflight",
            next_action=(
                "The route may be executed explicitly."
                if preflight.promotable
                else "Inspect every preflight finding before another attempt."
            ),
            retry_policy=(
                RetryPolicy.NOT_APPLICABLE if preflight.promotable else RetryPolicy.AFTER_REVIEW
            ),
            presentation_hint=PresentationHint.INLINE,
            reason_code=None if preflight.promotable else "preflight_not_promotable",
            parameters={
                "records_checked": preflight.records_checked,
                "promotable": preflight.promotable,
            },
        )
        status = (
            RouteStatus.READY
            if preflight.promotable
            else RouteStatus.REVIEW_REQUIRED
            if preflight.requires_review
            else RouteStatus.BLOCKED
        )
        if not reason_codes and status is not RouteStatus.READY:
            reason_codes = ("preflight_not_promotable",)
        self._preparation = assembled_preparation(
            status,
            plan=plan,
            preflight=preflight,
            reason_codes=reason_codes,
        )
        if status is RouteStatus.READY:
            self._emit(
                "run.ready",
                severity=EventSeverity.INFO,
                stage="run",
                next_action="Call execute() explicitly to cross the destination write boundary.",
                retry_policy=RetryPolicy.NOT_APPLICABLE,
                presentation_hint=PresentationHint.BANNER,
                parameters={"records_checked": preflight.records_checked},
            )
        else:
            self._emit(
                "run.blocked",
                severity=(
                    EventSeverity.REVIEW
                    if status is RouteStatus.REVIEW_REQUIRED
                    else EventSeverity.ERROR
                ),
                stage="run",
                next_action="Resolve preflight findings; no destination write was called.",
                retry_policy=RetryPolicy.AFTER_REVIEW,
                presentation_hint=PresentationHint.BANNER,
                reason_code=reason_codes[0],
            )
        return self._preparation

    def _result(
        self,
        status: RouteStatus,
        *,
        records_written: int | None,
        reason_code: str | None,
        next_action: str,
        retry_policy: RetryPolicy,
        destination_evidence: str,
    ) -> MoveResult:
        return MoveResult(
            run_id=self._run_id,
            status=status,
            records_written=records_written,
            reason_code=reason_code,
            next_action=next_action,
            retry_policy=retry_policy,
            destination_evidence=destination_evidence,
            event_delivery_failures=self._events.failure_count,
        )

    def _blocked_result(self, reason_code: str, next_action: str) -> MoveResult:
        self._emit(
            "run.blocked",
            severity=EventSeverity.ERROR,
            stage="run",
            next_action=next_action,
            retry_policy=RetryPolicy.AFTER_REVIEW,
            presentation_hint=PresentationHint.BANNER,
            reason_code=reason_code,
        )
        return self._result(
            RouteStatus.BLOCKED,
            records_written=0,
            reason_code=reason_code,
            next_action=next_action,
            retry_policy=RetryPolicy.AFTER_REVIEW,
            destination_evidence="The destination write method was not called.",
        )

    def execute(self) -> MoveResult:
        preparation = self.prepare()
        if not preparation.ready:
            policy = (
                RetryPolicy.AFTER_REVIEW
                if preparation.status is RouteStatus.REVIEW_REQUIRED
                else RetryPolicy.NEVER_BLIND
            )
            return self._result(
                preparation.status,
                records_written=0,
                reason_code=(preparation.reason_codes[0] if preparation.reason_codes else None),
                next_action="Resolve preparation findings before requesting a destination write.",
                retry_policy=policy,
                destination_evidence="The destination write method was not called.",
            )
        if self._inspection is None:
            return self._blocked_result(
                "source_snapshot_unproven",
                "Use a content-inspected immutable file source or the separately authorized "
                "secure agent workflow.",
            )
        if preparation.plan is None or preparation.preflight is None:
            return self._blocked_result(
                "prepared_route_incomplete",
                "Prepare the route again before execution.",
            )
        plan = preparation.plan
        preflight = preparation.preflight
        if any(rule.transform == "opaque_forward" for rule in plan.rules):
            return self._blocked_result(
                "local_mode_requires_encrypted_transport",
                "Execute secret or opaque fields through the recipient-key secure agent workflow.",
            )
        source = self._resolve_source()
        destination = self._resolve_destination()
        if destination.capabilities != self._destination_capabilities:
            return self._blocked_result(
                "destination_capability_changed",
                "Recreate and prepare the session against one stable connector contract.",
            )
        current_destination_schema = destination.inspect_schema()
        if current_destination_schema.fingerprint() != preparation.destination_schema.fingerprint():
            return self._blocked_result(
                "target_schema_drift",
                "Reinspect the destination and prepare a new route before writing.",
            )
        executor = DataPlaneExecutor(
            preparation.source_schema,
            preparation.destination_schema,
            plan,
        )
        prepared_count = 0

        def mapped_records() -> Iterable[Mapping[str, object]]:
            nonlocal prepared_count
            for record in source.iter_records():
                if prepared_count >= self._max_input_records:
                    raise ConnectorResolutionError(
                        "source exceeded the prepared input-record budget during execution"
                    )
                mapped = executor.execute_record(record)
                prepared_count += 1
                if prepared_count == 1 or prepared_count % self._progress_interval == 0:
                    self._emit(
                        "run.progress",
                        severity=EventSeverity.INFO,
                        stage="write",
                        next_action="Continue consuming the bounded local stream.",
                        retry_policy=RetryPolicy.NOT_APPLICABLE,
                        presentation_hint=PresentationHint.BACKGROUND,
                        parameters={
                            "records_prepared": prepared_count,
                            "records_total": preflight.records_checked,
                        },
                    )
                yield mapped

        self._emit(
            "destination.write_started",
            severity=EventSeverity.INFO,
            stage="write",
            next_action="Wait for an explicit connector durability outcome.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.BACKGROUND,
            connector_id=self._destination_connector_id,
            parameters={"records_expected": preflight.records_checked},
        )
        try:
            written = destination.write_records(mapped_records())
            if (
                isinstance(written, bool)
                or not isinstance(written, int)
                or written < 0
                or written != prepared_count
                or written != preflight.records_checked
            ):
                self._emit(
                    "destination.write_unknown",
                    severity=EventSeverity.ERROR,
                    stage="write",
                    next_action="Reconcile destination rows before any retry.",
                    retry_policy=RetryPolicy.NEVER_BLIND,
                    presentation_hint=PresentationHint.INCIDENT,
                    reason_code="destination_write_count_unproven",
                )
                return self._result(
                    RouteStatus.UNKNOWN,
                    records_written=None,
                    reason_code="destination_write_count_unproven",
                    next_action="Reconcile destination rows before any retry.",
                    retry_policy=RetryPolicy.NEVER_BLIND,
                    destination_evidence="The connector returned an inconsistent write count.",
                )
        except PartialConnectorWriteError as exc:
            self._emit(
                "destination.write_partial",
                severity=EventSeverity.ERROR,
                stage="write",
                next_action="Preserve the committed prefix and reconcile the unexecuted remainder.",
                retry_policy=RetryPolicy.NEVER_BLIND,
                presentation_hint=PresentationHint.INCIDENT,
                reason_code="destination_write_partial",
                parameters={"committed_records": exc.committed_count},
            )
            return self._result(
                RouteStatus.PARTIAL,
                records_written=exc.committed_count,
                reason_code="destination_write_partial",
                next_action=(
                    "Retry only a newly constructed remainder after preserving and reconciling "
                    "the committed prefix."
                ),
                retry_policy=RetryPolicy.NEVER_BLIND,
                destination_evidence=(
                    f"The connector proved a committed prefix of {exc.committed_count} record(s); "
                    f"the next record outcome is {exc.next_record_outcome.value}."
                ),
            )
        except ConnectorWriteError as exc:
            if exc.outcome is WriteOutcome.NOT_COMMITTED:
                self._emit(
                    "destination.write_not_committed",
                    severity=EventSeverity.WARNING,
                    stage="write",
                    next_action="Fix the connector or destination issue, then prepare again.",
                    retry_policy=RetryPolicy.SAFE_AFTER_FIX,
                    presentation_hint=PresentationHint.BANNER,
                    reason_code="write_not_committed",
                )
                return self._result(
                    RouteStatus.NOT_COMMITTED,
                    records_written=0,
                    reason_code="write_not_committed",
                    next_action="Fix the connector or destination issue, then prepare again.",
                    retry_policy=RetryPolicy.SAFE_AFTER_FIX,
                    destination_evidence="The connector explicitly proved that no write committed.",
                )
            self._emit(
                "destination.write_unknown",
                severity=EventSeverity.ERROR,
                stage="write",
                next_action="Reconcile destination state before any retry.",
                retry_policy=RetryPolicy.NEVER_BLIND,
                presentation_hint=PresentationHint.INCIDENT,
                reason_code="write_outcome_unknown",
            )
            return self._result(
                RouteStatus.UNKNOWN,
                records_written=None,
                reason_code="write_outcome_unknown",
                next_action="Reconcile destination state before any retry.",
                retry_policy=RetryPolicy.NEVER_BLIND,
                destination_evidence="The connector did not prove whether the write committed.",
            )
        except Exception as exc:
            self._emit(
                "destination.write_unknown",
                severity=EventSeverity.ERROR,
                stage="write",
                next_action="Reconcile destination state before any retry.",
                retry_policy=RetryPolicy.NEVER_BLIND,
                presentation_hint=PresentationHint.INCIDENT,
                reason_code="destination_write_exception_unknown",
                parameters={"error_type": type(exc).__name__},
            )
            return self._result(
                RouteStatus.UNKNOWN,
                records_written=None,
                reason_code="destination_write_exception_unknown",
                next_action="Reconcile destination state before any retry.",
                retry_policy=RetryPolicy.NEVER_BLIND,
                destination_evidence=(
                    "An exception crossed the write boundary without explicit durability evidence."
                ),
            )

        self._emit(
            "run.completed",
            severity=EventSeverity.INFO,
            stage="run",
            next_action="Retain the plan and connector outcome as run evidence.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            presentation_hint=PresentationHint.BANNER,
            parameters={"records_written": written},
        )
        return self._result(
            RouteStatus.COMPLETED,
            records_written=written,
            reason_code=None,
            next_action="Retain the plan and connector outcome as run evidence.",
            retry_policy=RetryPolicy.NOT_APPLICABLE,
            destination_evidence=(
                f"The connector synchronously reported {written} written record(s)."
            ),
        )


def move(
    source: SourceInput,
    destination: DestinationInput,
    **options: object,
) -> MoveSession:
    """Create an explicit two-phase move session; this function never writes by itself."""

    return MoveSession(source, destination, **options)  # type: ignore[arg-type]
