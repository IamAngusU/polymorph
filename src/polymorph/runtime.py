from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import islice

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .agents import BlindDestinationAgent, BlindTransportRecord
from .audit import AuditEvent, AuditLog
from .capabilities import CapabilityAuthorizer, CapabilityOperation
from .connectors.base import (
    BatchWriteItem,
    ConnectorCapabilities,
    DeliveryContext,
    DestinationConnector,
)
from .connectors.inference import value_satisfies_type
from .errors import (
    ConnectorWriteError,
    IntegrityError,
    PolicyViolation,
    WriteOutcome,
)
from .ledger import (
    DEFAULT_CLAIM_DURATION,
    MAX_CLAIM_DURATION,
    MAX_LEDGER_BATCH_ITEMS,
    ClaimDisposition,
    DeliveryLedger,
    DeliveryState,
)
from .models.mapping import MappingPlan
from .models.schema import FieldDescriptor, SchemaDescriptor
from .models.types import DataType
from .observability import MAX_EVENT_BATCH_EVENTS, EventStream, EventWriteStatus
from .spool import MAX_SPOOL_BATCH_ITEMS, SealedSpool
from .transforms import TransformStage, transform_stage


class DeliveryStatus(StrEnum):
    DELIVERED = "delivered"
    DUPLICATE = "duplicate"
    QUARANTINED = "quarantined"
    AMBIGUOUS = "ambiguous"


class AuditWriteStatus(StrEnum):
    DISABLED = "disabled"
    RECORDED = "recorded"
    APPEND_FAILED = "append_failed"


@dataclass(frozen=True, slots=True)
class DeliveryReceipt:
    status: DeliveryStatus
    tenant: str
    destination_connector: str
    transfer_id: str
    record_id: str
    record_digest: str
    plan_digest: str
    completed_at: str
    reason_code: str | None = None
    retry_safe: bool = False
    audit_recorded: bool = False
    audit_status: AuditWriteStatus = AuditWriteStatus.DISABLED
    operational_event_recorded: bool = False
    operational_event_status: EventWriteStatus = EventWriteStatus.DISABLED
    run_id: str | None = None
    correlation_id: str | None = None
    batch_attempt_id: str | None = None


class DeliveryBatchInterrupted(Exception):
    """A later internal chunk failed after earlier receipts became durable.

    The immutable tuple exposes only completed receipt evidence. The triggering exception is
    retained through normal exception chaining and is never copied into public diagnostics.
    """

    __slots__ = ("_completed_receipts",)

    def __init__(self, completed_receipts: Sequence[DeliveryReceipt]) -> None:
        materialized = tuple(completed_receipts)
        if not materialized:
            raise ValueError("an interrupted delivery batch requires completed receipts")
        super().__init__("delivery batch interrupted after completed chunks")
        self._completed_receipts = materialized

    @property
    def completed_receipts(self) -> tuple[DeliveryReceipt, ...]:
        return self._completed_receipts


@dataclass(frozen=True, slots=True)
class _ReceiptRequest:
    record: BlindTransportRecord
    status: DeliveryStatus
    reason_code: str | None = None
    retry_safe: bool | None = None
    event_type: str = "delivery"
    batch_attempt_id: str | None = None


def _idempotency_key(record: BlindTransportRecord) -> str:
    material = "\x00".join(
        (
            "angusu.bridge.delivery/v1",
            record.tenant,
            record.destination_connector,
            record.transfer_id,
            record.record_id,
            record.digest(),
        )
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _scalar_idempotency_contract_id(capabilities: ConnectorCapabilities) -> str | None:
    if not capabilities.supports_idempotency:
        return None
    return capabilities.idempotency_contract_id


def _batch_idempotency_contract_id(capabilities: ConnectorCapabilities) -> str | None:
    batch = capabilities.atomic_batch_write
    if (
        not capabilities.supports_idempotency
        or batch is None
        or not batch.per_item_idempotency_across_batch_and_scalar
    ):
        return None
    return capabilities.idempotency_contract_id


@dataclass(slots=True)
class DestinationRuntime:
    connector_id: str
    agent: BlindDestinationAgent
    connector: DestinationConnector
    ledger: DeliveryLedger
    spool: SealedSpool
    plan: MappingPlan
    target_schema: SchemaDescriptor
    authorizer: CapabilityAuthorizer | None = None
    audit: AuditLog | None = None
    events: EventStream | None = None
    actor_id: str = "destination-runtime"
    claim_lease: timedelta = DEFAULT_CLAIM_DURATION
    _plan_digest: str = field(init=False, repr=False)
    _mapped_target_fields: tuple[FieldDescriptor, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.actor_id or len(self.actor_id) > 128 or not self.actor_id.isprintable():
            raise ValueError("destination runtime actor id must be bounded printable metadata")
        if self.claim_lease <= timedelta(0) or self.claim_lease > MAX_CLAIM_DURATION:
            raise ValueError("claim duration is outside supported range")
        if not self.connector.capabilities.write_records:
            raise ValueError("destination connector does not advertise write capability")
        if self.connector.capabilities.atomic_batch_write is not None and not callable(
            getattr(self.connector, "write_batch", None)
        ):
            raise ValueError("destination connector advertises atomic batching without a writer")
        if self.agent.expected_connector_id is None:
            self.agent.expected_connector_id = self.connector_id
        elif self.agent.expected_connector_id != self.connector_id:
            raise ValueError("destination agent and runtime connector ids differ")

        if self.plan.target_schema_id != self.target_schema.id:
            raise ValueError("runtime plan and target schema ids differ")
        if self.plan.target_fingerprint != self.target_schema.fingerprint():
            raise ValueError("runtime plan target fingerprint does not match target schema")

        target_fields = self.target_schema.by_id()
        target_ids = tuple(rule.target_field_id for rule in self.plan.rules)
        if not target_ids:
            raise ValueError("runtime mapping plan has no target fields")
        if len(set(target_ids)) != len(target_ids):
            raise ValueError("runtime mapping plan targets a field more than once")
        if any(target_id not in target_fields for target_id in target_ids):
            raise ValueError("runtime mapping plan references an unknown target field")
        missing_required = tuple(
            field.id
            for field in self.target_schema.fields
            if field.id not in target_ids and not field.nullable and not field.destination_generated
        )
        if missing_required:
            raise ValueError("runtime mapping plan omits a required target field")

        plan_digest = self.plan.digest()
        if (
            self.agent.allowed_plan_digests is not None
            and plan_digest not in self.agent.allowed_plan_digests
        ):
            raise ValueError("runtime plan is not authorized by destination agent")
        # A runtime executes one immutable contract. Preserve an agent-side deny by failing
        # above, otherwise narrow any broader agent configuration to this exact plan.
        self.agent.allowed_plan_digests = frozenset({plan_digest})
        self._plan_digest = plan_digest
        self._mapped_target_fields = tuple(target_fields[target_id] for target_id in target_ids)

    def _authorize_capability(
        self,
        operation: CapabilityOperation,
        record: BlindTransportRecord,
    ) -> None:
        if self.authorizer is None:
            return
        self.authorizer.authorize(
            operation,
            tenant=record.tenant,
            connector_id=self.connector_id,
            plan_digest=record.plan_digest,
        )

    def _receipt(
        self,
        record: BlindTransportRecord,
        status: DeliveryStatus,
        *,
        reason_code: str | None = None,
        retry_safe: bool | None = None,
        event_type: str = "delivery",
        batch_attempt_id: str | None = None,
    ) -> DeliveryReceipt:
        audit_recorded = False
        audit_status = AuditWriteStatus.DISABLED
        if self.audit is not None:
            try:
                self.audit.append(
                    AuditEvent(
                        event_type=event_type,
                        actor=self.actor_id,
                        status=status.value,
                        tenant=record.tenant,
                        connector_id=record.destination_connector,
                        transfer_id=record.transfer_id,
                        record_id=record.record_id,
                        record_digest=record.digest(),
                        plan_digest=record.plan_digest,
                        reason_code=reason_code,
                        batch_attempt_id=batch_attempt_id,
                    )
                )
                audit_recorded = True
                audit_status = AuditWriteStatus.RECORDED
            except Exception:
                # Delivery state is authoritative in the ledger. An audit failure must never
                # make a caller retry an already committed non-idempotent write.
                audit_recorded = False
                audit_status = AuditWriteStatus.APPEND_FAILED
        operational_event_recorded = False
        operational_event_status = EventWriteStatus.DISABLED
        run_id = None
        correlation_id = None
        if self.events is not None:
            run_id = self.events.run_id
            try:
                correlation_id = self.events.correlation_id(f"record:{record.digest()}")
                self.events.emit(
                    component="destination_runtime",
                    event_type=event_type,
                    status=status.value,
                    correlation_id=correlation_id,
                    reason_code=reason_code,
                    item_count=1,
                )
                operational_event_recorded = True
                operational_event_status = EventWriteStatus.RECORDED
            except Exception:
                # The ledger still owns delivery truth. A broken diagnostic sink must be visible
                # to the caller, but it must not turn a committed write into a retry.
                operational_event_recorded = False
                operational_event_status = EventWriteStatus.APPEND_FAILED
        return DeliveryReceipt(
            status=status,
            tenant=record.tenant,
            destination_connector=record.destination_connector,
            transfer_id=record.transfer_id,
            record_id=record.record_id,
            record_digest=record.digest(),
            plan_digest=record.plan_digest,
            completed_at=datetime.now(UTC).isoformat(),
            reason_code=reason_code,
            retry_safe=False if retry_safe is None else retry_safe,
            audit_recorded=audit_recorded,
            audit_status=audit_status,
            operational_event_recorded=operational_event_recorded,
            operational_event_status=operational_event_status,
            run_id=run_id,
            correlation_id=correlation_id,
            batch_attempt_id=batch_attempt_id,
        )

    def _receipts_many(
        self,
        requests: Sequence[_ReceiptRequest],
        *,
        batch_event: bool = False,
    ) -> tuple[DeliveryReceipt, ...]:
        """Persist per-record evidence with one audit transaction and one event fsync."""

        materialized = tuple(requests)
        if not materialized:
            return ()

        audit_recorded = [False] * len(materialized)
        audit_status = [AuditWriteStatus.DISABLED] * len(materialized)
        if self.audit is not None:
            audit_timestamp = datetime.now(UTC)
            valid_audit_events: list[AuditEvent] = []
            valid_audit_indexes: list[int] = []
            for index, request in enumerate(materialized):
                event = AuditEvent(
                    event_type=request.event_type,
                    actor=self.actor_id,
                    status=request.status.value,
                    tenant=request.record.tenant,
                    connector_id=request.record.destination_connector,
                    transfer_id=request.record.transfer_id,
                    record_id=request.record.record_id,
                    record_digest=request.record.digest(),
                    plan_digest=request.record.plan_digest,
                    reason_code=request.reason_code,
                    timestamp=audit_timestamp,
                    batch_attempt_id=request.batch_attempt_id,
                )
                try:
                    event.canonical_dict()
                except Exception:
                    # Pre-boundary records may contain metadata that a current issuer rejects.
                    # One such record must not suppress valid sibling audit evidence.
                    audit_status[index] = AuditWriteStatus.APPEND_FAILED
                    continue
                valid_audit_events.append(event)
                valid_audit_indexes.append(index)
            if valid_audit_events:
                try:
                    self.audit.append_many(valid_audit_events)
                except Exception:
                    for index in valid_audit_indexes:
                        audit_status[index] = AuditWriteStatus.APPEND_FAILED
                else:
                    for index in valid_audit_indexes:
                        audit_recorded[index] = True
                        audit_status[index] = AuditWriteStatus.RECORDED

        correlations: list[str | None] = [None] * len(materialized)
        run_id = self.events.run_id if self.events is not None else None
        if self.events is None:
            operational_event_recorded = False
            operational_event_status = EventWriteStatus.DISABLED
        else:
            try:
                correlations = [
                    self.events.correlation_id(f"record:{request.record.digest()}")
                    for request in materialized
                ]
                event_specs: list[dict[str, object]] = [
                    {
                        "component": "destination_runtime",
                        "event_type": request.event_type,
                        "status": request.status.value,
                        "correlation_id": correlation,
                        "reason_code": request.reason_code,
                        "item_count": 1,
                    }
                    for request, correlation in zip(materialized, correlations, strict=True)
                ]
                if batch_event:
                    statuses = {request.status for request in materialized}
                    reasons = {request.reason_code for request in materialized}
                    event_types = {request.event_type for request in materialized}
                    batch_attempt_ids = {request.batch_attempt_id for request in materialized}
                    if (
                        len(statuses) != 1
                        or len(reasons) != 1
                        or event_types != {"delivery"}
                        or len(batch_attempt_ids) != 1
                        or None in batch_attempt_ids
                    ):
                        raise IntegrityError("atomic batch receipts have mixed outcomes")
                    batch_attempt_id = next(iter(batch_attempt_ids))
                    assert batch_attempt_id is not None
                    event_specs.append(
                        {
                            "component": "destination_runtime",
                            "event_type": "delivery_batch",
                            "status": next(iter(statuses)).value,
                            "correlation_id": self.events.correlation_id(
                                f"delivery-batch:{batch_attempt_id}"
                            ),
                            "reason_code": next(iter(reasons)),
                            "item_count": len(materialized),
                        }
                    )
                self.events.emit_many(event_specs)
                operational_event_recorded = True
                operational_event_status = EventWriteStatus.RECORDED
            except Exception:
                operational_event_recorded = False
                operational_event_status = EventWriteStatus.APPEND_FAILED

        completed_at = datetime.now(UTC).isoformat()
        return tuple(
            DeliveryReceipt(
                status=request.status,
                tenant=request.record.tenant,
                destination_connector=request.record.destination_connector,
                transfer_id=request.record.transfer_id,
                record_id=request.record.record_id,
                record_digest=request.record.digest(),
                plan_digest=request.record.plan_digest,
                completed_at=completed_at,
                reason_code=request.reason_code,
                retry_safe=False if request.retry_safe is None else request.retry_safe,
                audit_recorded=recorded,
                audit_status=current_audit_status,
                operational_event_recorded=operational_event_recorded,
                operational_event_status=operational_event_status,
                run_id=run_id,
                correlation_id=correlation,
                batch_attempt_id=request.batch_attempt_id,
            )
            for request, correlation, recorded, current_audit_status in zip(
                materialized,
                correlations,
                audit_recorded,
                audit_status,
                strict=True,
            )
        )

    def deliver(self, record: BlindTransportRecord) -> DeliveryReceipt:
        connector_capabilities = self.connector.capabilities
        return self._deliver_with_capabilities(record, connector_capabilities)

    def _deliver_with_capabilities(
        self,
        record: BlindTransportRecord,
        connector_capabilities: ConnectorCapabilities,
    ) -> DeliveryReceipt:
        if not connector_capabilities.write_records:
            raise PolicyViolation("destination connector no longer advertises write capability")
        private_key = self.agent._authorize_record(record)
        self._authorize_capability(CapabilityOperation.WRITE_RECORDS, record)
        claim = self.ledger.claim(record, lease_for=self.claim_lease)
        if claim.disposition is ClaimDisposition.ALREADY_COMMITTED:
            return self._receipt(
                record,
                DeliveryStatus.DUPLICATE,
                batch_attempt_id=claim.batch_attempt_id,
            )
        if claim.disposition is ClaimDisposition.IN_PROGRESS:
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="delivery_claim_in_progress",
                retry_safe=False,
                batch_attempt_id=claim.batch_attempt_id,
            )
        if claim.disposition is ClaimDisposition.AMBIGUOUS:
            reason_code = (
                "previous_write_started_ambiguous"
                if claim.state
                in {
                    DeliveryState.WRITE_STARTED,
                    DeliveryState.BATCH_WRITE_STARTED,
                    DeliveryState.REPLAY_WRITE_STARTED,
                }
                else "previous_delivery_ambiguous"
            )
            self.spool.quarantine(record, reason_code)
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code=reason_code,
                retry_safe=False,
                batch_attempt_id=claim.batch_attempt_id,
            )
        if claim.claim_token is None:
            raise IntegrityError("delivery ledger issued an unfenced claim")
        return self._deliver_claimed(
            record,
            claim.claim_token,
            authorized_private_key=private_key,
            authorized_capabilities=connector_capabilities,
        )

    def deliver_many(
        self,
        records: Sequence[BlindTransportRecord],
    ) -> tuple[DeliveryReceipt, ...]:
        """Deliver records in capability-gated atomic batches, preserving input order."""

        connector_capabilities = self.connector.capabilities
        if not connector_capabilities.write_records:
            raise PolicyViolation("destination connector no longer advertises write capability")
        materialized_list: list[BlindTransportRecord] = []
        total_wire_bytes = 0
        for record in islice(iter(records), 10_001):
            if len(materialized_list) >= 10_000:
                raise ValueError("delivery batch exceeds the record count limit")
            if not isinstance(record, BlindTransportRecord):
                raise TypeError("delivery batch items must be BlindTransportRecord instances")
            total_wire_bytes += len(record.canonical_wire_bytes())
            if total_wire_bytes > self.spool.max_batch_wire_bytes:
                raise ValueError("delivery batch exceeds the runtime wire byte limit")
            materialized_list.append(record)
        materialized = tuple(materialized_list)
        if not materialized:
            return ()
        capability = connector_capabilities.atomic_batch_write
        raw_writer = getattr(self.connector, "write_batch", None)
        if capability is None or not callable(raw_writer):
            scalar_receipts: list[DeliveryReceipt] = []
            for record in materialized:
                try:
                    scalar_receipts.append(
                        self._deliver_with_capabilities(record, connector_capabilities)
                    )
                except Exception as exc:
                    if not scalar_receipts:
                        raise
                    raise DeliveryBatchInterrupted(tuple(scalar_receipts)) from exc
            return tuple(scalar_receipts)

        write_batch: Callable[[Sequence[BatchWriteItem]], int] = raw_writer
        maximum_chunk_records = min(
            capability.max_records,
            MAX_LEDGER_BATCH_ITEMS,
            MAX_SPOOL_BATCH_ITEMS,
            MAX_EVENT_BATCH_EVENTS - 1 if self.events is not None else MAX_EVENT_BATCH_EVENTS,
        )
        maximum_chunk_wire_bytes = min(
            capability.max_wire_bytes,
            self.spool.max_batch_wire_bytes,
        )
        chunks: list[tuple[BlindTransportRecord, ...]] = []
        current: list[BlindTransportRecord] = []
        current_identities: set[tuple[str, str, str, str]] = set()
        current_bytes = 0
        current_scope: tuple[str, str, str, str] | None = None
        for record in materialized:
            wire_bytes = len(record.canonical_wire_bytes())
            identity = (
                record.tenant,
                record.destination_connector,
                record.transfer_id,
                record.record_id,
            )
            scope = (
                record.tenant,
                record.destination_connector,
                record.transfer_id,
                record.plan_digest,
            )
            would_overflow = bool(current) and (
                len(current) >= maximum_chunk_records
                or current_bytes + wire_bytes > maximum_chunk_wire_bytes
                or scope != current_scope
                or identity in current_identities
            )
            if would_overflow:
                chunks.append(tuple(current))
                current = []
                current_identities = set()
                current_bytes = 0
                current_scope = None
            if wire_bytes > maximum_chunk_wire_bytes:
                if current:
                    chunks.append(tuple(current))
                    current = []
                    current_identities = set()
                    current_bytes = 0
                    current_scope = None
                chunks.append((record,))
                continue
            if not current:
                current_scope = scope
            current.append(record)
            current_identities.add(identity)
            current_bytes += wire_bytes
        if current:
            chunks.append(tuple(current))

        receipts: list[DeliveryReceipt] = []
        for chunk in chunks:
            try:
                if len(chunk) == 1:
                    receipts.append(
                        self._deliver_with_capabilities(chunk[0], connector_capabilities)
                    )
                else:
                    receipts.extend(
                        self._deliver_atomic_batch(
                            chunk,
                            write_batch,
                            connector_capabilities,
                        )
                    )
            except DeliveryBatchInterrupted as exc:
                combined = (*receipts, *exc.completed_receipts)
                if combined:
                    raise DeliveryBatchInterrupted(combined) from exc
                raise
            except Exception as exc:
                if not receipts:
                    raise
                raise DeliveryBatchInterrupted(tuple(receipts)) from exc
        return tuple(receipts)

    def _deliver_atomic_batch(
        self,
        records: Sequence[BlindTransportRecord],
        write_batch: Callable[[Sequence[BatchWriteItem]], int],
        authorized_capabilities: ConnectorCapabilities,
    ) -> tuple[DeliveryReceipt, ...]:
        private_keys = tuple(self.agent._authorize_record(record) for record in records)
        for record in records:
            self._authorize_capability(CapabilityOperation.WRITE_RECORDS, record)

        claims = self.ledger.claim_many(records, lease_for=self.claim_lease)
        receipts: list[DeliveryReceipt | None] = [None] * len(records)
        claimed: list[tuple[int, BlindTransportRecord, str, X25519PrivateKey]] = []
        for index, (record, private_key, claim) in enumerate(
            zip(records, private_keys, claims, strict=True)
        ):
            if claim.disposition is ClaimDisposition.ALREADY_COMMITTED:
                receipts[index] = self._receipt(
                    record,
                    DeliveryStatus.DUPLICATE,
                    batch_attempt_id=claim.batch_attempt_id,
                )
                continue
            if claim.disposition is ClaimDisposition.IN_PROGRESS:
                receipts[index] = self._receipt(
                    record,
                    DeliveryStatus.AMBIGUOUS,
                    reason_code="delivery_claim_in_progress",
                    retry_safe=False,
                    batch_attempt_id=claim.batch_attempt_id,
                )
                continue
            if claim.disposition is ClaimDisposition.AMBIGUOUS:
                reason_code = (
                    "previous_write_started_ambiguous"
                    if claim.state
                    in {
                        DeliveryState.WRITE_STARTED,
                        DeliveryState.BATCH_WRITE_STARTED,
                        DeliveryState.REPLAY_WRITE_STARTED,
                    }
                    else "previous_delivery_ambiguous"
                )
                self.spool.quarantine(record, reason_code)
                receipts[index] = self._receipt(
                    record,
                    DeliveryStatus.AMBIGUOUS,
                    reason_code=reason_code,
                    retry_safe=False,
                    batch_attempt_id=claim.batch_attempt_id,
                )
                continue
            if claim.claim_token is None:
                raise IntegrityError("delivery ledger issued an unfenced batch claim")
            claimed.append((index, record, claim.claim_token, private_key))

        prepared: list[tuple[int, BlindTransportRecord, str, BatchWriteItem]] = []
        plaintext_record: dict[str, object] | None = None
        try:
            try:
                for index, record, claim_token, private_key in claimed:
                    try:
                        plaintext_record = self.agent._open_authorized_record(record, private_key)
                    except Exception:
                        receipts[index] = self._quarantine_before_write(
                            record,
                            "transport_verification_failed",
                            claim_token,
                        )
                        continue
                    if not self._record_uses_runtime_plan(
                        record
                    ) or not self._payload_has_exact_mapped_fields(plaintext_record):
                        plaintext_record.clear()
                        plaintext_record = None
                        receipts[index] = self._quarantine_before_write(
                            record,
                            "destination_contract_failed",
                            claim_token,
                        )
                        continue
                    try:
                        plaintext_record = self._apply_destination_transforms(
                            record, plaintext_record
                        )
                    except Exception:
                        plaintext_record.clear()
                        plaintext_record = None
                        receipts[index] = self._quarantine_before_write(
                            record,
                            "destination_resolution_failed",
                            claim_token,
                        )
                        continue
                    if not self._payload_satisfies_target_contract(plaintext_record):
                        plaintext_record.clear()
                        plaintext_record = None
                        receipts[index] = self._quarantine_before_write(
                            record,
                            "destination_contract_failed",
                            claim_token,
                        )
                        continue
                    context = DeliveryContext(
                        transfer_id=record.transfer_id,
                        record_id=record.record_id,
                        record_digest=record.digest(),
                        idempotency_key=_idempotency_key(record),
                    )
                    prepared.append(
                        (
                            index,
                            record,
                            claim_token,
                            BatchWriteItem(
                                values=plaintext_record,
                                context=context,
                                wire_bytes=len(record.canonical_wire_bytes()),
                            ),
                        )
                    )
                    plaintext_record = None

                self._execute_atomic_batch(
                    prepared,
                    receipts,
                    write_batch,
                    authorized_capabilities,
                )
                if any(receipt is None for receipt in receipts):
                    raise IntegrityError("delivery batch did not produce one receipt per record")
                return tuple(receipt for receipt in receipts if receipt is not None)
            except DeliveryBatchInterrupted:
                raise
            except Exception as exc:
                completed = tuple(receipt for receipt in receipts if receipt is not None)
                if completed:
                    raise DeliveryBatchInterrupted(completed) from exc
                raise
        finally:
            # Drop the runtime's normal Python references even when a post-decrypt state
            # operation raises. A connector may legitimately retain the batch items after
            # its synchronous return, so mutating their mappings here would violate the API.
            # CPython does not promise a secure memory wipe.
            if plaintext_record is not None:
                plaintext_record.clear()
            prepared.clear()
            claimed.clear()
            private_keys = ()

    def _execute_atomic_batch(
        self,
        prepared: Sequence[tuple[int, BlindTransportRecord, str, BatchWriteItem]],
        receipts: list[DeliveryReceipt | None],
        write_batch: Callable[[Sequence[BatchWriteItem]], int],
        authorized_capabilities: ConnectorCapabilities,
    ) -> None:
        if not prepared:
            return
        try:
            capability_changed = self.connector.capabilities != authorized_capabilities
        except Exception:
            capability_changed = True
        if capability_changed:
            for index, record, claim_token, _ in prepared:
                receipts[index] = self._quarantine_before_write(
                    record,
                    "atomic_batch_capability_changed",
                    claim_token,
                    retry_safe=True,
                )
            return
        transitions = tuple((record, token) for _, record, token, _ in prepared)
        try:
            batch_attempt_id = self.ledger.start_write_many(
                transitions,
                idempotency_contract_id=_batch_idempotency_contract_id(authorized_capabilities),
            )
        except IntegrityError:
            for index, record, _, _ in prepared:
                receipts[index] = self._receipt(
                    record,
                    DeliveryStatus.AMBIGUOUS,
                    reason_code="delivery_claim_lost",
                    retry_safe=False,
                )
            return

        write_outcome: WriteOutcome | None = None
        batch_items = tuple(item for _, _, _, item in prepared)
        try:
            written = write_batch(batch_items)
            if type(written) is not int or written != len(prepared):
                raise ConnectorWriteError(
                    "destination did not acknowledge the complete atomic batch",
                    outcome=WriteOutcome.UNKNOWN,
                )
        except ConnectorWriteError as exc:
            write_outcome = exc.outcome
        except Exception:
            write_outcome = WriteOutcome.UNKNOWN
        finally:
            batch_items = ()

        if write_outcome is not None:
            if write_outcome is WriteOutcome.NOT_COMMITTED:
                reason_code = "write_not_committed"
                self.spool.quarantine_many(
                    (record for _, record, _, _ in prepared),
                    reason_code=reason_code,
                )
                self.ledger.mark_quarantined_many(
                    transitions,
                    reason_code,
                    expected_state=DeliveryState.BATCH_WRITE_STARTED,
                )
                retry_safe = True
            else:
                reason_code = "atomic_batch_write_outcome_unknown"
                self.spool.quarantine_many(
                    (record for _, record, _, _ in prepared),
                    reason_code=reason_code,
                )
                self.ledger.mark_uncertain_many(transitions, reason_code)
                retry_safe = _batch_idempotency_contract_id(authorized_capabilities) is not None
            batch_receipts = self._receipts_many(
                tuple(
                    _ReceiptRequest(
                        record,
                        DeliveryStatus.QUARANTINED,
                        reason_code=reason_code,
                        retry_safe=retry_safe,
                        batch_attempt_id=batch_attempt_id,
                    )
                    for _, record, _, _ in prepared
                ),
                batch_event=True,
            )
            for (index, _, _, _), receipt in zip(prepared, batch_receipts, strict=True):
                receipts[index] = receipt
            return

        try:
            self.ledger.mark_committed_many(transitions)
        except Exception:
            with suppress(Exception):
                self.spool.quarantine_many(
                    (record for _, record, _, _ in prepared),
                    reason_code="delivery_outcome_record_failed",
                )
            batch_receipts = self._receipts_many(
                tuple(
                    _ReceiptRequest(
                        record,
                        DeliveryStatus.AMBIGUOUS,
                        reason_code="delivery_outcome_record_failed",
                        retry_safe=False,
                        batch_attempt_id=batch_attempt_id,
                    )
                    for _, record, _, _ in prepared
                ),
                batch_event=True,
            )
        else:
            cleanup_failed = False
            try:
                self.spool.remove_many(record.digest() for _, record, _, _ in prepared)
            except Exception:
                cleanup_failed = True
            batch_receipts = self._receipts_many(
                tuple(
                    _ReceiptRequest(
                        record,
                        DeliveryStatus.DELIVERED,
                        reason_code="sealed_spool_cleanup_failed" if cleanup_failed else None,
                        retry_safe=False if cleanup_failed else None,
                        batch_attempt_id=batch_attempt_id,
                    )
                    for _, record, _, _ in prepared
                ),
                batch_event=True,
            )
        for (index, _, _, _), receipt in zip(prepared, batch_receipts, strict=True):
            receipts[index] = receipt

    def _apply_destination_transforms(
        self,
        record: BlindTransportRecord,
        plaintext_record: dict[str, object],
    ) -> dict[str, object]:
        for rule in self.plan.rules:
            if transform_stage(rule.transform) is not TransformStage.DESTINATION:
                continue
            if rule.transform != "lookup_foreign_key":
                raise IntegrityError("unsupported destination transform")
            resolver = getattr(self.connector, "resolve_foreign_key", None)
            if resolver is None:
                raise PolicyViolation("destination connector cannot resolve foreign keys")
            match_column = rule.parameters.get("match_column")
            relation = self.target_schema.relation_for_source_field(rule.target_field_id)
            lookup_key = (
                relation.lookup_key(match_column)
                if relation is not None and isinstance(match_column, str)
                else None
            )
            if lookup_key is None:
                raise IntegrityError("foreign-key mapping is missing match_column")
            value = plaintext_record.get(rule.target_field_id)
            if value is None:
                # SQL NULL is not a business-key lookup value. Preserve it for nullable targets;
                # the target contract below rejects it for required targets.
                continue
            if not value_satisfies_type(value, lookup_key.data_type):
                raise PolicyViolation("foreign-key input violates lookup-column type")
            assert isinstance(match_column, str)
            resolved = resolver(
                target_field_id=rule.target_field_id,
                match_column=match_column,
                value=value,
            )
            if resolved is None:
                raise PolicyViolation("non-null foreign-key lookup input did not resolve")
            plaintext_record[rule.target_field_id] = resolved
        return plaintext_record

    def _record_uses_runtime_plan(self, record: BlindTransportRecord) -> bool:
        return record.plan_id == self.plan.id and record.plan_digest == self._plan_digest

    @staticmethod
    def _value_satisfies_type(value: object, target_type: DataType) -> bool:
        return value_satisfies_type(value, target_type)

    def _payload_satisfies_target_contract(self, record: dict[str, object]) -> bool:
        if not self._payload_has_exact_mapped_fields(record):
            return False
        for target in self._mapped_target_fields:
            value = record[target.id]
            if value is None:
                if not target.nullable:
                    return False
                continue
            if not self._value_satisfies_type(value, target.data_type):
                return False
        return True

    def _payload_has_exact_mapped_fields(self, record: dict[str, object]) -> bool:
        return set(record) == {field.id for field in self._mapped_target_fields}

    def _quarantine_before_write(
        self,
        record: BlindTransportRecord,
        reason_code: str,
        claim_token: str,
        *,
        event_type: str = "delivery",
        expected_state: DeliveryState = DeliveryState.CLAIMED,
        batch_attempt_id: str | None = None,
        retry_safe: bool | None = None,
    ) -> DeliveryReceipt:
        self.spool.quarantine(record, reason_code)
        try:
            self.ledger.mark_quarantined(
                record,
                reason_code,
                claim_token,
                expected_state=expected_state,
            )
        except IntegrityError:
            # The claim expired or was replaced while local validation was running. The
            # fenced token guarantees that this worker has not crossed the write boundary.
            # A replacement worker may already have committed and cleaned an older spool
            # row before this stale worker inserted its copy. Reconcile that exact terminal
            # state so the race does not leave a false quarantine alarm behind.
            try:
                current = self.ledger.get(record)
            except Exception:
                current = None
            if current is not None and current.state is DeliveryState.COMMITTED:
                cleanup_failed = False
                try:
                    self.spool.remove(record.digest())
                except Exception:
                    cleanup_failed = True
                return self._receipt(
                    record,
                    DeliveryStatus.DUPLICATE,
                    reason_code="sealed_spool_cleanup_failed" if cleanup_failed else None,
                    retry_safe=False,
                    event_type=event_type,
                    batch_attempt_id=current.current_write_batch_attempt_id,
                )
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="delivery_claim_lost",
                retry_safe=False,
                event_type=event_type,
                batch_attempt_id=batch_attempt_id,
            )
        return self._receipt(
            record,
            DeliveryStatus.QUARANTINED,
            reason_code=reason_code,
            retry_safe=retry_safe,
            event_type=event_type,
            batch_attempt_id=batch_attempt_id,
        )

    def _deliver_claimed(
        self,
        record: BlindTransportRecord,
        claim_token: str,
        *,
        event_type: str = "delivery",
        authorized_private_key: X25519PrivateKey | None = None,
        replay_attempt: bool = False,
        batch_attempt_id: str | None = None,
        historical_idempotency_contract_id: str | None = None,
        authorized_capabilities: ConnectorCapabilities,
    ) -> DeliveryReceipt:
        claimed_state = DeliveryState.REPLAY_CLAIMED if replay_attempt else DeliveryState.CLAIMED
        write_started_state = (
            DeliveryState.REPLAY_WRITE_STARTED if replay_attempt else DeliveryState.WRITE_STARTED
        )
        scalar_contract_id = _scalar_idempotency_contract_id(authorized_capabilities)
        write_retry_safe = scalar_contract_id is not None
        if replay_attempt:
            write_retry_safe = bool(
                historical_idempotency_contract_id is not None
                and historical_idempotency_contract_id == scalar_contract_id
                and (
                    batch_attempt_id is None
                    or _batch_idempotency_contract_id(authorized_capabilities) is not None
                )
            )
        try:
            plaintext_record = (
                self.agent.open_record(record)
                if authorized_private_key is None
                else self.agent._open_authorized_record(record, authorized_private_key)
            )
        except Exception:
            # No destination operation has started. Malformed authenticated plaintext and
            # unexpected decoder failures are therefore safely quarantinable. Never persist
            # the exception text because a parser may include plaintext in it.
            return self._quarantine_before_write(
                record,
                "transport_verification_failed",
                claim_token,
                event_type=event_type,
                expected_state=claimed_state,
                batch_attempt_id=batch_attempt_id,
                retry_safe=write_retry_safe,
            )
        if not self._record_uses_runtime_plan(record) or not self._payload_has_exact_mapped_fields(
            plaintext_record
        ):
            del plaintext_record
            return self._quarantine_before_write(
                record,
                "destination_contract_failed",
                claim_token,
                event_type=event_type,
                expected_state=claimed_state,
                batch_attempt_id=batch_attempt_id,
                retry_safe=write_retry_safe,
            )
        try:
            plaintext_record = self._apply_destination_transforms(record, plaintext_record)
        except Exception:
            # Resolution is still before the write boundary, so any failure is known no-write.
            # The fixed reason code prevents database/parser exceptions leaking payload values.
            del plaintext_record
            return self._quarantine_before_write(
                record,
                "destination_resolution_failed",
                claim_token,
                event_type=event_type,
                expected_state=claimed_state,
                batch_attempt_id=batch_attempt_id,
                retry_safe=write_retry_safe,
            )
        if not self._payload_satisfies_target_contract(plaintext_record):
            del plaintext_record
            return self._quarantine_before_write(
                record,
                "destination_contract_failed",
                claim_token,
                event_type=event_type,
                expected_state=claimed_state,
                batch_attempt_id=batch_attempt_id,
                retry_safe=write_retry_safe,
            )

        context = DeliveryContext(
            transfer_id=record.transfer_id,
            record_id=record.record_id,
            record_digest=record.digest(),
            idempotency_key=_idempotency_key(record),
        )
        try:
            capability_changed = self.connector.capabilities != authorized_capabilities
        except Exception:
            capability_changed = True
        if capability_changed:
            del plaintext_record
            return self._quarantine_before_write(
                record,
                "replay_capability_changed" if replay_attempt else "destination_capability_changed",
                claim_token,
                event_type=event_type,
                expected_state=claimed_state,
                batch_attempt_id=batch_attempt_id,
                retry_safe=not replay_attempt,
            )
        try:
            # This durable, fenced transition is the exact external-write boundary.
            # A replacement worker can reclaim CLAIMED, but never WRITE_STARTED.
            if replay_attempt:
                self.ledger.start_replay_write(record, claim_token)
            else:
                self.ledger.start_write(
                    record,
                    claim_token,
                    idempotency_contract_id=scalar_contract_id,
                )
        except IntegrityError:
            del plaintext_record
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="delivery_claim_lost",
                retry_safe=False,
                event_type=event_type,
                batch_attempt_id=batch_attempt_id,
            )
        try:
            written = self.connector.write_records([plaintext_record], context=context)
            if type(written) is not int or written != 1:
                raise IntegrityError("destination did not acknowledge exactly one record")
        except ConnectorWriteError as exc:
            if exc.outcome is WriteOutcome.NOT_COMMITTED:
                self.spool.quarantine(record, "write_not_committed")
                self.ledger.mark_quarantined(
                    record,
                    "write_not_committed",
                    claim_token,
                    expected_state=write_started_state,
                )
                return self._receipt(
                    record,
                    DeliveryStatus.QUARANTINED,
                    reason_code="write_not_committed",
                    retry_safe=True if not replay_attempt else write_retry_safe,
                    event_type=event_type,
                    batch_attempt_id=batch_attempt_id,
                )
            self.spool.quarantine(record, "write_outcome_unknown")
            if replay_attempt:
                self.ledger.mark_replay_uncertain(
                    record,
                    "write_outcome_unknown",
                    claim_token,
                )
            else:
                self.ledger.mark_uncertain(record, "write_outcome_unknown", claim_token)
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="write_outcome_unknown",
                retry_safe=write_retry_safe,
                event_type=event_type,
                batch_attempt_id=batch_attempt_id,
            )
        except Exception:
            # Unknown connector exceptions provide no durability proof. The safe default is
            # to assume the write may have committed and refuse a blind non-idempotent retry.
            self.spool.quarantine(record, "write_outcome_unknown")
            if replay_attempt:
                self.ledger.mark_replay_uncertain(
                    record,
                    "write_outcome_unknown",
                    claim_token,
                )
            else:
                self.ledger.mark_uncertain(record, "write_outcome_unknown", claim_token)
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="write_outcome_unknown",
                retry_safe=write_retry_safe,
                event_type=event_type,
                batch_attempt_id=batch_attempt_id,
            )
        finally:
            # This removes the normal Python reference. It is not a secure memory wipe and
            # no such guarantee is claimed for CPython-managed objects.
            if "plaintext_record" in locals():
                del plaintext_record

        try:
            if replay_attempt:
                self.ledger.mark_replay_committed(record, claim_token)
            else:
                self.ledger.mark_committed(record, claim_token)
        except Exception:
            # The destination acknowledged the write, but its durable ledger outcome could
            # not be recorded. Seal the record and report ambiguity, never an apparent
            # failure that invites a blind retry.
            self.spool.quarantine(record, "delivery_outcome_record_failed")
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="delivery_outcome_record_failed",
                retry_safe=write_retry_safe,
                event_type=event_type,
                batch_attempt_id=batch_attempt_id,
            )
        try:
            self.spool.remove(record.digest())
        except Exception:
            # Cleanup is idempotent and happens after both destination and ledger commits.
            # Never turn a stale quarantine row into a retry signal for committed data.
            return self._receipt(
                record,
                DeliveryStatus.DELIVERED,
                reason_code="sealed_spool_cleanup_failed",
                retry_safe=False,
                event_type=event_type,
                batch_attempt_id=batch_attempt_id,
            )
        return self._receipt(
            record,
            DeliveryStatus.DELIVERED,
            event_type=event_type,
            batch_attempt_id=batch_attempt_id,
        )

    def replay(self, record_digest: str, *, force_uncertain: bool = False) -> DeliveryReceipt:
        connector_capabilities = self.connector.capabilities
        if not connector_capabilities.write_records:
            raise PolicyViolation("destination connector no longer advertises write capability")
        record = self.spool.get(record_digest)
        if record is None:
            raise KeyError("sealed quarantine record does not exist")
        self._authorize_capability(CapabilityOperation.REPLAY, record)
        entry = self.ledger.get(record)
        if entry is None:
            raise IntegrityError("quarantine record has no delivery ledger entry")
        scalar_ambiguous_write_states = (
            DeliveryState.UNCERTAIN,
            DeliveryState.WRITE_STARTED,
        )
        batch_ambiguous_write_states = (
            DeliveryState.BATCH_UNCERTAIN,
            DeliveryState.BATCH_WRITE_STARTED,
        )
        guarded_replay_states = (
            DeliveryState.REPLAY_CLAIMED,
            DeliveryState.REPLAY_WRITE_STARTED,
            DeliveryState.REPLAY_UNCERTAIN,
            DeliveryState.REPLAY_QUARANTINED,
        )
        ambiguous_write_states = (
            *scalar_ambiguous_write_states,
            *batch_ambiguous_write_states,
        )
        current_contract_id = _scalar_idempotency_contract_id(connector_capabilities)
        historical_contract_matches = bool(
            entry.idempotency_contract_id is not None
            and entry.idempotency_contract_id == current_contract_id
        )
        requires_force = force_uncertain and entry.state in (
            *ambiguous_write_states,
            *guarded_replay_states,
            DeliveryState.CLAIMED,
        )
        event_type = "force_replay" if requires_force else "replay"
        if entry.state is DeliveryState.COMMITTED:
            cleanup_failed = False
            try:
                self.spool.remove(record_digest)
            except Exception:
                cleanup_failed = True
            return self._receipt(
                record,
                DeliveryStatus.DUPLICATE,
                reason_code="sealed_spool_cleanup_failed" if cleanup_failed else None,
                retry_safe=False,
                event_type=event_type,
                batch_attempt_id=entry.current_write_batch_attempt_id,
            )
        write_may_have_been_batched = bool(
            entry.state in batch_ambiguous_write_states
            or entry.current_write_batch_attempt_id is not None
        )
        if (
            entry.state in (*ambiguous_write_states, *guarded_replay_states)
            and not (
                historical_contract_matches
                and (
                    not write_may_have_been_batched
                    or _batch_idempotency_contract_id(connector_capabilities) is not None
                )
            )
            and not force_uncertain
        ):
            raise PolicyViolation(
                "uncertain write cannot be replayed without destination idempotency"
            )
        if entry.state is DeliveryState.CLAIMED and not force_uncertain:
            raise PolicyViolation("ambiguous claimed delivery requires explicit recovery")
        if requires_force:
            if self.authorizer is None:
                raise PolicyViolation(
                    "forced uncertain replay requires an explicit capability authorizer"
                )
            self._authorize_capability(CapabilityOperation.FORCE_UNCERTAIN_REPLAY, record)
        rearmed = self.ledger.rearm_for_retry(
            record,
            expected_state=entry.state,
            lease_for=self.claim_lease,
        )
        if rearmed.claim_token is None:
            raise IntegrityError("delivery ledger issued an unfenced retry claim")
        return self._deliver_claimed(
            record,
            rearmed.claim_token,
            event_type=event_type,
            replay_attempt=rearmed.state is DeliveryState.REPLAY_CLAIMED,
            batch_attempt_id=rearmed.batch_attempt_id,
            historical_idempotency_contract_id=entry.idempotency_contract_id,
            authorized_capabilities=connector_capabilities,
        )
