from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from .agents import BlindDestinationAgent, BlindTransportRecord
from .audit import AuditEvent, AuditLog
from .capabilities import CapabilityAuthorizer, CapabilityOperation
from .connectors.base import DeliveryContext, DestinationConnector
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
    ClaimDisposition,
    DeliveryLedger,
    DeliveryState,
)
from .models.mapping import MappingPlan
from .models.schema import FieldDescriptor, SchemaDescriptor
from .models.types import DataType
from .observability import EventStream, EventWriteStatus
from .spool import SealedSpool
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
        if self.claim_lease <= timedelta(0) or self.claim_lease > MAX_CLAIM_DURATION:
            raise ValueError("claim duration is outside supported range")
        if not self.connector.capabilities.write_records:
            raise ValueError("destination connector does not advertise write capability")
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
            retry_safe=(
                self.connector.capabilities.supports_idempotency
                if retry_safe is None
                else retry_safe
            ),
            audit_recorded=audit_recorded,
            audit_status=audit_status,
            operational_event_recorded=operational_event_recorded,
            operational_event_status=operational_event_status,
            run_id=run_id,
            correlation_id=correlation_id,
        )

    def deliver(self, record: BlindTransportRecord) -> DeliveryReceipt:
        self.agent._authorize_record(record)
        self._authorize_capability(CapabilityOperation.WRITE_RECORDS, record)
        claim = self.ledger.claim(record, lease_for=self.claim_lease)
        if claim.disposition is ClaimDisposition.ALREADY_COMMITTED:
            return self._receipt(record, DeliveryStatus.DUPLICATE)
        if claim.disposition is ClaimDisposition.IN_PROGRESS:
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="delivery_claim_in_progress",
                retry_safe=False,
            )
        if claim.disposition is ClaimDisposition.AMBIGUOUS:
            reason_code = (
                "previous_write_started_ambiguous"
                if claim.state is DeliveryState.WRITE_STARTED
                else "previous_delivery_ambiguous"
            )
            self.spool.quarantine(record, reason_code)
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code=reason_code,
            )
        if claim.claim_token is None:
            raise IntegrityError("delivery ledger issued an unfenced claim")
        return self._deliver_claimed(record, claim.claim_token)

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
    ) -> DeliveryReceipt:
        try:
            self.ledger.mark_quarantined(record, reason_code, claim_token)
        except IntegrityError:
            # The claim expired or was replaced while local validation was running. The
            # fenced token guarantees that this worker has not crossed the write boundary.
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="delivery_claim_lost",
                retry_safe=False,
                event_type=event_type,
            )
        self.spool.quarantine(record, reason_code)
        return self._receipt(
            record,
            DeliveryStatus.QUARANTINED,
            reason_code=reason_code,
            event_type=event_type,
        )

    def _deliver_claimed(
        self,
        record: BlindTransportRecord,
        claim_token: str,
        *,
        event_type: str = "delivery",
    ) -> DeliveryReceipt:
        try:
            plaintext_record = self.agent.open_record(record)
        except Exception:
            # No destination operation has started. Malformed authenticated plaintext and
            # unexpected decoder failures are therefore safely quarantinable. Never persist
            # the exception text because a parser may include plaintext in it.
            return self._quarantine_before_write(
                record,
                "transport_verification_failed",
                claim_token,
                event_type=event_type,
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
            )
        if not self._payload_satisfies_target_contract(plaintext_record):
            del plaintext_record
            return self._quarantine_before_write(
                record,
                "destination_contract_failed",
                claim_token,
                event_type=event_type,
            )

        context = DeliveryContext(
            transfer_id=record.transfer_id,
            record_id=record.record_id,
            record_digest=record.digest(),
            idempotency_key=_idempotency_key(record),
        )
        try:
            # This durable, fenced transition is the exact external-write boundary.
            # A replacement worker can reclaim CLAIMED, but never WRITE_STARTED.
            self.ledger.start_write(record, claim_token)
        except IntegrityError:
            del plaintext_record
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="delivery_claim_lost",
                retry_safe=False,
                event_type=event_type,
            )
        try:
            written = self.connector.write_records([plaintext_record], context=context)
            if written != 1:
                raise IntegrityError("destination did not acknowledge exactly one record")
        except ConnectorWriteError as exc:
            if exc.outcome is WriteOutcome.NOT_COMMITTED:
                self.ledger.mark_quarantined(
                    record,
                    "write_not_committed",
                    claim_token,
                    expected_state=DeliveryState.WRITE_STARTED,
                )
                self.spool.quarantine(record, "write_not_committed")
                return self._receipt(
                    record,
                    DeliveryStatus.QUARANTINED,
                    reason_code="write_not_committed",
                    retry_safe=True,
                    event_type=event_type,
                )
            self.ledger.mark_uncertain(record, "write_outcome_unknown", claim_token)
            self.spool.quarantine(record, "write_outcome_unknown")
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="write_outcome_unknown",
                event_type=event_type,
            )
        except Exception:
            # Unknown connector exceptions provide no durability proof. The safe default is
            # to assume the write may have committed and refuse a blind non-idempotent retry.
            self.ledger.mark_uncertain(record, "write_outcome_unknown", claim_token)
            self.spool.quarantine(record, "write_outcome_unknown")
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="write_outcome_unknown",
                event_type=event_type,
            )
        finally:
            # This removes the normal Python reference. It is not a secure memory wipe and
            # no such guarantee is claimed for CPython-managed objects.
            if "plaintext_record" in locals():
                del plaintext_record

        try:
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
                event_type=event_type,
            )
        self.spool.remove(record.digest())
        return self._receipt(record, DeliveryStatus.DELIVERED, event_type=event_type)

    def replay(self, record_digest: str, *, force_uncertain: bool = False) -> DeliveryReceipt:
        record = self.spool.get(record_digest)
        if record is None:
            raise KeyError("sealed quarantine record does not exist")
        self._authorize_capability(CapabilityOperation.REPLAY, record)
        entry = self.ledger.get(record)
        if entry is None:
            raise IntegrityError("quarantine record has no delivery ledger entry")
        ambiguous_write_states = (DeliveryState.UNCERTAIN, DeliveryState.WRITE_STARTED)
        requires_force = force_uncertain and entry.state in (
            *ambiguous_write_states,
            DeliveryState.CLAIMED,
        )
        event_type = "force_replay" if requires_force else "replay"
        if entry.state is DeliveryState.COMMITTED:
            self.spool.remove(record_digest)
            return self._receipt(record, DeliveryStatus.DUPLICATE, event_type=event_type)
        if (
            entry.state in ambiguous_write_states
            and not self.connector.capabilities.supports_idempotency
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
        return self._deliver_claimed(record, rearmed.claim_token, event_type=event_type)
