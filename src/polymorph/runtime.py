from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from .agents import BlindDestinationAgent, BlindTransportRecord
from .audit import AuditEvent, AuditLog
from .capabilities import CapabilityAuthorizer, CapabilityOperation
from .connectors.base import DeliveryContext, DestinationConnector
from .errors import (
    ConnectorWriteError,
    IntegrityError,
    PolicyViolation,
    PolymorphError,
    WriteOutcome,
)
from .ledger import ClaimDisposition, DeliveryLedger, DeliveryState
from .models.mapping import MappingPlan
from .transforms import TransformStage, transform_stage
from .spool import SealedSpool


class DeliveryStatus(StrEnum):
    DELIVERED = "delivered"
    DUPLICATE = "duplicate"
    QUARANTINED = "quarantined"
    AMBIGUOUS = "ambiguous"


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
    authorizer: CapabilityAuthorizer | None = None
    audit: AuditLog | None = None
    actor_id: str = "destination-runtime"
    plan: MappingPlan | None = None

    def __post_init__(self) -> None:
        if not self.connector.capabilities.write_records:
            raise ValueError("destination connector does not advertise write capability")
        if self.agent.expected_connector_id is None:
            self.agent.expected_connector_id = self.connector_id
        elif self.agent.expected_connector_id != self.connector_id:
            raise ValueError("destination agent and runtime connector ids differ")
        if self.plan is not None and self.agent.allowed_plan_digests is not None:
            if self.plan.digest() not in self.agent.allowed_plan_digests:
                raise ValueError("runtime plan is not authorized by destination agent")

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
    ) -> DeliveryReceipt:
        audit_recorded = False
        if self.audit is not None:
            try:
                self.audit.append(
                    AuditEvent(
                        event_type="delivery",
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
            except Exception:
                # Delivery state is authoritative in the ledger. An audit failure must never
                # make a caller retry an already committed non-idempotent write.
                audit_recorded = False
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
        )

    def deliver(self, record: BlindTransportRecord) -> DeliveryReceipt:
        self.agent._authorize_record(record)
        self._authorize_capability(CapabilityOperation.WRITE_RECORDS, record)
        claim = self.ledger.claim(record)
        if claim.disposition is ClaimDisposition.ALREADY_COMMITTED:
            return self._receipt(record, DeliveryStatus.DUPLICATE)
        if claim.disposition is ClaimDisposition.AMBIGUOUS:
            self.spool.quarantine(record, "previous_delivery_ambiguous")
            return self._receipt(
                record,
                DeliveryStatus.AMBIGUOUS,
                reason_code="previous_delivery_ambiguous",
            )
        return self._deliver_claimed(record)

    def _apply_destination_transforms(
        self,
        record: BlindTransportRecord,
        plaintext_record: dict[str, object],
    ) -> dict[str, object]:
        if self.plan is None:
            return plaintext_record
        if self.plan.digest() != record.plan_digest:
            raise IntegrityError("runtime mapping plan does not match authenticated transport")
        for rule in self.plan.rules:
            if transform_stage(rule.transform) is not TransformStage.DESTINATION:
                continue
            if rule.transform != "lookup_foreign_key":
                raise IntegrityError("unsupported destination transform")
            resolver = getattr(self.connector, "resolve_foreign_key", None)
            if resolver is None:
                raise PolicyViolation("destination connector cannot resolve foreign keys")
            match_column = rule.parameters.get("match_column")
            if not match_column:
                raise IntegrityError("foreign-key mapping is missing match_column")
            value = plaintext_record.get(rule.target_field_id)
            plaintext_record[rule.target_field_id] = resolver(
                target_field_id=rule.target_field_id,
                match_column=match_column,
                value=value,
            )
        return plaintext_record

    def _deliver_claimed(self, record: BlindTransportRecord) -> DeliveryReceipt:
        try:
            plaintext_record = self.agent.open_record(record)
        except PolymorphError:
            self.ledger.mark_quarantined(record, "transport_verification_failed")
            self.spool.quarantine(record, "transport_verification_failed")
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="transport_verification_failed",
            )
        try:
            plaintext_record = self._apply_destination_transforms(record, plaintext_record)
        except PolymorphError:
            self.ledger.mark_quarantined(record, "destination_resolution_failed")
            self.spool.quarantine(record, "destination_resolution_failed")
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="destination_resolution_failed",
            )

        context = DeliveryContext(
            transfer_id=record.transfer_id,
            record_id=record.record_id,
            record_digest=record.digest(),
            idempotency_key=_idempotency_key(record),
        )
        try:
            written = self.connector.write_records([plaintext_record], context=context)
            if written != 1:
                raise IntegrityError("destination did not acknowledge exactly one record")
        except ConnectorWriteError as exc:
            if exc.outcome is WriteOutcome.NOT_COMMITTED:
                self.ledger.mark_quarantined(record, "write_not_committed")
                self.spool.quarantine(record, "write_not_committed")
                return self._receipt(
                    record,
                    DeliveryStatus.QUARANTINED,
                    reason_code="write_not_committed",
                    retry_safe=True,
                )
            self.ledger.mark_uncertain(record, "write_outcome_unknown")
            self.spool.quarantine(record, "write_outcome_unknown")
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="write_outcome_unknown",
            )
        except Exception:
            # Unknown connector exceptions provide no durability proof. The safe default is
            # to assume the write may have committed and refuse a blind non-idempotent retry.
            self.ledger.mark_uncertain(record, "write_outcome_unknown")
            self.spool.quarantine(record, "write_outcome_unknown")
            return self._receipt(
                record,
                DeliveryStatus.QUARANTINED,
                reason_code="write_outcome_unknown",
            )
        finally:
            # This removes the normal Python reference. It is not a secure memory wipe and
            # no such guarantee is claimed for CPython-managed objects.
            if "plaintext_record" in locals():
                del plaintext_record

        self.ledger.mark_committed(record)
        self.spool.remove(record.digest())
        return self._receipt(record, DeliveryStatus.DELIVERED)

    def replay(self, record_digest: str, *, force_uncertain: bool = False) -> DeliveryReceipt:
        record = self.spool.get(record_digest)
        if record is None:
            raise KeyError("sealed quarantine record does not exist")
        self._authorize_capability(CapabilityOperation.REPLAY, record)
        entry = self.ledger.get(record)
        if entry is None:
            raise IntegrityError("quarantine record has no delivery ledger entry")
        if entry.state is DeliveryState.COMMITTED:
            self.spool.remove(record_digest)
            return self._receipt(record, DeliveryStatus.DUPLICATE)
        if entry.state is DeliveryState.UNCERTAIN:
            if not self.connector.capabilities.supports_idempotency and not force_uncertain:
                raise PolicyViolation(
                    "uncertain write cannot be replayed without destination idempotency"
                )
            if force_uncertain:
                self._authorize_capability(CapabilityOperation.FORCE_UNCERTAIN_REPLAY, record)
        self.ledger.rearm_for_retry(record)
        return self._deliver_claimed(record)
