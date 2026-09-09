from pathlib import Path

import pytest

from polymorph.agents import BlindDestinationAgent, BlindSourceAgent
from polymorph.connectors.base import ConnectorCapabilities, DeliveryContext
from polymorph.crypto import RecipientKeyPair
from polymorph.ledger import DeliveryLedger, DeliveryState
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.errors import PolicyViolation
from polymorph.runtime import DeliveryStatus, DestinationRuntime
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
    record = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="excel",
        destination_connector_id="db",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
    ).prepare_record({"token": secret}, record_id="r1", transfer_id="t1")
    return record, keys, plan


def _runtime(tmp_path: Path, destination):
    record, keys, plan = _transport()
    runtime = DestinationRuntime(
        connector_id="db",
        agent=BlindDestinationAgent(
            keys.private_key,
            expected_tenant="tenant",
            expected_connector_id="db",
            allowed_plan_digests=frozenset({plan.digest()}),
        ),
        connector=destination,
        ledger=DeliveryLedger(tmp_path / "ledger.db"),
        spool=SealedSpool(tmp_path / "spool.db"),
    )
    return record, runtime


def test_runtime_delivers_once_and_deduplicates(tmp_path):
    destination = MemoryDestination()
    record, runtime = _runtime(tmp_path, destination)

    first = runtime.deliver(record)
    second = runtime.deliver(record)

    assert first.status is DeliveryStatus.DELIVERED
    assert second.status is DeliveryStatus.DUPLICATE
    assert destination.calls == 1
    assert destination.records == [{"token": "s3cr3t"}]


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
    replayed = runtime.replay(transport.digest())
    assert replayed.status is DeliveryStatus.DELIVERED
    assert len(connector.records) == 1
