from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import polymorph.relay as relay_module
from polymorph.agents import BlindDestinationAgent, BlindSourceAgent
from polymorph.connectors.csv_file import CsvConnector
from polymorph.connectors.json_file import JsonFileConnector
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import IntegrityError
from polymorph.ledger import DeliveryLedger
from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.mapping import MappingStatus
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, FieldRole, Sensitivity
from polymorph.outbox import SourceOutbox
from polymorph.planning import build_plan
from polymorph.preflight import PreflightRunner
from polymorph.relay import RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.runtime import DeliveryStatus, DestinationRuntime
from polymorph.signing import (
    SigningKeyPair,
    SourceTrustStore,
    TrustedSourceKey,
    signing_key_id,
)
from polymorph.spool import SealedSpool


def test_csv_to_json_blind_delivery_workflow_survives_every_boundary(tmp_path: Path) -> None:
    source_path = tmp_path / "customer-upload.unknown"
    source_path.write_text(
        "Customer ID,API Token\nC-001,secret-one\nC-002,secret-two\n",
        encoding="utf-8",
    )
    source_connector = CsvConnector(source_path)
    source_schema = source_connector.inspect_schema()
    target_schema = SchemaDescriptor(
        "json-destination",
        (
            FieldDescriptor("customer_id", "Customer ID", DataType.STRING, nullable=False),
            FieldDescriptor(
                "api_token",
                "API Token",
                DataType.STRING,
                nullable=False,
                sensitivity=Sensitivity.SECRET,
                role=FieldRole.CREDENTIAL,
            ),
        ),
    )

    decisions = HybridMatcher().propose(source_schema, target_schema)
    assert all(decision.status is MappingStatus.AUTO for decision in decisions)
    plan = build_plan(source_schema, target_schema, decisions)
    records = list(source_connector.iter_records())
    preflight = PreflightRunner().run(records, source_schema, target_schema, plan)
    assert preflight.promotable

    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    signer_id = signing_key_id(signer.public_bytes())
    trust = SourceTrustStore(
        [TrustedSourceKey(signer.public_bytes(), "tenant-a", source_schema.id)]
    )
    source_agent = BlindSourceAgent(
        tenant="tenant-a",
        source_connector_id=source_schema.id,
        destination_connector_id="json-out",
        source_schema=source_schema,
        target_schema=target_schema,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    )
    outbox_path = tmp_path / "source-outbox.db"
    relay_path = tmp_path / "relay.db"
    outbox = SourceOutbox(outbox_path)
    relay = SealedRelayQueue(
        relay_path,
        RelayPolicy(
            (
                RouteBinding(
                    "tenant-a",
                    source_schema.id,
                    "json-out",
                    allowed_plan_digests=frozenset({plan.digest()}),
                    allowed_source_key_ids=frozenset({signer_id}),
                ),
            ),
            source_trust_store=trust,
        ),
    )

    for index, record in enumerate(records, start=1):
        sealed = source_agent.prepare_record(
            record,
            record_id=f"row-{index}",
            transfer_id="batch-1",
        )
        outbox.stage(sealed)

    staged = outbox.pending()
    assert len(staged) == 2
    first_receipt = relay.enqueue(staged[0].record)
    assert relay.enqueue(staged[0].record).duplicate
    relay.enqueue(staged[1].record)
    assert relay.depth(destination_connector="json-out") == 2

    destination_path = tmp_path / "delivered.json"
    runtime = DestinationRuntime(
        connector_id="json-out",
        agent=BlindDestinationAgent(
            recipient.private_key,
            expected_tenant="tenant-a",
            expected_connector_id="json-out",
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=JsonFileConnector(destination_path),
        ledger=DeliveryLedger(tmp_path / "delivery-ledger.db"),
        spool=SealedSpool(tmp_path / "sealed-spool.db"),
        plan=plan,
        target_schema=target_schema,
    )

    leased = relay.lease(destination_connector="json-out", lease_owner="worker-1")
    assert len(leased) == 2
    for item in leased:
        receipt = runtime.deliver(item.record)
        assert receipt.status is DeliveryStatus.DELIVERED
        relay.ack(
            item.record.digest(),
            lease_owner="worker-1",
            lease_id=item.lease_id,
        )
        assert outbox.ack(item.record.digest())

    assert relay.depth() == 0
    assert outbox.depth() == 0
    assert first_receipt.record_digest == staged[0].record.digest()
    assert json.loads(destination_path.read_text(encoding="utf-8")) == [
        {"customer_id": "C-001", "api_token": "secret-one"},
        {"customer_id": "C-002", "api_token": "secret-two"},
    ]

    for path in (outbox_path, relay_path, tmp_path / "delivery-ledger.db"):
        content = path.read_bytes()
        assert b"secret-one" not in content
        assert b"secret-two" not in content


def test_crash_after_destination_commit_recovers_without_duplicate_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_schema = SchemaDescriptor(
        "source",
        (FieldDescriptor("value", "Value", DataType.STRING, nullable=False),),
    )
    target_schema = SchemaDescriptor(
        "target",
        (FieldDescriptor("value", "Value", DataType.STRING, nullable=False),),
    )
    decisions = HybridMatcher().propose(source_schema, target_schema)
    plan = build_plan(source_schema, target_schema, decisions)

    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    signer_id = signing_key_id(signer.public_bytes())
    trust = SourceTrustStore(
        [TrustedSourceKey(signer.public_bytes(), "tenant-a", source_schema.id)]
    )
    record = BlindSourceAgent(
        tenant="tenant-a",
        source_connector_id=source_schema.id,
        destination_connector_id="json-out",
        source_schema=source_schema,
        target_schema=target_schema,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    ).prepare_record(
        {"value": "write-once"},
        record_id="row-1",
        transfer_id="batch-1",
    )

    outbox = SourceOutbox(tmp_path / "source-outbox.db")
    outbox.stage(record)
    relay = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    "tenant-a",
                    source_schema.id,
                    "json-out",
                    allowed_plan_digests=frozenset({plan.digest()}),
                    allowed_source_key_ids=frozenset({signer_id}),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    relay.enqueue(outbox.pending()[0].record)

    destination_path = tmp_path / "delivered.json"
    runtime = DestinationRuntime(
        connector_id="json-out",
        agent=BlindDestinationAgent(
            recipient.private_key,
            expected_tenant="tenant-a",
            expected_connector_id="json-out",
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=JsonFileConnector(destination_path),
        ledger=DeliveryLedger(tmp_path / "delivery-ledger.db"),
        spool=SealedSpool(tmp_path / "sealed-spool.db"),
        plan=plan,
        target_schema=target_schema,
    )

    clock = {"now": datetime.now(UTC)}

    class RelayClock:
        @classmethod
        def now(cls, timezone=None):
            current = clock["now"]
            return (
                current.astimezone(timezone)
                if timezone is not None
                else current.replace(tzinfo=None)
            )

    monkeypatch.setattr(relay_module, "datetime", RelayClock)
    first = relay.lease(
        destination_connector="json-out",
        lease_owner="worker-1",
        lease_for=timedelta(minutes=2),
    )[0]

    assert runtime.deliver(first.record).status is DeliveryStatus.DELIVERED
    assert outbox.depth() == 1
    assert relay.depth() == 1
    assert json.loads(destination_path.read_text(encoding="utf-8")) == [{"value": "write-once"}]

    # The worker crashes after commit and before either acknowledgement. A later lease must
    # get a fresh fencing token, while the destination ledger suppresses the duplicate write.
    clock["now"] += timedelta(minutes=3)
    second = relay.lease(
        destination_connector="json-out",
        lease_owner="worker-1",
    )[0]
    assert second.lease_id != first.lease_id
    assert runtime.deliver(second.record).status is DeliveryStatus.DUPLICATE
    assert json.loads(destination_path.read_text(encoding="utf-8")) == [{"value": "write-once"}]

    with pytest.raises(IntegrityError, match="does not own the active lease"):
        relay.ack(
            first.record.digest(),
            lease_owner="worker-1",
            lease_id=first.lease_id,
        )
    relay.ack(
        second.record.digest(),
        lease_owner="worker-1",
        lease_id=second.lease_id,
    )
    assert outbox.ack(second.record.digest())
    assert relay.depth() == 0
    assert outbox.depth() == 0
