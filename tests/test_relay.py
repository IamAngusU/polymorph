from __future__ import annotations

from datetime import timedelta

import pytest

from polymorph.agents import BlindSourceAgent
from polymorph.crypto import RecipientKeyPair
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.relay import RelayPolicy, RouteBinding, SealedRelayQueue


def _record(secret: str = "never-visible"):
    source = SchemaDescriptor("source", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),))
    target = SchemaDescriptor("target", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),))
    plan = MappingPlan(
        id="p1",
        source_schema_id=source.id,
        target_schema_id=target.id,
        source_fingerprint=source.fingerprint(),
        target_fingerprint=target.fingerprint(),
        rules=(MappingRule("token", "token", "opaque_forward"),),
    )
    keys = RecipientKeyPair.generate()
    agent = BlindSourceAgent(
        tenant="tenant-a",
        source_connector_id="src",
        destination_connector_id="dst",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        transfer_ttl=timedelta(hours=1),
    )
    return agent.prepare_record({"token": secret}, record_id="r1", transfer_id="t1"), plan


def test_relay_persists_only_sealed_record_and_leases(tmp_path) -> None:
    record, plan = _record()
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy((RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),)),
    )
    receipt = queue.enqueue(record)
    assert not receipt.duplicate
    assert queue.enqueue(record).duplicate
    assert b"never-visible" not in (tmp_path / "relay.db").read_bytes()

    leased = queue.lease(destination_connector="dst", lease_owner="worker-1")
    assert len(leased) == 1
    assert leased[0].record.digest() == record.digest()
    queue.ack(record.digest(), lease_owner="worker-1")
    assert queue.depth() == 0


def test_relay_rejects_unauthorized_route(tmp_path) -> None:
    record, _ = _record()
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy((RouteBinding("tenant-a", "src", "other"),)),
    )
    with pytest.raises(Exception, match="route is not authorized"):
        queue.enqueue(record)
