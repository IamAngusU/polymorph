from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

import pytest

import polymorph.relay as relay_module
from polymorph.agents import BlindSourceAgent
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import IntegrityError, ReplayDetected
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.relay import MAX_LEASE_DURATION, RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey


def _record(
    secret: str = "never-visible",
    *,
    record_id: str = "r1",
    transfer_id: str = "t1",
    transfer_ttl: timedelta | None = timedelta(hours=1),
):
    source = SchemaDescriptor(
        "source", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),)
    )
    target = SchemaDescriptor(
        "target", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),)
    )
    plan = MappingPlan(
        id="p1",
        source_schema_id=source.id,
        target_schema_id=target.id,
        source_fingerprint=source.fingerprint(),
        target_fingerprint=target.fingerprint(),
        rules=(MappingRule("token", "token", "opaque_forward"),),
    )
    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    agent = BlindSourceAgent(
        tenant="tenant-a",
        source_connector_id="src",
        destination_connector_id="dst",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        transfer_ttl=transfer_ttl,
    )
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant-a", "src")])
    return (
        agent.prepare_record({"token": secret}, record_id=record_id, transfer_id=transfer_id),
        plan,
        trust,
    )


def _add_record_key(trust: SourceTrustStore, record, record_trust: SourceTrustStore) -> None:
    assert record.authentication is not None
    key = record_trust.get(record.authentication.key_id)
    assert key is not None
    trust.add(key)


def _put_first(queue: SealedRelayQueue, first_digest: str, second_digest: str) -> None:
    with sqlite3.connect(queue.path) as connection:
        connection.execute(
            "UPDATE sealed_relay_queue SET received_at = ? WHERE record_digest = ?",
            ("2026-01-01T00:00:00+00:00", first_digest),
        )
        connection.execute(
            "UPDATE sealed_relay_queue SET received_at = ? WHERE record_digest = ?",
            ("2026-01-01T00:00:01+00:00", second_digest),
        )


def test_relay_persists_only_sealed_record_and_leases(tmp_path) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )
    receipt = queue.enqueue(record)
    assert not receipt.duplicate
    assert queue.enqueue(record).duplicate
    assert b"never-visible" not in (tmp_path / "relay.db").read_bytes()

    leased = queue.lease(destination_connector="dst", lease_owner="worker-1")
    assert len(leased) == 1
    assert leased[0].record.digest() == record.digest()
    queue.ack(
        record.digest(),
        lease_owner="worker-1",
        lease_id=leased[0].lease_id,
    )
    assert queue.depth() == 0


def test_malformed_first_record_is_dead_lettered_and_valid_second_is_leased(tmp_path) -> None:
    first, plan, trust = _record("first-never-visible", record_id="r1", transfer_id="t1")
    second, second_plan, second_trust = _record(
        "second-never-visible", record_id="r2", transfer_id="t2"
    )
    _add_record_key(trust, second, second_trust)
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    "tenant-a",
                    "src",
                    "dst",
                    frozenset({plan.digest(), second_plan.digest()}),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(first)
    queue.enqueue(second)
    _put_first(queue, first.digest(), second.digest())
    with sqlite3.connect(queue.path) as connection:
        connection.execute(
            "UPDATE sealed_relay_queue SET wire_json = ? WHERE record_digest = ?",
            (b'{"protocol":"opaque-record"', first.digest()),
        )

    leased = queue.lease(destination_connector="dst", lease_owner="worker-1", limit=1)

    assert [item.record.digest() for item in leased] == [second.digest()]
    assert queue.depth() == 1
    assert queue.dead_letter_depth() == 1
    dead_letter = queue.list_dead_letters()[0]
    assert dead_letter.record_digest == first.digest()
    assert dead_letter.reason_code == "relay_wire_invalid"
    database = queue.path.read_bytes()
    assert b"first-never-visible" not in database
    assert b"second-never-visible" not in database
    with pytest.raises(ReplayDetected, match="permanently dead-lettered"):
        queue.enqueue(first)

    queue.ack(second.digest(), lease_owner="worker-1", lease_id=leased[0].lease_id)
    assert queue.depth() == 0


def test_revoked_first_record_is_dead_lettered_and_valid_second_is_leased(tmp_path) -> None:
    first, plan, trust = _record(record_id="r1", transfer_id="t1")
    second, second_plan, second_trust = _record(record_id="r2", transfer_id="t2")
    _add_record_key(trust, second, second_trust)
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    "tenant-a",
                    "src",
                    "dst",
                    frozenset({plan.digest(), second_plan.digest()}),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(first)
    queue.enqueue(second)
    _put_first(queue, first.digest(), second.digest())
    assert first.authentication is not None
    trust.revoke(first.authentication.key_id)

    leased = queue.lease(destination_connector="dst", lease_owner="worker-1", limit=1)

    assert [item.record.digest() for item in leased] == [second.digest()]
    assert queue.dead_letter_depth() == 1
    assert queue.list_dead_letters()[0].reason_code == "relay_source_authentication_failed"


def test_expired_first_record_is_dead_lettered_and_valid_second_is_leased(
    tmp_path, monkeypatch
) -> None:
    first, plan, trust = _record(record_id="r1", transfer_id="t1")
    second, second_plan, second_trust = _record(record_id="r2", transfer_id="t2", transfer_ttl=None)
    _add_record_key(trust, second, second_trust)
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    "tenant-a",
                    "src",
                    "dst",
                    frozenset({plan.digest(), second_plan.digest()}),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(first)
    queue.enqueue(second)
    _put_first(queue, first.digest(), second.digest())
    expires_at = first.fields[0].context.expires_at
    assert expires_at is not None

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            future = expires_at + timedelta(seconds=1)
            return future if tz is not None else future.replace(tzinfo=None)

    monkeypatch.setattr(relay_module, "datetime", FutureDateTime)

    leased = queue.lease(destination_connector="dst", lease_owner="worker-1", limit=1)

    assert [item.record.digest() for item in leased] == [second.digest()]
    assert queue.dead_letter_depth() == 1
    assert queue.list_dead_letters()[0].reason_code == "relay_transfer_expired"


def test_reused_owner_cannot_ack_or_release_a_new_lease_with_stale_token(tmp_path) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(record)

    first = queue.lease(destination_connector="dst", lease_owner="worker-1")[0]
    queue.release(
        record.digest(),
        lease_owner="worker-1",
        lease_id=first.lease_id,
    )
    second = queue.lease(destination_connector="dst", lease_owner="worker-1")[0]

    assert first.lease_id != second.lease_id
    with pytest.raises(IntegrityError, match="does not own the active lease"):
        queue.ack(
            record.digest(),
            lease_owner="worker-1",
            lease_id=first.lease_id,
        )
    with pytest.raises(IntegrityError, match="does not own the active lease"):
        queue.release(
            record.digest(),
            lease_owner="worker-1",
            lease_id=first.lease_id,
        )
    assert queue.depth() == 1

    queue.ack(
        record.digest(),
        lease_owner="worker-1",
        lease_id=second.lease_id,
    )
    assert queue.depth() == 0


@pytest.mark.parametrize(
    "lease_for",
    (
        timedelta(0),
        timedelta(microseconds=-1),
        MAX_LEASE_DURATION + timedelta(microseconds=1),
    ),
)
def test_relay_rejects_non_positive_and_excessive_lease_durations(
    tmp_path, lease_for: timedelta
) -> None:
    _, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )

    with pytest.raises(ValueError, match="lease duration"):
        queue.lease(
            destination_connector="dst",
            lease_owner="worker-1",
            lease_for=lease_for,
        )


def test_relay_rejects_unauthorized_route(tmp_path) -> None:
    record, _, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "other"),),
            source_trust_store=trust,
        ),
    )
    with pytest.raises(Exception, match="route is not authorized"):
        queue.enqueue(record)
