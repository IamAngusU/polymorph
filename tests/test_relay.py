from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta

import pytest

import polymorph.relay as relay_module
from polymorph.agents import BlindSourceAgent, BlindTransportRecord, ProtocolLimits
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import IntegrityError, ReplayDetected
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.relay import (
    MAX_DEAD_LETTERS_PER_LEASE,
    MAX_LEASE_DURATION,
    MAX_RELAY_BATCH_ITEMS,
    RelayPolicy,
    RouteBinding,
    SealedRelayQueue,
)
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
        allow_unauthenticated_recipient_key=True,
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


def _record_batch(
    count: int,
    *,
    transfer_id: str,
) -> tuple[tuple[BlindTransportRecord, ...], RelayPolicy]:
    records_with_policy = tuple(
        _record(record_id=f"r{number}", transfer_id=transfer_id) for number in range(count)
    )
    first_record, first_plan, trust = records_with_policy[0]
    records = [first_record]
    plans = {first_plan.digest()}
    for record, record_plan, record_trust in records_with_policy[1:]:
        _add_record_key(trust, record, record_trust)
        records.append(record)
        plans.add(record_plan.digest())
    policy = RelayPolicy(
        (
            RouteBinding(
                "tenant-a",
                "src",
                "dst",
                frozenset(plans),
            ),
        ),
        source_trust_store=trust,
    )
    return tuple(records), policy


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


def test_relay_enqueues_and_acknowledges_atomic_batches(tmp_path) -> None:
    records_with_policy = tuple(
        _record(record_id=f"r{number}", transfer_id="batch") for number in range(3)
    )
    first_record, first_plan, trust = records_with_policy[0]
    plans = {first_plan.digest()}
    records = [first_record]
    for record, plan, record_trust in records_with_policy[1:]:
        _add_record_key(trust, record, record_trust)
        plans.add(plan.digest())
        records.append(record)
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset(plans)),),
            source_trust_store=trust,
        ),
    )

    receipts = queue.enqueue_many(records)
    assert len(receipts) == len(records)
    assert not any(receipt.duplicate for receipt in receipts)
    assert all(receipt.duplicate for receipt in queue.enqueue_many(records))

    leased = queue.lease(destination_connector="dst", lease_owner="worker-1", limit=3)
    acknowledgements = tuple((item.record.digest(), item.lease_id) for item in leased)
    invalid = (acknowledgements[0], (acknowledgements[1][0], "stale-lease-id"))
    with pytest.raises(IntegrityError, match="does not own the active lease"):
        queue.ack_many(invalid, lease_owner="worker-1")
    assert queue.depth() == len(records)

    queue.ack_many(acknowledgements, lease_owner="worker-1")
    assert queue.depth() == 0
    queue.ack_many((), lease_owner="worker-1")


def test_relay_batch_uses_one_source_trust_session_per_transaction(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records, policy = _record_batch(3, transfer_id="trust-session-batch")
    trust = policy.source_trust_store
    assert trust is not None
    original_session = trust.verification_session
    sessions = 0

    @contextmanager
    def counting_session():
        nonlocal sessions
        sessions += 1
        with original_session() as verification:
            yield verification

    monkeypatch.setattr(trust, "verification_session", counting_session)
    queue = SealedRelayQueue(tmp_path / "trust-session-batch.db", policy)

    queue.enqueue_many(records)
    assert sessions == 1
    assert len(queue.lease(destination_connector="dst", lease_owner="worker-1", limit=3)) == 3
    assert sessions == 2


def test_relay_hard_revocation_waits_for_verified_enqueue_commit(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "revocation-enqueue-fence.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )
    assert record.authentication is not None
    commit_pending = threading.Event()
    allow_commit = threading.Event()
    revocation_started = threading.Event()
    revocation_finished = threading.Event()
    enqueue_errors: list[BaseException] = []
    revocation_errors: list[BaseException] = []
    depth_after_revocation: list[int] = []
    original_postconditions = queue._assert_queue_postconditions

    def pause_before_commit(connection, postconditions) -> None:
        original_postconditions(connection, postconditions)
        commit_pending.set()
        if not allow_commit.wait(timeout=5):
            raise AssertionError("test did not release the relay enqueue commit")

    def enqueue() -> None:
        try:
            queue.enqueue(record)
        except BaseException as exc:
            enqueue_errors.append(exc)

    def revoke() -> None:
        revocation_started.set()
        try:
            trust.revoke(record.authentication.key_id)
            depth_after_revocation.append(queue.depth())
        except BaseException as exc:
            revocation_errors.append(exc)
        finally:
            revocation_finished.set()

    monkeypatch.setattr(queue, "_assert_queue_postconditions", pause_before_commit)
    enqueue_thread = threading.Thread(target=enqueue)
    enqueue_thread.start()
    assert commit_pending.wait(timeout=2)
    revocation_thread = threading.Thread(target=revoke)
    revocation_thread.start()
    assert revocation_started.wait(timeout=2)
    revocation_was_blocked = not revocation_finished.wait(timeout=0.2)
    allow_commit.set()
    enqueue_thread.join(timeout=2)
    revocation_thread.join(timeout=2)

    assert revocation_was_blocked
    assert not enqueue_thread.is_alive()
    assert not revocation_thread.is_alive()
    assert enqueue_errors == []
    assert revocation_errors == []
    assert depth_after_revocation == [1]
    assert queue.lease(destination_connector="dst", lease_owner="worker-1") == ()
    assert queue.depth() == 0
    assert queue.dead_letter_depth() == 1
    assert queue.list_dead_letters()[0].reason_code == "relay_source_authentication_failed"


def test_relay_hard_revocation_waits_for_verified_lease_commit(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "revocation-lease-fence.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(record)
    assert record.authentication is not None
    commit_pending = threading.Event()
    allow_commit = threading.Event()
    revocation_started = threading.Event()
    revocation_finished = threading.Event()
    lease_results: list[tuple] = []
    lease_errors: list[BaseException] = []
    revocation_errors: list[BaseException] = []
    lease_id_after_revocation: list[str | None] = []
    original_postconditions = queue._assert_dead_letter_postconditions

    def pause_before_commit(connection, postconditions) -> None:
        original_postconditions(connection, postconditions)
        commit_pending.set()
        if not allow_commit.wait(timeout=5):
            raise AssertionError("test did not release the relay lease commit")

    def lease() -> None:
        try:
            lease_results.append(queue.lease(destination_connector="dst", lease_owner="worker-1"))
        except BaseException as exc:
            lease_errors.append(exc)

    def revoke() -> None:
        revocation_started.set()
        try:
            trust.revoke(record.authentication.key_id)
            with sqlite3.connect(queue.path) as connection:
                row = connection.execute(
                    "SELECT lease_id FROM sealed_relay_queue WHERE record_digest = ?",
                    (record.digest(),),
                ).fetchone()
            lease_id_after_revocation.append(None if row is None else row[0])
        except BaseException as exc:
            revocation_errors.append(exc)
        finally:
            revocation_finished.set()

    monkeypatch.setattr(queue, "_assert_dead_letter_postconditions", pause_before_commit)
    lease_thread = threading.Thread(target=lease)
    lease_thread.start()
    assert commit_pending.wait(timeout=2)
    revocation_thread = threading.Thread(target=revoke)
    revocation_thread.start()
    assert revocation_started.wait(timeout=2)
    revocation_was_blocked = not revocation_finished.wait(timeout=0.2)
    allow_commit.set()
    lease_thread.join(timeout=2)
    revocation_thread.join(timeout=2)

    assert revocation_was_blocked
    assert not lease_thread.is_alive()
    assert not revocation_thread.is_alive()
    assert lease_errors == []
    assert revocation_errors == []
    assert len(lease_results) == 1
    assert len(lease_results[0]) == 1
    leased = lease_results[0][0]
    assert lease_id_after_revocation == [leased.lease_id]

    queue.release(record.digest(), lease_owner="worker-1", lease_id=leased.lease_id)
    assert queue.lease(destination_connector="dst", lease_owner="worker-2") == ()
    assert queue.dead_letter_depth() == 1
    assert queue.list_dead_letters()[0].reason_code == "relay_source_authentication_failed"


def test_relay_enqueue_many_rolls_back_the_complete_batch_on_replay(tmp_path) -> None:
    original, original_plan, trust = _record(record_id="r1", transfer_id="t1")
    new_record, new_plan, new_trust = _record(record_id="r2", transfer_id="t2")
    conflicting, conflicting_plan, conflicting_trust = _record(
        "changed", record_id="r1", transfer_id="t1"
    )
    _add_record_key(trust, new_record, new_trust)
    _add_record_key(trust, conflicting, conflicting_trust)
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    "tenant-a",
                    "src",
                    "dst",
                    frozenset(
                        {
                            original_plan.digest(),
                            new_plan.digest(),
                            conflicting_plan.digest(),
                        }
                    ),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(original)

    with pytest.raises(ReplayDetected, match="different authenticated content"):
        queue.enqueue_many((new_record, conflicting))

    assert queue.depth() == 1
    leased = queue.lease(destination_connector="dst", lease_owner="worker-1")
    assert [item.record.digest() for item in leased] == [original.digest()]


@pytest.mark.parametrize(
    "trigger_sql",
    (
        """
        CREATE TRIGGER silently_ignore_second_relay_insert
        BEFORE INSERT ON sealed_relay_queue
        WHEN NEW.record_id = 'r1'
        BEGIN
            SELECT RAISE(IGNORE);
        END
        """,
        """
        CREATE TRIGGER mutate_first_relay_insert
        AFTER INSERT ON sealed_relay_queue
        WHEN NEW.record_id = 'r1'
        BEGIN
            UPDATE sealed_relay_queue
            SET destination_connector = 'trigger-mutated'
            WHERE record_id = 'r0';
        END
        """,
    ),
    ids=("ignored-insert", "cross-record-mutation"),
)
def test_relay_enqueue_many_verifies_exact_batch_postconditions(
    tmp_path,
    trigger_sql: str,
) -> None:
    records, policy = _record_batch(2, transfer_id="postcondition-batch")
    queue = SealedRelayQueue(tmp_path / "postcondition.db", policy)
    with sqlite3.connect(queue.path) as connection:
        connection.execute(trigger_sql)

    with pytest.raises(IntegrityError, match="write postcondition"):
        queue.enqueue_many(records)

    assert queue.depth() == 0


def test_relay_dead_letter_rolls_back_if_insert_is_silently_ignored(tmp_path) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "dead-letter-ignore.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(record)
    assert record.authentication is not None
    trust.revoke(record.authentication.key_id)
    with sqlite3.connect(queue.path) as connection:
        connection.execute(
            """
            CREATE TRIGGER silently_ignore_dead_letter_insert
            BEFORE INSERT ON sealed_relay_dead_letter
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )

    with pytest.raises(IntegrityError, match="dead-letter transition postcondition"):
        queue.lease(destination_connector="dst", lease_owner="worker-1")

    assert queue.depth() == 1
    assert queue.dead_letter_depth() == 0


def test_relay_oversized_dead_letter_rolls_back_if_insert_is_silently_ignored(
    tmp_path,
) -> None:
    records, policy = _record_batch(1, transfer_id="oversized-postcondition")
    record = records[0]
    wire_limit = len(record.canonical_wire_bytes())
    queue = SealedRelayQueue(
        tmp_path / "oversized-dead-letter-ignore.db",
        policy,
        limits=ProtocolLimits(max_record_wire_bytes=wire_limit),
        max_batch_wire_bytes=wire_limit,
    )
    queue.enqueue(record)
    with sqlite3.connect(queue.path) as connection:
        connection.execute(
            "UPDATE sealed_relay_queue SET wire_json = zeroblob(?) WHERE record_digest = ?",
            (wire_limit + 1, record.digest()),
        )
        connection.execute(
            """
            CREATE TRIGGER silently_ignore_oversized_dead_letter_insert
            BEFORE INSERT ON sealed_relay_dead_letter
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )

    with pytest.raises(IntegrityError, match="dead-letter transition postcondition"):
        queue.lease(destination_connector="dst", lease_owner="worker-1")

    assert queue.depth() == 1
    assert queue.dead_letter_depth() == 0


def test_relay_dead_letter_rejects_a_conflicting_existing_digest(tmp_path) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "dead-letter-conflict.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(record)
    assert record.authentication is not None
    trust.revoke(record.authentication.key_id)
    with sqlite3.connect(queue.path) as connection:
        queued = connection.execute(
            """
            SELECT record_digest, tenant, source_connector, destination_connector,
                   transfer_id, record_id, plan_digest, received_at
            FROM sealed_relay_queue
            WHERE record_digest = ?
            """,
            (record.digest(),),
        ).fetchone()
        assert queued is not None
        connection.execute(
            """
            INSERT INTO sealed_relay_dead_letter (
                record_digest, tenant, source_connector, destination_connector,
                transfer_id, record_id, plan_digest, received_at,
                reason_code, dead_lettered_at, wire_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*queued, "conflicting-reason", "2026-01-01T00:00:00+00:00", b"conflict"),
        )

    with pytest.raises(IntegrityError, match="dead-letter conflict"):
        queue.lease(destination_connector="dst", lease_owner="worker-1")

    assert queue.depth() == 1
    assert queue.dead_letter_depth() == 1


def test_relay_dead_letter_preserves_an_exact_idempotent_conflict(tmp_path) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "dead-letter-idempotent.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )
    queue.enqueue(record)
    assert record.authentication is not None
    trust.revoke(record.authentication.key_id)
    dead_lettered_at = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(queue.path) as connection:
        queued = connection.execute(
            """
            SELECT record_digest, tenant, source_connector, destination_connector,
                   transfer_id, record_id, plan_digest, received_at
            FROM sealed_relay_queue
            WHERE record_digest = ?
            """,
            (record.digest(),),
        ).fetchone()
        assert queued is not None
        connection.execute(
            """
            INSERT INTO sealed_relay_dead_letter (
                record_digest, tenant, source_connector, destination_connector,
                transfer_id, record_id, plan_digest, received_at,
                reason_code, dead_lettered_at, wire_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *queued,
                "relay_source_authentication_failed",
                dead_lettered_at,
                record.canonical_wire_bytes(),
            ),
        )

    assert queue.lease(destination_connector="dst", lease_owner="worker-1") == ()
    assert queue.depth() == 0
    assert queue.dead_letter_depth() == 1
    assert queue.list_dead_letters()[0].dead_lettered_at == dead_lettered_at


def test_relay_lease_query_uses_availability_order_index(tmp_path) -> None:
    _, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )

    with sqlite3.connect(queue.path) as connection:
        query_plan = connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT record_digest, tenant, source_connector,
                   destination_connector, transfer_id, record_id,
                   plan_digest, received_at, LENGTH(wire_json) AS wire_bytes
            FROM sealed_relay_queue
            WHERE destination_connector = ?
              AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
            ORDER BY received_at ASC, record_digest ASC
            LIMIT ?
            """,
            ("dst", datetime.now().isoformat(), 100),
        ).fetchall()

    details = " ".join(str(row[3]) for row in query_plan)
    assert "relay_available_order" in details
    assert "USE TEMP B-TREE" not in details


def test_relay_batch_wire_limit_accepts_exact_boundary_and_rejects_one_over(
    tmp_path,
) -> None:
    records, policy = _record_batch(2, transfer_id="wire-boundary")
    wire_bytes = tuple(len(record.canonical_wire_bytes()) for record in records)
    batch_wire_bytes = sum(wire_bytes)
    limits = ProtocolLimits(max_record_wire_bytes=max(wire_bytes))
    exact = SealedRelayQueue(
        tmp_path / "exact-boundary.db",
        policy,
        limits=limits,
        max_batch_wire_bytes=batch_wire_bytes,
    )

    assert len(exact.enqueue_many(records)) == 2
    assert exact.depth() == 2

    one_over = SealedRelayQueue(
        tmp_path / "one-over-boundary.db",
        policy,
        limits=limits,
        max_batch_wire_bytes=batch_wire_bytes - 1,
    )
    with pytest.raises(ValueError, match="wire byte limit"):
        one_over.enqueue_many(records)
    assert one_over.depth() == 0


def test_relay_batch_wire_limit_stops_the_input_before_a_suffix(tmp_path) -> None:
    records, policy = _record_batch(1, transfer_id="streaming-wire-limit")
    record = records[0]
    wire_size = len(record.canonical_wire_bytes())
    queue = SealedRelayQueue(
        tmp_path / "streaming-wire-limit.db",
        policy,
        limits=ProtocolLimits(max_record_wire_bytes=wire_size),
        max_batch_wire_bytes=wire_size,
    )
    consumed = 0

    def repeated_records():
        nonlocal consumed
        for index in range(3):
            if index == 2:
                raise AssertionError("relay consumed after the aggregate wire limit failed")
            consumed += 1
            yield record

    with pytest.raises(ValueError, match="wire byte limit"):
        queue.enqueue_many(repeated_records())

    assert consumed == 2
    assert queue.depth() == 0


def test_relay_batch_wire_limit_must_admit_one_protocol_sized_record(tmp_path) -> None:
    limits = ProtocolLimits(max_record_wire_bytes=2_048)

    with pytest.raises(ValueError, match="admit one protocol-sized record"):
        SealedRelayQueue(
            tmp_path / "undersized-batch.db",
            RelayPolicy(()),
            limits=limits,
            max_batch_wire_bytes=2_047,
        )


def test_relay_lease_honors_wire_budget_and_leaves_remaining_record_available(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records, policy = _record_batch(3, transfer_id="lease-wire-budget")
    queue = SealedRelayQueue(tmp_path / "lease-wire-budget.db", policy)
    queue.enqueue_many(records)
    with sqlite3.connect(queue.path) as connection:
        for index, record in enumerate(records):
            connection.execute(
                "UPDATE sealed_relay_queue SET received_at = ? WHERE record_digest = ?",
                (f"2026-01-01T00:00:0{index}+00:00", record.digest()),
            )
    first_two_wire_bytes = sum(len(record.canonical_wire_bytes()) for record in records[:2])
    original_decode = relay_module._decode_queued_record
    decoded_records = 0

    def counting_decode(*args, **kwargs):
        nonlocal decoded_records
        decoded_records += 1
        return original_decode(*args, **kwargs)

    monkeypatch.setattr(relay_module, "_decode_queued_record", counting_decode)

    first_lease = queue.lease(
        destination_connector="dst",
        lease_owner="worker-1",
        limit=3,
        max_wire_bytes=first_two_wire_bytes,
    )

    assert decoded_records == 2
    assert tuple(item.record.digest() for item in first_lease) == tuple(
        record.digest() for record in records[:2]
    )
    second_lease = queue.lease(
        destination_connector="dst",
        lease_owner="worker-2",
        limit=3,
    )
    assert tuple(item.record.digest() for item in second_lease) == (records[2].digest(),)
    assert queue.depth() == 3


def test_relay_oversized_corrupted_blob_is_dead_lettered_before_decode(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records, policy = _record_batch(1, transfer_id="oversized-corruption")
    record = records[0]
    wire_limit = len(record.canonical_wire_bytes())
    queue = SealedRelayQueue(
        tmp_path / "oversized-corruption.db",
        policy,
        limits=ProtocolLimits(max_record_wire_bytes=wire_limit),
        max_batch_wire_bytes=wire_limit,
    )
    queue.enqueue(record)
    with sqlite3.connect(queue.path) as connection:
        connection.execute(
            "UPDATE sealed_relay_queue SET wire_json = zeroblob(?) WHERE record_digest = ?",
            (wire_limit + 1, record.digest()),
        )

    def fail_decode(*_args, **_kwargs):
        pytest.fail("oversized relay BLOB reached the Python decoder")

    monkeypatch.setattr(relay_module, "_decode_queued_record", fail_decode)

    assert queue.lease(destination_connector="dst", lease_owner="worker-1") == ()
    assert queue.depth() == 0
    assert queue.dead_letter_depth() == 1
    assert queue.list_dead_letters()[0].reason_code == "relay_wire_invalid"


def test_relay_oversized_prefix_larger_than_dead_letter_limit_makes_progress(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records, policy = _record_batch(1, transfer_id="oversized-prefix")
    valid = records[0]
    wire_limit = len(valid.canonical_wire_bytes())
    queue = SealedRelayQueue(
        tmp_path / "oversized-prefix.db",
        policy,
        limits=ProtocolLimits(max_record_wire_bytes=wire_limit),
        max_batch_wire_bytes=wire_limit,
    )
    queue.enqueue(valid)
    oversized_count = MAX_DEAD_LETTERS_PER_LEASE + 1
    with sqlite3.connect(queue.path) as connection:
        connection.execute(
            "UPDATE sealed_relay_queue SET received_at = ? WHERE record_digest = ?",
            ("9999-01-01T00:00:00+00:00", valid.digest()),
        )
        connection.executemany(
            """
            INSERT INTO sealed_relay_queue (
                record_digest, tenant, source_connector, destination_connector,
                transfer_id, record_id, plan_digest, received_at, wire_json
            ) VALUES (?, 'tenant-a', 'src', 'dst', ?, ?, 'synthetic-plan', ?, zeroblob(?))
            """,
            (
                (
                    f"{number + 1:064x}",
                    f"oversized-transfer-{number}",
                    f"oversized-record-{number}",
                    "2000-01-01T00:00:00+00:00",
                    wire_limit + 1,
                )
                for number in range(oversized_count)
            ),
        )

    original_decode = relay_module._decode_queued_record
    decoded_wire_sizes: list[int] = []

    def bounded_decode(wire: bytes, **kwargs):
        decoded_wire_sizes.append(len(wire))
        assert len(wire) <= wire_limit
        return original_decode(wire, **kwargs)

    monkeypatch.setattr(relay_module, "_decode_queued_record", bounded_decode)

    first = queue.lease(destination_connector="dst", lease_owner="worker-1", limit=1)

    assert first == ()
    assert decoded_wire_sizes == []
    assert queue.depth() == 2
    assert queue.dead_letter_depth() == MAX_DEAD_LETTERS_PER_LEASE
    with sqlite3.connect(queue.path) as connection:
        stored_wire_size = connection.execute(
            "SELECT MAX(LENGTH(wire_json)) FROM sealed_relay_dead_letter"
        ).fetchone()[0]
    assert stored_wire_size == 0

    second = queue.lease(destination_connector="dst", lease_owner="worker-2", limit=1)

    assert [item.record.digest() for item in second] == [valid.digest()]
    assert decoded_wire_sizes == [wire_limit]
    assert queue.depth() == 1
    assert queue.dead_letter_depth() == oversized_count


def test_relay_enqueue_and_acknowledgement_counts_are_bounded(tmp_path) -> None:
    record, plan, trust = _record()
    queue = SealedRelayQueue(
        tmp_path / "bounded-enqueue.db",
        RelayPolicy(
            (RouteBinding("tenant-a", "src", "dst", frozenset({plan.digest()})),),
            source_trust_store=trust,
        ),
    )

    with pytest.raises(ValueError, match="record count limit"):
        queue.enqueue_many(record for _ in range(MAX_RELAY_BATCH_ITEMS + 1))
    with pytest.raises(ValueError, match="acknowledgement batch"):
        queue.ack_many(
            (("0" * 64, "lease-id") for _ in range(MAX_RELAY_BATCH_ITEMS + 1)),
            lease_owner="worker-1",
        )

    assert queue.depth() == 0


def test_relay_ack_rejects_oversized_metadata_without_reading_a_suffix(tmp_path) -> None:
    queue = SealedRelayQueue(tmp_path / "invalid-ack-metadata.db", RelayPolicy(()))
    consumed = 0

    def acknowledgements():
        nonlocal consumed
        consumed += 1
        yield ("a" * (1024 * 1024), "lease-id")
        raise AssertionError("relay consumed beyond the invalid acknowledgement")

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        queue.ack_many(acknowledgements(), lease_owner="worker-1")

    assert consumed == 1
    assert queue.depth() == 0


@pytest.mark.parametrize("wire_limit", [True, False, 0, -1, 64 * 1024 * 1024 + 1])
def test_relay_rejects_invalid_lease_wire_limits(tmp_path, wire_limit: object) -> None:
    queue = SealedRelayQueue(tmp_path / "invalid-lease-wire-limit.db", RelayPolicy(()))

    with pytest.raises(ValueError, match="lease wire limit"):
        queue.lease(
            destination_connector="dst",
            lease_owner="worker-1",
            max_wire_bytes=wire_limit,  # type: ignore[arg-type]
        )
