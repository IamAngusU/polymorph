from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event, Lock

import pytest

import polymorph.relay as relay_module
from polymorph.agents import BlindDestinationAgent, BlindSourceAgent, BlindTransportRecord
from polymorph.connectors.base import ConnectorCapabilities, DeliveryContext
from polymorph.connectors.json_file import JsonFileConnector
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import IntegrityError
from polymorph.ledger import DeliveryLedger, DeliveryState
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
from polymorph.outbox import SourceOutbox
from polymorph.relay import LeasedRecord, RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.runtime import DeliveryStatus, DestinationRuntime
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey
from polymorph.spool import SealedSpool

_TENANT = "recovery-tenant"
_SOURCE = "recovery-source"
_DESTINATION = "recovery-destination"
_SECRET = "recovery-stress-secret"


@dataclass(frozen=True, slots=True)
class _Route:
    records: tuple[BlindTransportRecord, ...]
    recipient: RecipientKeyPair
    plan: MappingPlan
    target: SchemaDescriptor
    trust: SourceTrustStore


def _route(*, records: int = 1) -> _Route:
    source = SchemaDescriptor(
        "recovery-source-schema",
        (
            FieldDescriptor(
                "token",
                "API token",
                DataType.STRING,
                nullable=False,
                sensitivity=Sensitivity.SECRET,
            ),
        ),
    )
    target = SchemaDescriptor(
        "recovery-target-schema",
        (
            FieldDescriptor(
                "token",
                "API token",
                DataType.STRING,
                nullable=False,
                sensitivity=Sensitivity.SECRET,
            ),
        ),
    )
    plan = MappingPlan(
        "recovery-plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("token", "token", "opaque_forward"),),
    )
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), _TENANT, _SOURCE)])
    agent = BlindSourceAgent(
        tenant=_TENANT,
        source_connector_id=_SOURCE,
        destination_connector_id=_DESTINATION,
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    )
    prepared = tuple(
        agent.prepare_record(
            {"token": f"{_SECRET}-{index}"},
            record_id=f"record-{index}",
            transfer_id="recovery-transfer",
        )
        for index in range(records)
    )
    return _Route(prepared, recipient, plan, target, trust)


def _policy(route: _Route) -> RelayPolicy:
    first = route.records[0]
    assert first.authentication is not None
    return RelayPolicy(
        (
            RouteBinding(
                _TENANT,
                _SOURCE,
                _DESTINATION,
                allowed_plan_digests=frozenset({route.plan.digest()}),
                allowed_source_key_ids=frozenset({first.authentication.key_id}),
            ),
        ),
        source_trust_store=route.trust,
    )


def _runtime(
    route: _Route,
    connector: JsonFileConnector | _BlockingDestination,
    *,
    ledger_path: Path,
    spool_path: Path,
) -> DestinationRuntime:
    return DestinationRuntime(
        connector_id=_DESTINATION,
        agent=BlindDestinationAgent(
            route.recipient.private_key,
            expected_tenant=_TENANT,
            expected_connector_id=_DESTINATION,
            allowed_plan_digests=frozenset({route.plan.digest()}),
            source_trust_store=route.trust,
        ),
        connector=connector,
        ledger=DeliveryLedger(ledger_path),
        spool=SealedSpool(spool_path),
        plan=route.plan,
        target_schema=route.target,
    )


class _BlockingDestination:
    capabilities = ConnectorCapabilities(write_records=True)

    def __init__(self) -> None:
        self.write_started = Event()
        self.allow_write_to_finish = Event()
        self._lock = Lock()
        self.calls = 0
        self.records: list[dict[str, object]] = []

    def inspect_schema(self) -> SchemaDescriptor:
        raise NotImplementedError

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        del context
        materialized = [dict(record) for record in records]
        with self._lock:
            self.calls += 1
        self.write_started.set()
        if not self.allow_write_to_finish.wait(timeout=10):
            raise RuntimeError("test destination remained blocked")
        with self._lock:
            self.records.extend(materialized)
        return len(materialized)


def test_concurrent_source_retries_keep_one_outbox_and_relay_copy(tmp_path: Path) -> None:
    route = _route()
    record = route.records[0]
    outbox_path = tmp_path / "outbox.db"
    relay_path = tmp_path / "relay.db"
    policy = _policy(route)
    SourceOutbox(outbox_path)
    SealedRelayQueue(relay_path, policy)
    attempts = 12
    ready = Barrier(attempts)

    def retry() -> tuple[bool, bool]:
        outbox = SourceOutbox(outbox_path)
        relay = SealedRelayQueue(relay_path, policy)
        ready.wait(timeout=10)
        staged = outbox.stage(record)
        enqueued = relay.enqueue(outbox.pending(limit=1)[0].record)
        return staged.duplicate, enqueued.duplicate

    with ThreadPoolExecutor(max_workers=attempts) as pool:
        results = tuple(pool.map(lambda _index: retry(), range(attempts)))

    assert sum(not staged_duplicate for staged_duplicate, _ in results) == 1
    assert sum(not relay_duplicate for _, relay_duplicate in results) == 1
    assert SourceOutbox(outbox_path).depth() == 1
    assert SealedRelayQueue(relay_path, policy).depth() == 1
    assert _SECRET.encode() not in outbox_path.read_bytes()
    assert _SECRET.encode() not in relay_path.read_bytes()


def test_parallel_startup_migrates_legacy_relay_once(tmp_path: Path) -> None:
    path = tmp_path / "legacy-relay.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE sealed_relay_queue (
                record_digest TEXT PRIMARY KEY,
                tenant TEXT NOT NULL,
                source_connector TEXT NOT NULL,
                destination_connector TEXT NOT NULL,
                transfer_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                received_at TEXT NOT NULL,
                wire_json BLOB NOT NULL,
                lease_owner TEXT,
                lease_expires_at TEXT,
                UNIQUE (tenant, destination_connector, transfer_id, record_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO sealed_relay_queue (
                record_digest, tenant, source_connector, destination_connector,
                transfer_id, record_id, plan_digest, received_at, wire_json,
                lease_owner, lease_expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            """,
            (
                "legacy-digest",
                _TENANT,
                _SOURCE,
                _DESTINATION,
                "legacy-transfer",
                "legacy-record",
                "legacy-plan",
                datetime.now(UTC).isoformat(),
                b"{}",
            ),
        )
    workers = 12
    ready = Barrier(workers)

    def start(_worker: int) -> None:
        ready.wait(timeout=10)
        SealedRelayQueue(path, RelayPolicy(()))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        tuple(pool.map(start, range(workers)))

    with closing(sqlite3.connect(path)) as connection:
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(sealed_relay_queue)")
        }
        preserved = connection.execute("SELECT record_digest FROM sealed_relay_queue").fetchall()
    assert "lease_id" in columns
    assert preserved == [("legacy-digest",)]


def test_parallel_startup_migrates_legacy_delivery_ledger_once(tmp_path: Path) -> None:
    path = tmp_path / "legacy-ledger.db"
    with closing(sqlite3.connect(path)) as connection, connection:
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
        now = datetime.now(UTC).isoformat()
        connection.execute(
            """
            INSERT INTO deliveries (
                tenant, destination_connector, transfer_id, record_id,
                record_digest, plan_digest, state, created_at, updated_at, reason_code
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                _TENANT,
                _DESTINATION,
                "legacy-transfer",
                "legacy-record",
                "legacy-digest",
                "legacy-plan",
                DeliveryState.COMMITTED.value,
                now,
                now,
            ),
        )
    workers = 12
    ready = Barrier(workers)

    def start(_worker: int) -> None:
        ready.wait(timeout=10)
        DeliveryLedger(path)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        tuple(pool.map(start, range(workers)))

    with closing(sqlite3.connect(path)) as connection:
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(deliveries)")}
        preserved = connection.execute(
            "SELECT state, claim_token, claim_expires_at FROM deliveries"
        ).fetchall()
    assert {"claim_token", "claim_expires_at"} <= columns
    assert preserved == [(DeliveryState.COMMITTED.value, None, None)]


def test_parallel_relay_workers_receive_disjoint_active_leases(tmp_path: Path) -> None:
    route = _route(records=24)
    relay_path = tmp_path / "relay.db"
    policy = _policy(route)
    relay = SealedRelayQueue(relay_path, policy)
    for record in route.records:
        relay.enqueue(record)

    workers = 6
    ready = Barrier(workers)

    def lease(worker: int) -> tuple[LeasedRecord, ...]:
        queue = SealedRelayQueue(relay_path, policy)
        ready.wait(timeout=10)
        return queue.lease(
            destination_connector=_DESTINATION,
            lease_owner=f"worker-{worker}",
            limit=4,
            lease_for=timedelta(minutes=1),
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        batches = tuple(pool.map(lease, range(workers)))

    leased = tuple(item for batch in batches for item in batch)
    digests = tuple(item.record.digest() for item in leased)
    assert all(len(batch) == 4 for batch in batches)
    assert len(digests) == len(set(digests)) == len(route.records)
    assert len({item.lease_id for item in leased}) == len(route.records)

    for item in leased:
        relay.ack(
            item.record.digest(),
            lease_owner=item.lease_owner,
            lease_id=item.lease_id,
        )
    assert relay.depth() == 0


def test_parallel_destination_delivery_crosses_write_boundary_once(tmp_path: Path) -> None:
    route = _route()
    record = route.records[0]
    destination = _BlockingDestination()
    ledger_path = tmp_path / "ledger.db"
    spool_path = tmp_path / "spool.db"
    first_runtime = _runtime(
        route,
        destination,
        ledger_path=ledger_path,
        spool_path=spool_path,
    )
    second_runtime = _runtime(
        route,
        destination,
        ledger_path=ledger_path,
        spool_path=spool_path,
    )

    with ThreadPoolExecutor(max_workers=1) as pool:
        first_future = pool.submit(first_runtime.deliver, record)
        assert destination.write_started.wait(timeout=10)
        overlapping = second_runtime.deliver(record)
        destination.allow_write_to_finish.set()
        first = first_future.result(timeout=10)

    restarted_runtime = _runtime(
        route,
        destination,
        ledger_path=ledger_path,
        spool_path=spool_path,
    )
    repeated = restarted_runtime.deliver(record)

    assert first.status is DeliveryStatus.DELIVERED
    assert overlapping.status is DeliveryStatus.AMBIGUOUS
    assert overlapping.reason_code == "previous_write_started_ambiguous"
    assert repeated.status is DeliveryStatus.DUPLICATE
    assert destination.calls == 1
    assert destination.records == [{"token": f"{_SECRET}-0"}]
    assert restarted_runtime.ledger.get(record).state is DeliveryState.COMMITTED
    assert restarted_runtime.spool.get(record.digest()) is None


def test_expired_relay_lease_during_write_does_not_enable_second_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = _route()
    record = route.records[0]
    policy = _policy(route)
    relay = SealedRelayQueue(tmp_path / "relay.db", policy)
    relay.enqueue(record)
    clock = {"now": datetime.now(UTC)}

    class RelayClock:
        @classmethod
        def now(cls, timezone: object = None) -> datetime:
            current = clock["now"]
            if timezone is None:
                return current.replace(tzinfo=None)
            return current

    monkeypatch.setattr(relay_module, "datetime", RelayClock)
    stale_lease = relay.lease(
        destination_connector=_DESTINATION,
        lease_owner="slow-worker",
        lease_for=timedelta(seconds=30),
    )[0]
    destination = _BlockingDestination()
    ledger_path = tmp_path / "ledger.db"
    spool_path = tmp_path / "spool.db"
    slow_runtime = _runtime(
        route,
        destination,
        ledger_path=ledger_path,
        spool_path=spool_path,
    )
    replacement_runtime = _runtime(
        route,
        destination,
        ledger_path=ledger_path,
        spool_path=spool_path,
    )

    with ThreadPoolExecutor(max_workers=1) as pool:
        slow_future = pool.submit(slow_runtime.deliver, stale_lease.record)
        try:
            assert destination.write_started.wait(timeout=10)
            clock["now"] += timedelta(seconds=31)
            replacement_lease = relay.lease(
                destination_connector=_DESTINATION,
                lease_owner="replacement-worker",
            )[0]
            overlapping = replacement_runtime.deliver(replacement_lease.record)
        finally:
            destination.allow_write_to_finish.set()
        first = slow_future.result(timeout=10)

    with pytest.raises(IntegrityError, match="does not own the active lease"):
        relay.ack(
            record.digest(),
            lease_owner=stale_lease.lease_owner,
            lease_id=stale_lease.lease_id,
        )
    repeated = replacement_runtime.deliver(replacement_lease.record)
    relay.ack(
        record.digest(),
        lease_owner=replacement_lease.lease_owner,
        lease_id=replacement_lease.lease_id,
    )

    assert first.status is DeliveryStatus.DELIVERED
    assert overlapping.status is DeliveryStatus.AMBIGUOUS
    assert overlapping.reason_code == "previous_write_started_ambiguous"
    assert repeated.status is DeliveryStatus.DUPLICATE
    assert destination.calls == 1
    assert destination.records == [{"token": f"{_SECRET}-0"}]
    assert replacement_runtime.ledger.get(record).state is DeliveryState.COMMITTED
    assert relay.depth() == 0


def test_restart_after_commit_before_transport_ack_suppresses_second_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = _route()
    record = route.records[0]
    policy = _policy(route)
    outbox_path = tmp_path / "outbox.db"
    relay_path = tmp_path / "relay.db"
    ledger_path = tmp_path / "ledger.db"
    spool_path = tmp_path / "spool.db"
    destination_path = tmp_path / "destination.json"

    outbox = SourceOutbox(outbox_path)
    relay = SealedRelayQueue(relay_path, policy)
    outbox.stage(record)
    relay.enqueue(outbox.pending()[0].record)
    clock = {"now": datetime.now(UTC)}

    class RelayClock:
        @classmethod
        def now(cls, timezone: object = None) -> datetime:
            current = clock["now"]
            if timezone is None:
                return current.replace(tzinfo=None)
            return current

    monkeypatch.setattr(relay_module, "datetime", RelayClock)
    first_lease = relay.lease(
        destination_connector=_DESTINATION,
        lease_owner="worker-before-restart",
        lease_for=timedelta(seconds=30),
    )[0]
    first_runtime = _runtime(
        route,
        JsonFileConnector(destination_path),
        ledger_path=ledger_path,
        spool_path=spool_path,
    )
    first = first_runtime.deliver(first_lease.record)
    assert first.status is DeliveryStatus.DELIVERED

    clock["now"] += timedelta(seconds=31)
    restarted_outbox = SourceOutbox(outbox_path)
    restarted_relay = SealedRelayQueue(relay_path, policy)
    restarted_runtime = _runtime(
        route,
        JsonFileConnector(destination_path),
        ledger_path=ledger_path,
        spool_path=spool_path,
    )
    replacement_lease = restarted_relay.lease(
        destination_connector=_DESTINATION,
        lease_owner="worker-after-restart",
    )[0]

    with pytest.raises(IntegrityError, match="does not own the active lease"):
        restarted_relay.ack(
            record.digest(),
            lease_owner=first_lease.lease_owner,
            lease_id=first_lease.lease_id,
        )
    repeated = restarted_runtime.deliver(replacement_lease.record)
    restarted_relay.ack(
        record.digest(),
        lease_owner=replacement_lease.lease_owner,
        lease_id=replacement_lease.lease_id,
    )
    assert restarted_outbox.ack(record.digest())

    assert repeated.status is DeliveryStatus.DUPLICATE
    assert restarted_runtime.ledger.get(record).state is DeliveryState.COMMITTED
    assert json.loads(destination_path.read_text(encoding="utf-8")) == [{"token": f"{_SECRET}-0"}]
    assert restarted_outbox.depth() == 0
    assert restarted_relay.depth() == 0


def test_restart_after_destination_write_before_ledger_commit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = _route()
    record = route.records[0]
    ledger_path = tmp_path / "ledger.db"
    spool_path = tmp_path / "spool.db"
    destination_path = tmp_path / "destination.json"
    runtime = _runtime(
        route,
        JsonFileConnector(destination_path),
        ledger_path=ledger_path,
        spool_path=spool_path,
    )

    def crash_before_ledger_commit(*_args: object, **_kwargs: object) -> None:
        raise SystemExit("injected process death after destination acknowledgement")

    monkeypatch.setattr(runtime.ledger, "mark_committed", crash_before_ledger_commit)
    with pytest.raises(SystemExit, match="injected process death"):
        runtime.deliver(record)

    restarted = _runtime(
        route,
        JsonFileConnector(destination_path),
        ledger_path=ledger_path,
        spool_path=spool_path,
    )
    repeated = restarted.deliver(record)

    assert repeated.status is DeliveryStatus.AMBIGUOUS
    assert repeated.reason_code == "previous_write_started_ambiguous"
    assert restarted.ledger.get(record).state is DeliveryState.WRITE_STARTED
    assert restarted.spool.get(record.digest()) is not None
    assert json.loads(destination_path.read_text(encoding="utf-8")) == [{"token": f"{_SECRET}-0"}]
