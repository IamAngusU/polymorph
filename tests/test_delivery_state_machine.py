from __future__ import annotations

import json
import sqlite3
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from polymorph.agents import BlindDestinationAgent, BlindSourceAgent, BlindTransportRecord
from polymorph.audit import AuditLog
from polymorph.connectors.base import ConnectorCapabilities, DeliveryContext
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import ConnectorWriteError, IntegrityError, PolicyViolation, WriteOutcome
from polymorph.ledger import ClaimDisposition, DeliveryLedger, DeliveryState
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.observability import EventStream, EventWriteStatus
from polymorph.outbox import SourceOutbox
from polymorph.recipient_auth import RecipientKeyCertificate, RecipientKeyTrustStore
from polymorph.relay import LeasedRecord, RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.runtime import AuditWriteStatus, DeliveryReceipt, DeliveryStatus, DestinationRuntime
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey
from polymorph.spool import SealedSpool

_FAULTS = (
    "normal",
    "not_committed",
    "unknown_before_write",
    "unknown_after_write",
    "crash_after_write",
)

_AMBIGUOUS_SPOOL_REASONS = {
    "delivery_outcome_record_failed",
    "previous_delivery_ambiguous",
    "previous_write_started_ambiguous",
}


class _MutableClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 9, 10, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current


class _FaultingDestination:
    capabilities = ConnectorCapabilities(write_records=True)

    def __init__(self) -> None:
        self.next_fault = "normal"
        self.durable_writes: list[str] = []
        self.fault_invocations: Counter[str] = Counter()

    def inspect_schema(self) -> SchemaDescriptor:
        raise NotImplementedError

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        assert context is not None
        materialized = list(records)
        assert len(materialized) == 1
        fault = self.next_fault
        self.fault_invocations[fault] += 1
        if fault == "not_committed":
            raise ConnectorWriteError(
                "injected rollback",
                outcome=WriteOutcome.NOT_COMMITTED,
            )
        if fault == "unknown_before_write":
            raise RuntimeError("injected unknown pre-write failure")
        self.durable_writes.append(context.record_digest)
        if fault == "unknown_after_write":
            raise RuntimeError("injected lost destination acknowledgement")
        return len(materialized)


class _CrashableLedger(DeliveryLedger):
    def __init__(self, path: Path, *, clock: _MutableClock) -> None:
        self.crash_on_commit = False
        super().__init__(path, clock=clock)

    def mark_committed(self, record: BlindTransportRecord, claim_token: str) -> None:
        if self.crash_on_commit:
            self.crash_on_commit = False
            raise SystemExit("injected crash after destination commit")
        super().mark_committed(record, claim_token)

    def mark_replay_committed(self, record: BlindTransportRecord, claim_token: str) -> None:
        if self.crash_on_commit:
            self.crash_on_commit = False
            raise SystemExit("injected crash after destination commit")
        super().mark_replay_committed(record, claim_token)


class DeliveryPipelineStateMachine(RuleBasedStateMachine):
    """Exercise durable delivery components under reordered work and lost acknowledgements."""

    RECORD_COUNT = 7

    def __init__(self) -> None:
        super().__init__()
        self._temporary = tempfile.TemporaryDirectory(prefix="polymorph-state-machine-")
        self.root = Path(self._temporary.name)
        self.clock = _MutableClock()
        self.destination = _FaultingDestination()
        self.audit_signer = SigningKeyPair.generate()
        self.run_id = "01" * 16
        self.current_leases: dict[str, LeasedRecord] = {}
        self.lost_leases: list[LeasedRecord] = []
        self.stale_leases: list[LeasedRecord] = []
        self.ack_eligible: set[str] = set()
        self.relay_ack_history: set[str] = set()
        self.source_ack_history: set[str] = set()
        self.expected_outbox: set[str] = set()
        self.expected_relay: set[str] = set()
        self.expected_spool: dict[str, str] = {}
        self.expected_audit_events = 0
        self.expected_operational_events = 0
        self.expected_audit_diagnostics: Counter[tuple[str, str, str | None, str]] = Counter()
        self.expected_event_diagnostics: Counter[
            tuple[str, str, str, str | None, str, int | None]
        ] = Counter()

        source = SchemaDescriptor(
            "state-source",
            (FieldDescriptor("token", "API token", sensitivity=Sensitivity.SECRET),),
        )
        self.target = SchemaDescriptor(
            "state-target",
            (FieldDescriptor("token", "API token", sensitivity=Sensitivity.SECRET),),
        )
        self.plan = MappingPlan(
            "state-plan",
            source.id,
            self.target.id,
            source.fingerprint(),
            self.target.fingerprint(),
            (MappingRule("token", "token", "opaque_forward"),),
        )
        self.recipient = RecipientKeyPair.generate()
        recipient_identity = SigningKeyPair.generate()
        recipient_trust = RecipientKeyTrustStore(
            identity_public_key=recipient_identity.public_bytes(),
            tenant="state-tenant",
            destination_connector="state-destination",
        )
        certificate_time = datetime.now(UTC)
        recipient_trust.accept(
            RecipientKeyCertificate.issue(
                tenant="state-tenant",
                destination_connector="state-destination",
                public_key=self.recipient.public_bytes(),
                generation=1,
                previous_key_id=None,
                identity_signer=recipient_identity,
                issued_at=certificate_time,
                not_before=certificate_time - timedelta(minutes=1),
                not_after=certificate_time + timedelta(days=1),
            )
        )
        self.source_signer = SigningKeyPair.generate()
        self.trust = SourceTrustStore(
            [TrustedSourceKey(self.source_signer.public_bytes(), "state-tenant", source.id)]
        )
        source_agent = BlindSourceAgent(
            tenant="state-tenant",
            source_connector_id=source.id,
            destination_connector_id="state-destination",
            source_schema=source,
            target_schema=self.target,
            plan=self.plan,
            destination_public_key=None,
            signing_key=self.source_signer,
            recipient_key_trust_store=recipient_trust,
        )
        self.records = tuple(
            source_agent.prepare_record(
                {"token": f"secret-{index}"},
                record_id=f"record-{index}",
                transfer_id=f"transfer-{index}",
            )
            for index in range(self.RECORD_COUNT)
        )
        authentication = self.records[0].authentication
        assert authentication is not None
        self.policy = RelayPolicy(
            (
                RouteBinding(
                    "state-tenant",
                    source.id,
                    "state-destination",
                    allowed_plan_digests=frozenset({self.plan.digest()}),
                    allowed_source_key_ids=frozenset({authentication.key_id}),
                ),
            ),
            source_trust_store=self.trust,
        )
        self._reopen()
        for record in self.records:
            self.outbox.stage(record)
            self.relay.enqueue(record)
            self.expected_outbox.add(record.digest())
            self.expected_relay.add(record.digest())
        initial = self.relay.lease(
            destination_connector="state-destination",
            lease_owner="initial-worker",
            limit=self.RECORD_COUNT,
            lease_for=timedelta(seconds=30),
        )
        self.current_leases.update((item.record.digest(), item) for item in initial)

        committed = self.runtime.deliver(self.records[0])
        assert committed.status is DeliveryStatus.DELIVERED
        self._record_receipt(self.records[0], committed)
        self.ack_eligible.add(self.records[0].digest())
        self.destination.next_fault = "not_committed"
        quarantined = self.runtime.deliver(self.records[1])
        self.destination.next_fault = "normal"
        assert quarantined.status is DeliveryStatus.QUARANTINED
        assert quarantined.reason_code == "write_not_committed"
        self._record_receipt(self.records[1], quarantined)
        assert self.spool.get(self.records[1].digest()) is not None
        replayed = self.runtime.replay(self.records[1].digest())
        assert replayed.status is DeliveryStatus.DELIVERED
        self._record_receipt(self.records[1], replayed, replay=True)
        assert self.spool.get(self.records[1].digest()) is None
        self.ack_eligible.add(self.records[1].digest())

        relay_committed = self.runtime.deliver(self.records[2])
        assert relay_committed.status is DeliveryStatus.DELIVERED
        self._record_receipt(self.records[2], relay_committed)
        relay_committed_digest = self.records[2].digest()
        self.ack_eligible.add(relay_committed_digest)
        relay_lease = self.current_leases.pop(relay_committed_digest)
        self.relay.ack(
            relay_committed_digest,
            lease_owner=relay_lease.lease_owner,
            lease_id=relay_lease.lease_id,
        )
        self.expected_relay.remove(relay_committed_digest)
        self.relay_ack_history.add(relay_committed_digest)

        self.destination.next_fault = "unknown_before_write"
        unknown_before = self.runtime.deliver(self.records[3])
        self.destination.next_fault = "normal"
        assert unknown_before.status is DeliveryStatus.QUARANTINED
        assert unknown_before.reason_code == "write_outcome_unknown"
        assert Counter(self.destination.durable_writes)[self.records[3].digest()] == 0
        unknown_before_entry = self.ledger.get(self.records[3])
        assert unknown_before_entry is not None
        assert unknown_before_entry.state is DeliveryState.UNCERTAIN
        self._record_receipt(self.records[3], unknown_before)

        self.destination.next_fault = "unknown_after_write"
        unknown_after = self.runtime.deliver(self.records[4])
        self.destination.next_fault = "normal"
        assert unknown_after.status is DeliveryStatus.QUARANTINED
        assert unknown_after.reason_code == "write_outcome_unknown"
        assert Counter(self.destination.durable_writes)[self.records[4].digest()] == 1
        unknown_after_entry = self.ledger.get(self.records[4])
        assert unknown_after_entry is not None
        assert unknown_after_entry.state is DeliveryState.UNCERTAIN
        self._record_receipt(self.records[4], unknown_after)

        self.destination.next_fault = "crash_after_write"
        self.ledger.crash_on_commit = True
        try:
            with pytest.raises(SystemExit, match="injected crash after destination commit"):
                self.runtime.deliver(self.records[5])
        finally:
            self.destination.next_fault = "normal"
            self.ledger.crash_on_commit = False
        crash_entry = self.ledger.get(self.records[5])
        assert crash_entry is not None
        assert crash_entry.state is DeliveryState.WRITE_STARTED
        assert Counter(self.destination.durable_writes)[self.records[5].digest()] == 1
        assert self.spool.get(self.records[5].digest()) is None

        recovered_crash = self.runtime.deliver(self.records[5])
        assert recovered_crash.status is DeliveryStatus.AMBIGUOUS
        assert recovered_crash.reason_code == "previous_write_started_ambiguous"
        self._record_receipt(self.records[5], recovered_crash)

        expiring = self.records[6]
        first_claim = self.ledger.claim(expiring, lease_for=timedelta(seconds=30))
        assert first_claim.disposition is ClaimDisposition.NEW
        assert first_claim.claim_token is not None
        self.clock.current += timedelta(seconds=31)
        recovered_claim = self.ledger.claim(expiring, lease_for=timedelta(seconds=30))
        assert recovered_claim.disposition is ClaimDisposition.RECOVERED
        assert recovered_claim.claim_token is not None
        assert recovered_claim.claim_token != first_claim.claim_token
        with pytest.raises(IntegrityError, match="invalid delivery ledger state transition"):
            self.ledger.start_write(expiring, first_claim.claim_token)
        self.clock.current += timedelta(seconds=31)
        recovered_delivery = self.runtime.deliver(expiring)
        assert recovered_delivery.status is DeliveryStatus.DELIVERED
        self._record_receipt(expiring, recovered_delivery)
        self.ack_eligible.add(expiring.digest())

        assert all(self.destination.fault_invocations[fault] > 0 for fault in _FAULTS)

    def _reopen(self) -> None:
        self.outbox = SourceOutbox(self.root / "outbox.db")
        self.relay = SealedRelayQueue(self.root / "relay.db", self.policy)
        self.ledger = _CrashableLedger(self.root / "ledger.db", clock=self.clock)
        self.spool = SealedSpool(self.root / "spool.db")
        self.audit = AuditLog(self.root / "audit.db", signer=self.audit_signer)
        self.events = EventStream(
            self.root / "events.jsonl",
            run_id=self.run_id,
            clock=self.clock,
        )
        self.runtime = DestinationRuntime(
            connector_id="state-destination",
            agent=BlindDestinationAgent(
                self.recipient.private_key,
                expected_tenant="state-tenant",
                expected_connector_id="state-destination",
                allowed_plan_digests=frozenset({self.plan.digest()}),
                source_trust_store=self.trust,
            ),
            connector=self.destination,
            ledger=self.ledger,
            spool=self.spool,
            plan=self.plan,
            target_schema=self.target,
            audit=self.audit,
            events=self.events,
            actor_id="state-machine-destination",
            claim_lease=timedelta(seconds=30),
        )

    def _record_receipt(
        self,
        record: BlindTransportRecord,
        receipt: DeliveryReceipt,
        *,
        replay: bool = False,
    ) -> None:
        assert receipt.audit_recorded
        assert receipt.audit_status is AuditWriteStatus.RECORDED
        assert receipt.operational_event_recorded
        assert receipt.operational_event_status is EventWriteStatus.RECORDED
        self.expected_audit_events += 1
        self.expected_operational_events += 1
        event_type = "replay" if replay else "delivery"
        audit_key = (event_type, receipt.status.value, receipt.reason_code, record.digest())
        self.expected_audit_diagnostics[audit_key] += 1
        expected_correlation = self.events.correlation_id(f"record:{record.digest()}")
        assert receipt.correlation_id == expected_correlation
        self.expected_event_diagnostics[
            (
                "destination_runtime",
                event_type,
                receipt.status.value,
                receipt.reason_code,
                expected_correlation,
                1,
            )
        ] += 1

        digest = record.digest()
        if receipt.status is DeliveryStatus.DELIVERED or (
            replay and receipt.status is DeliveryStatus.DUPLICATE
        ):
            self.expected_spool.pop(digest, None)
        elif receipt.status is DeliveryStatus.QUARANTINED or (
            receipt.status is DeliveryStatus.AMBIGUOUS
            and receipt.reason_code in _AMBIGUOUS_SPOOL_REASONS
        ):
            assert receipt.reason_code is not None
            self.expected_spool[digest] = receipt.reason_code

    def _outbox_digests(self) -> set[str]:
        with closing(sqlite3.connect(self.outbox.path)) as connection:
            rows = connection.execute("SELECT record_digest FROM sealed_source_outbox").fetchall()
        return {str(row[0]) for row in rows}

    def _spool_reasons(self) -> dict[str, str]:
        return {
            entry.record_digest: entry.reason_code for entry in self.spool.list_entries(limit=100)
        }

    def _relay_digests(self) -> set[str]:
        with closing(sqlite3.connect(self.relay.path)) as connection:
            rows = connection.execute("SELECT record_digest FROM sealed_relay_queue").fetchall()
        return {str(row[0]) for row in rows}

    def _audit_diagnostics(self) -> Counter[tuple[str, str, str | None, str]]:
        with closing(sqlite3.connect(self.audit.path)) as connection:
            rows = connection.execute("SELECT event_json FROM audit_events").fetchall()
        diagnostics: Counter[tuple[str, str, str | None, str]] = Counter()
        for row in rows:
            payload = json.loads(str(row[0]))
            assert isinstance(payload, dict)
            reason = payload.get("reason_code")
            assert reason is None or isinstance(reason, str)
            diagnostics[
                (
                    str(payload["event_type"]),
                    str(payload["status"]),
                    reason,
                    str(payload["record_digest"]),
                )
            ] += 1
        return diagnostics

    def _connector_call_count(self) -> int:
        return sum(self.destination.fault_invocations.values())

    def _assert_exercised_fault(
        self,
        record: BlindTransportRecord,
        fault: str,
        *,
        calls_before: int,
        fault_calls_before: int,
        writes_before: int,
        receipt: DeliveryReceipt | None,
        crashed: bool,
        replay_attempt: bool = False,
    ) -> bool:
        calls_after = self._connector_call_count()
        assert calls_after in {calls_before, calls_before + 1}
        if calls_after == calls_before:
            assert not crashed
            return False

        assert self.destination.fault_invocations[fault] == fault_calls_before + 1
        writes_after = Counter(self.destination.durable_writes)[record.digest()]
        expected_write_delta = int(fault in {"normal", "unknown_after_write", "crash_after_write"})
        assert writes_after - writes_before == expected_write_delta
        entry = self.ledger.get(record)
        assert entry is not None
        if fault == "normal":
            assert not crashed
            assert receipt is not None
            assert receipt.status is DeliveryStatus.DELIVERED
            assert entry.state is DeliveryState.COMMITTED
        elif fault == "not_committed":
            assert not crashed
            assert receipt is not None
            assert receipt.status is DeliveryStatus.QUARANTINED
            assert receipt.reason_code == "write_not_committed"
            expected_state = (
                DeliveryState.REPLAY_QUARANTINED if replay_attempt else DeliveryState.QUARANTINED
            )
            assert entry.state is expected_state
        elif fault in {"unknown_before_write", "unknown_after_write"}:
            assert not crashed
            assert receipt is not None
            assert receipt.status is DeliveryStatus.QUARANTINED
            assert receipt.reason_code == "write_outcome_unknown"
            expected_state = (
                DeliveryState.REPLAY_UNCERTAIN if replay_attempt else DeliveryState.UNCERTAIN
            )
            assert entry.state is expected_state
        else:
            assert fault == "crash_after_write"
            assert crashed
            assert receipt is None
            expected_state = (
                DeliveryState.REPLAY_WRITE_STARTED
                if replay_attempt
                else DeliveryState.WRITE_STARTED
            )
            assert entry.state is expected_state
        return True

    def _relay_contains(self, digest: str) -> bool:
        with closing(sqlite3.connect(self.relay.path)) as connection:
            row = connection.execute(
                "SELECT 1 FROM sealed_relay_queue WHERE record_digest = ?",
                (digest,),
            ).fetchone()
        return row is not None

    def _outbox_contains(self, digest: str) -> bool:
        with closing(sqlite3.connect(self.outbox.path)) as connection:
            row = connection.execute(
                "SELECT 1 FROM sealed_source_outbox WHERE record_digest = ?",
                (digest,),
            ).fetchone()
        return row is not None

    @rule(index=st.integers(min_value=0, max_value=RECORD_COUNT - 1))
    def restage_exact_wire(self, index: int) -> None:
        record = self.records[index]
        self.outbox.stage(record)
        self.expected_outbox.add(record.digest())
        self.source_ack_history.discard(record.digest())

    @rule(index=st.integers(min_value=0, max_value=RECORD_COUNT - 1))
    def enqueue_pending(self, index: int) -> None:
        record = self.records[index]
        if not self._outbox_contains(record.digest()):
            return
        self.relay.enqueue(record)
        self.expected_relay.add(record.digest())
        self.relay_ack_history.discard(record.digest())

    @rule(owner=st.sampled_from(("worker-a", "worker-b", "worker-c")))
    def lease_available(self, owner: str) -> None:
        leased = self.relay.lease(
            destination_connector="state-destination",
            lease_owner=owner,
            limit=self.RECORD_COUNT,
            lease_for=timedelta(seconds=30),
        )
        self.current_leases.update((item.record.digest(), item) for item in leased)

    @rule(index=st.integers(min_value=0, max_value=RECORD_COUNT - 1))
    def release_for_reorder(self, index: int) -> None:
        digest = self.records[index].digest()
        leased = self.current_leases.get(digest)
        if leased is None:
            return
        self.relay.release(
            digest,
            lease_owner=leased.lease_owner,
            lease_id=leased.lease_id,
        )
        self.stale_leases.append(leased)
        del self.current_leases[digest]

    @rule()
    def expire_lost_leases(self) -> None:
        self.stale_leases.extend(self.current_leases.values())
        self.stale_leases.extend(self.lost_leases)
        self.current_leases.clear()
        self.lost_leases.clear()
        with closing(sqlite3.connect(self.relay.path)) as connection, connection:
            connection.execute(
                "UPDATE sealed_relay_queue SET lease_expires_at = ? "
                "WHERE lease_expires_at IS NOT NULL",
                ("1970-01-01T00:00:00+00:00",),
            )

    @rule()
    def restart_all_processes(self) -> None:
        self.lost_leases.extend(self.current_leases.values())
        self.current_leases.clear()
        self.ack_eligible.clear()
        self._reopen()

    @rule(
        index=st.integers(min_value=0, max_value=RECORD_COUNT - 1),
        fault=st.sampled_from(_FAULTS),
    )
    def deliver_leased(self, index: int, fault: str) -> None:
        record = self.records[index]
        leased = self.current_leases.get(record.digest())
        if leased is None:
            return
        calls_before = self._connector_call_count()
        fault_calls_before = self.destination.fault_invocations[fault]
        writes_before = Counter(self.destination.durable_writes)[record.digest()]
        receipt: DeliveryReceipt | None = None
        crashed = False
        self.destination.next_fault = fault
        self.ledger.crash_on_commit = fault == "crash_after_write"
        try:
            receipt = self.runtime.deliver(leased.record)
        except SystemExit as exc:
            crashed = True
            assert fault == "crash_after_write"
            assert str(exc) == "injected crash after destination commit"
        else:
            self._record_receipt(record, receipt)
            entry = self.ledger.get(record)
            assert entry is not None
            if receipt.status in {DeliveryStatus.DELIVERED, DeliveryStatus.DUPLICATE}:
                self.ack_eligible.add(record.digest())
                assert entry.state is DeliveryState.COMMITTED
        finally:
            self.destination.next_fault = "normal"
            self.ledger.crash_on_commit = False
        self._assert_exercised_fault(
            record,
            fault,
            calls_before=calls_before,
            fault_calls_before=fault_calls_before,
            writes_before=writes_before,
            receipt=receipt,
            crashed=crashed,
        )

    @rule(
        index=st.integers(min_value=0, max_value=RECORD_COUNT - 1),
        fault=st.sampled_from(_FAULTS),
    )
    def replay_quarantined_record(self, index: int, fault: str) -> None:
        record = self.records[index]
        digest = record.digest()
        if self.spool.get(digest) is None:
            return
        entry_before = self.ledger.get(record)
        assert entry_before is not None
        writes_before = Counter(self.destination.durable_writes)[digest]
        calls_before = self._connector_call_count()
        fault_calls_before = self.destination.fault_invocations[fault]
        receipt: DeliveryReceipt | None = None
        crashed = False
        self.destination.next_fault = fault
        self.ledger.crash_on_commit = fault == "crash_after_write"
        try:
            receipt = self.runtime.replay(digest)
        except PolicyViolation:
            assert entry_before.state in {
                DeliveryState.CLAIMED,
                DeliveryState.WRITE_STARTED,
                DeliveryState.UNCERTAIN,
                DeliveryState.REPLAY_CLAIMED,
                DeliveryState.REPLAY_WRITE_STARTED,
                DeliveryState.REPLAY_UNCERTAIN,
                DeliveryState.REPLAY_QUARANTINED,
            }
            assert Counter(self.destination.durable_writes)[digest] == writes_before
        except SystemExit as exc:
            crashed = True
            assert entry_before.state is DeliveryState.QUARANTINED
            assert fault == "crash_after_write"
            assert str(exc) == "injected crash after destination commit"
        else:
            self._record_receipt(record, receipt, replay=True)
            entry_after = self.ledger.get(record)
            assert entry_after is not None
            if receipt.status in {DeliveryStatus.DELIVERED, DeliveryStatus.DUPLICATE}:
                self.ack_eligible.add(digest)
                assert entry_after.state is DeliveryState.COMMITTED
        finally:
            self.destination.next_fault = "normal"
            self.ledger.crash_on_commit = False
        self._assert_exercised_fault(
            record,
            fault,
            calls_before=calls_before,
            fault_calls_before=fault_calls_before,
            writes_before=writes_before,
            receipt=receipt,
            crashed=crashed,
            replay_attempt=True,
        )

    @rule(index=st.integers(min_value=0, max_value=RECORD_COUNT - 1))
    def acknowledge_committed_relay_delivery(self, index: int) -> None:
        record = self.records[index]
        digest = record.digest()
        leased = self.current_leases.get(digest)
        if leased is None or digest not in self.ack_eligible:
            return
        self.relay.ack(
            digest,
            lease_owner=leased.lease_owner,
            lease_id=leased.lease_id,
        )
        self.expected_relay.remove(digest)
        self.relay_ack_history.add(digest)
        del self.current_leases[digest]

    @rule(index=st.integers(min_value=0, max_value=RECORD_COUNT - 1))
    def acknowledge_source_after_relay(self, index: int) -> None:
        record = self.records[index]
        digest = record.digest()
        if digest not in self.relay_ack_history:
            return
        if self.outbox.ack(digest):
            self.expected_outbox.remove(digest)
            self.source_ack_history.add(digest)

    @rule()
    def stale_lease_cannot_ack_reordered_work(self) -> None:
        if not self.stale_leases:
            return
        stale = self.stale_leases[-1]
        try:
            self.relay.ack(
                stale.record.digest(),
                lease_owner=stale.lease_owner,
                lease_id=stale.lease_id,
            )
        except IntegrityError:
            return
        raise AssertionError("a stale relay lease acknowledged reordered work")

    @invariant()
    def durable_stores_and_acknowledgements_match_the_reference_model(self) -> None:
        assert self._outbox_digests() == self.expected_outbox
        assert self._relay_digests() == self.expected_relay
        assert self._spool_reasons() == self.expected_spool
        writes = Counter(self.destination.durable_writes)
        for record in self.records:
            digest = record.digest()
            entry = self.ledger.get(record)
            assert writes[digest] <= 1
            if entry is not None and entry.state is DeliveryState.COMMITTED:
                assert writes[digest] == 1
            if digest in self.relay_ack_history:
                assert entry is not None
                assert entry.state is DeliveryState.COMMITTED
            if digest in self.source_ack_history:
                assert entry is not None
                assert entry.state is DeliveryState.COMMITTED
                assert not self._relay_contains(digest)
                assert not self._outbox_contains(digest)

    @invariant()
    def healthy_diagnostics_survive_restarts_and_match_expected_receipts(self) -> None:
        audit_summary = self.audit.summary(trusted_public_key=self.audit_signer.public_bytes())
        events = self.events.read()
        assert audit_summary.events == self.expected_audit_events
        assert len(events) == self.expected_operational_events
        assert self.expected_audit_events > 0
        assert self.expected_operational_events > 0
        assert self._audit_diagnostics() == self.expected_audit_diagnostics
        assert (
            Counter(
                (
                    event.component,
                    event.event_type,
                    event.status,
                    event.reason_code,
                    event.correlation_id,
                    event.item_count,
                )
                for event in events
            )
            == self.expected_event_diagnostics
        )
        assert audit_summary.statuses == dict(
            sorted(Counter(event.status for event in events).items())
        )
        assert audit_summary.event_types == dict(
            sorted(Counter(event.event_type for event in events).items())
        )
        assert audit_summary.reasons == dict(
            sorted(
                Counter(
                    event.reason_code for event in events if event.reason_code is not None
                ).items()
            )
        )
        assert len({event.event_id for event in events}) == len(events)
        assert all(event.run_id == self.run_id for event in events)
        expected_correlations = {
            self.events.correlation_id(f"record:{record.digest()}") for record in self.records
        }
        assert all(event.correlation_id in expected_correlations for event in events)

    def teardown(self) -> None:
        self._temporary.cleanup()


TestDeliveryPipelineStateMachine = DeliveryPipelineStateMachine.TestCase
TestDeliveryPipelineStateMachine.settings = settings(
    max_examples=25,
    stateful_step_count=30,
    deadline=None,
)
