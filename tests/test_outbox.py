from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

import polymorph.outbox as outbox_module
from polymorph.agents import (
    BlindSourceAgent,
    BlindTransportRecord,
    PayloadCodec,
    ProtocolLimits,
    SealedField,
)
from polymorph.crypto import RecipientKeyPair, TransferContext, seal_for_recipient
from polymorph.errors import IntegrityError, ProtocolError, ReplayDetected
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.outbox import MAX_OUTBOX_BATCH_ITEMS, SourceOutbox
from polymorph.signing import SigningKeyPair


def _source_agent() -> BlindSourceAgent:
    source = SchemaDescriptor(
        "source", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),)
    )
    target = SchemaDescriptor(
        "target", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),)
    )
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("token", "token", "opaque_forward"),),
    )
    return BlindSourceAgent(
        tenant="tenant-a",
        source_connector_id="src",
        destination_connector_id="dst",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=RecipientKeyPair.generate().public_bytes(),
        signing_key=SigningKeyPair.generate(),
        allow_unauthenticated_recipient_key=True,
    )


def test_outbox_restarts_and_retries_exact_sealed_bytes(tmp_path: Path) -> None:
    record = _source_agent().prepare_record(
        {"token": "never-write-this-plaintext"},
        record_id="row-1",
        transfer_id="transfer-1",
    )
    expected_wire = record.canonical_wire_bytes()
    path = tmp_path / "source-outbox.db"

    receipt = SourceOutbox(path).stage(record)
    assert not receipt.duplicate
    assert SourceOutbox(path).stage(record).duplicate

    pending = SourceOutbox(path).pending()
    assert len(pending) == 1
    assert pending[0].wire_bytes == expected_wire
    assert pending[0].record.digest() == record.digest()
    for stored_file in tmp_path.iterdir():
        assert b"never-write-this-plaintext" not in stored_file.read_bytes()

    assert SourceOutbox(path).ack(record.digest())
    assert not SourceOutbox(path).ack(record.digest())
    assert SourceOutbox(path).depth() == 0


@pytest.mark.parametrize("legacy_record_id", ("r" * 257, "legacy\nrecord"))
def test_outbox_can_drain_a_pre_boundary_v3_record_with_invalid_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_record_id: str,
) -> None:
    agent = _source_agent()
    current = agent.prepare_record(
        {"token": "legacy-secret"}, record_id="current", transfer_id="transfer-1"
    )
    legacy_context = replace(current.fields[0].context, record_id=legacy_record_id)
    assert agent.destination_public_key is not None
    # Simulate an older issuer. Current public sealing and signing APIs reject this metadata,
    # while current readers must remain able to drain already-persisted signed records.
    with monkeypatch.context() as legacy_issuer:
        legacy_issuer.setattr(TransferContext, "validate_new_metadata", lambda _self: None)
        legacy_envelope = seal_for_recipient(
            PayloadCodec.encode("legacy-secret"),
            agent.destination_public_key,
            legacy_context,
        )
        legacy = BlindTransportRecord(
            legacy_record_id,
            (SealedField("token", legacy_context, legacy_envelope),),
        ).signed(agent.signing_key)
    outbox = SourceOutbox(tmp_path / "legacy-outbox.db")

    outbox.stage(legacy)
    pending = outbox.pending()

    assert len(pending) == 1
    assert pending[0].record.record_id == legacy_record_id
    assert pending[0].wire_bytes == legacy.canonical_wire_bytes()


def test_outbox_rejects_resealing_an_existing_transfer_identity(tmp_path: Path) -> None:
    agent = _source_agent()
    original = agent.prepare_record(
        {"token": "same-value"}, record_id="row-1", transfer_id="transfer-1"
    )
    resealed = agent.prepare_record(
        {"token": "same-value"}, record_id="row-1", transfer_id="transfer-1"
    )
    assert original.canonical_wire_bytes() != resealed.canonical_wire_bytes()

    outbox = SourceOutbox(tmp_path / "source-outbox.db")
    outbox.stage(original)
    with pytest.raises(ReplayDetected, match="different sealed bytes"):
        outbox.stage(resealed)


def test_outbox_rejects_unsigned_v3_record(tmp_path: Path) -> None:
    signed = _source_agent().prepare_record(
        {"token": "secret"}, record_id="row-1", transfer_id="transfer-1"
    )
    unsigned = type(signed)(signed.record_id, signed.fields)

    with pytest.raises(ProtocolError, match="no source authentication"):
        SourceOutbox(tmp_path / "source-outbox.db").stage(unsigned)


def test_outbox_stages_and_acknowledges_batches(tmp_path: Path) -> None:
    agent = _source_agent()
    records = tuple(
        agent.prepare_record(
            {"token": f"secret-{number}"},
            record_id=f"row-{number}",
            transfer_id="transfer-batch",
        )
        for number in range(3)
    )
    outbox = SourceOutbox(tmp_path / "source-outbox.db")

    receipts = outbox.stage_many(records)
    assert len(receipts) == len(records)
    assert not any(receipt.duplicate for receipt in receipts)
    assert all(receipt.duplicate for receipt in outbox.stage_many(records))
    assert outbox.depth() == len(records)

    digests = tuple(record.digest() for record in records)
    assert outbox.ack_many(digests) == (True, True, True)
    assert outbox.ack_many(digests) == (False, False, False)
    assert outbox.ack_many(()) == ()
    assert outbox.depth() == 0


def test_outbox_stage_many_rolls_back_the_complete_batch_on_replay(tmp_path: Path) -> None:
    agent = _source_agent()
    original = agent.prepare_record(
        {"token": "original"}, record_id="row-1", transfer_id="transfer-1"
    )
    new_record = agent.prepare_record({"token": "new"}, record_id="row-2", transfer_id="transfer-2")
    conflicting = agent.prepare_record(
        {"token": "changed"}, record_id="row-1", transfer_id="transfer-1"
    )
    outbox = SourceOutbox(tmp_path / "source-outbox.db")
    outbox.stage(original)

    with pytest.raises(ReplayDetected, match="different sealed bytes"):
        outbox.stage_many((new_record, conflicting))

    pending = outbox.pending()
    assert len(pending) == 1
    assert pending[0].record.digest() == original.digest()


@pytest.mark.parametrize(
    "trigger_sql",
    (
        """
        CREATE TRIGGER silently_ignore_second_outbox_insert
        BEFORE INSERT ON sealed_source_outbox
        WHEN NEW.record_id = 'row-2'
        BEGIN
            SELECT RAISE(IGNORE);
        END
        """,
        """
        CREATE TRIGGER mutate_first_outbox_insert
        AFTER INSERT ON sealed_source_outbox
        WHEN NEW.record_id = 'row-2'
        BEGIN
            UPDATE sealed_source_outbox
            SET plan_digest = 'trigger-mutated'
            WHERE record_id = 'row-1';
        END
        """,
    ),
    ids=("ignored-insert", "cross-record-mutation"),
)
def test_outbox_stage_many_verifies_exact_batch_postconditions(
    tmp_path: Path,
    trigger_sql: str,
) -> None:
    agent = _source_agent()
    records = tuple(
        agent.prepare_record(
            {"token": f"secret-{number}"},
            record_id=f"row-{number}",
            transfer_id="postcondition-batch",
        )
        for number in (1, 2)
    )
    outbox = SourceOutbox(tmp_path / "postcondition.db")
    with sqlite3.connect(outbox.path) as connection:
        connection.execute(trigger_sql)

    with pytest.raises(IntegrityError, match="write postcondition"):
        outbox.stage_many(records)

    assert outbox.depth() == 0


def test_outbox_batch_wire_limit_accepts_exact_boundary_and_rejects_one_over(
    tmp_path: Path,
) -> None:
    agent = _source_agent()
    records = tuple(
        agent.prepare_record(
            {"token": f"secret-{number}"},
            record_id=f"row-{number}",
            transfer_id="wire-boundary",
        )
        for number in range(2)
    )
    wire_bytes = tuple(len(record.canonical_wire_bytes()) for record in records)
    batch_wire_bytes = sum(wire_bytes)
    limits = ProtocolLimits(max_record_wire_bytes=max(wire_bytes))
    exact = SourceOutbox(
        tmp_path / "exact-boundary.db",
        limits=limits,
        max_batch_wire_bytes=batch_wire_bytes,
    )

    assert len(exact.stage_many(records)) == 2
    assert exact.depth() == 2

    one_over = SourceOutbox(
        tmp_path / "one-over-boundary.db",
        limits=limits,
        max_batch_wire_bytes=batch_wire_bytes - 1,
    )
    with pytest.raises(ValueError, match="wire byte limit"):
        one_over.stage_many(records)
    assert one_over.depth() == 0


def test_outbox_batch_wire_limit_stops_the_input_before_a_suffix(tmp_path: Path) -> None:
    record = _source_agent().prepare_record(
        {"token": "same-size"},
        record_id="row-1",
        transfer_id="streaming-wire-limit",
    )
    wire_size = len(record.canonical_wire_bytes())
    outbox = SourceOutbox(
        tmp_path / "streaming-wire-limit.db",
        limits=ProtocolLimits(max_record_wire_bytes=wire_size),
        max_batch_wire_bytes=wire_size,
    )
    consumed = 0

    def records():
        nonlocal consumed
        for index in range(3):
            if index == 2:
                raise AssertionError("outbox consumed after the aggregate wire limit failed")
            consumed += 1
            yield record

    with pytest.raises(ValueError, match="wire byte limit"):
        outbox.stage_many(records())

    assert consumed == 2
    assert outbox.depth() == 0


def test_outbox_batch_wire_limit_must_admit_one_protocol_sized_record(
    tmp_path: Path,
) -> None:
    limits = ProtocolLimits(max_record_wire_bytes=2_048)

    with pytest.raises(ValueError, match="admit one protocol-sized record"):
        SourceOutbox(
            tmp_path / "undersized-batch.db",
            limits=limits,
            max_batch_wire_bytes=2_047,
        )


def test_outbox_pending_honors_wire_budget_without_removing_remaining_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = _source_agent()
    records = tuple(
        agent.prepare_record(
            {"token": f"secret-{number}"},
            record_id=f"row-{number}",
            transfer_id="pending-wire-budget",
        )
        for number in range(3)
    )
    outbox = SourceOutbox(tmp_path / "pending-wire-budget.db")
    outbox.stage_many(records)
    ordered = outbox.pending(limit=3)
    first_two_wire_bytes = sum(len(item.wire_bytes) for item in ordered[:2])
    original_decode = outbox_module.BlindTransportRecord.from_wire
    decoded_records = 0

    def counting_decode(payload, **kwargs):
        nonlocal decoded_records
        decoded_records += 1
        return original_decode(payload, **kwargs)

    monkeypatch.setattr(
        outbox_module.BlindTransportRecord,
        "from_wire",
        staticmethod(counting_decode),
    )

    bounded = outbox.pending(limit=3, max_wire_bytes=first_two_wire_bytes)

    assert decoded_records == 2
    assert tuple(item.record.digest() for item in bounded) == tuple(
        item.record.digest() for item in ordered[:2]
    )
    assert outbox.depth() == 3
    assert len(outbox.pending(limit=3)) == 3


def test_outbox_pending_query_uses_order_index(tmp_path: Path) -> None:
    outbox = SourceOutbox(tmp_path / "pending-order-index.db")

    with sqlite3.connect(outbox.path) as connection:
        query_plan = connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT record_digest, staged_at, LENGTH(wire_json) AS wire_bytes
            FROM sealed_source_outbox
            ORDER BY staged_at ASC, record_digest ASC
            LIMIT ?
            """,
            (100,),
        ).fetchall()

    details = " ".join(str(row[3]) for row in query_plan)
    assert "source_outbox_pending_order" in details
    assert "USE TEMP B-TREE" not in details


def test_outbox_pending_reads_only_the_ordered_prefix_of_a_large_backlog(
    tmp_path: Path,
) -> None:
    record = _source_agent().prepare_record(
        {"token": "real-prefix"},
        record_id="row-prefix",
        transfer_id="large-backlog",
    )
    outbox = SourceOutbox(tmp_path / "large-backlog.db")
    outbox.stage(record)
    with sqlite3.connect(outbox.path) as connection:
        connection.executemany(
            """
            INSERT INTO sealed_source_outbox (
                record_digest, tenant, source_connector, destination_connector,
                transfer_id, record_id, plan_digest, staged_at, wire_json
            ) VALUES (?, 'tenant-a', 'src', 'dst', ?, ?, 'synthetic-plan', ?, zeroblob(1))
            """,
            (
                (
                    f"{number + 1:064x}",
                    f"synthetic-transfer-{number}",
                    f"synthetic-record-{number}",
                    "9999-01-01T00:00:00+00:00",
                )
                for number in range(5_000)
            ),
        )

    pending = outbox.pending(limit=1, max_wire_bytes=len(record.canonical_wire_bytes()))

    assert [item.record.digest() for item in pending] == [record.digest()]
    assert outbox.depth() == 5_001


@pytest.mark.parametrize("wire_limit", [True, False, 0, -1, 64 * 1024 * 1024 + 1])
def test_outbox_pending_rejects_invalid_wire_limits(
    tmp_path: Path,
    wire_limit: object,
) -> None:
    outbox = SourceOutbox(tmp_path / "pending-invalid-wire-limit.db")

    with pytest.raises(ValueError, match="pending wire limit"):
        outbox.pending(max_wire_bytes=wire_limit)  # type: ignore[arg-type]


def test_outbox_stage_many_rejects_more_than_bounded_record_count(tmp_path: Path) -> None:
    record = _source_agent().prepare_record(
        {"token": "secret"},
        record_id="row-1",
        transfer_id="bounded-stage",
    )
    outbox = SourceOutbox(tmp_path / "bounded-stage.db")

    with pytest.raises(ValueError, match="record count limit"):
        outbox.stage_many(record for _ in range(MAX_OUTBOX_BATCH_ITEMS + 1))
    with pytest.raises(ValueError, match="acknowledgement batch"):
        outbox.ack_many("0" * 64 for _ in range(MAX_OUTBOX_BATCH_ITEMS + 1))

    assert outbox.depth() == 0


def test_outbox_ack_rejects_an_oversized_digest_without_reading_a_suffix(
    tmp_path: Path,
) -> None:
    outbox = SourceOutbox(tmp_path / "invalid-ack-digest.db")
    consumed = 0

    def digests():
        nonlocal consumed
        consumed += 1
        yield "a" * (1024 * 1024)
        raise AssertionError("outbox consumed beyond the invalid digest")

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        outbox.ack_many(digests())

    assert consumed == 1
    assert outbox.depth() == 0
