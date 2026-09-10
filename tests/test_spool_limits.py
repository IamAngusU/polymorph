import sqlite3
from pathlib import Path

import pytest

from polymorph.agents import BlindSourceAgent, BlindTransportRecord, ProtocolLimits
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import IntegrityError
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.signing import SigningKeyPair
from polymorph.spool import MAX_SPOOL_BATCH_ITEMS, SealedSpool


def _records(count: int = 2) -> tuple[BlindTransportRecord, ...]:
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
    recipient = RecipientKeyPair.generate()
    agent = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="source",
        destination_connector_id="destination",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        signing_key=SigningKeyPair.generate(),
        allow_unauthenticated_recipient_key=True,
    )
    return tuple(
        agent.prepare_record(
            {"token": f"secret-{index}"},
            record_id=f"r{index}",
            transfer_id="batch",
        )
        for index in range(1, count + 1)
    )


@pytest.mark.parametrize("limit", [True, False, 0, -1, 10_001, 1.5, "1"])
def test_spool_rejects_unbounded_list_limits(tmp_path: Path, limit: object) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")

    with pytest.raises(ValueError, match="outside supported range"):
        spool.list_entries(limit=limit)  # type: ignore[arg-type]


def test_spool_accepts_minimum_bounded_list_limit(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")

    assert spool.list_entries(limit=1) == ()


def test_spool_quarantine_batch_is_atomic_and_ordered(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")
    records = _records(3)

    entries = spool.quarantine_many(records, reason_code="batch_failure")

    assert tuple(entry.record_id for entry in entries) == ("r1", "r2", "r3")
    assert tuple(entry.record_digest for entry in entries) == tuple(
        record.digest() for record in records
    )
    assert len(spool.list_entries()) == 3
    assert all(spool.get(record.digest()) == record for record in records)


def test_spool_quarantine_batch_validates_every_record_before_writing(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")
    first, second = _records()

    with pytest.raises(TypeError, match="BlindTransportRecord"):
        spool.quarantine_many(
            (first, object(), second),  # type: ignore[arg-type]
            reason_code="batch_failure",
        )

    assert spool.list_entries() == ()


def test_spool_quarantine_batch_database_failure_rolls_back_every_record(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    records = _records(3)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER reject_second_spool_record
            BEFORE INSERT ON sealed_quarantine
            WHEN NEW.record_id = 'r2'
            BEGIN
                SELECT RAISE(ABORT, 'simulated spool failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="simulated spool failure"):
        spool.quarantine_many(records, reason_code="batch_failure")

    assert spool.list_entries() == ()


def test_spool_quarantine_batch_silent_noop_rolls_back_every_record(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    records = _records(3)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER ignore_second_spool_record
            BEFORE INSERT ON sealed_quarantine
            WHEN NEW.record_id = 'r2'
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="persistence postcondition failed"):
        spool.quarantine_many(records, reason_code="batch_failure")

    assert spool.list_entries() == ()


def test_spool_quarantine_batch_trigger_mutation_rolls_back_every_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    records = _records(3)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER mutate_second_spool_record
            AFTER INSERT ON sealed_quarantine
            WHEN NEW.record_id = 'r2'
            BEGIN
                UPDATE sealed_quarantine
                SET reason_code = 'mutated'
                WHERE record_digest = NEW.record_digest;
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="persistence postcondition failed"):
        spool.quarantine_many(records, reason_code="batch_failure")

    assert spool.list_entries() == ()


def test_spool_remove_batch_is_atomic_on_database_failure(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    records = _records()
    spool.quarantine_many(records, reason_code="batch_failure")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER reject_second_spool_delete
            BEFORE DELETE ON sealed_quarantine
            WHEN OLD.record_id = 'r2'
            BEGIN
                SELECT RAISE(ABORT, 'simulated spool delete failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="simulated spool delete failure"):
        spool.remove_many(record.digest() for record in records)

    assert len(spool.list_entries()) == 2


def test_spool_remove_batch_silent_noop_rolls_back_every_delete(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    records = _records(3)
    spool.quarantine_many(records, reason_code="batch_failure")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER ignore_second_spool_delete
            BEFORE DELETE ON sealed_quarantine
            WHEN OLD.record_id = 'r2'
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="removal postcondition failed"):
        spool.remove_many(record.digest() for record in records)

    assert len(spool.list_entries()) == 3
    assert all(spool.get(record.digest()) == record for record in records)


def test_spool_remove_batch_allows_already_absent_digests(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")
    record = _records(1)[0]
    spool.quarantine(record, "batch_failure")

    assert spool.remove_many((record.digest(), "f" * 64)) == 1
    assert spool.get(record.digest()) is None


def test_spool_remove_batch_validates_all_digests_before_writing(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")
    record = _records(1)[0]
    spool.quarantine(record, "batch_failure")

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        spool.remove_many((record.digest(), "not-a-digest"))

    assert spool.get(record.digest()) == record


def test_spool_batch_counts_are_bounded_before_writing(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")
    record = _records(1)[0]

    with pytest.raises(ValueError, match="record count limit"):
        spool.quarantine_many(
            (record for _ in range(MAX_SPOOL_BATCH_ITEMS + 1)),
            reason_code="batch_failure",
        )
    with pytest.raises(ValueError, match="record count limit"):
        spool.remove_many(record.digest() for _ in range(MAX_SPOOL_BATCH_ITEMS + 1))

    assert spool.list_entries() == ()


def test_spool_empty_batches_are_noops(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")

    assert spool.quarantine_many((), reason_code="batch_failure") == ()
    assert spool.remove_many(()) == 0


def test_spool_batch_wire_limit_accepts_exact_boundary_and_rejects_one_over(
    tmp_path: Path,
) -> None:
    records = _records(2)
    wire_bytes = tuple(len(record.canonical_wire_bytes()) for record in records)
    batch_wire_bytes = sum(wire_bytes)
    limits = ProtocolLimits(max_record_wire_bytes=max(wire_bytes))
    exact = SealedSpool(
        tmp_path / "exact-boundary.sqlite3",
        limits=limits,
        max_batch_wire_bytes=batch_wire_bytes,
    )

    assert len(exact.quarantine_many(records, reason_code="batch_failure")) == 2
    assert len(exact.list_entries()) == 2

    one_over = SealedSpool(
        tmp_path / "one-over-boundary.sqlite3",
        limits=limits,
        max_batch_wire_bytes=batch_wire_bytes - 1,
    )
    with pytest.raises(ValueError, match="wire byte limit"):
        one_over.quarantine_many(records, reason_code="batch_failure")
    assert one_over.list_entries() == ()


def test_spool_batch_wire_limit_stops_the_input_before_a_suffix(tmp_path: Path) -> None:
    record = _records(1)[0]
    wire_size = len(record.canonical_wire_bytes())
    spool = SealedSpool(
        tmp_path / "streaming-wire-limit.sqlite3",
        limits=ProtocolLimits(max_record_wire_bytes=wire_size),
        max_batch_wire_bytes=wire_size,
    )
    consumed = 0

    def records():
        nonlocal consumed
        for index in range(3):
            if index == 2:
                raise AssertionError("spool consumed after the aggregate wire limit failed")
            consumed += 1
            yield record

    with pytest.raises(ValueError, match="wire byte limit"):
        spool.quarantine_many(records(), reason_code="batch_failure")

    assert consumed == 2
    assert spool.list_entries() == ()


def test_spool_remove_rejects_an_oversized_digest_without_reading_a_suffix(
    tmp_path: Path,
) -> None:
    spool = SealedSpool(tmp_path / "invalid-remove-digest.sqlite3")
    consumed = 0

    def digests():
        nonlocal consumed
        consumed += 1
        yield "a" * (1024 * 1024)
        raise AssertionError("spool consumed beyond the invalid digest")

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        spool.remove_many(digests())

    assert consumed == 1
    assert spool.list_entries() == ()


def test_spool_batch_wire_limit_must_admit_one_protocol_sized_record(
    tmp_path: Path,
) -> None:
    limits = ProtocolLimits(max_record_wire_bytes=2_048)

    with pytest.raises(ValueError, match="admit one protocol-sized record"):
        SealedSpool(
            tmp_path / "undersized-batch.sqlite3",
            limits=limits,
            max_batch_wire_bytes=2_047,
        )


@pytest.mark.parametrize("digest", [None, 1, b"a" * 64])
def test_spool_get_rejects_non_string_digests(tmp_path: Path, digest: object) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")

    with pytest.raises(TypeError, match="must be a string"):
        spool.get(digest)  # type: ignore[arg-type]


@pytest.mark.parametrize("digest", ["", "A" * 64, "g" * 64, "a" * 63, "a" * 65])
def test_spool_get_rejects_invalid_sha256_digests(tmp_path: Path, digest: str) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        spool.get(digest)


def test_spool_get_rejects_oversized_persisted_blob_before_decoding(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    record = _records(1)[0]
    wire_size = len(record.canonical_wire_bytes())
    limits = ProtocolLimits(max_record_wire_bytes=wire_size)
    spool = SealedSpool(path, limits=limits, max_batch_wire_bytes=wire_size)
    spool.quarantine(record, "batch_failure")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE sealed_quarantine SET wire_json = zeroblob(?) WHERE record_digest = ?",
            (wire_size + 1, record.digest()),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="invalid wire size"):
        spool.get(record.digest())


def test_spool_get_rejects_non_blob_storage(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    record = _records(1)[0]
    spool.quarantine(record, "batch_failure")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE sealed_quarantine SET wire_json = ? WHERE record_digest = ?",
            (record.canonical_wire_bytes().decode("utf-8"), record.digest()),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="not stored as a blob"):
        spool.get(record.digest())


@pytest.mark.parametrize(
    "wire",
    [
        b'{"duplicate":1,"duplicate":2}',
        b'{"value":NaN}',
        b"not-json",
        b"\xff",
    ],
)
def test_spool_get_rejects_ambiguous_or_invalid_json(tmp_path: Path, wire: bytes) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    record = _records(1)[0]
    spool.quarantine(record, "batch_failure")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE sealed_quarantine SET wire_json = ? WHERE record_digest = ?",
            (wire, record.digest()),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="not valid canonical wire data"):
        spool.get(record.digest())


def test_spool_get_rejects_noncanonical_wire_bytes(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    record = _records(1)[0]
    spool.quarantine(record, "batch_failure")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE sealed_quarantine SET wire_json = ? WHERE record_digest = ?",
            (record.canonical_wire_bytes() + b" ", record.digest()),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="not canonical"):
        spool.get(record.digest())


def test_spool_get_rejects_wire_stored_under_the_wrong_digest(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    spool = SealedSpool(path)
    first, second = _records(2)
    spool.quarantine(first, "batch_failure")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE sealed_quarantine SET wire_json = ? WHERE record_digest = ?",
            (second.canonical_wire_bytes(), first.digest()),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="digest mismatch"):
        spool.get(first.digest())
