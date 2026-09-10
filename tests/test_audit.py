import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime

import pytest

import polymorph.audit as audit_module
from polymorph.audit import MAX_AUDIT_BATCH_EVENTS, AuditEvent, AuditLog
from polymorph.errors import IntegrityError
from polymorph.signing import SigningKeyPair


def _event(record_id="r1"):
    return AuditEvent(
        event_type="delivery",
        actor="destination-agent",
        status="delivered",
        tenant="tenant",
        connector_id="db",
        transfer_id="tx",
        record_id=record_id,
        record_digest="a" * 64,
        plan_digest="b" * 64,
    )


def test_signed_audit_chain_verifies_and_contains_no_payload(tmp_path):
    signer = SigningKeyPair.generate()
    path = tmp_path / "audit.db"
    audit = AuditLog(path, signer=signer)
    audit.append(_event("r1"))
    audit.append(_event("r2"))

    assert audit.verify(trusted_public_key=signer.public_bytes()) == 2
    exported = audit.export_jsonl()
    assert "payload" not in exported
    assert "secret-value" not in exported


def test_audit_tamper_is_detected(tmp_path):
    signer = SigningKeyPair.generate()
    path = tmp_path / "audit.db"
    audit = AuditLog(path, signer=signer)
    audit.append(_event())

    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE audit_events SET event_json = replace(event_json, 'delivered', 'blocked') "
        "WHERE sequence = 1"
    )
    connection.commit()
    connection.close()

    with pytest.raises(IntegrityError):
        audit.verify(trusted_public_key=signer.public_bytes())


def test_audit_summary_explains_status_and_reason_counts(tmp_path):
    path = tmp_path / "audit.db"
    audit = AuditLog(path)
    audit.append(_event("r1"))
    audit.append(
        AuditEvent(
            event_type="replay",
            actor="destination-agent",
            status="quarantined",
            tenant="tenant",
            connector_id="db",
            transfer_id="tx",
            record_id="r2",
            record_digest="c" * 64,
            plan_digest="b" * 64,
            reason_code="write_not_committed",
        )
    )

    summary = audit.summary()

    assert summary.events == 2
    assert summary.event_types == {"delivery": 1, "replay": 1}
    assert summary.statuses == {"delivered": 1, "quarantined": 1}
    assert summary.reasons == {"write_not_committed": 1}
    assert summary.signature_fields_absent == 2
    assert not summary.signatures_verified


def test_audit_event_rejects_unbounded_or_malformed_metadata(tmp_path):
    audit = AuditLog(tmp_path / "audit.db")

    with pytest.raises(ValueError, match="bounded printable"):
        audit.append(
            AuditEvent(
                event_type="delivery",
                actor="line one\nsecret",
                status="delivered",
                tenant="tenant",
                connector_id="db",
                transfer_id="tx",
                record_id="r1",
                record_digest="a" * 64,
                plan_digest="b" * 64,
            )
        )


def test_signed_audit_batch_preserves_order_hash_chain_and_signatures(tmp_path):
    signer = SigningKeyPair.generate()
    audit = AuditLog(tmp_path / "audit.db", signer=signer)
    timestamp = datetime(2026, 9, 10, 12, 30, tzinfo=UTC)

    first = audit.append(replace(_event("r0"), timestamp=timestamp))
    records = audit.append_many(
        replace(_event(record_id), timestamp=timestamp) for record_id in ("r1", "r2", "r3")
    )

    assert [record.sequence for record in records] == [2, 3, 4]
    assert [record.event["record_id"] for record in records] == ["r1", "r2", "r3"]
    assert records[0].previous_hash == first.event_hash
    assert records[1].previous_hash == records[0].event_hash
    assert records[2].previous_hash == records[1].event_hash
    assert all(record.signature is not None for record in records)
    assert audit.verify(trusted_public_key=signer.public_bytes()) == 4


def test_audit_batch_validation_is_all_or_none(tmp_path):
    audit = AuditLog(tmp_path / "audit.db")
    invalid = replace(_event("bad"), actor="private\nvalue")

    with pytest.raises(ValueError, match="bounded printable"):
        audit.append_many((_event("r1"), invalid, _event("r3")))

    assert audit.verify() == 0


def test_audit_batch_database_failure_rolls_back_every_event(tmp_path):
    path = tmp_path / "audit.db"
    audit = AuditLog(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER reject_second_batch_event
            BEFORE INSERT ON audit_events
            WHEN instr(NEW.event_json, '\"record_id\":\"r2\"') > 0
            BEGIN
                SELECT RAISE(ABORT, 'simulated audit failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="simulated audit failure"):
        audit.append_many((_event("r1"), _event("r2"), _event("r3")))

    assert audit.verify() == 0


def test_audit_batch_silent_insert_noop_rolls_back_every_event(tmp_path):
    path = tmp_path / "audit.db"
    audit = AuditLog(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER ignore_second_batch_event
            BEFORE INSERT ON audit_events
            WHEN instr(NEW.event_json, '\"record_id\":\"r2\"') > 0
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="append postcondition failed"):
        audit.append_many((_event("r1"), _event("r2"), _event("r3")))

    assert audit.verify() == 0


@pytest.mark.parametrize(
    "trigger_body",
    [
        "UPDATE audit_events SET event_json = '{}' WHERE sequence = NEW.sequence;",
        "DELETE FROM audit_events WHERE sequence = NEW.sequence;",
    ],
    ids=("mutation", "deletion"),
)
def test_audit_batch_silent_after_insert_change_rolls_back_every_event(
    tmp_path,
    trigger_body,
):
    path = tmp_path / "audit.db"
    audit = AuditLog(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f"""
            CREATE TRIGGER change_second_batch_event
            AFTER INSERT ON audit_events
            WHEN instr(NEW.event_json, '\"record_id\":\"r2\"') > 0
            BEGIN
                {trigger_body}
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(IntegrityError, match="append postcondition failed"):
        audit.append_many((_event("r1"), _event("r2"), _event("r3")))

    assert audit.verify() == 0


def test_audit_batch_is_bounded_before_opening_the_store(tmp_path):
    path = tmp_path / "audit.db"
    audit = AuditLog(path)

    with pytest.raises(ValueError, match="event count limit"):
        audit.append_many(_event(str(index)) for index in range(MAX_AUDIT_BATCH_EVENTS + 1))

    assert audit.verify() == 0


def test_audit_batch_size_limit_stops_the_input_before_a_suffix(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timestamp = datetime(2026, 9, 10, 12, 30, tzinfo=UTC)
    event = replace(_event("same-size"), timestamp=timestamp)
    encoded_size = len(
        json.dumps(
            event.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    monkeypatch.setattr(audit_module, "MAX_AUDIT_BATCH_BYTES", encoded_size)
    audit = AuditLog(tmp_path / "bounded-audit.db")
    consumed = 0

    def events():
        nonlocal consumed
        for index in range(3):
            if index == 2:
                raise AssertionError("audit consumed after the aggregate size limit failed")
            consumed += 1
            yield event

    with pytest.raises(ValueError, match="batch exceeds the encoded size limit"):
        audit.append_many(events())

    assert consumed == 2
    assert audit.verify() == 0


def test_empty_audit_batch_is_a_noop(tmp_path):
    audit = AuditLog(tmp_path / "audit.db")

    assert audit.append_many(()) == ()
    assert audit.verify() == 0
