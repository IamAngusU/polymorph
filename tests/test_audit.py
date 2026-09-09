import sqlite3

import pytest

from polymorph.audit import AuditEvent, AuditLog
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
