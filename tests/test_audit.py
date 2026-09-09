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
