from datetime import UTC, datetime, timedelta

import pytest

from polymorph.crypto import RecipientKeyPair, TransferContext, open_envelope, seal_for_recipient
from polymorph.errors import IntegrityError, TransferExpired


def context(record_id: str = "42", **kwargs) -> TransferContext:
    return TransferContext(
        tenant="acme",
        source_connector="excel-1",
        destination_connector="db-1",
        field_id="password",
        schema_version="1",
        record_id=record_id,
        transfer_id="transfer-1",
        plan_id="plan-1",
        plan_digest="a" * 64,
        **kwargs,
    )


def test_opaque_roundtrip_and_repr_redaction():
    recipient = RecipientKeyPair.generate()
    envelope = seal_for_recipient(b"correct horse battery staple", recipient.public_bytes(), context())

    assert "correct" not in repr(envelope)
    assert open_envelope(envelope, recipient.private_key, context()) == b"correct horse battery staple"


def test_route_metadata_is_authenticated():
    recipient = RecipientKeyPair.generate()
    envelope = seal_for_recipient(b"secret", recipient.public_bytes(), context())

    with pytest.raises(IntegrityError):
        open_envelope(envelope, recipient.private_key, context(record_id="43"))


def test_plan_digest_is_authenticated():
    recipient = RecipientKeyPair.generate()
    envelope = seal_for_recipient(b"secret", recipient.public_bytes(), context())
    tampered = TransferContext(
        tenant="acme",
        source_connector="excel-1",
        destination_connector="db-1",
        field_id="password",
        schema_version="1",
        record_id="42",
        transfer_id="transfer-1",
        plan_id="plan-1",
        plan_digest="b" * 64,
    )

    with pytest.raises(IntegrityError):
        open_envelope(envelope, recipient.private_key, tampered)


def test_expired_context_is_rejected_before_use():
    now = datetime.now(UTC)
    expired = context(issued_at=now - timedelta(minutes=2), expires_at=now - timedelta(minutes=1))
    recipient = RecipientKeyPair.generate()

    with pytest.raises(TransferExpired):
        seal_for_recipient(b"secret", recipient.public_bytes(), expired)
