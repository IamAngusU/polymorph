from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from polymorph.agents import (
    BlindDestinationAgent,
    BlindSourceAgent,
    BlindTransportRecord,
    PayloadCodec,
    SealedField,
)
from polymorph.crypto import RecipientKeyPair, seal_for_recipient
from polymorph.errors import IntegrityError, PolicyViolation, ProtocolError
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.relay import RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey


def _plan() -> tuple[SchemaDescriptor, SchemaDescriptor, MappingPlan]:
    source = SchemaDescriptor("source", (FieldDescriptor("value", "Value"),))
    target = SchemaDescriptor("target", (FieldDescriptor("value", "Value"),))
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("value", "value"),),
    )
    return source, target, plan


def _record(
    recipient: RecipientKeyPair,
    signer: SigningKeyPair,
    *,
    source_connector: str = "source-1",
) -> BlindTransportRecord:
    source, target, plan = _plan()
    return BlindSourceAgent(
        tenant="tenant-1",
        source_connector_id=source_connector,
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        signing_key=signer,
    ).prepare_record({"value": "hello"}, record_id="row-1", transfer_id="transfer-1")


def _trust(signer: SigningKeyPair, *, source_connector: str = "source-1") -> SourceTrustStore:
    return SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant-1", source_connector)])


def test_attacker_with_recipient_public_key_cannot_forge_source(tmp_path) -> None:
    recipient = RecipientKeyPair.generate()
    trusted_signer = SigningKeyPair.generate()
    attacker = SigningKeyPair.generate()
    forged = _record(recipient, attacker)
    trust = _trust(trusted_signer)
    _, _, plan = _plan()

    destination = BlindDestinationAgent(
        recipient.private_key,
        expected_tenant="tenant-1",
        expected_connector_id="destination-1",
        allowed_plan_digests=frozenset({plan.digest()}),
        source_trust_store=trust,
    )
    with pytest.raises(IntegrityError, match="not trusted"):
        destination.open_record(forged)

    relay = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-1", "source-1", "destination-1"),),
            source_trust_store=trust,
        ),
    )
    with pytest.raises(IntegrityError, match="not trusted"):
        relay.enqueue(forged)


def test_v3_fails_closed_without_a_source_trust_store(tmp_path) -> None:
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    record = _record(recipient, signer)

    with pytest.raises(IntegrityError, match="no trusted source key"):
        BlindDestinationAgent(recipient.private_key).open_record(record)
    relay = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy((RouteBinding("tenant-1", "source-1", "destination-1"),)),
    )
    with pytest.raises(PolicyViolation, match="no trusted source key"):
        relay.enqueue(record)


def test_v3_wire_without_authentication_is_rejected() -> None:
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    wire = _record(recipient, signer).to_wire()
    del wire["authentication"]

    with pytest.raises(ProtocolError, match="no source authentication"):
        BlindTransportRecord.from_wire(wire)


def test_ciphertext_tamper_invalidates_source_signature() -> None:
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    record = _record(recipient, signer)
    wire = deepcopy(record.to_wire())
    ciphertext = wire["fields"][0]["envelope"]["ciphertext"]
    wire["fields"][0]["envelope"]["ciphertext"] = (
        "A" if ciphertext[0] != "A" else "B"
    ) + ciphertext[1:]
    tampered = BlindTransportRecord.from_wire(wire)

    with pytest.raises(IntegrityError, match="signature verification"):
        _trust(signer).verify_record(tampered)


def test_revoked_source_key_is_rejected_at_relay_and_destination(tmp_path) -> None:
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    record = _record(recipient, signer)
    trust = _trust(signer)
    assert record.authentication is not None
    trust.revoke(record.authentication.key_id)

    relay = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-1", "source-1", "destination-1"),),
            source_trust_store=trust,
        ),
    )
    with pytest.raises(IntegrityError, match="revoked"):
        relay.enqueue(record)
    with pytest.raises(IntegrityError, match="revoked"):
        BlindDestinationAgent(
            recipient.private_key,
            source_trust_store=trust,
        ).open_record(record)


def test_relay_rechecks_revocation_when_leasing_a_queued_record(tmp_path) -> None:
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    record = _record(recipient, signer)
    trust = _trust(signer)
    relay = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (RouteBinding("tenant-1", "source-1", "destination-1"),),
            source_trust_store=trust,
        ),
    )
    relay.enqueue(record)
    assert record.authentication is not None
    trust.revoke(record.authentication.key_id)

    assert relay.lease(destination_connector="destination-1", lease_owner="worker-1") == ()
    assert relay.depth() == 0
    assert relay.dead_letter_depth() == 1
    assert relay.list_dead_letters()[0].reason_code == "relay_source_authentication_failed"
    assert relay.dead_letter_depth(destination_connector="destination-1") == 1


def test_source_key_is_bound_to_the_declared_connector() -> None:
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    record = _record(recipient, signer, source_connector="source-2")

    with pytest.raises(IntegrityError, match="identity"):
        BlindDestinationAgent(
            recipient.private_key,
            source_trust_store=_trust(signer, source_connector="source-1"),
        ).open_record(record)


def test_rotation_accepts_both_keys_until_old_key_is_revoked() -> None:
    recipient = RecipientKeyPair.generate()
    old_signer = SigningKeyPair.generate()
    new_signer = SigningKeyPair.generate()
    old_record = _record(recipient, old_signer)
    trust = _trust(old_signer)
    assert old_record.authentication is not None
    changed_at = datetime.now(UTC)
    trust.rotate(
        old_record.authentication.key_id,
        TrustedSourceKey(new_signer.public_bytes(), "tenant-1", "source-1"),
        changed_at=changed_at,
    )
    new_record = _record(recipient, new_signer)

    trust.verify_record(old_record)
    trust.verify_record(new_record)
    old_field = old_record.fields[0]
    late_context = replace(old_field.context, issued_at=changed_at + timedelta(seconds=1))
    late_old_record = BlindTransportRecord(
        old_record.record_id,
        (
            SealedField(
                old_field.target_field_id,
                late_context,
                seal_for_recipient(
                    PayloadCodec.encode("hello"),
                    recipient.public_bytes(),
                    late_context,
                ),
            ),
        ),
    ).signed(old_signer)
    with pytest.raises(IntegrityError, match="issued after source key rotation"):
        trust.verify_record(late_old_record)
    trust.revoke(old_record.authentication.key_id)
    with pytest.raises(IntegrityError, match="revoked"):
        trust.verify_record(old_record)


def test_rotation_verification_window_expires() -> None:
    recipient = RecipientKeyPair.generate()
    old_signer = SigningKeyPair.generate()
    new_signer = SigningKeyPair.generate()
    old_record = _record(recipient, old_signer)
    trust = _trust(old_signer)
    assert old_record.authentication is not None
    changed_at = datetime.now(UTC)
    trust.rotate(
        old_record.authentication.key_id,
        TrustedSourceKey(new_signer.public_bytes(), "tenant-1", "source-1"),
        changed_at=changed_at,
        verification_grace=timedelta(minutes=5),
    )

    trust.verify_record(old_record, now=changed_at + timedelta(minutes=4))
    with pytest.raises(IntegrityError, match="expired"):
        trust.verify_record(old_record, now=changed_at + timedelta(minutes=6))


def test_unsigned_v2_requires_explicit_legacy_policy(tmp_path) -> None:
    recipient = RecipientKeyPair.generate()
    source, target, plan = _plan()
    legacy = BlindSourceAgent(
        tenant="tenant-1",
        source_connector_id="source-1",
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        protocol_version=2,
        allow_legacy_unsigned=True,
    ).prepare_record({"value": "legacy"}, record_id="row-1", transfer_id="transfer-1")

    with pytest.raises(ProtocolError, match="explicit legacy"):
        BlindTransportRecord.from_wire(legacy.to_wire())
    restored = BlindTransportRecord.from_wire(
        legacy.to_wire(),
        allow_legacy_unsigned=True,
    )
    with pytest.raises(IntegrityError, match="not allowed"):
        BlindDestinationAgent(recipient.private_key).open_record(restored)
    assert BlindDestinationAgent(
        recipient.private_key,
        allow_legacy_unsigned=True,
    ).open_record(restored) == {"value": "legacy"}

    secure_relay = SealedRelayQueue(
        tmp_path / "secure-relay.db",
        RelayPolicy((RouteBinding("tenant-1", "source-1", "destination-1"),)),
    )
    with pytest.raises(PolicyViolation, match="not allowed"):
        secure_relay.enqueue(restored)
    legacy_relay = SealedRelayQueue(
        tmp_path / "legacy-relay.db",
        RelayPolicy(
            (RouteBinding("tenant-1", "source-1", "destination-1"),),
            allow_legacy_unsigned=True,
        ),
    )
    legacy_relay.enqueue(restored)
