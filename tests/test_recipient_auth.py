from __future__ import annotations

import json
import os
import stat
import threading
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import polymorph.recipient_auth as recipient_auth
from polymorph.agents import (
    BlindDestinationAgent,
    BlindSourceAgent,
    BlindTransportRecord,
    PayloadCodec,
    SealedField,
)
from polymorph.crypto import RecipientKeyPair, TransferContext, seal_for_recipient
from polymorph.errors import IntegrityError, PolicyViolation, ProtocolError
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.outbox import SourceOutbox
from polymorph.recipient_auth import (
    RecipientKeyCertificate,
    RecipientKeyTrustStore,
    recipient_key_id,
)
from polymorph.relay import RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey
from polymorph.spool import SealedSpool

NOW = datetime.now(UTC).replace(microsecond=0)


def _certificate(
    identity: SigningKeyPair,
    recipient: RecipientKeyPair,
    *,
    generation: int = 1,
    previous_key_id: str | None = None,
    tenant: str = "tenant-1",
    destination: str = "destination-1",
    issued_at: datetime = NOW,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> RecipientKeyCertificate:
    return RecipientKeyCertificate.issue(
        tenant=tenant,
        destination_connector=destination,
        public_key=recipient.public_bytes(),
        generation=generation,
        previous_key_id=previous_key_id,
        identity_signer=identity,
        issued_at=issued_at,
        not_before=not_before or NOW - timedelta(minutes=1),
        not_after=not_after or NOW + timedelta(days=30),
    )


def _store(
    identity: SigningKeyPair,
    *,
    state_path: str | Path | None = None,
) -> RecipientKeyTrustStore:
    return RecipientKeyTrustStore(
        identity_public_key=identity.public_bytes(),
        tenant="tenant-1",
        destination_connector="destination-1",
        state_path=state_path,
    )


def _route() -> tuple[SchemaDescriptor, SchemaDescriptor, MappingPlan]:
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


def _secure_agent(
    store: RecipientKeyTrustStore,
    source_signer: SigningKeyPair,
) -> tuple[BlindSourceAgent, MappingPlan, SourceTrustStore]:
    source, target, plan = _route()
    source_trust = SourceTrustStore(
        [TrustedSourceKey(source_signer.public_bytes(), "tenant-1", source.id)]
    )
    return (
        BlindSourceAgent(
            tenant="tenant-1",
            source_connector_id=source.id,
            destination_connector_id="destination-1",
            source_schema=source,
            target_schema=target,
            plan=plan,
            signing_key=source_signer,
            recipient_key_trust_store=store,
        ),
        plan,
        source_trust,
    )


def _legacy_blank_recipient_record(
    recipient: RecipientKeyPair,
    signer: SigningKeyPair,
) -> BlindTransportRecord:
    source, target, plan = _route()
    context = TransferContext(
        tenant="tenant-1",
        source_connector=source.id,
        destination_connector="destination-1",
        field_id=target.fields[0].id,
        schema_version="1",
        record_id="legacy-row",
        transfer_id="legacy-transfer",
        plan_id=plan.id,
        plan_digest=plan.digest(),
        protocol_version=3,
        issued_at=NOW,
    )
    field = SealedField(
        target.fields[0].id,
        context,
        seal_for_recipient(PayloadCodec.encode("legacy"), recipient.public_bytes(), context),
    )
    return BlindTransportRecord(
        "legacy-row",
        (field,),
        allow_legacy_blank_recipient_key_id=True,
    ).signed(signer)


def test_signed_recipient_certificate_roundtrip_and_secure_delivery() -> None:
    identity = SigningKeyPair.generate()
    recipient = RecipientKeyPair.generate()
    certificate = _certificate(identity, recipient)
    restored = RecipientKeyCertificate.from_wire(certificate.to_wire())
    assert restored == certificate
    assert restored.key_id == recipient_key_id(recipient.public_bytes())

    store = _store(identity)
    store.accept(restored, now=NOW)
    source_signer = SigningKeyPair.generate()
    agent, plan, source_trust = _secure_agent(store, source_signer)
    record = agent.prepare_record({"value": "hello"}, record_id="row-1", transfer_id="transfer-1")

    assert record.fields[0].context.recipient_key_id == certificate.key_id
    assert BlindDestinationAgent(
        recipient.private_key,
        expected_tenant="tenant-1",
        expected_connector_id="destination-1",
        allowed_plan_digests=frozenset({plan.digest()}),
        source_trust_store=source_trust,
    ).open_record(record) == {"value": "hello"}


def test_v3_rejects_raw_control_plane_recipient_key_by_default() -> None:
    source, target, plan = _route()
    attacker_key = RecipientKeyPair.generate()

    with pytest.raises(ValueError, match="authenticated recipient key trust store"):
        BlindSourceAgent(
            tenant="tenant-1",
            source_connector_id=source.id,
            destination_connector_id="destination-1",
            source_schema=source,
            target_schema=target,
            plan=plan,
            destination_public_key=attacker_key.public_bytes(),
            signing_key=SigningKeyPair.generate(),
        )


def test_raw_recipient_key_requires_explicit_migration_opt_in() -> None:
    source, target, plan = _route()
    recipient = RecipientKeyPair.generate()
    agent = BlindSourceAgent(
        tenant="tenant-1",
        source_connector_id=source.id,
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        signing_key=SigningKeyPair.generate(),
        allow_unauthenticated_recipient_key=True,
    )

    record = agent.prepare_record({"value": "hello"}, record_id="row-1")
    assert record.fields[0].context.recipient_key_id == recipient_key_id(recipient.public_bytes())


def test_v2_with_authenticated_recipient_store_keeps_recipient_key_id_blank() -> None:
    identity = SigningKeyPair.generate()
    recipient = RecipientKeyPair.generate()
    store = _store(identity)
    store.accept(_certificate(identity, recipient), now=NOW)
    source, target, plan = _route()
    agent = BlindSourceAgent(
        tenant="tenant-1",
        source_connector_id=source.id,
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        protocol_version=2,
        allow_legacy_unsigned=True,
        recipient_key_trust_store=store,
    )

    record = agent.prepare_record({"value": "hello"}, record_id="legacy-row")

    assert record.protocol_version == 2
    assert record.fields[0].context.recipient_key_id == ""
    assert (
        BlindTransportRecord.from_wire(
            record.to_wire(),
            allow_legacy_unsigned=True,
        )
        == record
    )


def test_v2_wire_rejects_nonstandard_recipient_key_id() -> None:
    identity = SigningKeyPair.generate()
    recipient = RecipientKeyPair.generate()
    store = _store(identity)
    store.accept(_certificate(identity, recipient), now=NOW)
    source, target, plan = _route()
    record = BlindSourceAgent(
        tenant="tenant-1",
        source_connector_id=source.id,
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        protocol_version=2,
        allow_legacy_unsigned=True,
        recipient_key_trust_store=store,
    ).prepare_record({"value": "hello"}, record_id="legacy-row")
    wire = deepcopy(record.to_wire())
    fields = wire["fields"]
    assert isinstance(fields, list)
    context = fields[0]["context"]
    assert isinstance(context, dict)
    context["recipient_key_id"] = recipient_key_id(recipient.public_bytes())

    with pytest.raises(ProtocolError, match="v2 .* may not carry"):
        BlindTransportRecord.from_wire(wire, allow_legacy_unsigned=True)


def test_substituted_key_signed_by_untrusted_identity_is_rejected() -> None:
    trusted_identity = SigningKeyPair.generate()
    attacker_identity = SigningKeyPair.generate()
    substituted = _certificate(attacker_identity, RecipientKeyPair.generate())

    with pytest.raises(IntegrityError, match="identity is not trusted"):
        _store(trusted_identity).accept(substituted, now=NOW)


def test_route_rebinding_and_signed_payload_tampering_are_rejected() -> None:
    identity = SigningKeyPair.generate()
    recipient = RecipientKeyPair.generate()
    certificate = _certificate(identity, recipient)
    other_route = _certificate(identity, recipient, tenant="tenant-2")
    with pytest.raises(IntegrityError, match="route binding"):
        _store(identity).accept(other_route, now=NOW)

    wire = deepcopy(certificate.to_wire())
    wire["destination_connector"] = "attacker-destination"
    tampered = RecipientKeyCertificate.from_wire(wire)
    attacker_store = RecipientKeyTrustStore(
        identity_public_key=identity.public_bytes(),
        tenant="tenant-1",
        destination_connector="attacker-destination",
    )
    with pytest.raises(IntegrityError, match="signature verification"):
        attacker_store.accept(tampered, now=NOW)


def test_rotation_advances_exactly_one_generation_and_blocks_rollback() -> None:
    identity = SigningKeyPair.generate()
    first_recipient = RecipientKeyPair.generate()
    second_recipient = RecipientKeyPair.generate()
    first = _certificate(identity, first_recipient)
    second = _certificate(
        identity,
        second_recipient,
        generation=2,
        previous_key_id=first.key_id,
        issued_at=NOW + timedelta(minutes=1),
    )
    store = _store(identity)
    store.accept(first, now=NOW)
    store.accept(second, now=NOW)
    assert store.current(now=NOW) == second

    with pytest.raises(IntegrityError, match="rollback or conflicting fork"):
        store.accept(first, now=NOW)


def test_rotation_blocks_fork_wrong_predecessor_and_generation_gap() -> None:
    identity = SigningKeyPair.generate()
    first = _certificate(identity, RecipientKeyPair.generate())
    store = _store(identity)
    store.accept(first, now=NOW)

    fork = _certificate(
        identity,
        RecipientKeyPair.generate(),
        generation=1,
        previous_key_id=None,
    )
    with pytest.raises(IntegrityError, match="rollback or conflicting fork"):
        store.accept(fork, now=NOW)

    wrong_previous = _certificate(
        identity,
        RecipientKeyPair.generate(),
        generation=2,
        previous_key_id="0" * 64,
    )
    with pytest.raises(IntegrityError, match="continue the trusted chain"):
        store.accept(wrong_previous, now=NOW)

    skipped = _certificate(
        identity,
        RecipientKeyPair.generate(),
        generation=3,
        previous_key_id=first.key_id,
    )
    with pytest.raises(IntegrityError, match="skipped a generation"):
        store.accept(skipped, now=NOW)


def test_expired_or_not_yet_active_certificate_fails_closed() -> None:
    identity = SigningKeyPair.generate()
    expired = _certificate(
        identity,
        RecipientKeyPair.generate(),
        issued_at=NOW - timedelta(days=3),
        not_before=NOW - timedelta(days=2),
        not_after=NOW - timedelta(days=1),
    )
    future = _certificate(
        identity,
        RecipientKeyPair.generate(),
        issued_at=NOW,
        not_before=NOW + timedelta(days=1),
        not_after=NOW + timedelta(days=2),
    )

    with pytest.raises(IntegrityError, match="expired"):
        _store(identity).accept(expired, now=NOW)
    with pytest.raises(IntegrityError, match="not active yet"):
        _store(identity).accept(future, now=NOW)


def test_persisted_head_survives_restart_and_rejects_old_certificate(tmp_path) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    first = _certificate(identity, RecipientKeyPair.generate())
    second = _certificate(
        identity,
        RecipientKeyPair.generate(),
        generation=2,
        previous_key_id=first.key_id,
        issued_at=NOW + timedelta(minutes=1),
    )
    store = _store(identity, state_path=state)
    store.accept(first, now=NOW)
    store.accept(second, now=NOW)

    restarted = _store(identity, state_path=state)
    assert restarted.current(now=NOW) == second
    with pytest.raises(IntegrityError, match="rollback or conflicting fork"):
        restarted.accept(first, now=NOW)


def test_failed_initial_state_write_restores_memory_and_allows_safe_retry(
    tmp_path,
    monkeypatch,
) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    certificate = _certificate(identity, RecipientKeyPair.generate())
    store = _store(identity, state_path=state)
    real_atomic_write = recipient_auth.atomic_write_text

    def fail_before_publish(*args, **kwargs) -> None:
        raise OSError("simulated pre-publish failure")

    monkeypatch.setattr(recipient_auth, "atomic_write_text", fail_before_publish)
    with pytest.raises(IntegrityError, match="update outcome is uncertain"):
        store.accept(certificate, now=NOW)
    assert not state.exists()

    monkeypatch.setattr(recipient_auth, "atomic_write_text", real_atomic_write)
    assert store.accept(certificate, now=NOW) == certificate
    assert store.current(now=NOW) == certificate


def test_directory_sync_failure_is_ambiguous_and_duplicate_accept_retries_it(
    tmp_path,
    monkeypatch,
) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    certificate = _certificate(identity, RecipientKeyPair.generate())
    store = _store(identity, state_path=state)
    real_sync = recipient_auth._sync_parent_directory
    calls = 0

    def fail_once(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated directory sync failure")
        real_sync(path)

    monkeypatch.setattr(recipient_auth, "_sync_parent_directory", fail_once)
    with pytest.raises(IntegrityError, match="durability is uncertain after replacement"):
        store.accept(certificate, now=NOW)

    assert state.exists()
    assert store.accept(certificate, now=NOW) == certificate
    assert calls == 2


@pytest.mark.skipif(os.name != "posix", reason="directory fsync is a POSIX durability primitive")
def test_persistent_accept_fsyncs_parent_directory_on_posix(tmp_path, monkeypatch) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    certificate = _certificate(identity, RecipientKeyPair.generate())
    fsync_modes: list[int] = []
    real_fsync = os.fsync

    def track_fsync(descriptor: int) -> None:
        fsync_modes.append(os.fstat(descriptor).st_mode)
        real_fsync(descriptor)

    monkeypatch.setattr(recipient_auth.os, "fsync", track_fsync)
    _store(identity, state_path=state).accept(certificate, now=NOW)

    assert any(stat.S_ISDIR(mode) for mode in fsync_modes)


def test_persisted_state_tampering_fails_closed(tmp_path) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    store = _store(identity, state_path=state)
    store.accept(_certificate(identity, RecipientKeyPair.generate()), now=NOW)
    payload = json.loads(state.read_text(encoding="utf-8"))
    payload["current_certificate"]["tenant"] = "attacker"
    state.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IntegrityError, match="route binding"):
        _store(identity, state_path=state)


def test_two_writers_cannot_accept_competing_rotation_forks(tmp_path) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    first = _certificate(identity, RecipientKeyPair.generate())
    _store(identity, state_path=state).accept(first, now=NOW)
    forks = (
        _certificate(
            identity,
            RecipientKeyPair.generate(),
            generation=2,
            previous_key_id=first.key_id,
            issued_at=NOW + timedelta(minutes=1),
        ),
        _certificate(
            identity,
            RecipientKeyPair.generate(),
            generation=2,
            previous_key_id=first.key_id,
            issued_at=NOW + timedelta(minutes=1),
        ),
    )
    barrier = threading.Barrier(2)
    results: list[str] = []

    def accept(certificate: RecipientKeyCertificate) -> None:
        candidate_store = _store(identity, state_path=state)
        barrier.wait()
        try:
            candidate_store.accept(certificate, now=NOW)
            results.append("accepted")
        except IntegrityError:
            results.append("rejected")

    threads = [threading.Thread(target=accept, args=(certificate,)) for certificate in forks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == ["accepted", "rejected"]
    assert _store(identity, state_path=state).current(now=NOW) in forks


def test_live_source_switches_only_after_valid_rotation() -> None:
    identity = SigningKeyPair.generate()
    first_recipient = RecipientKeyPair.generate()
    second_recipient = RecipientKeyPair.generate()
    first = _certificate(identity, first_recipient)
    store = _store(identity)
    store.accept(first, now=NOW)
    source_signer = SigningKeyPair.generate()
    agent, plan, source_trust = _secure_agent(store, source_signer)
    first_record = agent.prepare_record({"value": "first"}, record_id="row-1")

    second = _certificate(
        identity,
        second_recipient,
        generation=2,
        previous_key_id=first.key_id,
        issued_at=NOW + timedelta(minutes=1),
    )
    store.accept(second, now=NOW)
    second_record = agent.prepare_record({"value": "second"}, record_id="row-2")

    assert BlindDestinationAgent(
        first_recipient.private_key,
        allowed_plan_digests=frozenset({plan.digest()}),
        source_trust_store=source_trust,
    ).open_record(first_record) == {"value": "first"}
    assert BlindDestinationAgent(
        second_recipient.private_key,
        allowed_plan_digests=frozenset({plan.digest()}),
        source_trust_store=source_trust,
    ).open_record(second_record) == {"value": "second"}
    draining_destination = BlindDestinationAgent(
        second_recipient.private_key,
        additional_private_keys=(first_recipient.private_key,),
        source_trust_store=source_trust,
    )
    assert draining_destination.open_record(first_record) == {"value": "first"}
    assert draining_destination.open_record(second_record) == {"value": "second"}
    with pytest.raises(IntegrityError, match="unavailable recipient key"):
        BlindDestinationAgent(
            first_recipient.private_key,
            source_trust_store=source_trust,
        ).open_record(second_record)


def test_certificate_wire_is_strict_and_key_id_is_derived() -> None:
    identity = SigningKeyPair.generate()
    certificate = _certificate(identity, RecipientKeyPair.generate())
    unexpected = certificate.to_wire()
    unexpected["ignored"] = True
    with pytest.raises(ProtocolError, match="unexpected or missing"):
        RecipientKeyCertificate.from_wire(unexpected)

    wrong_id = certificate.to_wire()
    wrong_id["key_id"] = "0" * 64
    with pytest.raises(ProtocolError, match="does not match"):
        RecipientKeyCertificate.from_wire(wrong_id)

    with pytest.raises(ProtocolError, match="generation"):
        RecipientKeyCertificate.from_wire({**certificate.to_wire(), "generation": True})

    for field in ("tenant", "destination_connector", "identity_key_id", "algorithm", "key_id"):
        malformed = certificate.to_wire()
        malformed[field] = 7
        with pytest.raises(ProtocolError, match=f"{field} must be a string"):
            RecipientKeyCertificate.from_wire(malformed)

    with pytest.raises(ProtocolError, match="format is unsupported"):
        RecipientKeyCertificate.from_wire({**certificate.to_wire(), "version": True})


def test_certificate_json_rejects_duplicate_keys() -> None:
    with pytest.raises(ProtocolError, match="duplicate object key"):
        RecipientKeyCertificate.from_json(
            '{"format":"angusu.bridge/recipient-key-certificate","format":"duplicate"}'
        )


def test_certificate_load_errors_name_the_certificate(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError, match="recipient key certificate is unavailable"):
        RecipientKeyCertificate.load(tmp_path / "missing-certificate.json")


def test_certificate_timestamp_normalization_overflow_is_a_protocol_error() -> None:
    identity = SigningKeyPair.generate()
    malformed = _certificate(identity, RecipientKeyPair.generate()).to_wire()
    malformed["not_after"] = "9999-12-31T23:59:59-23:59"

    with pytest.raises(ProtocolError, match="expiry time is invalid"):
        RecipientKeyCertificate.from_wire(malformed)


def test_certificate_invalid_route_binding_is_a_protocol_error() -> None:
    malformed = _certificate(SigningKeyPair.generate(), RecipientKeyPair.generate()).to_wire()
    malformed["tenant"] = ""

    with pytest.raises(ProtocolError, match="field validation failed"):
        RecipientKeyCertificate.from_wire(malformed)


def test_changed_or_missing_persisted_state_fails_closed(tmp_path) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    store = _store(identity, state_path=state)
    store.accept(_certificate(identity, RecipientKeyPair.generate()), now=NOW)
    state.unlink()
    with pytest.raises(IntegrityError, match="not initialized"):
        store.current(now=NOW)

    state.write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(ProtocolError, match="size limit"):
        _store(identity, state_path=state)


def test_linked_state_parent_is_rejected(tmp_path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory links is not permitted on this host")

    with pytest.raises(IntegrityError, match="link or reparse point"):
        _store(SigningKeyPair.generate(), state_path=linked_parent / "state.json")


def test_certificate_signature_covers_validity_and_rotation_metadata() -> None:
    identity = SigningKeyPair.generate()
    first = _certificate(identity, RecipientKeyPair.generate())
    store = _store(identity)
    store.accept(first, now=NOW)
    altered = replace(first, not_after=first.not_after + timedelta(days=1))
    with pytest.raises(IntegrityError, match="signature verification"):
        _store(identity).accept(altered, now=NOW)


def test_recipient_key_a_b_a_reuse_is_rejected_after_restart(tmp_path) -> None:
    state = tmp_path / "recipient-trust.json"
    identity = SigningKeyPair.generate()
    recipient_a = RecipientKeyPair.generate()
    recipient_b = RecipientKeyPair.generate()
    first = _certificate(identity, recipient_a)
    second = _certificate(
        identity,
        recipient_b,
        generation=2,
        previous_key_id=first.key_id,
        issued_at=NOW + timedelta(minutes=1),
    )
    store = _store(identity, state_path=state)
    store.accept(first, now=NOW)
    store.accept(second, now=NOW)

    restarted = _store(identity, state_path=state)
    reused = _certificate(
        identity,
        recipient_a,
        generation=3,
        previous_key_id=second.key_id,
        issued_at=NOW + timedelta(minutes=2),
    )
    with pytest.raises(IntegrityError, match="reuses retired key material"):
        restarted.accept(reused, now=NOW)

    persisted = json.loads(state.read_text(encoding="utf-8"))
    assert sorted(persisted["used_key_ids"]) == sorted((first.key_id, second.key_id))


def test_recipient_key_history_is_bounded_and_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(recipient_auth, "_MAX_USED_KEY_IDS", 2)
    identity = SigningKeyPair.generate()
    first = _certificate(identity, RecipientKeyPair.generate())
    second = _certificate(
        identity,
        RecipientKeyPair.generate(),
        generation=2,
        previous_key_id=first.key_id,
        issued_at=NOW + timedelta(minutes=1),
    )
    third = _certificate(
        identity,
        RecipientKeyPair.generate(),
        generation=3,
        previous_key_id=second.key_id,
        issued_at=NOW + timedelta(minutes=2),
    )
    store = _store(identity)
    store.accept(first, now=NOW)
    store.accept(second, now=NOW)
    with pytest.raises(IntegrityError, match="history capacity is exhausted"):
        store.accept(third, now=NOW)


@pytest.mark.parametrize(
    "low_order_key",
    (
        b"\0" * 32,
        b"\x01" + b"\0" * 31,
        bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    ),
)
def test_low_order_x25519_keys_are_rejected_before_certificate_or_seal(
    low_order_key: bytes,
) -> None:
    with pytest.raises(ProtocolError, match="unusable or low-order"):
        recipient_key_id(low_order_key)
    with pytest.raises(ProtocolError, match="unusable or low-order"):
        RecipientKeyCertificate.issue(
            tenant="tenant-1",
            destination_connector="destination-1",
            public_key=low_order_key,
            generation=1,
            previous_key_id=None,
            identity_signer=SigningKeyPair.generate(),
            issued_at=NOW,
            not_before=NOW,
            not_after=NOW + timedelta(days=1),
        )
    context = TransferContext(
        tenant="tenant-1",
        source_connector="source",
        destination_connector="destination-1",
        field_id="value",
        schema_version="1",
        record_id="row",
        transfer_id="transfer",
    )
    with pytest.raises(ProtocolError, match="unusable or low-order"):
        seal_for_recipient(b"secret", low_order_key, context)


def test_recipient_key_id_collapses_the_rfc7748_high_bit_alias() -> None:
    identity = SigningKeyPair.generate()
    recipient = RecipientKeyPair.generate()
    raw = recipient.public_bytes()
    alias = raw[:-1] + bytes((raw[-1] | 0x80,))

    assert alias != raw
    assert recipient_key_id(alias) == recipient_key_id(raw)
    first = _certificate(identity, recipient)
    with pytest.raises(ProtocolError, match="rotation must change the public key"):
        RecipientKeyCertificate.issue(
            tenant="tenant-1",
            destination_connector="destination-1",
            public_key=alias,
            generation=2,
            previous_key_id=first.key_id,
            identity_signer=identity,
            issued_at=NOW + timedelta(minutes=1),
            not_before=NOW,
            not_after=NOW + timedelta(days=1),
        )


def test_recipient_key_id_collapses_the_rfc7748_noncanonical_field_alias() -> None:
    identity = SigningKeyPair.generate()
    field_prime = (1 << 255) - 19
    canonical = (9).to_bytes(32, "little")
    alias = (field_prime + 9).to_bytes(32, "little")

    assert alias != canonical
    assert recipient_key_id(alias) == recipient_key_id(canonical)
    first = RecipientKeyCertificate.issue(
        tenant="tenant-1",
        destination_connector="destination-1",
        public_key=canonical,
        generation=1,
        previous_key_id=None,
        identity_signer=identity,
        issued_at=NOW,
        not_before=NOW,
        not_after=NOW + timedelta(days=1),
    )
    with pytest.raises(ProtocolError, match="rotation must change the public key"):
        RecipientKeyCertificate.issue(
            tenant="tenant-1",
            destination_connector="destination-1",
            public_key=alias,
            generation=2,
            previous_key_id=first.key_id,
            identity_signer=identity,
            issued_at=NOW + timedelta(minutes=1),
            not_before=NOW,
            not_after=NOW + timedelta(days=1),
        )


def test_raw_source_key_validation_rejects_low_order_key_during_setup() -> None:
    source, target, plan = _route()
    with pytest.raises(ProtocolError, match="unusable or low-order"):
        BlindSourceAgent(
            tenant="tenant-1",
            source_connector_id=source.id,
            destination_connector_id="destination-1",
            source_schema=source,
            target_schema=target,
            plan=plan,
            destination_public_key=b"\0" * 32,
            signing_key=SigningKeyPair.generate(),
            allow_unauthenticated_recipient_key=True,
        )


def test_blank_v3_recipient_key_id_requires_explicit_migration_at_every_boundary(
    tmp_path,
) -> None:
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    record = _legacy_blank_recipient_record(recipient, signer)
    wire = record.to_wire()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant-1", "source")])
    route = RouteBinding("tenant-1", "source", "destination-1")

    with pytest.raises(ProtocolError, match="no authenticated recipient key id"):
        BlindTransportRecord.from_wire(wire)
    restored = BlindTransportRecord.from_wire(
        wire,
        allow_legacy_blank_recipient_key_id=True,
    )
    trust.verify_record(restored, now=NOW)

    with pytest.raises(PolicyViolation, match="no authenticated recipient key id"):
        RelayPolicy((route,), source_trust_store=trust).validate(restored, now=NOW)
    legacy_policy = RelayPolicy(
        (route,),
        source_trust_store=trust,
        allow_legacy_blank_recipient_key_id=True,
    )
    legacy_policy.validate(restored, now=NOW)

    with pytest.raises(IntegrityError, match="no authenticated recipient key id"):
        BlindDestinationAgent(
            recipient.private_key,
            source_trust_store=trust,
        ).open_record(restored)
    assert BlindDestinationAgent(
        recipient.private_key,
        source_trust_store=trust,
        allow_legacy_blank_recipient_key_id=True,
    ).open_record(restored) == {"value": "legacy"}

    with pytest.raises(ProtocolError, match="no authenticated recipient key id"):
        SourceOutbox(tmp_path / "default-outbox.sqlite").stage(restored)
    legacy_outbox = SourceOutbox(
        tmp_path / "legacy-outbox.sqlite",
        allow_legacy_blank_recipient_key_id=True,
    )
    legacy_outbox.stage(restored)
    assert legacy_outbox.pending()[0].record.allow_legacy_blank_recipient_key_id is True
    with pytest.raises(ProtocolError, match="no authenticated recipient key id"):
        SourceOutbox(tmp_path / "legacy-outbox.sqlite").pending()

    with pytest.raises(ProtocolError, match="no authenticated recipient key id"):
        SealedSpool(tmp_path / "default-spool.sqlite").quarantine(restored, "legacy")
    legacy_spool = SealedSpool(
        tmp_path / "legacy-spool.sqlite",
        allow_legacy_blank_recipient_key_id=True,
    )
    entry = legacy_spool.quarantine(restored, "legacy")
    restored_spool = legacy_spool.get(entry.record_digest)
    assert restored_spool is not None
    assert restored_spool.allow_legacy_blank_recipient_key_id is True
    with pytest.raises(ProtocolError, match="no authenticated recipient key id"):
        SealedSpool(tmp_path / "legacy-spool.sqlite").get(entry.record_digest)

    legacy_relay = SealedRelayQueue(tmp_path / "legacy-relay.sqlite", legacy_policy)
    legacy_relay.enqueue(restored)
    leased = legacy_relay.lease(destination_connector="destination-1", lease_owner="worker")
    assert len(leased) == 1
    assert leased[0].record.allow_legacy_blank_recipient_key_id is True

    persisted = SealedRelayQueue(tmp_path / "default-relay.sqlite", legacy_policy)
    persisted.enqueue(restored)
    strict_reopen = SealedRelayQueue(
        tmp_path / "default-relay.sqlite",
        RelayPolicy((route,), source_trust_store=trust),
    )
    assert strict_reopen.lease(destination_connector="destination-1", lease_owner="worker") == ()
    assert strict_reopen.dead_letter_depth() == 1
