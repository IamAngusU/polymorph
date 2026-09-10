from __future__ import annotations

from pathlib import Path

import pytest

from polymorph.agents import BlindSourceAgent
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import ProtocolError, ReplayDetected
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.outbox import SourceOutbox
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
