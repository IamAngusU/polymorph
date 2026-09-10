from dataclasses import replace
from decimal import Decimal

import pytest

from polymorph.agents import (
    DEFAULT_SOURCE_BATCH_WIRE_BYTES,
    BlindDestinationAgent,
    BlindSourceAgent,
    PayloadCodec,
)
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import ProtocolError
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey


def _single_field_source_agent() -> BlindSourceAgent:
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
    return BlindSourceAgent(
        tenant="tenant",
        source_connector_id="source",
        destination_connector_id="destination",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=RecipientKeyPair.generate().public_bytes(),
        signing_key=SigningKeyPair.generate(),
        allow_unauthenticated_recipient_key=True,
    )


@pytest.mark.parametrize(
    "value",
    (Decimal("NaN"), Decimal("Infinity"), float("nan"), float("inf")),
)
def test_payload_codec_rejects_non_finite_numbers(value: object) -> None:
    with pytest.raises(ValueError, match="non-finite"):
        PayloadCodec.encode(value)


@pytest.mark.parametrize(
    "payload",
    (
        b'{"kind":"decimal","value":"NaN"}',
        b'{"kind":"json","value":NaN}',
        b'{"kind":"json","value":{"amount":Infinity}}',
        b'{"kind":"json","kind":"json","value":1}',
    ),
)
def test_payload_codec_rejects_non_canonical_or_non_finite_wire_payloads(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError):
        PayloadCodec.decode(payload)


def test_blind_transport_hides_entire_record_from_orchestrator():
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor("customer", "Customer", DataType.STRING),
            FieldDescriptor("amount", "Net Amount", DataType.STRING),
            FieldDescriptor("token", "API Token", DataType.STRING, sensitivity=Sensitivity.SECRET),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("customer_name", "customer name", DataType.STRING),
            FieldDescriptor("net_amount", "net amount", DataType.DECIMAL),
            FieldDescriptor(
                "api_token", "API token", DataType.STRING, sensitivity=Sensitivity.SECRET
            ),
        ),
    )
    plan = MappingPlan(
        "plan",
        "source",
        "target",
        source.fingerprint(),
        target.fingerprint(),
        (
            MappingRule("customer", "customer_name"),
            MappingRule(
                "amount",
                "net_amount",
                "parse_decimal",
                {"decimal_separator": ",", "thousands_separator": "."},
            ),
            MappingRule("token", "api_token", "opaque_forward"),
        ),
    )
    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant-1", "excel-1")])
    source_agent = BlindSourceAgent(
        tenant="tenant-1",
        source_connector_id="excel-1",
        destination_connector_id="db-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    )

    transport = source_agent.prepare_record(
        {"customer": "Müller GmbH", "amount": "1.234,56", "token": "opaque-token-value"},
        record_id="row-7",
        transfer_id="transfer-7",
    )

    visible = repr(transport)
    assert "Müller" not in visible
    assert "1.234" not in visible
    assert "opaque-token-value" not in visible

    recovered = BlindDestinationAgent(
        keys.private_key,
        source_trust_store=trust,
    ).open_record(transport)
    assert recovered == {
        "customer_name": "Müller GmbH",
        "net_amount": Decimal("1234.56"),
        "api_token": "opaque-token-value",
    }


def test_blind_transport_wire_roundtrip_remains_opaque():
    from polymorph.agents import BlindTransportRecord

    source = SchemaDescriptor(
        "source", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),)
    )
    target = SchemaDescriptor(
        "target", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),)
    )
    plan = MappingPlan(
        "plan-wire",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("token", "token", "opaque_forward"),),
    )
    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant", "source-1")])
    transport = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="source-1",
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    ).prepare_record({"token": "top-secret-token"}, record_id="row-1", transfer_id="tx-1")

    wire = transport.to_wire()
    rendered = str(wire)
    assert "top-secret-token" not in rendered
    restored = BlindTransportRecord.from_wire(wire)
    assert restored.digest() == transport.digest()
    assert (
        BlindDestinationAgent(keys.private_key, source_trust_store=trust).open_record(restored)[
            "token"
        ]
        == "top-secret-token"
    )


def test_destination_agent_rejects_unapproved_plan():
    source = SchemaDescriptor("source", (FieldDescriptor("v", "Value"),))
    target = SchemaDescriptor("target", (FieldDescriptor("v", "Value"),))
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("v", "v"),),
    )
    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant", "source-1")])
    transport = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="source-1",
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    ).prepare_record({"v": "hello"}, record_id="row-1", transfer_id="tx-1")

    import pytest

    from polymorph.errors import IntegrityError

    with pytest.raises(IntegrityError):
        BlindDestinationAgent(
            keys.private_key,
            expected_tenant="tenant",
            expected_connector_id="destination-1",
            allowed_plan_digests=frozenset({"not-this-plan"}),
            source_trust_store=trust,
        ).open_record(transport)


def test_source_batch_count_limit_stops_bounded_iterables() -> None:
    agent = _single_field_source_agent()
    records_consumed = 0
    identities_consumed = 0

    def records():
        nonlocal records_consumed
        for index in range(10_002):
            if index > 10_000:
                raise AssertionError("source consumed beyond its count guard")
            records_consumed += 1
            yield {"value": index}

    def identities():
        nonlocal identities_consumed
        for index in range(10_002):
            if index > 10_000:
                raise AssertionError("identity stream consumed beyond its count guard")
            identities_consumed += 1
            yield f"r{index}"

    with pytest.raises(ValueError, match="record count limit"):
        agent.prepare_records(records(), record_ids=identities())

    assert records_consumed == 10_001
    assert identities_consumed == 10_001


def test_source_batch_wire_limit_accepts_exactly_one_and_rejects_one_over() -> None:
    agent = _single_field_source_agent()
    sample = agent.prepare_records(
        ({"value": "same-size"},),
        record_ids=("r1",),
        transfer_id="sample",
    )[0]
    exact_limit = len(sample.canonical_wire_bytes())

    accepted = agent.prepare_records(
        ({"value": "same-size"},),
        record_ids=("r2",),
        transfer_id="sample",
        max_wire_bytes=exact_limit,
    )
    assert len(accepted) == 1

    with pytest.raises(ValueError, match="wire byte limit"):
        agent.prepare_records(
            ({"value": "same-size"}, {"value": "same-size"}),
            record_ids=("r3", "r4"),
            transfer_id="sample",
            max_wire_bytes=exact_limit,
        )


def test_source_batch_wire_limit_stops_both_inputs_at_the_failing_record() -> None:
    agent = _single_field_source_agent()
    sample = agent.prepare_records(
        ({"value": "same-size"},),
        record_ids=("r1",),
        transfer_id="sample",
    )[0]
    records_consumed = 0
    identities_consumed = 0

    def records():
        nonlocal records_consumed
        for index in range(3):
            if index == 2:
                raise AssertionError("source consumed after the aggregate wire limit failed")
            records_consumed += 1
            yield {"value": "same-size"}

    def identities():
        nonlocal identities_consumed
        for index in range(3):
            if index == 2:
                raise AssertionError("source consumed ids after the aggregate wire limit failed")
            identities_consumed += 1
            yield f"r{index + 2}"

    with pytest.raises(ValueError, match="wire byte limit"):
        agent.prepare_records(
            records(),
            record_ids=identities(),
            transfer_id="sample",
            max_wire_bytes=len(sample.canonical_wire_bytes()),
        )

    assert records_consumed == 2
    assert identities_consumed == 2


@pytest.mark.parametrize(
    "max_wire_bytes",
    (True, 0, DEFAULT_SOURCE_BATCH_WIRE_BYTES + 1),
)
def test_source_batch_rejects_invalid_wire_limit_before_side_effects(
    monkeypatch: pytest.MonkeyPatch,
    max_wire_bytes: object,
) -> None:
    agent = _single_field_source_agent()
    record_iterator_calls = 0
    identity_iterator_calls = 0
    crypto_calls = 0

    class SideEffectRecords:
        def __iter__(self):
            nonlocal record_iterator_calls
            record_iterator_calls += 1
            raise AssertionError("records were iterated before validating the wire limit")

    class SideEffectIdentities:
        def __iter__(self):
            nonlocal identity_iterator_calls
            identity_iterator_calls += 1
            raise AssertionError("record ids were iterated before validating the wire limit")

    def fail_crypto(*_args: object, **_kwargs: object) -> None:
        nonlocal crypto_calls
        crypto_calls += 1
        raise AssertionError("crypto ran before validating the wire limit")

    monkeypatch.setattr("polymorph.agents.seal_for_recipient", fail_crypto)

    with pytest.raises(ValueError, match="outside supported range"):
        agent.prepare_records(
            SideEffectRecords(),
            record_ids=SideEffectIdentities(),
            max_wire_bytes=max_wire_bytes,  # type: ignore[arg-type]
        )

    assert record_iterator_calls == 0
    assert identity_iterator_calls == 0
    assert crypto_calls == 0


def test_source_batch_rejects_non_mapping_records_without_reading_a_suffix() -> None:
    agent = _single_field_source_agent()
    records_consumed = 0

    def records():
        nonlocal records_consumed
        records_consumed += 1
        yield object()
        raise AssertionError("source consumed beyond the invalid record")

    with pytest.raises(TypeError, match="must be mappings"):
        agent.prepare_records(records(), record_ids=("r1", "r2"))  # type: ignore[arg-type]

    assert records_consumed == 1


@pytest.mark.parametrize(
    ("record_id", "transfer_id"),
    (
        ("r" * 257, "transfer"),
        ("record", "t" * 257),
        ("record\nvalue", "transfer"),
        ("   ", "transfer"),
        ("", "transfer"),
    ),
)
def test_new_source_records_reject_unbounded_audit_metadata(
    record_id: str,
    transfer_id: str,
) -> None:
    agent = _single_field_source_agent()

    with pytest.raises(ProtocolError, match="bounded printable metadata"):
        agent.prepare_record(
            {"value": "test"},
            record_id=record_id,
            transfer_id=transfer_id,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("tenant", "t" * 129),
        ("source_connector_id", "source\nconnector"),
        ("source_connector_id", "   "),
        ("destination_connector_id", ""),
    ),
)
def test_new_source_agent_rejects_unbounded_route_metadata(
    field: str,
    value: str,
) -> None:
    agent = _single_field_source_agent()

    with pytest.raises(ProtocolError, match="bounded printable metadata"):
        replace(agent, **{field: value})
