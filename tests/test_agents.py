from decimal import Decimal

import pytest

from polymorph.agents import BlindDestinationAgent, BlindSourceAgent, PayloadCodec
from polymorph.crypto import RecipientKeyPair
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey


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
