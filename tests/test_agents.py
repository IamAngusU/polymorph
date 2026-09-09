from decimal import Decimal

from polymorph.agents import BlindDestinationAgent, BlindSourceAgent
from polymorph.crypto import RecipientKeyPair
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity


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
            FieldDescriptor("api_token", "API token", DataType.STRING, sensitivity=Sensitivity.SECRET),
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
    source_agent = BlindSourceAgent(
        tenant="tenant-1",
        source_connector_id="excel-1",
        destination_connector_id="db-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
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

    recovered = BlindDestinationAgent(keys.private_key).open_record(transport)
    assert recovered == {
        "customer_name": "Müller GmbH",
        "net_amount": Decimal("1234.56"),
        "api_token": "opaque-token-value",
    }


def test_blind_transport_wire_roundtrip_remains_opaque():
    from polymorph.agents import BlindTransportRecord

    source = SchemaDescriptor("source", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),))
    target = SchemaDescriptor("target", (FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),))
    plan = MappingPlan(
        "plan-wire",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("token", "token", "opaque_forward"),),
    )
    keys = RecipientKeyPair.generate()
    transport = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="source-1",
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
    ).prepare_record({"token": "top-secret-token"}, record_id="row-1", transfer_id="tx-1")

    wire = transport.to_wire()
    rendered = str(wire)
    assert "top-secret-token" not in rendered
    restored = BlindTransportRecord.from_wire(wire)
    assert restored.digest() == transport.digest()
    assert BlindDestinationAgent(keys.private_key).open_record(restored)["token"] == "top-secret-token"


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
    transport = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="source-1",
        destination_connector_id="destination-1",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
    ).prepare_record({"v": "hello"}, record_id="row-1", transfer_id="tx-1")

    from polymorph.errors import IntegrityError
    import pytest

    with pytest.raises(IntegrityError):
        BlindDestinationAgent(
            keys.private_key,
            expected_tenant="tenant",
            expected_connector_id="destination-1",
            allowed_plan_digests=frozenset({"not-this-plan"}),
        ).open_record(transport)
