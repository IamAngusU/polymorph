from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.serialization import plan_from_dict, plan_to_dict


def test_plan_roundtrip_preserves_digest():
    source = SchemaDescriptor("s", (FieldDescriptor("a", "A"),))
    target = SchemaDescriptor("t", (FieldDescriptor("b", "B"),))
    plan = MappingPlan(
        "p",
        "s",
        "t",
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("a", "b", "trim", {"x": "y"}),),
    )
    payload = plan_to_dict(plan)
    recovered = plan_from_dict(payload)
    assert recovered.digest() == plan.digest()


def test_plan_roundtrip_detects_tamper():
    source = SchemaDescriptor("s", (FieldDescriptor("a", "A"),))
    target = SchemaDescriptor("t", (FieldDescriptor("b", "B"),))
    plan = MappingPlan(
        "p",
        "s",
        "t",
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("a", "b"),),
    )
    payload = plan_to_dict(plan)
    payload["rules"][0]["target_field_id"] = "elsewhere"

    try:
        plan_from_dict(payload)
    except ValueError as exc:
        assert "digest mismatch" in str(exc)
    else:
        raise AssertionError("tampered plan was accepted")
