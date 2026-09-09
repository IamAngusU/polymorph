from pathlib import Path

import pytest

from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.serialization import (
    load_plan,
    load_schema,
    plan_from_dict,
    plan_to_dict,
    schema_from_dict,
)


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


@pytest.mark.parametrize("loader", [load_schema, load_plan])
def test_serialized_descriptors_reject_duplicate_json_keys(tmp_path: Path, loader) -> None:
    path = tmp_path / "descriptor.json"
    path.write_text('{"id":"first","id":"second","fields":[]}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate key"):
        loader(path)


def test_schema_parser_does_not_coerce_string_to_boolean() -> None:
    payload = {
        "id": "source",
        "fields": [{"id": "value", "name": "Value", "nullable": "false"}],
    }

    with pytest.raises(ValueError, match="must be a boolean"):
        schema_from_dict(payload)


def test_serialized_descriptor_size_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "schema.json"
    path.write_text('{"id":"source","fields":[]}', encoding="utf-8")

    with pytest.raises(ValueError, match="size limit"):
        load_schema(path, max_bytes=4)
