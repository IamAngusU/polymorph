from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Never, cast

from .filesystem import atomic_write_text
from .models.mapping import MappingPlan, MappingRule
from .models.schema import FieldDescriptor, RelationDescriptor, SchemaDescriptor
from .models.types import DataType, FieldRole, Sensitivity

MAX_DESCRIPTOR_BYTES = 16 * 1024 * 1024


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"serialized descriptor contains duplicate key {key!r}")
        output[key] = value
    return output


def _reject_nonfinite_constant(value: str) -> Never:
    raise ValueError(f"serialized descriptor contains non-finite number {value}")


def _object_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    output: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{label} contains a non-string key")
        output[key] = item
    return output


def _object_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return list(value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string or null")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _text_tuple(value: object, label: str) -> tuple[str, ...]:
    return tuple(_text(item, label) for item in _object_list(value, label))


def schema_to_dict(schema: SchemaDescriptor) -> dict[str, object]:
    return {
        "id": schema.id,
        "fields": [
            {
                **asdict(field),
                "data_type": field.data_type.value,
                "sensitivity": field.sensitivity.value,
                "role": field.role.value,
                "aliases": list(field.aliases),
            }
            for field in schema.fields
        ],
        "relations": [asdict(relation) for relation in schema.relations],
        "metadata": schema.metadata,
    }


def schema_from_dict(payload: Mapping[str, object]) -> SchemaDescriptor:
    raw_fields = _object_list(payload.get("fields", []), "schema fields")
    fields = tuple(
        FieldDescriptor(
            id=_text(field.get("id"), "field id"),
            name=_text(field.get("name"), "field name"),
            data_type=DataType(_text(field.get("data_type", "unknown"), "field data type")),
            nullable=_boolean(field.get("nullable", True), "field nullable"),
            destination_generated=_boolean(
                field.get("destination_generated", False),
                "field destination_generated",
            ),
            sensitivity=Sensitivity(
                _text(field.get("sensitivity", "internal"), "field sensitivity")
            ),
            role=FieldRole(_text(field.get("role", "value"), "field role")),
            description=_optional_text(field.get("description"), "field description"),
            aliases=_text_tuple(field.get("aliases", []), "field aliases"),
            container=_optional_text(field.get("container"), "field container"),
        )
        for item in raw_fields
        for field in (_object_mapping(item, "schema field"),)
    )
    raw_relations = _object_list(payload.get("relations", []), "schema relations")
    relations = tuple(
        RelationDescriptor(
            source_field_id=_text(relation.get("source_field_id"), "relation source field id"),
            target_container=_text(relation.get("target_container"), "relation target container"),
            target_field=_text(relation.get("target_field"), "relation target field"),
            name=_optional_text(relation.get("name"), "relation name"),
            target_schema=_optional_text(relation.get("target_schema"), "relation target schema"),
            lookup_keys=_text_tuple(relation.get("lookup_keys", []), "relation lookup keys"),
        )
        for item in raw_relations
        for relation in (_object_mapping(item, "schema relation"),)
    )
    metadata = _object_mapping(payload.get("metadata", {}), "schema metadata")
    return SchemaDescriptor(
        id=_text(payload.get("id"), "schema id"),
        fields=fields,
        relations=relations,
        metadata={key: _text(value, "schema metadata value") for key, value in metadata.items()},
    )


def save_schema(path: str | Path, schema: SchemaDescriptor) -> None:
    atomic_write_text(path, json.dumps(schema_to_dict(schema), indent=2) + "\n")


def _load_serialized_object(
    path: str | Path,
    label: str,
    *,
    max_bytes: int = MAX_DESCRIPTOR_BYTES,
) -> dict[str, object]:
    source = Path(path)
    if max_bytes < 1:
        raise ValueError("serialized descriptor size limit must be positive")
    if source.stat().st_size > max_bytes:
        raise ValueError(f"{label} exceeds configured size limit")
    try:
        text = source.read_bytes().decode("utf-8-sig")
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    return _object_mapping(cast(object, parsed), label)


def load_schema(
    path: str | Path,
    *,
    max_bytes: int = MAX_DESCRIPTOR_BYTES,
) -> SchemaDescriptor:
    return schema_from_dict(_load_serialized_object(path, "schema", max_bytes=max_bytes))


def plan_to_dict(plan: MappingPlan) -> dict[str, object]:
    return {
        **plan.canonical_dict(),
        "created_at": plan.created_at.isoformat(),
        "digest": plan.digest(),
    }


def plan_from_dict(payload: Mapping[str, object]) -> MappingPlan:
    raw_rules = _object_list(payload.get("rules", []), "mapping rules")
    plan = MappingPlan(
        id=_text(payload.get("id"), "plan id"),
        source_schema_id=_text(payload.get("source_schema_id"), "source schema id"),
        target_schema_id=_text(payload.get("target_schema_id"), "target schema id"),
        source_fingerprint=_text(payload.get("source_fingerprint"), "source fingerprint"),
        target_fingerprint=_text(payload.get("target_fingerprint"), "target fingerprint"),
        rules=tuple(
            MappingRule(
                source_field_id=_text(rule.get("source_field_id"), "rule source field id"),
                target_field_id=_text(rule.get("target_field_id"), "rule target field id"),
                transform=_text(rule.get("transform", "copy"), "rule transform"),
                parameters={
                    key: _text(value, "rule parameter value")
                    for key, value in _object_mapping(
                        rule.get("parameters", {}), "rule parameters"
                    ).items()
                },
            )
            for item in raw_rules
            for rule in (_object_mapping(item, "mapping rule"),)
        ),
        version=_integer(payload.get("version", 1), "plan version"),
        created_at=datetime.fromisoformat(_text(payload.get("created_at"), "plan created_at")),
    )
    expected = payload.get("digest")
    if expected is not None and str(expected) != plan.digest():
        raise ValueError("mapping plan digest mismatch")
    return plan


def save_plan(path: str | Path, plan: MappingPlan) -> None:
    atomic_write_text(
        path,
        json.dumps(plan_to_dict(plan), indent=2, ensure_ascii=False) + "\n",
    )


def load_plan(
    path: str | Path,
    *,
    max_bytes: int = MAX_DESCRIPTOR_BYTES,
) -> MappingPlan:
    return plan_from_dict(_load_serialized_object(path, "mapping plan", max_bytes=max_bytes))
