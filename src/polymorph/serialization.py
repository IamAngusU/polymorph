from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .filesystem import atomic_write_text
from .models.mapping import MappingPlan, MappingRule
from .models.schema import FieldDescriptor, RelationDescriptor, SchemaDescriptor
from .models.types import DataType, FieldRole, Sensitivity


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


def schema_from_dict(payload: dict[str, object]) -> SchemaDescriptor:
    raw_fields = payload.get("fields", [])
    fields = tuple(
        FieldDescriptor(
            id=item["id"],
            name=item["name"],
            data_type=DataType(item.get("data_type", "unknown")),
            nullable=bool(item.get("nullable", True)),
            sensitivity=Sensitivity(item.get("sensitivity", "internal")),
            role=FieldRole(item.get("role", "value")),
            description=item.get("description"),
            aliases=tuple(item.get("aliases", [])),
            container=item.get("container"),
        )
        for item in raw_fields
    )
    relations = tuple(
        RelationDescriptor(
            source_field_id=item["source_field_id"],
            target_container=item["target_container"],
            target_field=item["target_field"],
            name=item.get("name"),
            target_schema=item.get("target_schema"),
            lookup_keys=tuple(item.get("lookup_keys", [])),
        )
        for item in payload.get("relations", [])
    )
    return SchemaDescriptor(
        id=str(payload["id"]),
        fields=fields,
        relations=relations,
        metadata=dict(payload.get("metadata", {})),
    )


def save_schema(path: str | Path, schema: SchemaDescriptor) -> None:
    atomic_write_text(path, json.dumps(schema_to_dict(schema), indent=2) + "\n")


def load_schema(path: str | Path) -> SchemaDescriptor:
    return schema_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def plan_to_dict(plan: MappingPlan) -> dict[str, object]:
    return {
        **plan.canonical_dict(),
        "created_at": plan.created_at.isoformat(),
        "digest": plan.digest(),
    }


def plan_from_dict(payload: dict[str, object]) -> MappingPlan:
    plan = MappingPlan(
        id=str(payload["id"]),
        source_schema_id=str(payload["source_schema_id"]),
        target_schema_id=str(payload["target_schema_id"]),
        source_fingerprint=str(payload["source_fingerprint"]),
        target_fingerprint=str(payload["target_fingerprint"]),
        rules=tuple(
            MappingRule(
                source_field_id=str(item["source_field_id"]),
                target_field_id=str(item["target_field_id"]),
                transform=str(item.get("transform", "copy")),
                parameters={str(k): str(v) for k, v in dict(item.get("parameters", {})).items()},
            )
            for item in payload.get("rules", [])
        ),
        version=int(payload.get("version", 1)),
        created_at=datetime.fromisoformat(str(payload["created_at"])),
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


def load_plan(path: str | Path) -> MappingPlan:
    return plan_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
