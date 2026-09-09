from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .types import DataType, FieldRole, Sensitivity


def _required_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if "\x00" in value:
        raise ValueError(f"{label} must not contain NUL")
    return value


@dataclass(frozen=True, slots=True)
class FieldDescriptor:
    id: str
    name: str
    data_type: DataType = DataType.UNKNOWN
    nullable: bool = True
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    role: FieldRole = FieldRole.VALUE
    description: str | None = None
    aliases: tuple[str, ...] = ()
    container: str | None = None
    destination_generated: bool = False

    def __post_init__(self) -> None:
        _required_text(self.id, "field id")
        _required_text(self.name, "field name")
        object.__setattr__(self, "aliases", tuple(self.aliases))
        if len(set(self.aliases)) != len(self.aliases):
            raise ValueError(f"field {self.id!r} contains duplicate aliases")
        for alias in self.aliases:
            _required_text(alias, "field alias")
        if self.description is not None and "\x00" in self.description:
            raise ValueError("field description must not contain NUL")
        if self.container is not None:
            _required_text(self.container, "field container")

    def canonical_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "id": self.id,
            "name": self.name,
            "data_type": self.data_type.value,
            "nullable": self.nullable,
            "sensitivity": self.sensitivity.value,
            "role": self.role.value,
            "description": self.description,
            "aliases": list(self.aliases),
            "container": self.container,
        }
        # Keep legacy fingerprints stable for the overwhelmingly common false value.
        # A generated field is contract-relevant and therefore changes the fingerprint.
        if self.destination_generated:
            payload["destination_generated"] = True
        return payload

    def semantic_text(self) -> str:
        parts = [f"name: {self.name}"]
        if self.aliases:
            parts.append(f"aliases: {', '.join(self.aliases)}")
        if self.description:
            parts.append(f"description: {self.description}")
        parts.extend((f"type: {self.data_type.value}", f"role: {self.role.value}"))
        if self.container:
            parts.append(f"container: {self.container}")
        return "; ".join(parts)


@dataclass(frozen=True, slots=True)
class RelationDescriptor:
    source_field_id: str
    target_container: str
    target_field: str
    name: str | None = None
    target_schema: str | None = None
    lookup_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _required_text(self.source_field_id, "relation source field id")
        _required_text(self.target_container, "relation target container")
        _required_text(self.target_field, "relation target field")
        object.__setattr__(self, "lookup_keys", tuple(self.lookup_keys))
        if len(set(self.lookup_keys)) != len(self.lookup_keys):
            raise ValueError("relation contains duplicate lookup keys")
        for key in self.lookup_keys:
            _required_text(key, "relation lookup key")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "source_field_id": self.source_field_id,
            "target_container": self.target_container,
            "target_field": self.target_field,
            "name": self.name,
            "target_schema": self.target_schema,
            "lookup_keys": list(self.lookup_keys),
        }


@dataclass(frozen=True, slots=True)
class SchemaDescriptor:
    id: str
    fields: tuple[FieldDescriptor, ...]
    relations: tuple[RelationDescriptor, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _required_text(self.id, "schema id")
        object.__setattr__(self, "fields", tuple(self.fields))
        object.__setattr__(self, "relations", tuple(self.relations))
        object.__setattr__(self, "metadata", dict(self.metadata))
        ids = [item.id for item in self.fields]
        if len(set(ids)) != len(ids):
            raise ValueError("schema contains duplicate field ids")
        field_ids = set(ids)
        relation_fields: set[str] = set()
        for relation in self.relations:
            if relation.source_field_id not in field_ids:
                raise ValueError("relation references an unknown source field")
            if relation.source_field_id in relation_fields:
                raise ValueError("schema contains multiple relations for one source field")
            relation_fields.add(relation.source_field_id)

    def by_id(self) -> dict[str, FieldDescriptor]:
        return {item.id: item for item in self.fields}

    def relation_for_source_field(self, field_id: str) -> RelationDescriptor | None:
        return next(
            (item for item in self.relations if item.source_field_id == field_id),
            None,
        )

    def canonical_dict(self, *, structural: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "fields": [item.canonical_dict() for item in self.fields],
            "relations": [item.canonical_dict() for item in self.relations],
        }
        if not structural:
            payload["id"] = self.id
            payload["metadata"] = dict(sorted(self.metadata.items()))
        return payload

    def _digest(self, *, structural: bool) -> str:
        encoded = json.dumps(
            self.canonical_dict(structural=structural),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def fingerprint(self) -> str:
        return self._digest(structural=False)

    def structural_fingerprint(self) -> str:
        return self._digest(structural=True)
