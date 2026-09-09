from __future__ import annotations

import uuid

from .matching.deterministic import name_similarity
from .models.mapping import MappingDecision, MappingPlan, MappingRule, MappingStatus
from .models.schema import FieldDescriptor, SchemaDescriptor
from .models.types import FieldRole, Sensitivity
from .policy import PolicyEngine


def _mapping_rule(
    source: FieldDescriptor,
    target: FieldDescriptor,
    target_schema: SchemaDescriptor,
) -> MappingRule:
    if source.sensitivity in {Sensitivity.OPAQUE, Sensitivity.SECRET}:
        return MappingRule(source.id, target.id, "opaque_forward")

    if target.role is FieldRole.FOREIGN_KEY and source.role is FieldRole.NATURAL_KEY:
        relation = target_schema.relation_for_source_field(target.id)
        if relation is not None and relation.lookup_keys:
            scored: list[tuple[float, str]] = []
            for key in relation.lookup_keys:
                candidate = FieldDescriptor(id=key, name=key, role=FieldRole.NATURAL_KEY)
                score, _ = name_similarity(source, candidate)
                scored.append((score, key))
            scored.sort(reverse=True)
            if scored and scored[0][0] >= 0.42:
                return MappingRule(
                    source.id,
                    target.id,
                    "lookup_foreign_key",
                    {"match_column": scored[0][1]},
                )

    return MappingRule(source.id, target.id, "copy")


def build_plan(
    source_schema: SchemaDescriptor,
    target_schema: SchemaDescriptor,
    decisions: list[MappingDecision],
    *,
    allow_review: bool = False,
) -> MappingPlan:
    source_fields = source_schema.by_id()
    target_fields = target_schema.by_id()
    policy = PolicyEngine()
    rules: list[MappingRule] = []

    for decision in decisions:
        if decision.target_field_id is None:
            continue
        if decision.status is MappingStatus.BLOCKED:
            continue
        if decision.status is MappingStatus.REVIEW and not allow_review:
            continue
        source = source_fields[decision.source_field_id]
        target = target_fields[decision.target_field_id]
        rule = _mapping_rule(source, target, target_schema)
        policy.validate_route(source, target, rule.transform)
        rules.append(rule)

    return MappingPlan(
        id=str(uuid.uuid4()),
        source_schema_id=source_schema.id,
        target_schema_id=target_schema.id,
        source_fingerprint=source_schema.fingerprint(),
        target_fingerprint=target_schema.fingerprint(),
        rules=tuple(rules),
    )
