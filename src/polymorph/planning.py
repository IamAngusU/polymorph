from __future__ import annotations

import uuid

from .errors import PolicyViolation
from .matching.deterministic import (
    automatic_mapping_contract_safe,
    foreign_key_lookup_key,
    reviewable_foreign_key_lookup_key,
)
from .models.mapping import MappingDecision, MappingPlan, MappingRule, MappingStatus
from .models.schema import FieldDescriptor, SchemaDescriptor
from .models.types import Sensitivity
from .policy import PolicyEngine


def _mapping_rule(
    source: FieldDescriptor,
    target: FieldDescriptor,
    target_schema: SchemaDescriptor,
    *,
    reviewed: bool = False,
) -> MappingRule:
    if source.sensitivity in {Sensitivity.OPAQUE, Sensitivity.SECRET}:
        return MappingRule(source.id, target.id, "opaque_forward")

    lookup_key = foreign_key_lookup_key(source, target, target_schema)
    if lookup_key is None and reviewed:
        lookup_key = reviewable_foreign_key_lookup_key(source, target, target_schema)
    if lookup_key is not None:
        return MappingRule(
            source.id,
            target.id,
            "lookup_foreign_key",
            {"match_column": lookup_key},
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
        if decision.status is MappingStatus.AUTO and not automatic_mapping_contract_safe(
            source, target, target_schema
        ):
            raise PolicyViolation("automatic mapping decision lacks an executable contract")
        rule = _mapping_rule(
            source,
            target,
            target_schema,
            reviewed=decision.status is MappingStatus.REVIEW,
        )
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
