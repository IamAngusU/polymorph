from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from .matching.deterministic import name_similarity
from .matching.hybrid import HybridMatcher
from .models.mapping import MappingPlan, MappingRule, MappingStatus
from .models.schema import FieldDescriptor, SchemaDescriptor
from .validation import PlanValidator, ValidationSeverity


class RepairSeverity(StrEnum):
    SAFE = "safe"
    REVIEW = "review"
    BLOCKING = "blocking"


@dataclass(frozen=True, slots=True)
class RepairFinding:
    severity: RepairSeverity
    field_id: str
    message: str
    replacement_field_id: str | None = None
    side: str = "source"


@dataclass(frozen=True, slots=True)
class RepairProposal:
    findings: tuple[RepairFinding, ...]
    plan: MappingPlan | None

    @property
    def auto_applicable(self) -> bool:
        return self.plan is not None and all(
            item.severity is RepairSeverity.SAFE for item in self.findings
        )

    @property
    def blocked(self) -> bool:
        return any(item.severity is RepairSeverity.BLOCKING for item in self.findings)


def _descriptor_is_stable(old: FieldDescriptor, current: FieldDescriptor) -> bool:
    if old.sensitivity != current.sensitivity:
        return False
    if old.name == current.name:
        return True
    score, _ = name_similarity(old, current)
    return score >= 0.88


def _resolve_field(
    old: FieldDescriptor,
    new_schema: SchemaDescriptor,
    matcher: HybridMatcher,
    *,
    side: str,
) -> tuple[FieldDescriptor | None, RepairFinding | None]:
    same_id = new_schema.by_id().get(old.id)
    if same_id is not None and _descriptor_is_stable(old, same_id):
        if same_id.sensitivity != old.sensitivity:
            return None, RepairFinding(
                RepairSeverity.BLOCKING,
                old.id,
                "field sensitivity changed",
                same_id.id,
                side,
            )
        if same_id.data_type != old.data_type:
            return same_id, RepairFinding(
                RepairSeverity.REVIEW,
                old.id,
                "field type changed",
                same_id.id,
                side,
            )
        return same_id, None

    decision = matcher.decide(old, new_schema)
    if decision.status is not MappingStatus.AUTO or decision.target_field_id is None:
        return None, RepairFinding(
            RepairSeverity.BLOCKING,
            old.id,
            "mapped field cannot be resolved safely after schema drift",
            side=side,
        )
    replacement = new_schema.by_id()[decision.target_field_id]
    if replacement.sensitivity != old.sensitivity:
        return None, RepairFinding(
            RepairSeverity.BLOCKING,
            old.id,
            "replacement would change sensitivity",
            replacement.id,
            side,
        )
    severity = (
        RepairSeverity.REVIEW if replacement.data_type != old.data_type else RepairSeverity.SAFE
    )
    message = "field appears moved or renamed"
    if severity is RepairSeverity.REVIEW:
        message += " and its declared type changed"
    return replacement, RepairFinding(severity, old.id, message, replacement.id, side)


def propose_plan_repair(
    plan: MappingPlan,
    old_source: SchemaDescriptor,
    new_source: SchemaDescriptor,
    old_target: SchemaDescriptor,
    new_target: SchemaDescriptor,
    matcher: HybridMatcher,
) -> RepairProposal:
    if (
        new_source.fingerprint() == plan.source_fingerprint
        and new_target.fingerprint() == plan.target_fingerprint
    ):
        return RepairProposal((), plan)

    old_source_fields = old_source.by_id()
    old_target_fields = old_target.by_id()
    findings: list[RepairFinding] = []
    rules: list[MappingRule] = []

    for rule in plan.rules:
        old_source_field = old_source_fields.get(rule.source_field_id)
        old_target_field = old_target_fields.get(rule.target_field_id)
        if old_source_field is None or old_target_field is None:
            findings.append(
                RepairFinding(
                    RepairSeverity.BLOCKING,
                    rule.source_field_id,
                    "approved plan references a field absent from its baseline schema",
                )
            )
            continue

        new_source_field, source_finding = _resolve_field(
            old_source_field,
            new_source,
            matcher,
            side="source",
        )
        if source_finding is not None:
            findings.append(source_finding)
        new_target_field, target_finding = _resolve_field(
            old_target_field,
            new_target,
            matcher,
            side="target",
        )
        if target_finding is not None:
            findings.append(target_finding)
        if new_source_field is None or new_target_field is None:
            continue

        if rule.transform == "lookup_foreign_key":
            relation = new_target.relation_for_source_field(new_target_field.id)
            match_column = rule.parameters.get("match_column")
            if (
                relation is None
                or not isinstance(match_column, str)
                or relation.lookup_key(match_column) is None
            ):
                findings.append(
                    RepairFinding(
                        RepairSeverity.BLOCKING,
                        old_target_field.id,
                        "approved foreign-key lookup path no longer exists",
                        new_target_field.id,
                        "target",
                    )
                )
                continue

        rules.append(
            MappingRule(
                new_source_field.id,
                new_target_field.id,
                rule.transform,
                dict(rule.parameters),
            )
        )

    if any(item.severity is RepairSeverity.BLOCKING for item in findings):
        return RepairProposal(tuple(findings), None)

    repaired = MappingPlan(
        id=plan.id,
        source_schema_id=new_source.id,
        target_schema_id=new_target.id,
        source_fingerprint=new_source.fingerprint(),
        target_fingerprint=new_target.fingerprint(),
        rules=tuple(rules),
        version=plan.version + 1,
        created_at=datetime.now(UTC),
    )
    validation = PlanValidator().validate(repaired, new_source, new_target)
    for item in validation.findings:
        if item.severity is ValidationSeverity.INFO:
            continue
        severity = (
            RepairSeverity.BLOCKING
            if item.severity is ValidationSeverity.BLOCKING
            else RepairSeverity.REVIEW
        )
        findings.append(
            RepairFinding(
                severity,
                item.source_field_id or item.target_field_id or "plan",
                item.message,
                item.target_field_id,
                "plan",
            )
        )

    if any(item.severity is RepairSeverity.BLOCKING for item in findings):
        return RepairProposal(tuple(findings), None)
    return RepairProposal(tuple(findings), repaired)


def assess_plan_drift(
    plan: MappingPlan,
    old_source: SchemaDescriptor,
    new_source: SchemaDescriptor,
    target: SchemaDescriptor,
    matcher: HybridMatcher,
) -> list[RepairFinding]:
    """Backward-compatible source-only drift assessment."""

    return list(
        propose_plan_repair(
            plan,
            old_source,
            new_source,
            target,
            target,
            matcher,
        ).findings
    )
