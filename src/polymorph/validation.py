from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .errors import PolicyViolation
from .matching.deterministic import type_compatibility
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .models.types import FieldRole
from .policy import PolicyEngine
from .transforms import is_known_transform


class ValidationSeverity(StrEnum):
    INFO = "info"
    REVIEW = "review"
    BLOCKING = "blocking"


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    severity: ValidationSeverity
    code: str
    message: str
    source_field_id: str | None = None
    target_field_id: str | None = None


@dataclass(frozen=True, slots=True)
class PlanValidationReport:
    findings: tuple[ValidationFinding, ...]

    @property
    def valid(self) -> bool:
        return not any(item.severity is ValidationSeverity.BLOCKING for item in self.findings)

    @property
    def requires_review(self) -> bool:
        return any(item.severity is ValidationSeverity.REVIEW for item in self.findings)

    def raise_if_invalid(self) -> None:
        if self.valid:
            return
        codes = ", ".join(item.code for item in self.findings if item.severity is ValidationSeverity.BLOCKING)
        raise PolicyViolation(f"mapping plan validation failed: {codes}")


class PlanValidator:
    """Validate an immutable mapping plan before any payload is touched."""

    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self._policy = policy or PolicyEngine()

    def validate(
        self,
        plan: MappingPlan,
        source_schema: SchemaDescriptor,
        target_schema: SchemaDescriptor,
    ) -> PlanValidationReport:
        findings: list[ValidationFinding] = []

        if plan.source_schema_id != source_schema.id:
            findings.append(
                ValidationFinding(
                    ValidationSeverity.BLOCKING,
                    "source_schema_id_mismatch",
                    "plan source schema id does not match the supplied schema",
                )
            )
        if plan.target_schema_id != target_schema.id:
            findings.append(
                ValidationFinding(
                    ValidationSeverity.BLOCKING,
                    "target_schema_id_mismatch",
                    "plan target schema id does not match the supplied schema",
                )
            )
        if plan.source_fingerprint != source_schema.fingerprint():
            findings.append(
                ValidationFinding(
                    ValidationSeverity.BLOCKING,
                    "source_schema_drift",
                    "source schema fingerprint differs from the approved plan",
                )
            )
        if plan.target_fingerprint != target_schema.fingerprint():
            findings.append(
                ValidationFinding(
                    ValidationSeverity.BLOCKING,
                    "target_schema_drift",
                    "target schema fingerprint differs from the approved plan",
                )
            )

        source_fields = source_schema.by_id()
        target_fields = target_schema.by_id()
        targeted: set[str] = set()

        for rule in plan.rules:
            source = source_fields.get(rule.source_field_id)
            target = target_fields.get(rule.target_field_id)
            if source is None:
                findings.append(
                    ValidationFinding(
                        ValidationSeverity.BLOCKING,
                        "unknown_source_field",
                        "mapping rule references a source field that does not exist",
                        source_field_id=rule.source_field_id,
                        target_field_id=rule.target_field_id,
                    )
                )
                continue
            if target is None:
                findings.append(
                    ValidationFinding(
                        ValidationSeverity.BLOCKING,
                        "unknown_target_field",
                        "mapping rule references a target field that does not exist",
                        source_field_id=rule.source_field_id,
                        target_field_id=rule.target_field_id,
                    )
                )
                continue

            if target.id in targeted:
                findings.append(
                    ValidationFinding(
                        ValidationSeverity.BLOCKING,
                        "duplicate_target",
                        "multiple rules write the same target field",
                        source.id,
                        target.id,
                    )
                )
                continue
            targeted.add(target.id)

            if not is_known_transform(rule.transform):
                findings.append(
                    ValidationFinding(
                        ValidationSeverity.BLOCKING,
                        "unknown_transform",
                        "mapping rule references an unregistered transform",
                        source.id,
                        target.id,
                    )
                )
                continue

            try:
                self._policy.validate_route(source, target, rule.transform)
            except PolicyViolation as exc:
                findings.append(
                    ValidationFinding(
                        ValidationSeverity.BLOCKING,
                        "policy_violation",
                        str(exc),
                        source.id,
                        target.id,
                    )
                )
                continue

            compatibility = type_compatibility(source.data_type, target.data_type)
            if rule.transform == "copy" and compatibility == 0.0:
                findings.append(
                    ValidationFinding(
                        ValidationSeverity.REVIEW,
                        "type_mismatch",
                        "copy transform crosses incompatible declared data types",
                        source.id,
                        target.id,
                    )
                )

        for field in target_schema.fields:
            if field.id in targeted or field.nullable or field.role is FieldRole.PRIMARY_KEY:
                continue
            findings.append(
                ValidationFinding(
                    ValidationSeverity.REVIEW,
                    "required_target_unmapped",
                    "non-nullable target field is not supplied by this plan",
                    target_field_id=field.id,
                )
            )

        return PlanValidationReport(tuple(findings))
