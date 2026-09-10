from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .errors import PolicyViolation
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .models.types import DataType, FieldRole, automatic_copy_type_safe, runtime_type_satisfies
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
        codes = ", ".join(
            item.code for item in self.findings if item.severity is ValidationSeverity.BLOCKING
        )
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

            if source.nullable and not target.nullable:
                findings.append(
                    ValidationFinding(
                        ValidationSeverity.REVIEW,
                        "nullable_source_to_required_target",
                        "source schema permits null but the destination field is required",
                        source.id,
                        target.id,
                    )
                )

            if rule.transform in {"copy", "opaque_forward"}:
                if source.data_type is DataType.UNKNOWN:
                    findings.append(
                        ValidationFinding(
                            ValidationSeverity.REVIEW,
                            "source_type_unknown",
                            "non-coercing transform lacks a declared source type",
                            source.id,
                            target.id,
                        )
                    )
                elif not runtime_type_satisfies(source.data_type, target.data_type):
                    findings.append(
                        ValidationFinding(
                            ValidationSeverity.BLOCKING,
                            "type_mismatch",
                            (
                                "non-coercing transform cannot satisfy the destination runtime "
                                "type contract"
                            ),
                            source.id,
                            target.id,
                        )
                    )
            elif rule.transform == "lookup_foreign_key":
                relation = target_schema.relation_for_source_field(target.id)
                match_column = rule.parameters.get("match_column")
                lookup_key = (
                    relation.lookup_key(match_column)
                    if relation is not None and isinstance(match_column, str)
                    else None
                )
                lookup_contract_valid = (
                    set(rule.parameters) == {"match_column"}
                    and relation is not None
                    and lookup_key is not None
                    and source.role is FieldRole.NATURAL_KEY
                    and target.role is FieldRole.FOREIGN_KEY
                )
                if not lookup_contract_valid:
                    findings.append(
                        ValidationFinding(
                            ValidationSeverity.BLOCKING,
                            "foreign_key_lookup_contract_invalid",
                            (
                                "foreign-key lookup lacks an exact single-column relation and "
                                "declared unique lookup key"
                            ),
                            source.id,
                            target.id,
                        )
                    )
                elif lookup_key is not None and DataType.UNKNOWN in {
                    source.data_type,
                    lookup_key.data_type,
                }:
                    findings.append(
                        ValidationFinding(
                            ValidationSeverity.REVIEW,
                            "foreign_key_lookup_type_unknown",
                            (
                                "foreign-key lookup requires review because its type contract "
                                "is incomplete"
                            ),
                            source.id,
                            target.id,
                        )
                    )
                elif lookup_key is not None and not automatic_copy_type_safe(
                    source.data_type, lookup_key.data_type
                ):
                    findings.append(
                        ValidationFinding(
                            ValidationSeverity.BLOCKING,
                            "foreign_key_lookup_type_mismatch",
                            (
                                "source type cannot satisfy the selected foreign-key lookup "
                                "column contract"
                            ),
                            source.id,
                            target.id,
                        )
                    )

        for field in target_schema.fields:
            if field.id in targeted or field.nullable or field.destination_generated:
                continue
            findings.append(
                ValidationFinding(
                    ValidationSeverity.BLOCKING,
                    "required_target_unmapped",
                    "non-nullable target field is not supplied by this plan",
                    target_field_id=field.id,
                )
            )

        return PlanValidationReport(tuple(findings))
