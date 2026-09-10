from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .connectors.inference import value_satisfies_type
from .errors import PolymorphError
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .models.types import Sensitivity
from .transforms import TransformStage, apply_transform, transform_stage
from .validation import PlanValidationReport, PlanValidator, ValidationSeverity


class PreflightSeverity(StrEnum):
    INFO = "info"
    REVIEW = "review"
    BLOCKING = "blocking"


@dataclass(frozen=True, slots=True)
class PreflightFinding:
    severity: PreflightSeverity
    code: str
    message: str
    record_index: int | None = None
    source_field_id: str | None = None
    target_field_id: str | None = None


class ForeignKeyResolver(Protocol):
    def resolve_foreign_key(
        self,
        *,
        target_field_id: str,
        match_column: str,
        value: object,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class PreflightReport:
    plan_digest: str
    records_checked: int
    complete_scan: bool
    plan_validation: PlanValidationReport
    findings: tuple[PreflightFinding, ...]
    destination_lookups_checked: int = 0

    @property
    def valid(self) -> bool:
        if not self.plan_validation.valid:
            return False
        return not any(item.severity is PreflightSeverity.BLOCKING for item in self.findings)

    @property
    def requires_review(self) -> bool:
        return self.plan_validation.requires_review or any(
            item.severity is PreflightSeverity.REVIEW for item in self.findings
        )

    @property
    def promotable(self) -> bool:
        """Strict automatic-promotion gate.

        A sampled run can inform a human but cannot create a trusted recipe automatically.
        """

        return (
            self.valid
            and not self.requires_review
            and self.complete_scan
            and self.records_checked > 0
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "plan_digest": self.plan_digest,
            "records_checked": self.records_checked,
            "complete_scan": self.complete_scan,
            "destination_lookups_checked": self.destination_lookups_checked,
            "valid": self.valid,
            "requires_review": self.requires_review,
            "promotable": self.promotable,
            "plan_findings": [
                {
                    "severity": item.severity.value,
                    "code": item.code,
                    "message": item.message,
                    "source_field_id": item.source_field_id,
                    "target_field_id": item.target_field_id,
                }
                for item in self.plan_validation.findings
            ],
            "findings": [
                {
                    "severity": item.severity.value,
                    "code": item.code,
                    "message": item.message,
                    "record_index": item.record_index,
                    "source_field_id": item.source_field_id,
                    "target_field_id": item.target_field_id,
                }
                for item in self.findings
            ],
        }


class PreflightRunner:
    """Read-only contract sandbox for a mapping plan.

    It validates the plan and exercises transforms against source records without writing to the
    destination. Optional foreign-key resolution performs reads only. Findings contain field IDs
    and reason codes, never record values.
    """

    def __init__(self, validator: PlanValidator | None = None) -> None:
        self.validator = validator or PlanValidator()

    def run(
        self,
        records: Iterable[Mapping[str, object]],
        source_schema: SchemaDescriptor,
        target_schema: SchemaDescriptor,
        plan: MappingPlan,
        *,
        max_records: int | None = None,
        foreign_key_resolver: ForeignKeyResolver | None = None,
    ) -> PreflightReport:
        plan_report = self.validator.validate(plan, source_schema, target_schema)
        if not plan_report.valid:
            return PreflightReport(plan.digest(), 0, False, plan_report, ())

        source_fields = source_schema.by_id()
        target_fields = target_schema.by_id()
        findings: list[PreflightFinding] = []
        if source_schema.metadata.get("formula_cells_present") == "true":
            findings.append(
                PreflightFinding(
                    PreflightSeverity.REVIEW,
                    "spreadsheet_formula_cache",
                    (
                        "source worksheet contains formulas; values are workbook-provided cached "
                        "results and freshness cannot be proven by the parser"
                    ),
                )
            )
        checked = 0
        lookup_checks = 0
        complete = True

        try:
            iterator = iter(records)
            while True:
                if max_records is not None and checked >= max_records:
                    try:
                        next(iterator)
                    except StopIteration:
                        complete = True
                    else:
                        complete = False
                    break
                try:
                    record = next(iterator)
                except StopIteration:
                    break
                checked += 1
                index = checked
                unknown = set(record) - set(source_fields)
                if unknown:
                    findings.append(
                        PreflightFinding(
                            PreflightSeverity.BLOCKING,
                            "record_schema_mismatch",
                            "record contains fields absent from the inspected source schema",
                            record_index=index,
                        )
                    )

                for rule in plan.rules:
                    source = source_fields[rule.source_field_id]
                    target = target_fields[rule.target_field_id]
                    present = source.id in record
                    value = record.get(source.id)
                    if not present and not source.nullable:
                        findings.append(
                            PreflightFinding(
                                PreflightSeverity.BLOCKING,
                                "required_source_missing",
                                "required source field is absent in a record",
                                index,
                                source.id,
                                target.id,
                            )
                        )
                        continue
                    if value is None:
                        if not target.nullable:
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "required_target_null",
                                    "mapping would produce null for a non-nullable target",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                        continue

                    # Opaque/secret routes are deliberately not value-inspected during preflight.
                    if source.sensitivity in {Sensitivity.SECRET, Sensitivity.OPAQUE}:
                        continue

                    stage = transform_stage(rule.transform)
                    if stage is TransformStage.SOURCE:
                        try:
                            transformed = apply_transform(rule.transform, value, rule.parameters)
                        except (PolymorphError, ValueError, TypeError, OverflowError):
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "source_transform_failed",
                                    "source transform rejected a record",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                            continue
                        if transformed is None and not target.nullable:
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "required_target_null",
                                    "source transform produced null for a non-nullable target",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                        elif transformed is not None and not value_satisfies_type(
                            transformed, target.data_type
                        ):
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "transformed_type_mismatch",
                                    "transformed value does not satisfy target type contract",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                        continue

                    if rule.transform == "lookup_foreign_key":
                        if foreign_key_resolver is None:
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.REVIEW,
                                    "foreign_key_lookup_not_exercised",
                                    "foreign-key lookup requires a read-only destination probe",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                            continue
                        match_column = rule.parameters.get("match_column")
                        relation = target_schema.relation_for_source_field(target.id)
                        lookup_key = (
                            relation.lookup_key(match_column)
                            if relation is not None and isinstance(match_column, str)
                            else None
                        )
                        if lookup_key is None:
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "foreign_key_lookup_invalid",
                                    "foreign-key rule does not declare its unique match column",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                            continue
                        assert isinstance(match_column, str)
                        if not value_satisfies_type(value, lookup_key.data_type):
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "foreign_key_lookup_input_type_mismatch",
                                    "foreign-key input does not satisfy the lookup-column type",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                            continue
                        try:
                            resolved = foreign_key_resolver.resolve_foreign_key(
                                target_field_id=target.id,
                                match_column=match_column,
                                value=value,
                            )
                        except Exception:
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "foreign_key_lookup_failed",
                                    "read-only foreign-key resolution failed",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                            continue
                        lookup_checks += 1
                        if resolved is None:
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "foreign_key_resolved_null",
                                    "non-null foreign-key lookup input did not resolve",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
                        elif resolved is not None and not value_satisfies_type(
                            resolved, target.data_type
                        ):
                            findings.append(
                                PreflightFinding(
                                    PreflightSeverity.BLOCKING,
                                    "foreign_key_resolved_type_mismatch",
                                    "foreign-key resolution returned an invalid target type",
                                    index,
                                    source.id,
                                    target.id,
                                )
                            )
        except Exception:
            findings.append(
                PreflightFinding(
                    PreflightSeverity.BLOCKING,
                    "source_iteration_failed",
                    "source failed while the preflight scan was reading records",
                )
            )
            complete = False

        if checked == 0:
            findings.append(
                PreflightFinding(
                    PreflightSeverity.REVIEW,
                    "empty_source",
                    "preflight did not observe any records",
                )
            )
        if not complete:
            findings.append(
                PreflightFinding(
                    PreflightSeverity.INFO,
                    "sampled_scan",
                    "preflight used a bounded sample and cannot auto-promote a recipe",
                )
            )

        return PreflightReport(
            plan.digest(),
            checked,
            complete,
            plan_report,
            tuple(findings),
            lookup_checks,
        )


def preflight_severity_from_validation(severity: ValidationSeverity) -> PreflightSeverity:
    if severity is ValidationSeverity.BLOCKING:
        return PreflightSeverity.BLOCKING
    if severity is ValidationSeverity.REVIEW:
        return PreflightSeverity.REVIEW
    return PreflightSeverity.INFO
