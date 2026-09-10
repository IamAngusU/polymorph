from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import (
    FieldDescriptor,
    LookupKeyDescriptor,
    RelationDescriptor,
    SchemaDescriptor,
)
from polymorph.models.types import DataType, FieldRole, Sensitivity
from polymorph.validation import PlanValidator, ValidationSeverity


def _plan(source, target, rules):
    return MappingPlan(
        "plan-1",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        tuple(rules),
    )


def test_validator_rejects_duplicate_target_and_secret_downgrade():
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor("token", "API Token", sensitivity=Sensitivity.SECRET),
            FieldDescriptor("name", "Name"),
        ),
    )
    target = SchemaDescriptor("target", (FieldDescriptor("value", "Value"),))
    plan = _plan(
        source,
        target,
        (
            MappingRule("token", "value", "copy"),
            MappingRule("name", "value", "copy"),
        ),
    )

    report = PlanValidator().validate(plan, source, target)
    codes = {item.code for item in report.findings}
    assert not report.valid
    assert "policy_violation" in codes
    assert "duplicate_target" in codes


def test_validator_blocks_copy_that_runtime_cannot_accept():
    source = SchemaDescriptor("source", (FieldDescriptor("v", "Value", DataType.BOOLEAN),))
    target = SchemaDescriptor("target", (FieldDescriptor("v2", "Value", DataType.DATE),))
    plan = _plan(source, target, (MappingRule("v", "v2"),))

    report = PlanValidator().validate(plan, source, target)
    assert not report.valid
    assert any(item.severity is ValidationSeverity.BLOCKING for item in report.findings)


def test_validator_blocks_runtime_unsafe_opaque_forward() -> None:
    source = SchemaDescriptor(
        "source",
        (FieldDescriptor("v", "Value", DataType.DECIMAL, sensitivity=Sensitivity.SECRET),),
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("v2", "Value", DataType.INTEGER, sensitivity=Sensitivity.SECRET),),
    )
    plan = _plan(source, target, (MappingRule("v", "v2", "opaque_forward"),))

    report = PlanValidator().validate(plan, source, target)

    assert not report.valid
    assert {item.code for item in report.findings} == {"type_mismatch"}


def test_validator_keeps_unknown_source_type_reviewable_for_runtime_check() -> None:
    source = SchemaDescriptor("source", (FieldDescriptor("v", "Value", DataType.UNKNOWN),))
    target = SchemaDescriptor("target", (FieldDescriptor("v2", "Value", DataType.INTEGER),))
    plan = _plan(source, target, (MappingRule("v", "v2", "copy"),))

    report = PlanValidator().validate(plan, source, target)

    assert report.valid
    assert report.requires_review
    assert {item.code for item in report.findings} == {"source_type_unknown"}


def test_validator_marks_nullable_source_to_required_target_for_review() -> None:
    source = SchemaDescriptor(
        "source", (FieldDescriptor("v", "Value", DataType.STRING, nullable=True),)
    )
    target = SchemaDescriptor(
        "target", (FieldDescriptor("v2", "Value", DataType.STRING, nullable=False),)
    )
    plan = _plan(source, target, (MappingRule("v", "v2", "copy"),))

    report = PlanValidator().validate(plan, source, target)

    assert report.valid
    assert report.requires_review
    assert {item.code for item in report.findings} == {"nullable_source_to_required_target"}


def test_validator_applies_nullability_review_to_foreign_key_lookup() -> None:
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "number",
                "customer number",
                DataType.STRING,
                nullable=True,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                nullable=False,
                role=FieldRole.FOREIGN_KEY,
            ),
        ),
        (
            RelationDescriptor(
                "customer_id",
                "customers",
                "id",
                lookup_keys=(LookupKeyDescriptor("customer_number", DataType.STRING),),
            ),
        ),
    )
    plan = _plan(
        source,
        target,
        (
            MappingRule(
                "number",
                "customer_id",
                "lookup_foreign_key",
                {"match_column": "customer_number"},
            ),
        ),
    )

    report = PlanValidator().validate(plan, source, target)

    assert report.valid
    assert report.requires_review
    assert {item.code for item in report.findings} == {"nullable_source_to_required_target"}


def test_validator_blocks_unproven_foreign_key_lookup_contract() -> None:
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "number",
                "customer number",
                DataType.STRING,
                nullable=False,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                nullable=False,
                role=FieldRole.FOREIGN_KEY,
            ),
        ),
    )
    plan = _plan(
        source,
        target,
        (
            MappingRule(
                "number",
                "customer_id",
                "lookup_foreign_key",
                {"match_column": "customer_number"},
            ),
        ),
    )

    report = PlanValidator().validate(plan, source, target)

    assert not report.valid
    assert {item.code for item in report.findings} == {"foreign_key_lookup_contract_invalid"}


def test_validator_requires_review_for_unknown_foreign_key_lookup_type() -> None:
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "number",
                "customer number",
                DataType.UNKNOWN,
                nullable=False,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                nullable=False,
                role=FieldRole.FOREIGN_KEY,
            ),
        ),
        (
            RelationDescriptor(
                "customer_id",
                "customers",
                "id",
                lookup_keys=(LookupKeyDescriptor("customer_number", DataType.STRING),),
            ),
        ),
    )
    plan = _plan(
        source,
        target,
        (
            MappingRule(
                "number",
                "customer_id",
                "lookup_foreign_key",
                {"match_column": "customer_number"},
            ),
        ),
    )

    report = PlanValidator().validate(plan, source, target)

    assert report.valid
    assert report.requires_review
    assert {item.code for item in report.findings} == {"foreign_key_lookup_type_unknown"}


def test_validator_blocks_foreign_key_lookup_with_incompatible_key_type() -> None:
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "number",
                "customer number",
                DataType.JSON,
                nullable=False,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor(
                "customer_id",
                "customer id",
                DataType.INTEGER,
                nullable=False,
                role=FieldRole.FOREIGN_KEY,
            ),
        ),
        (
            RelationDescriptor(
                "customer_id",
                "customers",
                "id",
                lookup_keys=(LookupKeyDescriptor("customer_number", DataType.INTEGER),),
            ),
        ),
    )
    plan = _plan(
        source,
        target,
        (
            MappingRule(
                "number",
                "customer_id",
                "lookup_foreign_key",
                {"match_column": "customer_number"},
            ),
        ),
    )

    report = PlanValidator().validate(plan, source, target)

    assert not report.valid
    assert {item.code for item in report.findings} == {"foreign_key_lookup_type_mismatch"}
