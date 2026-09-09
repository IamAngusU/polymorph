from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
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


def test_validator_marks_incompatible_copy_for_review():
    source = SchemaDescriptor("source", (FieldDescriptor("v", "Value", DataType.BOOLEAN),))
    target = SchemaDescriptor("target", (FieldDescriptor("v2", "Value", DataType.DATE),))
    plan = _plan(source, target, (MappingRule("v", "v2"),))

    report = PlanValidator().validate(plan, source, target)
    assert report.valid
    assert report.requires_review
    assert any(item.severity is ValidationSeverity.REVIEW for item in report.findings)
