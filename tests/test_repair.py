from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import (
    FieldDescriptor,
    LookupKeyDescriptor,
    RelationDescriptor,
    SchemaDescriptor,
)
from polymorph.models.types import DataType, FieldRole, Sensitivity
from polymorph.repair import RepairSeverity, assess_plan_drift, propose_plan_repair


def test_renamed_source_field_can_be_repaired():
    old = SchemaDescriptor(
        "s", (FieldDescriptor("customer_no", "customer number", DataType.STRING),)
    )
    new = SchemaDescriptor("s", (FieldDescriptor("client_no", "client number", DataType.STRING),))
    target = SchemaDescriptor(
        "t", (FieldDescriptor("customer_number", "customer number", DataType.STRING),)
    )
    plan = MappingPlan(
        "p",
        "s",
        "t",
        old.fingerprint(),
        target.fingerprint(),
        (MappingRule("customer_no", "customer_number"),),
    )

    findings = assess_plan_drift(
        plan,
        old,
        new,
        target,
        HybridMatcher(auto_threshold=0.7, minimum_margin=0.0),
    )
    assert findings[0].severity is RepairSeverity.SAFE
    assert findings[0].replacement_field_id == "client_no"


def test_excel_position_ids_are_not_treated_as_identity_after_columns_move():
    old = SchemaDescriptor(
        "s",
        (
            FieldDescriptor("c1", "Customer Number", DataType.STRING),
            FieldDescriptor("c2", "Amount", DataType.DECIMAL),
        ),
    )
    new = SchemaDescriptor(
        "s",
        (
            FieldDescriptor("c1", "Amount", DataType.DECIMAL),
            FieldDescriptor("c2", "Customer Number", DataType.STRING),
        ),
    )
    target = SchemaDescriptor(
        "t",
        (
            FieldDescriptor("customer_number", "Customer Number", DataType.STRING),
            FieldDescriptor("amount", "Amount", DataType.DECIMAL),
        ),
    )
    plan = MappingPlan(
        "p",
        old.id,
        target.id,
        old.fingerprint(),
        target.fingerprint(),
        (
            MappingRule("c1", "customer_number"),
            MappingRule("c2", "amount"),
        ),
    )

    proposal = propose_plan_repair(
        plan,
        old,
        new,
        target,
        target,
        HybridMatcher(auto_threshold=0.7, minimum_margin=0.05),
    )
    assert proposal.plan is not None
    assert proposal.auto_applicable
    assert [(r.source_field_id, r.target_field_id) for r in proposal.plan.rules] == [
        ("c2", "customer_number"),
        ("c1", "amount"),
    ]
    assert proposal.plan.digest() != plan.digest()


def test_sensitivity_change_blocks_repair():
    old = SchemaDescriptor("s", (FieldDescriptor("x", "Value", sensitivity=Sensitivity.INTERNAL),))
    new = SchemaDescriptor("s", (FieldDescriptor("x", "Value", sensitivity=Sensitivity.SECRET),))
    target = SchemaDescriptor("t", (FieldDescriptor("y", "Value"),))
    plan = MappingPlan(
        "p",
        old.id,
        target.id,
        old.fingerprint(),
        target.fingerprint(),
        (MappingRule("x", "y"),),
    )

    proposal = propose_plan_repair(
        plan,
        old,
        new,
        target,
        target,
        HybridMatcher(auto_threshold=0.7, minimum_margin=0.0),
    )
    assert proposal.blocked
    assert proposal.plan is None


def test_removed_fk_lookup_key_blocks_repair():
    source = SchemaDescriptor(
        "s",
        (
            FieldDescriptor(
                "customer",
                "Customer Number",
                DataType.STRING,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    old_target = SchemaDescriptor(
        "t",
        (
            FieldDescriptor(
                "customer_id", "customer id", DataType.INTEGER, role=FieldRole.FOREIGN_KEY
            ),
        ),
        (
            RelationDescriptor(
                "customer_id",
                "customers",
                "id",
                lookup_keys=(LookupKeyDescriptor("external_customer_number", DataType.STRING),),
            ),
        ),
    )
    new_target = SchemaDescriptor(
        "t",
        (
            FieldDescriptor(
                "customer_id", "customer id", DataType.INTEGER, role=FieldRole.FOREIGN_KEY
            ),
        ),
        (RelationDescriptor("customer_id", "customers", "id", lookup_keys=()),),
    )
    plan = MappingPlan(
        "p",
        source.id,
        old_target.id,
        source.fingerprint(),
        old_target.fingerprint(),
        (
            MappingRule(
                "customer",
                "customer_id",
                "lookup_foreign_key",
                {"match_column": "external_customer_number"},
            ),
        ),
    )

    proposal = propose_plan_repair(
        plan,
        source,
        source,
        old_target,
        new_target,
        HybridMatcher(auto_threshold=0.7, minimum_margin=0.0),
    )
    assert proposal.blocked
    assert any("lookup path" in finding.message for finding in proposal.findings)
