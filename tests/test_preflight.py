from __future__ import annotations

from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, RelationDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, FieldRole
from polymorph.preflight import PreflightRunner


def _basic():
    source = SchemaDescriptor(
        "source",
        (FieldDescriptor("c1", "Amount", DataType.STRING, nullable=False),),
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("amount", "Amount", DataType.DECIMAL, nullable=False),),
    )
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("c1", "amount", "parse_decimal", {"decimal_separator": ",", "thousands_separator": "."}),),
    )
    return source, target, plan


def test_full_preflight_can_be_promotable_without_writes() -> None:
    source, target, plan = _basic()
    report = PreflightRunner().run([{"c1": "1.234,50"}, {"c1": "2,00"}], source, target, plan)

    assert report.valid
    assert report.complete_scan
    assert report.promotable
    assert report.records_checked == 2


def test_sampled_preflight_never_auto_promotes() -> None:
    source, target, plan = _basic()
    report = PreflightRunner().run(
        [{"c1": "1,00"}, {"c1": "2,00"}, {"c1": "3,00"}],
        source,
        target,
        plan,
        max_records=2,
    )

    assert report.valid
    assert not report.complete_scan
    assert not report.promotable


def test_preflight_reports_transform_failure_without_exposing_value() -> None:
    source, target, plan = _basic()
    secret_marker = "THIS_VALUE_MUST_NEVER_APPEAR"
    report = PreflightRunner().run([{"c1": secret_marker}], source, target, plan)

    assert not report.valid
    rendered = str(report.as_dict())
    assert secret_marker not in rendered
    assert any(item.code == "source_transform_failed" for item in report.findings)


def test_foreign_key_preflight_uses_read_only_resolver() -> None:
    source = SchemaDescriptor(
        "source",
        (FieldDescriptor("c1", "Customer Number", DataType.STRING, role=FieldRole.NATURAL_KEY),),
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("customer_id", "Customer ID", DataType.INTEGER, nullable=False, role=FieldRole.FOREIGN_KEY),),
        relations=(
            RelationDescriptor(
                source_field_id="customer_id",
                target_container="customers",
                target_field="id",
                lookup_keys=("customer_number",),
            ),
        ),
    )
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("c1", "customer_id", "lookup_foreign_key", {"match_column": "customer_number"}),),
    )

    class Resolver:
        def resolve_foreign_key(self, *, target_field_id, match_column, value):
            assert target_field_id == "customer_id"
            assert match_column == "customer_number"
            return 42

    report = PreflightRunner().run(
        [{"c1": "C-42"}], source, target, plan, foreign_key_resolver=Resolver()
    )
    assert report.promotable
    assert report.destination_lookups_checked == 1


def test_preflight_does_not_auto_promote_unproven_formula_cache() -> None:
    source = SchemaDescriptor(
        "source",
        (FieldDescriptor("a", "amount", DataType.DECIMAL, nullable=False),),
        metadata={"formula_cells_present": "true", "formula_value_source": "cached_workbook_value"},
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("amount", "amount", DataType.DECIMAL, nullable=False),),
    )
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("a", "amount", "copy"),),
    )

    report = PreflightRunner().run([{"a": 12.5}], source, target, plan)

    assert report.valid
    assert report.requires_review
    assert not report.promotable
    assert any(item.code == "spreadsheet_formula_cache" for item in report.findings)
