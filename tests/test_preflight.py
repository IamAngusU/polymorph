from __future__ import annotations

from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import (
    FieldDescriptor,
    LookupKeyDescriptor,
    RelationDescriptor,
    SchemaDescriptor,
)
from polymorph.models.types import DataType, FieldRole
from polymorph.preflight import PreflightRunner, PreflightSeverity


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
        (
            MappingRule(
                "c1",
                "amount",
                "parse_decimal",
                {"decimal_separator": ",", "thousands_separator": "."},
            ),
        ),
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


def test_preflight_blocks_an_input_record_blast_radius_overrun() -> None:
    source, target, plan = _basic()
    yielded = 0

    def records():
        nonlocal yielded
        for value in ("1,00", "2,00", "3,00", "4,00"):
            yielded += 1
            yield {"c1": value}

    report = PreflightRunner().run(
        records(),
        source,
        target,
        plan,
        max_input_records=2,
    )

    assert not report.valid
    assert not report.promotable
    assert not report.complete_scan
    assert report.records_checked == 2
    assert report.max_input_records == 2
    assert report.input_record_limit_exceeded
    assert yielded == 3
    finding = next(item for item in report.findings if item.code == "input_record_limit_exceeded")
    assert finding.severity is PreflightSeverity.BLOCKING
    assert finding.record_index == 3


def test_preflight_accepts_a_source_exactly_at_the_input_record_limit() -> None:
    source, target, plan = _basic()
    report = PreflightRunner().run(
        ({"c1": value} for value in ("1,00", "2,00")),
        source,
        target,
        plan,
        max_input_records=2,
    )

    assert report.valid
    assert report.complete_scan
    assert report.promotable
    assert report.records_checked == 2
    assert not report.input_record_limit_exceeded


def test_input_record_limit_remains_enforced_after_diagnostic_sample() -> None:
    source, target, plan = _basic()
    yielded = 0

    def records():
        nonlocal yielded
        for index in range(1, 7):
            yielded += 1
            yield {"c1": f"{index},00"}

    report = PreflightRunner().run(
        records(),
        source,
        target,
        plan,
        max_records=2,
        max_input_records=5,
    )

    assert not report.valid
    assert not report.promotable
    assert not report.complete_scan
    assert report.records_checked == 2
    assert report.input_record_limit_exceeded
    assert yielded == 6
    finding = next(item for item in report.findings if item.code == "input_record_limit_exceeded")
    assert finding.record_index == 6


def test_diagnostic_sample_counts_to_input_limit_without_validating_extra_records() -> None:
    source, target, plan = _basic()
    records = [{"c1": "1,00"}, {"c1": "2,00"}, object(), object()]

    report = PreflightRunner().run(
        records,
        source,
        target,
        plan,
        max_records=2,
        max_input_records=5,
    )

    assert report.valid
    assert not report.promotable
    assert not report.complete_scan
    assert report.records_checked == 2
    assert not report.input_record_limit_exceeded
    assert {finding.code for finding in report.findings} == {"sampled_scan"}


def test_preflight_reports_transform_failure_without_exposing_value() -> None:
    source, target, plan = _basic()
    secret_marker = "THIS_VALUE_MUST_NEVER_APPEAR"
    report = PreflightRunner().run([{"c1": secret_marker}], source, target, plan)

    assert not report.valid
    rendered = str(report.as_dict())
    assert secret_marker not in rendered
    assert any(item.code == "source_transform_failed" for item in report.findings)


def test_preflight_blocks_transform_that_produces_null_for_required_target() -> None:
    source, target, plan = _basic()

    report = PreflightRunner().run([{"c1": ""}], source, target, plan)

    assert not report.valid
    assert not report.promotable
    assert {item.code for item in report.findings} == {"required_target_null"}


def test_foreign_key_preflight_uses_read_only_resolver() -> None:
    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor(
                "c1",
                "Customer Number",
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
                "Customer ID",
                DataType.INTEGER,
                nullable=True,
                role=FieldRole.FOREIGN_KEY,
            ),
        ),
        relations=(
            RelationDescriptor(
                source_field_id="customer_id",
                target_container="customers",
                target_field="id",
                lookup_keys=(LookupKeyDescriptor("customer_number", DataType.STRING),),
            ),
        ),
    )
    plan = MappingPlan(
        "plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (
            MappingRule(
                "c1", "customer_id", "lookup_foreign_key", {"match_column": "customer_number"}
            ),
        ),
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

    class MustNotCoerceResolver:
        def resolve_foreign_key(self, *, target_field_id, match_column, value):
            raise AssertionError("wrong-typed lookup input must not reach the resolver")

    wrong_input = PreflightRunner().run(
        [{"c1": 42}],
        source,
        target,
        plan,
        foreign_key_resolver=MustNotCoerceResolver(),
    )
    assert not wrong_input.valid
    assert wrong_input.destination_lookups_checked == 0
    assert {item.code for item in wrong_input.findings} == {
        "foreign_key_lookup_input_type_mismatch"
    }

    class WrongTypeResolver:
        def resolve_foreign_key(self, *, target_field_id, match_column, value):
            return "42"

    wrong_type = PreflightRunner().run(
        [{"c1": "C-42"}], source, target, plan, foreign_key_resolver=WrongTypeResolver()
    )
    assert not wrong_type.valid
    assert wrong_type.destination_lookups_checked == 1
    assert {item.code for item in wrong_type.findings} == {"foreign_key_resolved_type_mismatch"}

    class MissingResolver:
        def resolve_foreign_key(self, *, target_field_id, match_column, value):
            return None

    unresolved = PreflightRunner().run(
        [{"c1": "C-missing"}],
        source,
        target,
        plan,
        foreign_key_resolver=MissingResolver(),
    )
    assert not unresolved.valid
    assert unresolved.destination_lookups_checked == 1
    assert {item.code for item in unresolved.findings} == {"foreign_key_resolved_null"}


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
