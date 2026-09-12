from __future__ import annotations

from polymorph.data_quality import (
    CleaningAction,
    CleaningPlan,
    CleaningRule,
    DataQualityAnalyzer,
    QualityLimits,
)
from polymorph.serialization import schema_from_dict


class _Schema:
    def to_dict(self) -> dict[str, object]:
        return {
            "fields": [
                {"name": "id", "nullable": False},
                {"name": "label", "nullable": True},
            ]
        }

    def fingerprint(self) -> str:
        return "a" * 64


def test_quality_report_is_bounded_and_contains_no_values() -> None:
    analyzer = DataQualityAnalyzer(
        _Schema(), QualityLimits(max_records=2, max_samples_per_group=1, max_groups=20)
    )
    report = analyzer.inspect(
        iter(
            [
                {"id": 1, "label": " secret ", "extra": "x"},
                {"id": None, "label": ""},
                {"id": 3, "label": "not-consumed-in-report"},
            ]
        )
    )
    payload = report.to_dict()
    assert report.complete is False
    assert report.records_scanned == 2
    assert payload["privacy"] == "metadata_only_no_record_values"
    assert " secret " not in str(payload)
    assert all(len(group.record_samples) <= 1 for group in report.issue_groups)


def test_cleaning_plan_is_explicit_non_mutating_and_lazy() -> None:
    consumed = 0

    def rows():
        nonlocal consumed
        consumed += 1
        yield {"label": "  Cafe\u0301  "}
        consumed += 1
        yield {"label": ""}

    plan = CleaningPlan(
        schema_fingerprint="a" * 64,
        reviewed_by="operator-1",
        rules=(
            CleaningRule("label", CleaningAction.NORMALIZE_UNICODE_NFC),
            CleaningRule("label", CleaningAction.TRIM_WHITESPACE),
            CleaningRule("label", CleaningAction.EMPTY_TO_NULL),
        ),
    )
    source = rows()
    cleaned = plan.apply(source)
    assert consumed == 0
    assert next(cleaned) == {"label": "Caf\u00e9"}
    assert consumed == 1
    assert next(cleaned) == {"label": None}


def test_quality_analyzer_accepts_the_real_schema_descriptor() -> None:
    schema = schema_from_dict(
        {
            "id": "real-schema",
            "fields": [{"id": "id", "name": "id", "data_type": "integer", "nullable": False}],
        }
    )
    report = DataQualityAnalyzer(schema).inspect([{"id": 1}])
    assert report.complete is True
    assert report.schema_fingerprint == schema.fingerprint()
