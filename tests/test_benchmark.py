from __future__ import annotations

import tracemalloc

from polymorph.benchmark import benchmark_call


def test_benchmark_default_avoids_python_allocation_tracing_and_returns_metrics(
    monkeypatch,
) -> None:
    def unexpected_start() -> None:
        raise AssertionError("default benchmark started tracemalloc")

    monkeypatch.setattr(tracemalloc, "start", unexpected_start)
    result, metrics = benchmark_call("unit", lambda: [1, 2, 3], result_count=len)

    assert result == [1, 2, 3]
    assert metrics.result_count == 3
    assert metrics.wall_ms >= 0
    assert metrics.cpu_ms >= 0
    assert metrics.peak_python_bytes is None
    assert not metrics.python_allocation_tracing
    assert metrics.as_dict()["measurement_mode"] == "standard"


def test_benchmark_can_trace_python_allocations_when_explicitly_requested() -> None:
    result, metrics = benchmark_call(
        "unit",
        lambda: [1, 2, 3],
        result_count=len,
        trace_python_allocations=True,
    )

    assert result == [1, 2, 3]
    assert metrics.result_count == 3
    assert metrics.peak_python_bytes is not None
    assert metrics.peak_python_bytes >= 0
    assert metrics.python_allocation_tracing
    assert metrics.as_dict()["measurement_mode"] == "python_allocation_trace"


def test_mapping_benchmark_separates_precision_from_coverage() -> None:
    from polymorph.benchmark import MappingBenchmarkCase, benchmark_mapping_cases
    from polymorph.matching.hybrid import HybridMatcher
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType

    source = SchemaDescriptor(
        "s",
        (
            FieldDescriptor("customer", "customer id", DataType.STRING),
            FieldDescriptor("ambiguous", "ref", DataType.STRING),
        ),
    )
    target = SchemaDescriptor(
        "t",
        (
            FieldDescriptor("customer_id", "customer id", DataType.STRING),
            FieldDescriptor("order_ref", "order reference", DataType.STRING),
        ),
    )
    report = benchmark_mapping_cases(
        [
            MappingBenchmarkCase(
                "case-1",
                source,
                target,
                {"customer": "customer_id", "ambiguous": None},
            )
        ],
        HybridMatcher(),
    )

    assert report.auto_precision == 1.0
    assert report.auto_incorrect == 0
    assert report.unsafe_auto_on_unmappable == 0


def test_mapping_benchmark_reports_wrong_review_suggestions() -> None:
    from polymorph.benchmark import MappingBenchmarkCase, benchmark_mapping_cases
    from polymorph.models.mapping import MappingDecision, MappingStatus
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor

    source = SchemaDescriptor("source", (FieldDescriptor("reference", "reference"),))
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("customer_reference", "customer reference"),
            FieldDescriptor("order_reference", "order reference"),
        ),
    )

    class WrongReviewMatcher:
        @staticmethod
        def propose(
            source_schema: SchemaDescriptor, target_schema: SchemaDescriptor
        ) -> list[MappingDecision]:
            del source_schema, target_schema
            return [
                MappingDecision(
                    "reference",
                    "customer_reference",
                    MappingStatus.REVIEW,
                    0.7,
                    0.01,
                    ("ambiguous",),
                )
            ]

    report = benchmark_mapping_cases(
        [MappingBenchmarkCase("ambiguous", source, target, {"reference": None})],
        WrongReviewMatcher(),  # type: ignore[arg-type]
    )

    assert report.auto_incorrect == 0
    assert report.unsafe_auto_on_unmappable == 0
    assert report.suggestion_accuracy == 0.0
    assert len(report.failures) == 1

    assert report.failures[0].status == "review"
    payload = report.as_dict()
    assert payload["suggestion_mismatch_count"] == 1
    assert len(payload["suggestion_mismatches"]) == 1
    assert payload["safety_failure_count"] == 0
    assert payload["safety_failures"] == []
    assert payload["failures"] == []
    assert 0.0 <= report.automation_coverage <= 1.0


def test_mapping_benchmark_rejects_auto_when_target_is_review_only_or_not_executable() -> None:
    from polymorph.benchmark import MappingBenchmarkCase, benchmark_mapping_cases
    from polymorph.models.mapping import MappingDecision, MappingStatus
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType

    source = SchemaDescriptor(
        "source",
        (
            FieldDescriptor("review", "customer id", DataType.STRING),
            FieldDescriptor("temporal", "created date", DataType.DATE),
        ),
    )
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("customer_id", "customer id", DataType.STRING),
            FieldDescriptor("created_at", "created date", DataType.DATETIME),
        ),
    )

    class UnsafeAutoMatcher:
        @staticmethod
        def propose(
            source_schema: SchemaDescriptor, target_schema: SchemaDescriptor
        ) -> list[MappingDecision]:
            del source_schema, target_schema
            return [
                MappingDecision("review", "customer_id", MappingStatus.AUTO, 1.0, 1.0, ("exact",)),
                MappingDecision("temporal", "created_at", MappingStatus.AUTO, 1.0, 1.0, ("exact",)),
            ]

    report = benchmark_mapping_cases(
        [
            MappingBenchmarkCase(
                "unsafe-auto",
                source,
                target,
                {"review": "customer_id", "temporal": "created_at"},
                review_only=frozenset({"review"}),
            )
        ],
        UnsafeAutoMatcher(),  # type: ignore[arg-type]
    )

    assert report.suggestion_accuracy == 1.0
    assert report.auto_correct == 0
    assert report.auto_incorrect == 2
    assert report.unsafe_auto_on_review_only == 1
    assert report.unsafe_auto_on_contract_mismatch == 1
    assert report.automation_eligible_fields == 1
    assert report.automation_coverage == 0.0
    assert report.overall_automation_rate == 0.0
    payload = report.as_dict()
    assert payload["suggestion_mismatch_count"] == 0
    assert payload["safety_failure_count"] == 2
    assert {tuple(item["reason_codes"]) for item in payload["safety_failures"]} == {
        ("auto_on_review_only",),
        ("auto_contract_mismatch",),
    }


def test_mapping_benchmark_rejects_duplicate_and_unknown_source_decisions() -> None:
    from polymorph.benchmark import MappingBenchmarkCase, benchmark_mapping_cases
    from polymorph.models.mapping import MappingDecision, MappingStatus
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType

    source = SchemaDescriptor("source", (FieldDescriptor("a", "a", DataType.STRING),))
    target = SchemaDescriptor(
        "target",
        (
            FieldDescriptor("a", "a", DataType.STRING),
            FieldDescriptor("b", "b", DataType.STRING),
        ),
    )

    class InvalidMatcher:
        @staticmethod
        def propose(
            source_schema: SchemaDescriptor, target_schema: SchemaDescriptor
        ) -> list[MappingDecision]:
            del source_schema, target_schema
            return [
                MappingDecision("a", "b", MappingStatus.AUTO, 1.0, 1.0, ()),
                MappingDecision("unknown", "b", MappingStatus.REVIEW, 0.7, 0.1, ()),
                MappingDecision("a", "a", MappingStatus.AUTO, 1.0, 1.0, ()),
            ]

    report = benchmark_mapping_cases(
        [MappingBenchmarkCase("invalid-output", source, target, {"a": "a"})],
        InvalidMatcher(),  # type: ignore[arg-type]
    )

    assert report.auto_decisions == 2
    assert report.auto_correct == 0
    assert report.auto_incorrect == 2
    assert report.unsafe_auto_on_invalid_output == 2
    assert len(report.decision_contract_failures) == 3
    payload = report.as_dict()
    assert payload["decision_contract_valid"] is False
    assert payload["decision_contract_failure_count"] == 3
    assert payload["safety_failure_count"] == 3


def test_mapping_benchmark_rejects_unusable_decision_contracts() -> None:
    from polymorph.benchmark import MappingBenchmarkCase, benchmark_mapping_cases
    from polymorph.models.mapping import MappingDecision, MappingStatus
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor

    source = SchemaDescriptor("source", tuple(FieldDescriptor(key, key) for key in "abcde"))
    target = SchemaDescriptor("target", tuple(FieldDescriptor(key, key) for key in "abcde"))

    class InvalidContractMatcher:
        @staticmethod
        def propose(
            source_schema: SchemaDescriptor, target_schema: SchemaDescriptor
        ) -> list[MappingDecision]:
            del source_schema, target_schema
            return [
                MappingDecision("a", "unknown", MappingStatus.REVIEW, 0.7, 0.1),
                MappingDecision("b", "b", MappingStatus.BLOCKED, 0.4, 0.1),
                MappingDecision("c", None, MappingStatus.AUTO, 1.0, 1.0),
                MappingDecision("d", "d", MappingStatus.REVIEW, float("nan"), 2.0),
                MappingDecision("e", "e", "review", 0.7, 0.1),  # type: ignore[arg-type]
            ]

    report = benchmark_mapping_cases(
        [
            MappingBenchmarkCase(
                "invalid-contracts",
                source,
                target,
                {key: key for key in "abcde"},
            )
        ],
        InvalidContractMatcher(),  # type: ignore[arg-type]
    )

    assert len(report.decision_contract_failures) == 5
    assert report.unsafe_auto_on_invalid_output == 1
    assert report.auto_incorrect == 1
    codes = {code for failure in report.decision_contract_failures for code in failure.reason_codes}
    assert codes == {
        "decision_for_unknown_target",
        "blocked_decision_has_target",
        "actionable_decision_missing_target",
        "invalid_score",
        "invalid_margin",
        "invalid_mapping_status",
    }
