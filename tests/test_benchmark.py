from __future__ import annotations

from polymorph.benchmark import benchmark_call


def test_benchmark_is_explicit_and_returns_resource_metrics() -> None:
    result, metrics = benchmark_call("unit", lambda: [1, 2, 3], result_count=len)

    assert result == [1, 2, 3]
    assert metrics.result_count == 3
    assert metrics.wall_ms >= 0
    assert metrics.cpu_ms >= 0
    assert metrics.peak_python_bytes >= 0


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
    assert 0.0 <= report.automation_coverage <= 1.0
