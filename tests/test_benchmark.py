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
    assert 0.0 <= report.automation_coverage <= 1.0
