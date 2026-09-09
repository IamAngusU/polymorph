from __future__ import annotations

import os
import statistics
import threading
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Protocol, TypeVar, cast

from .matching.hybrid import HybridMatcher
from .models.mapping import MappingStatus
from .models.schema import SchemaDescriptor

T = TypeVar("T")


class _MemoryInfo(Protocol):
    rss: int


class _Process(Protocol):
    def memory_info(self) -> _MemoryInfo: ...


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    name: str
    wall_ms: float
    cpu_ms: float
    peak_python_bytes: int
    result_count: int | None = None
    pid: int = 0
    rss_before_bytes: int | None = None
    rss_after_bytes: int | None = None
    peak_rss_bytes: int | None = None

    @property
    def throughput_per_second(self) -> float | None:
        if self.result_count is None or self.wall_ms <= 0:
            return None
        return self.result_count / (self.wall_ms / 1000.0)

    def as_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["throughput_per_second"] = self.throughput_per_second
        return payload


class _RssSampler:
    """Optional process RSS sampler used only inside explicit benchmark commands."""

    def __init__(self) -> None:
        self._process: _Process | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.before: int | None = None
        self.after: int | None = None
        self.peak: int | None = None
        try:
            import psutil
        except ImportError:
            return
        self._process = cast(_Process, psutil.Process(os.getpid()))

    def start(self) -> None:
        if self._process is None:
            return
        process = self._process
        self.before = int(process.memory_info().rss)
        self.peak = self.before

        def sample() -> None:
            while not self._stop.wait(0.005):
                try:
                    rss = int(process.memory_info().rss)
                except Exception:
                    return
                if self.peak is None or rss > self.peak:
                    self.peak = rss

        self._thread = threading.Thread(target=sample, name="polymorph-rss-sampler", daemon=True)
        self._thread.start()

    def finish(self) -> None:
        if self._process is None:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.2)
        try:
            self.after = int(self._process.memory_info().rss)
        except Exception:
            self.after = None
        if self.after is not None and (self.peak is None or self.after > self.peak):
            self.peak = self.after


def benchmark_call(
    name: str,
    operation: Callable[[], T],
    *,
    result_count: Callable[[T], int] | None = None,
) -> tuple[T, BenchmarkResult]:
    """Measure one explicit diagnostic operation.

    There is intentionally no global instrumentation hook. Production paths pay no tracing,
    RSS polling or allocation-accounting overhead unless this function is called directly.
    """

    rss = _RssSampler()
    tracemalloc.start()
    rss.start()
    wall_start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    try:
        result = operation()
        wall_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
        cpu_ms = (time.process_time_ns() - cpu_start) / 1_000_000
        _, peak = tracemalloc.get_traced_memory()
    finally:
        rss.finish()
        tracemalloc.stop()
    count = result_count(result) if result_count is not None else None
    return result, BenchmarkResult(
        name=name,
        wall_ms=wall_ms,
        cpu_ms=cpu_ms,
        peak_python_bytes=peak,
        result_count=count,
        pid=os.getpid(),
        rss_before_bytes=rss.before,
        rss_after_bytes=rss.after,
        peak_rss_bytes=rss.peak,
    )


@dataclass(frozen=True, slots=True)
class MappingBenchmarkCase:
    id: str
    source_schema: SchemaDescriptor
    target_schema: SchemaDescriptor
    expected: dict[str, str | None]


@dataclass(frozen=True, slots=True)
class MappingBenchmarkFailure:
    case_id: str
    source_field_id: str
    expected_target_field_id: str | None
    actual_target_field_id: str | None
    status: str


@dataclass(frozen=True, slots=True)
class MappingBenchmarkReport:
    cases: int
    fields_scored: int
    mappable_fields: int
    auto_decisions: int
    auto_correct: int
    auto_incorrect: int
    review_decisions: int
    blocked_decisions: int
    suggestion_correct: int
    unsafe_auto_on_unmappable: int
    case_latency_p50_ms: float
    case_latency_p95_ms: float
    failures: tuple[MappingBenchmarkFailure, ...]

    @property
    def auto_precision(self) -> float | None:
        if self.auto_decisions == 0:
            return None
        return self.auto_correct / self.auto_decisions

    @property
    def automation_coverage(self) -> float:
        if self.mappable_fields == 0:
            return 1.0
        return self.auto_correct / self.mappable_fields

    @property
    def suggestion_accuracy(self) -> float:
        if self.fields_scored == 0:
            return 1.0
        return self.suggestion_correct / self.fields_scored

    def as_dict(self) -> dict[str, object]:
        return {
            "cases": self.cases,
            "fields_scored": self.fields_scored,
            "mappable_fields": self.mappable_fields,
            "auto_decisions": self.auto_decisions,
            "auto_correct": self.auto_correct,
            "auto_incorrect": self.auto_incorrect,
            "auto_precision": self.auto_precision,
            "automation_coverage": self.automation_coverage,
            "review_decisions": self.review_decisions,
            "blocked_decisions": self.blocked_decisions,
            "suggestion_correct": self.suggestion_correct,
            "suggestion_accuracy": self.suggestion_accuracy,
            "unsafe_auto_on_unmappable": self.unsafe_auto_on_unmappable,
            "case_latency_p50_ms": self.case_latency_p50_ms,
            "case_latency_p95_ms": self.case_latency_p95_ms,
            "failures": [asdict(item) for item in self.failures],
        }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def benchmark_mapping_cases(
    cases: list[MappingBenchmarkCase],
    matcher: HybridMatcher,
) -> MappingBenchmarkReport:
    """Evaluate mapping safety and coverage against an explicit labelled corpus.

    The key metric is auto precision, not raw automation coverage. A model-assisted matcher is
    useful only when it improves ranking without introducing incorrect automatic decisions.
    """

    fields_scored = 0
    mappable_fields = 0
    auto_decisions = 0
    auto_correct = 0
    auto_incorrect = 0
    review_decisions = 0
    blocked_decisions = 0
    suggestion_correct = 0
    unsafe_auto_on_unmappable = 0
    failures: list[MappingBenchmarkFailure] = []
    latencies: list[float] = []

    for case in cases:
        started = time.perf_counter_ns()
        decisions = matcher.propose(case.source_schema, case.target_schema)
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        by_source = {item.source_field_id: item for item in decisions}

        for source_id, expected_target in case.expected.items():
            fields_scored += 1
            if expected_target is not None:
                mappable_fields += 1
            decision = by_source.get(source_id)
            if decision is None:
                failures.append(
                    MappingBenchmarkFailure(
                        case.id,
                        source_id,
                        expected_target,
                        None,
                        "missing_decision",
                    )
                )
                continue

            if decision.target_field_id == expected_target:
                suggestion_correct += 1

            if decision.status is MappingStatus.AUTO:
                auto_decisions += 1
                if decision.target_field_id == expected_target and expected_target is not None:
                    auto_correct += 1
                else:
                    auto_incorrect += 1
                    if expected_target is None:
                        unsafe_auto_on_unmappable += 1
                    failures.append(
                        MappingBenchmarkFailure(
                            case.id,
                            source_id,
                            expected_target,
                            decision.target_field_id,
                            decision.status.value,
                        )
                    )
            elif decision.status is MappingStatus.REVIEW:
                review_decisions += 1
            else:
                blocked_decisions += 1

    return MappingBenchmarkReport(
        cases=len(cases),
        fields_scored=fields_scored,
        mappable_fields=mappable_fields,
        auto_decisions=auto_decisions,
        auto_correct=auto_correct,
        auto_incorrect=auto_incorrect,
        review_decisions=review_decisions,
        blocked_decisions=blocked_decisions,
        suggestion_correct=suggestion_correct,
        unsafe_auto_on_unmappable=unsafe_auto_on_unmappable,
        case_latency_p50_ms=statistics.median(latencies) if latencies else 0.0,
        case_latency_p95_ms=_percentile(latencies, 0.95),
        failures=tuple(failures),
    )
