from __future__ import annotations

import math
import os
import statistics
import threading
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Protocol, TypeVar, cast

from .matching.deterministic import automatic_mapping_contract_safe
from .matching.hybrid import HybridMatcher
from .models.mapping import MappingDecision, MappingStatus
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
    peak_python_bytes: int | None
    python_allocation_tracing: bool = False
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
        payload["measurement_mode"] = (
            "python_allocation_trace" if self.python_allocation_tracing else "standard"
        )
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
    trace_python_allocations: bool = False,
) -> tuple[T, BenchmarkResult]:
    """Measure one explicit diagnostic operation.

    There is intentionally no global instrumentation hook. Production paths pay no tracing,
    RSS polling or allocation-accounting overhead unless this function is called directly.
    CPython allocation tracing is separately opt-in because its observer effect can materially
    distort parser wall time.
    """

    rss = _RssSampler()
    tracing_started_here = trace_python_allocations and not tracemalloc.is_tracing()
    if tracing_started_here:
        tracemalloc.start()
    rss.start()
    wall_start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    try:
        result = operation()
        wall_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
        cpu_ms = (time.process_time_ns() - cpu_start) / 1_000_000
        peak = tracemalloc.get_traced_memory()[1] if trace_python_allocations else None
    finally:
        rss.finish()
        if tracing_started_here:
            tracemalloc.stop()
    count = result_count(result) if result_count is not None else None
    return result, BenchmarkResult(
        name=name,
        wall_ms=wall_ms,
        cpu_ms=cpu_ms,
        peak_python_bytes=peak,
        python_allocation_tracing=trace_python_allocations,
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
    review_only: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class MappingBenchmarkFailure:
    case_id: str
    source_field_id: str
    expected_target_field_id: str | None
    actual_target_field_id: str | None
    status: str
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MappingBenchmarkReport:
    cases: int
    fields_scored: int
    mappable_fields: int
    automation_eligible_fields: int
    auto_decisions: int
    auto_correct: int
    auto_incorrect: int
    review_decisions: int
    blocked_decisions: int
    suggestion_correct: int
    unsafe_auto_on_unmappable: int
    unsafe_auto_on_review_only: int
    unsafe_auto_on_contract_mismatch: int
    unsafe_auto_on_invalid_output: int
    case_latency_p50_ms: float
    case_latency_p95_ms: float
    failures: tuple[MappingBenchmarkFailure, ...]
    unsafe_failures: tuple[MappingBenchmarkFailure, ...]
    decision_contract_failures: tuple[MappingBenchmarkFailure, ...]

    @property
    def auto_precision(self) -> float | None:
        if self.auto_decisions == 0:
            return None
        return self.auto_correct / self.auto_decisions

    @property
    def automation_coverage(self) -> float:
        if self.automation_eligible_fields == 0:
            return 1.0
        return self.auto_correct / self.automation_eligible_fields

    @property
    def overall_automation_rate(self) -> float:
        if self.mappable_fields == 0:
            return 1.0
        return self.auto_correct / self.mappable_fields

    @property
    def suggestion_accuracy(self) -> float:
        if self.fields_scored == 0:
            return 1.0
        return self.suggestion_correct / self.fields_scored

    def as_dict(self) -> dict[str, object]:
        suggestion_mismatches = [asdict(item) for item in self.failures]
        decision_contract_failures = [asdict(item) for item in self.decision_contract_failures]
        safety_failures = [
            asdict(item) for item in (*self.unsafe_failures, *self.decision_contract_failures)
        ]
        return {
            "cases": self.cases,
            "fields_scored": self.fields_scored,
            "mappable_fields": self.mappable_fields,
            "automation_eligible_fields": self.automation_eligible_fields,
            "auto_decisions": self.auto_decisions,
            "auto_correct": self.auto_correct,
            "auto_incorrect": self.auto_incorrect,
            "auto_precision": self.auto_precision,
            "automation_coverage": self.automation_coverage,
            "overall_automation_rate": self.overall_automation_rate,
            "review_decisions": self.review_decisions,
            "blocked_decisions": self.blocked_decisions,
            "suggestion_correct": self.suggestion_correct,
            "suggestion_accuracy": self.suggestion_accuracy,
            "suggestion_mismatch_count": len(suggestion_mismatches),
            "suggestion_mismatches": suggestion_mismatches,
            "unsafe_auto_decisions": self.auto_incorrect,
            "unsafe_auto_on_unmappable": self.unsafe_auto_on_unmappable,
            "unsafe_auto_on_review_only": self.unsafe_auto_on_review_only,
            "unsafe_auto_on_contract_mismatch": self.unsafe_auto_on_contract_mismatch,
            "unsafe_auto_on_invalid_output": self.unsafe_auto_on_invalid_output,
            "decision_contract_valid": not self.decision_contract_failures,
            "decision_contract_failure_count": len(decision_contract_failures),
            "decision_contract_failures": decision_contract_failures,
            "case_latency_p50_ms": self.case_latency_p50_ms,
            "case_latency_p95_ms": self.case_latency_p95_ms,
            "safety_failure_count": len(safety_failures),
            "safety_failures": safety_failures,
            # Retain the old key for report consumers while making its safety meaning explicit.
            "failures": safety_failures,
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


def _finite_unit_interval(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0.0 <= float(value) <= 1.0
    )


def _decision_contract_reasons(
    decision: MappingDecision,
    *,
    expected_sources: set[str],
    target_fields: set[str],
) -> tuple[str, ...]:
    reasons: list[str] = []
    if decision.source_field_id not in expected_sources:
        reasons.append("decision_for_unknown_source")
    if not isinstance(decision.status, MappingStatus):
        reasons.append("invalid_mapping_status")
    if not _finite_unit_interval(decision.score):
        reasons.append("invalid_score")
    if not _finite_unit_interval(decision.margin):
        reasons.append("invalid_margin")

    if decision.status is MappingStatus.BLOCKED:
        if decision.target_field_id is not None:
            reasons.append("blocked_decision_has_target")
    elif decision.status in {MappingStatus.AUTO, MappingStatus.REVIEW}:
        if decision.target_field_id is None:
            reasons.append("actionable_decision_missing_target")
        elif decision.target_field_id not in target_fields:
            reasons.append("decision_for_unknown_target")
    return tuple(reasons)


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
    automation_eligible_fields = 0
    auto_decisions = 0
    auto_correct = 0
    auto_incorrect = 0
    review_decisions = 0
    blocked_decisions = 0
    suggestion_correct = 0
    unsafe_auto_on_unmappable = 0
    unsafe_auto_on_review_only = 0
    unsafe_auto_on_contract_mismatch = 0
    unsafe_auto_on_invalid_output = 0
    suggestion_failures: list[MappingBenchmarkFailure] = []
    safety_failures: list[MappingBenchmarkFailure] = []
    decision_contract_failures: list[MappingBenchmarkFailure] = []
    latencies: list[float] = []

    for case in cases:
        started = time.perf_counter_ns()
        decisions = matcher.propose(case.source_schema, case.target_schema)
        latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        source_fields = case.source_schema.by_id()
        target_fields = case.target_schema.by_id()
        expected_source_ids = set(case.expected)
        target_field_ids = set(target_fields)
        grouped: dict[str, list[MappingDecision]] = {}
        for proposed_decision in decisions:
            grouped.setdefault(proposed_decision.source_field_id, []).append(proposed_decision)
        by_source: dict[str, MappingDecision] = {}
        for decision_source_id, source_decisions in grouped.items():
            duplicate = len(source_decisions) != 1
            expected_target = case.expected.get(decision_source_id)
            for invalid_decision in source_decisions:
                reasons = list(
                    _decision_contract_reasons(
                        invalid_decision,
                        expected_sources=expected_source_ids,
                        target_fields=target_field_ids,
                    )
                )
                if duplicate:
                    reasons.append("duplicate_source_decision")
                if not reasons:
                    by_source[decision_source_id] = invalid_decision
                    continue
                failure = MappingBenchmarkFailure(
                    case.id,
                    decision_source_id,
                    expected_target,
                    invalid_decision.target_field_id,
                    (
                        invalid_decision.status.value
                        if isinstance(invalid_decision.status, MappingStatus)
                        else str(invalid_decision.status)
                    ),
                    tuple(reasons),
                )
                decision_contract_failures.append(failure)
                if invalid_decision.status is MappingStatus.AUTO:
                    auto_decisions += 1
                    auto_incorrect += 1
                    unsafe_auto_on_invalid_output += 1

        for source_id, expected_target in case.expected.items():
            fields_scored += 1
            if expected_target is not None:
                mappable_fields += 1
                if source_id not in case.review_only:
                    automation_eligible_fields += 1
            decision = by_source.get(source_id)
            if decision is None:
                failure = MappingBenchmarkFailure(
                    case.id,
                    source_id,
                    expected_target,
                    None,
                    "missing_decision",
                    ("missing_decision",),
                )
                suggestion_failures.append(failure)
                if source_id not in grouped:
                    decision_contract_failures.append(failure)
                continue

            suggestion_matches = decision.target_field_id == expected_target
            if suggestion_matches:
                suggestion_correct += 1

            if decision.status is MappingStatus.AUTO:
                auto_decisions += 1
                target = target_fields.get(decision.target_field_id or "")
                source = source_fields[source_id]
                contract_safe = target is not None and automatic_mapping_contract_safe(
                    source, target, case.target_schema
                )
                auto_allowed = source_id not in case.review_only
                safety_reasons: list[str] = []
                if expected_target is None:
                    unsafe_auto_on_unmappable += 1
                    safety_reasons.append("auto_on_unmappable")
                elif decision.target_field_id != expected_target:
                    safety_reasons.append("auto_target_mismatch")
                if not auto_allowed:
                    unsafe_auto_on_review_only += 1
                    safety_reasons.append("auto_on_review_only")
                if not contract_safe:
                    unsafe_auto_on_contract_mismatch += 1
                    safety_reasons.append("auto_contract_mismatch")
                if not safety_reasons:
                    auto_correct += 1
                else:
                    auto_incorrect += 1
                    safety_failures.append(
                        MappingBenchmarkFailure(
                            case.id,
                            source_id,
                            expected_target,
                            decision.target_field_id,
                            decision.status.value,
                            tuple(safety_reasons),
                        )
                    )
            elif decision.status is MappingStatus.REVIEW:
                review_decisions += 1
            else:
                blocked_decisions += 1

            # A review suggestion can still be wrong, and a blocked decision can still miss a
            # known correspondence. Neither is an unsafe automatic write, but hiding those
            # mismatches made the diagnostic report look better than the actual ranking.
            if not suggestion_matches:
                suggestion_failures.append(
                    MappingBenchmarkFailure(
                        case.id,
                        source_id,
                        expected_target,
                        decision.target_field_id,
                        decision.status.value,
                        ("target_mismatch",),
                    )
                )

    return MappingBenchmarkReport(
        cases=len(cases),
        fields_scored=fields_scored,
        mappable_fields=mappable_fields,
        automation_eligible_fields=automation_eligible_fields,
        auto_decisions=auto_decisions,
        auto_correct=auto_correct,
        auto_incorrect=auto_incorrect,
        review_decisions=review_decisions,
        blocked_decisions=blocked_decisions,
        suggestion_correct=suggestion_correct,
        unsafe_auto_on_unmappable=unsafe_auto_on_unmappable,
        unsafe_auto_on_review_only=unsafe_auto_on_review_only,
        unsafe_auto_on_contract_mismatch=unsafe_auto_on_contract_mismatch,
        unsafe_auto_on_invalid_output=unsafe_auto_on_invalid_output,
        case_latency_p50_ms=statistics.median(latencies) if latencies else 0.0,
        case_latency_p95_ms=_percentile(latencies, 0.95),
        failures=tuple(suggestion_failures),
        unsafe_failures=tuple(safety_failures),
        decision_contract_failures=tuple(decision_contract_failures),
    )
