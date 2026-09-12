"""Local RAM-budget advice and calibration for the secure workflow benchmark.

The advisor deliberately separates an evidence-backed recommendation from an
operating-system memory boundary.  Its budget is an admission and tuning policy;
it does not claim to be a hard process limit.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import math
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import cast

from . import __version__

MIB = 1024 * 1024
DEFAULT_BATCH_SIZES = (100, 250, 500, 1000)
DEFAULT_HEADROOM_PERCENT = 15.0
DEFAULT_NEAR_OPTIMAL_PERCENT = 2.0
DEFAULT_RECORDS = 5000
CALIBRATION_CONTRACT_SCHEMA_VERSION = 2
CALIBRATION_MATRIX_SCHEMA_VERSION = 2
WORKFLOW_RECORD_SHAPE_ID = "workflow-v1-five-field-customer-record"
WORKFLOW_BENCHMARK_REPORT_VERSION = 1
WORKFLOW_EVENT_STREAM_MAX_BYTES = 64 * MIB
_MAX_RUNTIME_TREE_FILES = 8192
_MAX_RUNTIME_TREE_BYTES = 128 * MIB


class MemoryAdvisorError(ValueError):
    """Raised when calibration evidence cannot support a recommendation."""


@dataclass(frozen=True, slots=True)
class SystemMemory:
    total_bytes: int | None
    available_bytes: int | None
    source: str

    def as_json(self) -> dict[str, object]:
        return {
            "total_bytes": self.total_bytes,
            "available_bytes": self.available_bytes,
            "source": self.source,
        }


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


@dataclass(frozen=True, slots=True)
class BatchProfile:
    batch_size: int
    throughput_rows_per_second: float
    peak_rss_bytes: int
    runs: int


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise MemoryAdvisorError(f"{label} must be a JSON object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise MemoryAdvisorError(f"{label} must be a JSON array")
    return cast(Sequence[object], value)


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MemoryAdvisorError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise MemoryAdvisorError(f"{label} must be finite")
    return result


def _integer(value: object, label: str) -> int:
    result = _number(value, label)
    if not result.is_integer():
        raise MemoryAdvisorError(f"{label} must be an integer")
    return int(result)


def _optional_number(value: object, label: str) -> float | None:
    if value is None:
        return None
    return _number(value, label)


def detect_system_memory() -> SystemMemory:
    """Return total and currently available memory without a required dependency."""

    try:
        psutil = importlib.import_module("psutil")
        virtual_memory = getattr(psutil, "virtual_memory", None)
        if callable(virtual_memory):
            snapshot = virtual_memory()
            total = int(snapshot.total)
            available = int(snapshot.available)
            if total > 0 and available > 0:
                return SystemMemory(total, available, "psutil.virtual_memory")
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        pass

    if os.name == "nt":
        windows_loader = vars(ctypes).get("WinDLL")
        if callable(windows_loader):
            try:
                kernel32 = windows_loader("kernel32", use_last_error=True)
                status = _MemoryStatusEx()
                status.dwLength = ctypes.sizeof(status)
                if kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                    total = int(status.ullTotalPhys)
                    available = int(status.ullAvailPhys)
                    if total > 0 and available > 0:
                        return SystemMemory(total, available, "windows.GlobalMemoryStatusEx")
            except (AttributeError, OSError, TypeError, ValueError):
                pass

    system_configuration = vars(os).get("sysconf")
    if callable(system_configuration):
        try:
            page_size = int(system_configuration("SC_PAGE_SIZE"))
            total_pages = int(system_configuration("SC_PHYS_PAGES"))
            available_pages = int(system_configuration("SC_AVPHYS_PAGES"))
            total = page_size * total_pages
            available = page_size * available_pages
            if total > 0 and available > 0:
                return SystemMemory(total, available, "os.sysconf")
        except (OSError, TypeError, ValueError):
            pass

    return SystemMemory(None, None, "unavailable")


def suggest_memory_budget(memory: SystemMemory) -> tuple[int, str]:
    """Choose a conservative advisory budget while leaving host headroom."""

    if memory.available_bytes is None:
        return 256 * MIB, "fallback_without_system_memory"

    available = memory.available_bytes
    candidate = min(512 * MIB, max(128 * MIB, available // 10))
    candidate = min(candidate, max(32 * MIB, available // 4))
    rounded = max(16 * MIB, (candidate // (16 * MIB)) * (16 * MIB))
    return rounded, "ten_percent_available_capped_at_512_mib"


@lru_cache(maxsize=1)
def runtime_tree_sha256() -> str:
    """Bind calibration evidence to the package bytes actually executing it."""

    root = Path(__file__).resolve().parent
    candidates: list[Path] = []
    for candidate in root.rglob("*"):
        if "__pycache__" in candidate.parts or candidate.suffix in {".pyc", ".pyo"}:
            continue
        if candidate.is_symlink():
            raise MemoryAdvisorError("runtime package tree contains a symbolic link")
        if candidate.is_file():
            candidates.append(candidate)
    if len(candidates) > _MAX_RUNTIME_TREE_FILES:
        raise MemoryAdvisorError("runtime package tree exceeds the file-count limit")

    digest = hashlib.sha256()
    total_bytes = 0
    for candidate in sorted(candidates, key=lambda path: path.relative_to(root).as_posix()):
        relative = candidate.relative_to(root).as_posix().encode("utf-8")
        try:
            size = candidate.stat().st_size
        except OSError as exc:
            raise MemoryAdvisorError(f"cannot inspect runtime package file: {candidate}") from exc
        total_bytes += size
        if total_bytes > _MAX_RUNTIME_TREE_BYTES:
            raise MemoryAdvisorError("runtime package tree exceeds the byte limit")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(size.to_bytes(8, "big"))
        try:
            with candidate.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
        except OSError as exc:
            raise MemoryAdvisorError(f"cannot hash runtime package file: {candidate}") from exc
    return digest.hexdigest()


def current_calibration_contract() -> dict[str, object]:
    memory = detect_system_memory()
    cpu_identity = "|".join(
        (
            platform.processor(),
            os.environ.get("PROCESSOR_IDENTIFIER", ""),
            platform.machine(),
            str(os.cpu_count() or 0),
        )
    ).casefold()
    return {
        "schema_version": CALIBRATION_CONTRACT_SCHEMA_VERSION,
        "polymorph_version": __version__,
        "runtime_tree_sha256": runtime_tree_sha256(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "operating_system": platform.system(),
        "operating_system_release": platform.release(),
        "architecture": platform.machine(),
        "cpu_fingerprint_sha256": hashlib.sha256(cpu_identity.encode("utf-8")).hexdigest(),
        "logical_cpus": os.cpu_count(),
        "total_memory_bytes": memory.total_bytes,
        "connector_id": "sqlite",
        "sqlite_version": sqlite3.sqlite_version,
        "durability_contract": "sqlite-selected-journal-full-sync-v1",
        "signed_audit": True,
        "record_shape_id": WORKFLOW_RECORD_SHAPE_ID,
        "benchmark_report_version": WORKFLOW_BENCHMARK_REPORT_VERSION,
        "event_stream_max_bytes": WORKFLOW_EVENT_STREAM_MAX_BYTES,
    }


def calibration_contract_mismatches(
    observed: object,
    expected: Mapping[str, object],
) -> tuple[str, ...]:
    if not isinstance(observed, dict):
        return ("missing:calibration_contract",)
    observed_contract = cast(Mapping[str, object], observed)
    mismatches: list[str] = []
    for key, expected_value in sorted(expected.items()):
        if key not in observed_contract:
            mismatches.append(f"missing:{key}")
        elif observed_contract[key] != expected_value:
            mismatches.append(f"mismatch:{key}")
    return tuple(mismatches)


def profiles_from_matrix(document: Mapping[str, object]) -> list[BatchProfile]:
    summaries = _sequence(document.get("summaries"), "summaries")
    profiles: list[BatchProfile] = []
    seen: set[int] = set()
    for index, raw_summary in enumerate(summaries):
        summary = _mapping(raw_summary, f"summaries[{index}]")
        batch_size = _integer(summary.get("batch_size"), f"summaries[{index}].batch_size")
        throughput = _number(
            summary.get("throughput_rows_per_second_median"),
            f"summaries[{index}].throughput_rows_per_second_median",
        )
        peak_value = summary.get("peak_rss_bytes_max")
        if peak_value is None:
            peak_value = summary.get("peak_rss_bytes_median")
        peak_rss = _integer(peak_value, f"summaries[{index}].peak_rss_bytes_max")
        runs = _integer(summary.get("runs", 1), f"summaries[{index}].runs")
        if batch_size <= 0 or throughput <= 0 or peak_rss <= 0 or runs <= 0:
            raise MemoryAdvisorError(f"summaries[{index}] contains a non-positive metric")
        if batch_size in seen:
            raise MemoryAdvisorError(f"duplicate batch_size in matrix: {batch_size}")
        seen.add(batch_size)
        profiles.append(BatchProfile(batch_size, throughput, peak_rss, runs))
    if not profiles:
        raise MemoryAdvisorError("matrix contains no batch summaries")
    return sorted(profiles, key=lambda profile: profile.batch_size)


def load_matrix_document(path: Path) -> Mapping[str, object]:
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryAdvisorError(f"cannot read matrix {path}: {exc}") from exc
    return _mapping(raw, "matrix")


def load_profiles(path: Path) -> list[BatchProfile]:
    return profiles_from_matrix(load_matrix_document(path))


def matrix_minimum_authoritative_runs(
    document: Mapping[str, object],
    profiles: Sequence[BatchProfile],
) -> int:
    if not profiles:
        raise MemoryAdvisorError("matrix contains no batch profiles")
    policy = document.get("measurement_policy")
    if isinstance(policy, dict):
        admitted = policy.get("admitted_batch_sizes")
        if isinstance(admitted, list) and admitted:
            admitted_sizes = {
                item for item in admitted if isinstance(item, int) and not isinstance(item, bool)
            }
            authoritative = [
                profile.runs for profile in profiles if profile.batch_size in admitted_sizes
            ]
            if authoritative:
                return min(authoritative)
    return min(profile.runs for profile in profiles)


def recommend_batch(
    profiles: Sequence[BatchProfile],
    *,
    max_ram_bytes: int,
    headroom_percent: float = DEFAULT_HEADROOM_PERCENT,
    near_optimal_percent: float = DEFAULT_NEAR_OPTIMAL_PERCENT,
) -> dict[str, object]:
    """Select the lowest-memory profile within the near-optimal speed band."""

    if max_ram_bytes <= 0:
        raise MemoryAdvisorError("max RAM must be positive")
    if not 0.0 <= headroom_percent < 100.0:
        raise MemoryAdvisorError("headroom percent must be in [0, 100)")
    if not 0.0 <= near_optimal_percent < 100.0:
        raise MemoryAdvisorError("near-optimal percent must be in [0, 100)")
    if not profiles:
        raise MemoryAdvisorError("at least one batch profile is required")

    factor = 1.0 + (headroom_percent / 100.0)
    evaluated: list[tuple[BatchProfile, int]] = []
    for profile in sorted(profiles, key=lambda item: item.batch_size):
        if profile.batch_size <= 0:
            raise MemoryAdvisorError("batch sizes must be positive")
        if profile.throughput_rows_per_second <= 0 or profile.peak_rss_bytes <= 0:
            raise MemoryAdvisorError("profile metrics must be positive")
        required = math.ceil(profile.peak_rss_bytes * factor)
        evaluated.append((profile, required))

    eligible = [item for item in evaluated if item[1] <= max_ram_bytes]
    profile_rows = [
        {
            "batch_size": profile.batch_size,
            "throughput_rows_per_second": profile.throughput_rows_per_second,
            "observed_peak_rss_bytes": profile.peak_rss_bytes,
            "required_budget_bytes": required,
            "runs": profile.runs,
            "eligible": required <= max_ram_bytes,
        }
        for profile, required in evaluated
    ]
    common: dict[str, object] = {
        "advisory_only": True,
        "hard_limit_enforced": False,
        "max_ram_bytes": max_ram_bytes,
        "headroom_percent": headroom_percent,
        "near_optimal_percent": near_optimal_percent,
        "profiles": profile_rows,
    }
    if not eligible:
        minimum_required = min(required for _, required in evaluated)
        return {
            **common,
            "status": "blocked",
            "reason_code": "memory_budget_below_measured_minimum",
            "minimum_required_budget_bytes": minimum_required,
            "recommended_batch_size": None,
        }

    fastest_profile, _ = max(
        eligible,
        key=lambda item: item[0].throughput_rows_per_second,
    )
    near_optimal_floor = fastest_profile.throughput_rows_per_second * (
        1.0 - (near_optimal_percent / 100.0)
    )
    near_optimal = [
        item for item in eligible if item[0].throughput_rows_per_second >= near_optimal_floor
    ]
    selected, selected_required = min(
        near_optimal,
        key=lambda item: (item[0].peak_rss_bytes, item[0].batch_size),
    )
    speed_gap = (
        (fastest_profile.throughput_rows_per_second - selected.throughput_rows_per_second)
        / fastest_profile.throughput_rows_per_second
        * 100.0
    )
    return {
        **common,
        "status": "recommended",
        "reason_code": "lowest_memory_near_optimal_profile",
        "recommended_batch_size": selected.batch_size,
        "expected_throughput_rows_per_second": selected.throughput_rows_per_second,
        "observed_peak_rss_bytes": selected.peak_rss_bytes,
        "required_budget_bytes": selected_required,
        "available_budget_after_observed_peak_bytes": max_ram_bytes - selected.peak_rss_bytes,
        "speed_gap_to_fastest_eligible_percent": speed_gap,
        "fastest_eligible_batch_size": fastest_profile.batch_size,
    }


def discover_latest_matrix(
    root: Path,
    expected_contract: Mapping[str, object] | None = None,
) -> Path:
    candidates = list((root / ".polymorph" / "performance-matrix").glob("*/matrix.json"))
    if not candidates:
        raise MemoryAdvisorError(
            "no local performance matrix found; run the calibrate command first"
        )
    usable: list[tuple[Path, int, int, bool]] = []
    for candidate in candidates:
        try:
            document = load_matrix_document(candidate)
            profiles = profiles_from_matrix(document)
            modified = candidate.stat().st_mtime_ns
        except (MemoryAdvisorError, OSError):
            continue
        exact = expected_contract is None or not calibration_contract_mismatches(
            document.get("calibration_contract"), expected_contract
        )
        usable.append(
            (
                candidate,
                matrix_minimum_authoritative_runs(document, profiles),
                modified,
                exact,
            )
        )
    if not usable:
        raise MemoryAdvisorError("no valid local performance matrix found")
    return max(usable, key=lambda item: (item[3], item[1] >= 3, item[2]))[0]


def atomic_write_json(path: Path, document: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            json.dump(document, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except OSError:
        if temporary_name is not None:
            with suppress(OSError):
                Path(temporary_name).unlink(missing_ok=True)
        raise


def _run_benchmark(records: int, batch_size: int, run_index: int) -> dict[str, object]:
    command = [
        sys.executable,
        "-m",
        "polymorph",
        "benchmark",
        "workflow",
        "--records",
        str(records),
        "--batch-size",
        str(batch_size),
        "--audit",
    ]
    started_at = _utc_now()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    completed_at = _utc_now()
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise MemoryAdvisorError(
            f"workflow benchmark failed for batch {batch_size}: {detail[-1000:]}"
        )
    try:
        raw: object = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise MemoryAdvisorError(
            f"workflow benchmark returned invalid JSON for batch {batch_size}"
        ) from exc
    document = _mapping(raw, "workflow benchmark")
    resources = _mapping(document.get("resources"), "resources")
    workflow = _mapping(document.get("workflow"), "workflow")
    final_state = _mapping(workflow.get("final_state"), "workflow.final_state")
    storage = _mapping(final_state.get("storage_bytes"), "workflow.final_state.storage_bytes")
    stages: dict[str, object] = {}
    for index, raw_stage in enumerate(_sequence(workflow.get("stages"), "workflow.stages")):
        stage = _mapping(raw_stage, f"workflow.stages[{index}]")
        name = stage.get("name")
        if not isinstance(name, str) or not name:
            raise MemoryAdvisorError(f"workflow.stages[{index}].name must be text")
        stages[name] = {
            "status": stage.get("status"),
            "wall_ms": _number(stage.get("wall_ms"), f"{name}.wall_ms"),
            "cpu_ms": _number(stage.get("cpu_ms"), f"{name}.cpu_ms"),
            "throughput_per_second": _number(
                stage.get("throughput_per_second"), f"{name}.throughput_per_second"
            ),
            "calls": _integer(stage.get("calls"), f"{name}.calls"),
            "call_latency_p50_ms": _optional_number(
                stage.get("call_latency_p50_ms"), f"{name}.call_latency_p50_ms"
            ),
            "call_latency_p95_ms": _optional_number(
                stage.get("call_latency_p95_ms"), f"{name}.call_latency_p95_ms"
            ),
        }
    return {
        "run_index": run_index,
        "batch_size": batch_size,
        "records": records,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "throughput_rows_per_second": _number(
            resources.get("throughput_per_second"), "resources.throughput_per_second"
        ),
        "wall_ms": _number(resources.get("wall_ms"), "resources.wall_ms"),
        "cpu_ms": _number(resources.get("cpu_ms"), "resources.cpu_ms"),
        "peak_rss_bytes": _integer(resources.get("peak_rss_bytes"), "resources.peak_rss_bytes"),
        "rss_before_bytes": _integer(
            resources.get("rss_before_bytes"), "resources.rss_before_bytes"
        ),
        "rss_after_bytes": _integer(resources.get("rss_after_bytes"), "resources.rss_after_bytes"),
        "storage_total_bytes": _integer(storage.get("total"), "storage_bytes.total"),
        "success": workflow.get("success") is True,
        "stages": stages,
        "raw_report": dict(document),
    }


def _run_float(run: Mapping[str, object], key: str) -> float:
    return _number(run.get(key), f"run.{key}")


def _run_int(run: Mapping[str, object], key: str) -> int:
    return _integer(run.get(key), f"run.{key}")


def _median_optional(values: Sequence[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return statistics.median(present) if present else None


def summarize_runs(runs: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    batch_sizes = sorted({_run_int(run, "batch_size") for run in runs})
    summaries: list[dict[str, object]] = []
    for batch_size in batch_sizes:
        group = [run for run in runs if _run_int(run, "batch_size") == batch_size]
        throughputs = [_run_float(run, "throughput_rows_per_second") for run in group]
        wall_times = [_run_float(run, "wall_ms") for run in group]
        cpu_times = [_run_float(run, "cpu_ms") for run in group]
        peaks = [_run_int(run, "peak_rss_bytes") for run in group]
        storage_totals = [_run_int(run, "storage_total_bytes") for run in group]
        stage_maps = [_mapping(run.get("stages"), "run.stages") for run in group]
        stage_names = sorted({name for stages in stage_maps for name in stages})
        stage_summary: dict[str, object] = {}
        for name in stage_names:
            stage_group = [
                _mapping(stages[name], f"run.stages.{name}")
                for stages in stage_maps
                if name in stages
            ]
            stage_summary[name] = {
                "median_wall_ms": statistics.median(
                    _number(stage.get("wall_ms"), f"{name}.wall_ms") for stage in stage_group
                ),
                "median_cpu_ms": statistics.median(
                    _number(stage.get("cpu_ms"), f"{name}.cpu_ms") for stage in stage_group
                ),
                "median_throughput_per_second": statistics.median(
                    _number(
                        stage.get("throughput_per_second"),
                        f"{name}.throughput_per_second",
                    )
                    for stage in stage_group
                ),
                "median_call_latency_p50_ms": _median_optional(
                    [
                        _optional_number(
                            stage.get("call_latency_p50_ms"),
                            f"{name}.call_latency_p50_ms",
                        )
                        for stage in stage_group
                    ]
                ),
                "median_call_latency_p95_ms": _median_optional(
                    [
                        _optional_number(
                            stage.get("call_latency_p95_ms"),
                            f"{name}.call_latency_p95_ms",
                        )
                        for stage in stage_group
                    ]
                ),
            }
        summaries.append(
            {
                "batch_size": batch_size,
                "runs": len(group),
                "throughput_rows_per_second_median": statistics.median(throughputs),
                "throughput_rows_per_second_min": min(throughputs),
                "throughput_rows_per_second_max": max(throughputs),
                "wall_ms_median": statistics.median(wall_times),
                "cpu_ms_median": statistics.median(cpu_times),
                "peak_rss_bytes_median": int(statistics.median(peaks)),
                "peak_rss_bytes_max": max(peaks),
                "storage_total_bytes_median": int(statistics.median(storage_totals)),
                "success_count": sum(run.get("success") is True for run in group),
                "stages": stage_summary,
            }
        )
    return summaries


def _profiles_from_summaries(summaries: Sequence[Mapping[str, object]]) -> list[BatchProfile]:
    return [
        BatchProfile(
            batch_size=_integer(summary.get("batch_size"), "summary.batch_size"),
            throughput_rows_per_second=_number(
                summary.get("throughput_rows_per_second_median"),
                "summary.throughput_rows_per_second_median",
            ),
            peak_rss_bytes=_integer(
                summary.get("peak_rss_bytes_max"), "summary.peak_rss_bytes_max"
            ),
            runs=_integer(summary.get("runs"), "summary.runs"),
        )
        for summary in summaries
    ]


def calibrate(
    *,
    records: int,
    repetitions: int,
    batch_sizes: Sequence[int],
    max_ram_bytes: int,
    headroom_percent: float,
    near_optimal_percent: float,
) -> dict[str, object]:
    if records <= 0 or repetitions <= 0:
        raise MemoryAdvisorError("records and repetitions must be positive")
    if max_ram_bytes <= 0:
        raise MemoryAdvisorError("max RAM must be positive")
    if not 0.0 <= headroom_percent < 100.0:
        raise MemoryAdvisorError("headroom percent must be in [0, 100)")
    if not 0.0 <= near_optimal_percent < 100.0:
        raise MemoryAdvisorError("near-optimal percent must be in [0, 100)")
    candidates = sorted(set(batch_sizes))
    if not candidates or candidates[0] <= 0:
        raise MemoryAdvisorError("batch sizes must be positive")

    runs: list[dict[str, object]] = []
    admitted: list[int] = []
    skipped: list[int] = []
    run_index = 0
    factor = 1.0 + (headroom_percent / 100.0)

    for batch_size in candidates:
        run_index += 1
        print(
            f"calibration {run_index}: batch={batch_size} records={records}",
            file=sys.stderr,
            flush=True,
        )
        run = _run_benchmark(records, batch_size, run_index)
        runs.append(run)
        required = math.ceil(_run_int(run, "peak_rss_bytes") * factor)
        if required <= max_ram_bytes:
            admitted.append(batch_size)
            continue
        skipped.extend(candidate for candidate in candidates if candidate > batch_size)
        break

    for repetition in range(1, repetitions):
        order = admitted if repetition % 2 == 0 else list(reversed(admitted))
        for batch_size in order:
            run_index += 1
            print(
                f"calibration {run_index}: batch={batch_size} records={records}",
                file=sys.stderr,
                flush=True,
            )
            runs.append(_run_benchmark(records, batch_size, run_index))

    summaries = summarize_runs(runs)
    profiles = _profiles_from_summaries([_mapping(item, "summary") for item in summaries])
    recommendation = recommend_batch(
        profiles,
        max_ram_bytes=max_ram_bytes,
        headroom_percent=headroom_percent,
        near_optimal_percent=near_optimal_percent,
    )
    first_report = _mapping(runs[0].get("raw_report"), "run.raw_report")
    return {
        "schema_version": CALIBRATION_MATRIX_SCHEMA_VERSION,
        "generated_at_utc": _utc_now(),
        "benchmark": "secure_e2e_memory_calibration",
        "evidence_level": "publishable" if repetitions >= 3 else "preliminary",
        "calibration_contract": current_calibration_contract(),
        "measurement_policy": {
            "records_per_run": records,
            "requested_repetitions_per_batch_size": repetitions,
            "signed_audit": True,
            "candidate_batch_sizes": candidates,
            "admitted_batch_sizes": admitted,
            "skipped_after_budget_observation": skipped,
            "max_ram_bytes": max_ram_bytes,
            "headroom_percent": headroom_percent,
            "near_optimal_percent": near_optimal_percent,
            "hard_limit_enforced": False,
        },
        "environment": first_report.get("environment"),
        "recommendation": recommendation,
        "summaries": summaries,
        "runs": runs,
    }


def _parse_batch_sizes(value: str) -> tuple[int, ...]:
    try:
        values = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("batch sizes must be comma-separated integers") from exc
    if not values or any(item <= 0 for item in values):
        raise argparse.ArgumentTypeError("batch sizes must be positive")
    return values


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be numeric") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be finite and positive")
    return parsed


def _percentage(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("percentage must be numeric") from exc
    if not math.isfinite(parsed) or not 0.0 <= parsed < 100.0:
        raise argparse.ArgumentTypeError("percentage must be finite and in [0, 100)")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    executable = Path(sys.argv[0]).stem.casefold()
    program = (
        Path(sys.argv[0]).name
        if executable in {"polymorph-memory", "polymorph-memory.exe"}
        else "python -m polymorph.memory_advisor"
    )
    parser = argparse.ArgumentParser(
        prog=program,
        description=(
            "Recommend a secure workflow batch size from local evidence and an "
            "advisory RAM budget. No model, network service or GPU is used."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    recommend = subparsers.add_parser(
        "recommend", help="recommend from the latest or selected local matrix"
    )
    recommend.add_argument("--matrix", type=Path)
    recommend.add_argument("--max-ram-mib", type=_positive_float)
    recommend.add_argument(
        "--allow-stale",
        action="store_true",
        help="use mismatched calibration evidence explicitly; never enabled by default",
    )
    recommend.add_argument("--headroom-percent", type=_percentage, default=DEFAULT_HEADROOM_PERCENT)
    recommend.add_argument(
        "--near-optimal-percent",
        type=_percentage,
        default=DEFAULT_NEAR_OPTIMAL_PERCENT,
    )
    recommend.add_argument("--output", type=Path)

    calibration = subparsers.add_parser(
        "calibrate", help="measure this machine and recommend within its RAM budget"
    )
    calibration.add_argument("--max-ram-mib", type=_positive_float)
    calibration.add_argument("--records", type=_positive_int, default=DEFAULT_RECORDS)
    calibration.add_argument("--runs", type=_positive_int, default=1)
    calibration.add_argument(
        "--batch-sizes",
        type=_parse_batch_sizes,
        default=DEFAULT_BATCH_SIZES,
        metavar="LIST",
    )
    calibration.add_argument(
        "--headroom-percent", type=_percentage, default=DEFAULT_HEADROOM_PERCENT
    )
    calibration.add_argument(
        "--near-optimal-percent",
        type=_percentage,
        default=DEFAULT_NEAR_OPTIMAL_PERCENT,
    )
    calibration.add_argument("--output", type=Path)
    return parser


def _resolve_budget(max_ram_mib: float | None) -> tuple[int, str, SystemMemory]:
    memory = detect_system_memory()
    if max_ram_mib is not None:
        return math.floor(max_ram_mib * MIB), "user", memory
    budget, source = suggest_memory_budget(memory)
    return budget, source, memory


def _default_calibration_path(root: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return root / ".polymorph" / "performance-matrix" / stamp / "matrix.json"


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        max_ram_bytes, budget_source, memory = _resolve_budget(args.max_ram_mib)
        if args.command == "recommend":
            expected_contract = current_calibration_contract()
            matrix_path = args.matrix or discover_latest_matrix(
                Path.cwd(), expected_contract=expected_contract
            )
            matrix_document = load_matrix_document(matrix_path)
            profiles = profiles_from_matrix(matrix_document)
            minimum_profile_runs = matrix_minimum_authoritative_runs(matrix_document, profiles)
            mismatches = calibration_contract_mismatches(
                matrix_document.get("calibration_contract"), expected_contract
            )
            recommendation: dict[str, object]
            if mismatches and not args.allow_stale:
                recommendation = {
                    "status": "stale",
                    "reason_code": "calibration_contract_mismatch",
                    "recommended_batch_size": None,
                    "advisory_only": True,
                    "hard_limit_enforced": False,
                }
                binding_status = "stale"
            else:
                recommendation = recommend_batch(
                    profiles,
                    max_ram_bytes=max_ram_bytes,
                    headroom_percent=args.headroom_percent,
                    near_optimal_percent=args.near_optimal_percent,
                )
                binding_status = "stale_allowed" if mismatches else "exact"
            report: dict[str, object] = {
                "schema_version": 1,
                "generated_at_utc": _utc_now(),
                "command": "recommend",
                "matrix": str(matrix_path.resolve()),
                "matrix_evidence": {
                    "level": "publishable" if minimum_profile_runs >= 3 else "preliminary",
                    "minimum_runs_per_profile": minimum_profile_runs,
                },
                "calibration_binding": {
                    "status": binding_status,
                    "mismatches": list(mismatches),
                },
                "memory_budget": {
                    "bytes": max_ram_bytes,
                    "source": budget_source,
                },
                "system_memory": memory.as_json(),
                "recommendation": recommendation,
                "limitations": [
                    "The budget is advisory and does not enforce an OS process limit.",
                    "Recalibrate after material hardware, payload or runtime changes.",
                ],
            }
            if args.output is not None:
                atomic_write_json(args.output, report)
        else:
            matrix = calibrate(
                records=args.records,
                repetitions=args.runs,
                batch_sizes=args.batch_sizes,
                max_ram_bytes=max_ram_bytes,
                headroom_percent=args.headroom_percent,
                near_optimal_percent=args.near_optimal_percent,
            )
            output = args.output or _default_calibration_path(Path.cwd())
            atomic_write_json(output, matrix)
            report = {
                "schema_version": 1,
                "generated_at_utc": _utc_now(),
                "command": "calibrate",
                "artifact": str(output.resolve()),
                "memory_budget": {
                    "bytes": max_ram_bytes,
                    "source": budget_source,
                },
                "system_memory": memory.as_json(),
                "recommendation": matrix["recommendation"],
                "limitations": [
                    "Calibration observes RSS after a run; it is not an OS hard cap.",
                    "The secure benchmark keeps signed audit and durability enabled.",
                ],
            }
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
        result_recommendation = _mapping(report.get("recommendation"), "recommendation")
        return 0 if result_recommendation.get("status") == "recommended" else 2
    except (MemoryAdvisorError, OSError) as exc:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason_code": "memory_advisor_error",
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
