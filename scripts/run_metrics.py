"""Collect sanitized Polymorph Run history and render a local light-mode SVG."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import statistics
from collections.abc import Callable
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_JSON_BYTES = 16 * 1024 * 1024


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_JSON_BYTES:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:
    if type(value) not in (int, float) or not math.isfinite(value):
        return None
    return float(value)


def _integer(value: Any) -> int | None:
    return value if type(value) is int else None


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _nested(payload: dict[str, Any], *keys: str) -> Any:
    value: Any = payload
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _record(folder: Path) -> dict[str, Any] | None:
    run = _load(folder / "01_run.json")
    if not isinstance(run.get("run_id"), str) or not run["run_id"]:
        return None
    device_report = _load(folder / "02_device.json")
    project = _load(folder / "03_project.json")
    lab_report = _load(folder / "04_laboratory.json")
    training_report = _load(folder / "05_training.json")
    comparison = _load(folder / "06_comparison.json")

    device = device_report.get("device")
    device = device if isinstance(device, dict) else {}
    interpreter = device_report.get("interpreter")
    interpreter = interpreter if isinstance(interpreter, dict) else {}
    tests = project.get("tests")
    tests = tests if isinstance(tests, dict) else {}
    workflow_statistics = project.get("workflow_statistics")
    workflow_statistics = workflow_statistics if isinstance(workflow_statistics, dict) else {}
    workflow_measurements = project.get("workflow_measurements")
    workflow_measurements = workflow_measurements if isinstance(workflow_measurements, dict) else {}
    workflow_samples = [
        value
        for key, value in sorted(workflow_measurements.items())
        if key.endswith("-gate") and isinstance(value, dict)
    ]
    rates = [
        number
        for sample in workflow_samples
        if (number := _number(sample.get("throughput_per_second"))) is not None
    ]
    walls = [
        number
        for sample in workflow_samples
        if (number := _number(sample.get("wall_seconds"))) is not None
    ]
    rss_values = [
        number
        for sample in workflow_samples
        if (number := _number(sample.get("peak_rss_mib"))) is not None
    ]
    record_counts = [rate * wall for rate, wall in zip(rates, walls, strict=False)]

    laboratory = lab_report.get("campaign")
    laboratory = laboratory if isinstance(laboratory, dict) else {}
    quality = laboratory.get("quality")
    quality = quality if isinstance(quality, dict) else {}
    precision = quality.get("precision")
    precision = precision if isinstance(precision, dict) else {}
    selftests = lab_report.get("selftests")
    selftests = selftests if isinstance(selftests, dict) else {}

    campaign = training_report.get("campaign")
    campaign = campaign if isinstance(campaign, dict) else {}
    target = training_report.get("target_comparison")
    target = target if isinstance(target, dict) else {}
    current_validation = campaign.get("current_validation")
    current_validation = current_validation if isinstance(current_validation, dict) else {}
    best_validation = campaign.get("best_validation")
    best_validation = best_validation if isinstance(best_validation, dict) else {}

    gpu = device.get("gpu")
    gpu = gpu if isinstance(gpu, dict) else {}
    gpu_devices = gpu.get("devices")
    gpu_devices = gpu_devices if isinstance(gpu_devices, list) else []
    gpu_names = [
        item["name"]
        for item in gpu_devices
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    steps = run.get("steps")
    steps = steps if isinstance(steps, list) else []
    source = run.get("source_after")
    source = source if isinstance(source, dict) else {}
    archive = folder.parent / f"{run['run_id']}.zip"

    started = run.get("started_at")
    finished = run.get("finished_at")
    duration: float | None = None
    if isinstance(started, str) and isinstance(finished, str):
        with contextlib.suppress(ValueError):
            duration = (
                datetime.fromisoformat(finished) - datetime.fromisoformat(started)
            ).total_seconds()

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run["run_id"],
        "started_at": started,
        "finished_at": finished,
        "status": run.get("status"),
        "mode": run.get("mode"),
        "commit": source.get("commit"),
        "source_dirty": source.get("dirty"),
        "duration_seconds": duration,
        "archive_bytes": archive.stat().st_size if archive.is_file() else None,
        "steps": {
            str(step.get("name")): {
                "status": step.get("status"),
                "wall_seconds": _number(step.get("wall_seconds")),
            }
            for step in steps
            if isinstance(step, dict) and isinstance(step.get("name"), str)
        },
        "environment": {
            "python": interpreter.get("python"),
            "architecture": interpreter.get("architecture"),
            "cpu_model": device.get("cpu_model"),
            "logical_cpus": _integer(device.get("logical_cpus")),
            "physical_cores": _integer(device.get("physical_cores")),
            "ram_total_mib": (
                value / (1024 * 1024)
                if (value := _number(device.get("ram_total_bytes"))) is not None
                else None
            ),
            "gpu_names": gpu_names,
            "gpu_inventory_status": gpu.get("status"),
        },
        "tests": {
            key: _integer(tests.get(key))
            for key in ("collected", "passed", "skipped", "failed", "errors")
        },
        "workflow": {
            "samples": len(rates),
            "records_per_sample_estimate": (
                round(statistics.median(record_counts)) if record_counts else None
            ),
            "rows_per_second": rates,
            "median_rows_per_second": _number(workflow_statistics.get("median_records_per_second"))
            or _median(rates),
            "min_rows_per_second": min(rates) if rates else None,
            "max_rows_per_second": max(rates) if rates else None,
            "wall_seconds": walls,
            "median_wall_seconds": _median(walls),
            "peak_rss_mib": rss_values,
            "max_peak_rss_mib": max(rss_values) if rss_values else None,
        },
        "laboratory": {
            "selftests": _integer(selftests.get("test_count")),
            "unique_cases": _integer(quality.get("unique_cases")),
            "case_executions": _integer(quality.get("case_executions_including_repeats")),
            "verified_rows": _integer(quality.get("verified_rows")),
            "case_failures": _integer(quality.get("case_failures")),
            "unsafe_auto": _integer(quality.get("unsafe_auto")),
            "auto_decisions": _integer(quality.get("auto_decisions")),
            "correct_auto": _integer(quality.get("correct_auto")),
            "observed_precision": _number(precision.get("observed_precision")),
            "automation_coverage": _number(quality.get("automation_coverage")),
        },
        "training": {
            "status": training_report.get("status"),
            "round": _integer(campaign.get("round")),
            "checkpoint": _integer(campaign.get("checkpoint")),
            "updates": _integer(campaign.get("updates")),
            "best_updates": _integer(campaign.get("best_updates")),
            "completed_epochs": _integer(campaign.get("completed_epochs")),
            "gpu_used": campaign.get("gpu_used"),
            "pair_count": _integer(campaign.get("pair_count")),
            "unique_train_queries": _integer(campaign.get("unique_train_queries")),
            "current_top1_accuracy": _number(current_validation.get("top1_accuracy")),
            "best_top1_accuracy": _number(best_validation.get("top1_accuracy")),
            "current_mrr": _number(current_validation.get("mrr")),
            "active_wall_seconds": (
                value / 1000
                if (value := _number(campaign.get("active_wall_ms"))) is not None
                else None
            ),
            "reason": campaign.get("reason"),
        },
        "candidate_comparison": {
            key: target.get(key)
            for key in (
                "status",
                "queries",
                "deterministic_correct",
                "untrained_correct",
                "trained_correct",
                "paired_gains",
                "paired_regressions",
                "unsafe_auto",
                "authority_identical",
                "writes_performed",
                "activated",
                "split",
            )
        },
        "historical_comparison_status": comparison.get("status"),
    }


def collect(project: Path) -> list[dict[str, Any]]:
    outgoing = project / ".polymorph" / "checkbuddy" / "outgoing"
    records: dict[str, dict[str, Any]] = {}
    if outgoing.is_dir():
        for folder in sorted(outgoing.iterdir()):
            if folder.is_dir() and not folder.is_symlink():
                record = _record(folder)
                if record is not None:
                    records[record["run_id"]] = record
    return sorted(
        records.values(), key=lambda item: (str(item.get("finished_at") or ""), item["run_id"])
    )


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(value, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def _timestamp(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _chart(records: list[dict[str, Any]]) -> str:
    width, height = 1400, 860
    left, right = 110, 1340
    chart_top, chart_height, gap = 150, 170, 42
    times = [_timestamp(record.get("finished_at")) for record in records]
    valid_times = [value for value in times if value is not None]
    low_time = min(valid_times) if valid_times else 0.0
    high_time = max(valid_times) if valid_times else 1.0
    if high_time <= low_time:
        high_time = low_time + 1.0

    def x_at(index: int) -> float:
        timestamp = times[index]
        if timestamp is None:
            return left + (right - left) * index / max(1, len(records) - 1)
        return left + (right - left) * (timestamp - low_time) / (high_time - low_time)

    panels: list[tuple[str, str, Callable[[dict[str, Any]], Any], float | None]] = [
        (
            "Workflow throughput",
            "rows/s",
            lambda item: _nested(item, "workflow", "median_rows_per_second"),
            None,
        ),
        (
            "Peak resident memory",
            "MiB",
            lambda item: _nested(item, "workflow", "max_peak_rss_mib"),
            None,
        ),
        (
            "Trained advisory top-1",
            "%",
            lambda item: (
                value * 100
                if (value := _number(_nested(item, "training", "current_top1_accuracy")))
                is not None
                else None
            ),
            100.0,
        ),
    ]
    parts = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}">'
        ),
        (
            "<style>text{font-family:'Segoe UI',sans-serif;fill:#17352f}"
            ".title{font-size:34px;font-weight:700}"
            ".sub{font-size:16px;fill:#58736c}"
            ".label{font-size:18px;font-weight:650}"
            ".tick{font-size:13px;fill:#6b817b}"
            ".value{font-size:12px;font-weight:600}</style>"
        ),
        '<rect width="1400" height="860" rx="24" fill="#f7fbf8"/>',
        '<path d="M0 0H1400V88C1130 122 940 35 674 75S210 145 0 92Z" fill="#dcefe5"/>',
        '<text x="72" y="62" class="title">Polymorph Run history</text>',
        (
            f'<text x="74" y="108" class="sub">{len(records)} local runs, '
            "append-only and sanitized for trend analysis</text>"
        ),
    ]
    colors = ("#087f5b", "#d97706", "#1d4ed8")
    for panel_index, (title, unit, getter, fixed_max) in enumerate(panels):
        top = chart_top + panel_index * (chart_height + gap)
        bottom = top + chart_height
        values = [_number(getter(record)) for record in records]
        present = [value for value in values if value is not None]
        maximum = fixed_max or (max(present) * 1.12 if present else 1.0)
        maximum = max(maximum, 1.0)
        parts += [
            (
                f'<rect x="56" y="{top - 36}" width="1328" '
                f'height="{chart_height + 60}" rx="18" fill="#ffffff" '
                'stroke="#dce8e3"/>'
            ),
            f'<text x="78" y="{top - 9}" class="label">{escape(title)}</text>',
            f'<text x="1320" y="{top - 9}" text-anchor="end" class="tick">{escape(unit)}</text>',
        ]
        for grid in range(5):
            y = bottom - chart_height * grid / 4
            label = maximum * grid / 4
            parts.append(
                f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" stroke="#e5eeea"/>'
            )
            parts.append(
                f'<text x="96" y="{y + 5:.1f}" text-anchor="end" class="tick">{label:.0f}</text>'
            )
        points: list[tuple[float, float, float, str]] = []
        for index, value in enumerate(values):
            if value is None:
                continue
            x = x_at(index)
            y = bottom - chart_height * min(1.0, max(0.0, value / maximum))
            points.append((x, y, value, str(records[index].get("status"))))
        if len(points) > 1:
            coordinates = " ".join(f"{x:.1f},{y:.1f}" for x, y, _, _ in points)
            parts.append(
                f'<polyline points="{coordinates}" fill="none" '
                f'stroke="{colors[panel_index]}" stroke-width="4" '
                'stroke-linejoin="round" stroke-linecap="round"/>'
            )
        for x, y, value, status in points:
            fill = colors[panel_index] if status == "passed" else "#c2410c"
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="{fill}"/>')
            parts.append(
                f'<text x="{x:.1f}" y="{y - 11:.1f}" text-anchor="middle" '
                f'class="value">{value:.1f}</text>'
            )
    timeline_y = 812
    parts.append('<text x="72" y="785" class="label">Run status over time</text>')
    for index, record in enumerate(records):
        x = x_at(index)
        color = "#16a34a" if record.get("status") == "passed" else "#dc6b28"
        parts.append(
            f'<rect x="{x - 6:.1f}" y="{timeline_y}" width="12" height="22" rx="4" fill="{color}"/>'
        )
    if records:
        first = str(records[0].get("finished_at") or "")[:10]
        last = str(records[-1].get("finished_at") or "")[:10]
        parts.append(f'<text x="{left}" y="854" class="tick">{escape(first)}</text>')
        parts.append(
            f'<text x="{right}" y="854" text-anchor="end" class="tick">{escape(last)}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def write_outputs(
    project: Path, records: list[dict[str, Any]], *, export_public: bool
) -> dict[str, Path]:
    local = project / ".polymorph" / "metrics"
    history = local / "run-history.jsonl"
    latest = local / "latest.json"
    chart = local / "performance-history.svg"
    encoded = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        for record in records
    )
    _atomic_text(history, encoded)
    _atomic_text(
        latest, json.dumps(records[-1] if records else {}, indent=2, sort_keys=True) + "\n"
    )
    _atomic_text(chart, _chart(records))
    outputs = {"history": history, "latest": latest, "chart": chart}
    if export_public:
        public_history = project / "benchmarks" / "results" / "run-history.jsonl"
        public_chart = project / "docs" / "assets" / "performance-history.svg"
        _atomic_text(public_history, encoded)
        _atomic_text(public_chart, _chart(records))
        outputs.update(public_history=public_history, public_chart=public_chart)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument(
        "--export-public",
        action="store_true",
        help="also refresh tracked sanitized JSONL and SVG files; does not commit or push",
    )
    args = parser.parse_args()
    project = args.project.absolute()
    if not (project / "pyproject.toml").is_file():
        parser.error("project must contain pyproject.toml")
    records = collect(project)
    outputs = write_outputs(project, records, export_public=args.export_public)
    print(
        json.dumps(
            {"records": len(records), **{key: str(value) for key, value in outputs.items()}},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
