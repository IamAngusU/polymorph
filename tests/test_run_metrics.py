from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_metrics.py"
SPEC = importlib.util.spec_from_file_location("tested_run_metrics", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
run_metrics = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_metrics
SPEC.loader.exec_module(run_metrics)


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_collects_sanitized_history_and_renders_light_chart(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    outgoing = project / ".polymorph" / "checkbuddy" / "outgoing"
    folder = outgoing / "20260912T100000Z-12345678"
    folder.mkdir(parents=True)
    _write(
        folder / "01_run.json",
        {
            "run_id": folder.name,
            "started_at": "2026-09-12T10:00:00+00:00",
            "finished_at": "2026-09-12T10:03:00+00:00",
            "status": "passed",
            "mode": "all",
            "source_after": {"commit": "a" * 40, "dirty": False},
            "steps": [{"name": "contracts", "status": "passed", "wall_seconds": 70}],
        },
    )
    _write(
        folder / "02_device.json",
        {
            "interpreter": {"python": "3.11.9", "architecture": "AMD64"},
            "device": {
                "cpu_model": "Fixture CPU",
                "logical_cpus": 8,
                "physical_cores": 4,
                "ram_total_bytes": 16 * 1024 * 1024,
                "gpu": {"status": "detected", "devices": [{"name": "Fixture GPU"}]},
            },
        },
    )
    _write(
        folder / "03_project.json",
        {
            "tests": {"collected": 10, "passed": 10, "skipped": 0, "failed": 0, "errors": 0},
            "workflow_statistics": {"median_records_per_second": 400.0},
            "workflow_measurements": {
                "workflow-1-gate": {
                    "throughput_per_second": 400.0,
                    "wall_seconds": 2.5,
                    "peak_rss_mib": 80.0,
                }
            },
        },
    )
    _write(
        folder / "04_laboratory.json",
        {
            "selftests": {"test_count": 193},
            "campaign": {
                "quality": {
                    "unique_cases": 108,
                    "verified_rows": 3600,
                    "case_failures": 0,
                    "unsafe_auto": 0,
                    "precision": {"observed_precision": 1.0},
                }
            },
        },
    )
    _write(
        folder / "05_training.json",
        {
            "status": "completed",
            "campaign": {
                "round": 8,
                "updates": 94502,
                "gpu_used": False,
                "current_validation": {"top1_accuracy": 0.75},
            },
            "target_comparison": {
                "status": "completed",
                "queries": 84,
                "untrained_correct": 47,
                "trained_correct": 61,
                "paired_gains": 14,
                "paired_regressions": 0,
            },
        },
    )
    _write(folder / "06_comparison.json", {"status": "no_comparable_baseline"})

    records = run_metrics.collect(project)
    outputs = run_metrics.write_outputs(project, records, export_public=True)

    assert len(records) == 1
    assert records[0]["duration_seconds"] == 180
    assert records[0]["workflow"]["median_rows_per_second"] == 400
    assert records[0]["workflow"]["max_peak_rss_mib"] == 80
    assert records[0]["laboratory"]["verified_rows"] == 3600
    assert records[0]["training"]["gpu_used"] is False
    assert records[0]["candidate_comparison"]["paired_gains"] == 14
    chart = outputs["chart"].read_text(encoding="utf-8")
    assert 'fill="#f7fbf8"' in chart
    assert "Polymorph Run history" in chart
    assert "Fixture CPU" not in chart
    assert outputs["public_history"].is_file()
