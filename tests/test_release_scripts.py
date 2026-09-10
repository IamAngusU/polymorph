from __future__ import annotations

import ast
import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.bootstrap import (
    PythonDetails,
    _parse_args,
    _require_matching_venv,
    _research_profiles,
)
from scripts.check_sdist import (
    archive_file_paths,
    expected_release_paths,
    mismatched_release_paths,
    missing_release_paths,
)
from scripts.check_workflow_performance import (
    _expected_atomic_batch_events,
    evaluate_report,
    load_report,
)


def _passing_workflow_report() -> dict[str, object]:
    records = 1_000
    return {
        "benchmark": "workflow",
        "version": 1,
        "measurement": {
            "mode": "standard",
            "python_allocation_tracing": False,
        },
        "resources": {
            "throughput_per_second": 350.0,
            "wall_ms": 2_857.0,
            "peak_rss_bytes": 100 * 1024 * 1024,
            "result_count": records,
            "measurement_mode": "standard",
            "python_allocation_tracing": False,
        },
        "workflow": {
            "success": True,
            "failure": None,
            "configuration": {
                "records": records,
                "batch_size": 100,
                "signed_audit": True,
            },
            "progress": {
                "records_read": records,
                "records_staged": records,
                "records_relayed": records,
                "records_leased": records,
                "records_delivered": records,
                "records_acknowledged": records,
                "batches_completed": 10,
            },
            "final_state": {
                "destination_rows": records,
                "ledger_committed": records,
                "outbox_depth": 0,
                "relay_depth": 0,
                "quarantine_depth": 0,
                "mismatch_count": 0,
                "content_verified": True,
                "known_plaintext_canaries_absent": True,
                "audit_signatures_verified": True,
                "audit_events": records,
                "sqlite_durability": {
                    "destination": {"synchronous": 2},
                    "blind_state_synchronous_levels": [2],
                },
            },
            "observability": {
                "stream_valid": True,
                "run_closed": True,
                "workflow_lifecycle_valid": True,
                "event_ids_unique": True,
                "event_contract_valid": True,
                "workflow_counts_valid": True,
                "event_types": {"delivery": records, "delivery_batch": 10},
            },
            "stages": [
                {
                    "name": name,
                    "status": "passed",
                    "reason_code": None,
                    "calls": 10,
                    "items_processed": records,
                }
                for name in (
                    "source_seal_and_outbox_stage",
                    "outbox_reload_and_relay_enqueue",
                    "relay_lease",
                    "destination_delivery",
                    "acknowledgements",
                )
            ],
        },
    }


def test_workflow_performance_gate_accepts_complete_report() -> None:
    result = evaluate_report(
        _passing_workflow_report(),
        min_throughput=125,
        max_wall_seconds=8,
        max_peak_rss_mib=200,
        expected_records=1_000,
        expected_batch_size=100,
    )

    assert result["passed"] is True
    assert result["failures"] == []
    assert result["batch_size"] == 100
    assert result["batches"] == 10
    assert result["observed"] == {
        "throughput_per_second": 350.0,
        "wall_seconds": 2.857,
        "peak_rss_mib": 100.0,
    }


def test_workflow_performance_gate_reports_integrity_and_resource_regressions() -> None:
    report = _passing_workflow_report()
    resources = report["resources"]
    workflow = report["workflow"]
    assert isinstance(resources, dict)
    assert isinstance(workflow, dict)
    resources["throughput_per_second"] = 50.0
    resources["wall_ms"] = 20_000.0
    resources["peak_rss_bytes"] = 300 * 1024 * 1024
    workflow["success"] = False

    result = evaluate_report(
        report,
        min_throughput=125,
        max_wall_seconds=8,
        max_peak_rss_mib=200,
        expected_records=1_000,
        expected_batch_size=100,
    )

    assert result["passed"] is False
    assert result["failures"] == [
        "workflow_not_successful",
        "throughput_below_floor",
        "wall_time_above_ceiling",
        "peak_rss_above_ceiling",
    ]


def test_workflow_performance_gate_rejects_wrong_or_fake_batch_shape() -> None:
    report = _passing_workflow_report()
    workflow = report["workflow"]
    assert isinstance(workflow, dict)
    configuration = workflow["configuration"]
    observability = workflow["observability"]
    assert isinstance(configuration, dict)
    assert isinstance(observability, dict)
    configuration["batch_size"] = 50
    observability["event_types"] = {"delivery": 1_000}

    result = evaluate_report(
        report,
        min_throughput=125,
        max_wall_seconds=8,
        max_peak_rss_mib=200,
        expected_records=1_000,
        expected_batch_size=100,
    )

    assert result["passed"] is False
    assert "configuration_batch_size_mismatch" in result["failures"]
    assert "progress_batch_count_mismatch" in result["failures"]
    assert "observability_delivery_batch_event_count_mismatch" in result["failures"]
    assert "stage_destination_delivery_call_count_mismatch" in result["failures"]


@pytest.mark.parametrize(
    ("records", "batch_size", "expected"),
    ((1_000, 100, 10), (5, 2, 2), (3_002, 1_501, 4), (3_000, 1, 0)),
)
def test_workflow_performance_gate_counts_real_atomic_batch_events(
    records: int,
    batch_size: int,
    expected: int,
) -> None:
    assert _expected_atomic_batch_events(records, batch_size) == expected


def test_workflow_performance_gate_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    report = tmp_path / "workflow.json"
    report.write_text('{"benchmark":"workflow","benchmark":"fake"}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate key"):
        load_report(report)


def _write_sdist(path: Path, names: tuple[str, ...]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name in names:
            payload = name.encode("utf-8")
            info = tarfile.TarInfo(f"polymorph_bridge-1.0/{name}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def _write_sdist_contents(path: Path, contents: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in contents.items():
            info = tarfile.TarInfo(f"polymorph_bridge-1.0/{name}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def test_sdist_gate_requires_every_current_package_source() -> None:
    root = Path(__file__).resolve().parent.parent
    current_source = {
        path.relative_to(root).as_posix()
        for path in (root / "src" / "polymorph").rglob("*")
        if path.is_file() and (path.suffix == ".py" or path.name == "py.typed")
    }

    assert expected_release_paths(root).issuperset(current_source)


def test_sdist_gate_reports_missing_source_file(tmp_path) -> None:
    sdist = tmp_path / "release.tar.gz"
    _write_sdist(sdist, ("pyproject.toml", "src/polymorph/__init__.py"))

    assert missing_release_paths(
        sdist,
        {
            "pyproject.toml",
            "src/polymorph/__init__.py",
            "src/polymorph/sqlite_safety.py",
        },
    ) == ["src/polymorph/sqlite_safety.py"]


def test_sdist_gate_normalizes_one_release_root(tmp_path) -> None:
    sdist = tmp_path / "release.tar.gz"
    _write_sdist(sdist, ("pyproject.toml", "src/polymorph/new_module.py"))

    assert archive_file_paths(sdist) == {
        "pyproject.toml",
        "src/polymorph/new_module.py",
    }


def test_sdist_gate_accepts_files_matching_workspace_bytes(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    local = workspace / "src" / "polymorph" / "new_module.py"
    local.parent.mkdir(parents=True)
    local.write_bytes(b"current release bytes\n")
    sdist = tmp_path / "release.tar.gz"
    _write_sdist_contents(
        sdist,
        {"src/polymorph/new_module.py": local.read_bytes()},
    )

    assert (
        mismatched_release_paths(
            sdist,
            {"src/polymorph/new_module.py"},
            root=workspace,
        )
        == []
    )


def test_sdist_gate_reports_stale_file_bytes(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    local = workspace / "tests" / "fixtures" / "LICENSE.txt"
    local.parent.mkdir(parents=True)
    local.write_bytes(b"corrected upstream notice\n")
    sdist = tmp_path / "release.tar.gz"
    _write_sdist_contents(
        sdist,
        {"tests/fixtures/LICENSE.txt": b"incorrect upstream notice\n"},
    )

    assert mismatched_release_paths(
        sdist,
        {"tests/fixtures/LICENSE.txt"},
        root=workspace,
    ) == ["tests/fixtures/LICENSE.txt"]


def test_recovery_manifest_matches_every_executable_recovery_test() -> None:
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads(
        (root / "benchmarks" / "recovery-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["schema_version"] == 1
    assert manifest["suite"] == "recovery-stress"
    scenarios = manifest["scenarios"]
    assert isinstance(scenarios, list) and scenarios
    assert all(
        isinstance(item, dict) and {"id", "test", "boundary", "expected"} <= set(item)
        for item in scenarios
    )
    scenario_ids = [item["id"] for item in scenarios]
    declared_tests = [item["test"] for item in scenarios]
    assert len(scenario_ids) == len(set(scenario_ids))
    assert len(declared_tests) == len(set(declared_tests))

    executable_tests = set()
    for test_file in ("test_recovery_stress.py", "test_recovery_processes.py"):
        tree = ast.parse((root / "tests" / test_file).read_text(encoding="utf-8"))
        executable_tests.update(
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        )
    assert set(declared_tests) == executable_tests


@pytest.mark.parametrize(
    "existing",
    (
        PythonDetails((3, 11), "amd64", "win-amd64", 64),
        PythonDetails((3, 14), "arm64", "win-arm64", 64),
        PythonDetails((3, 14), "amd64", "win32", 32),
    ),
)
def test_bootstrap_rejects_existing_venv_from_different_python(existing) -> None:
    requested = PythonDetails((3, 14), "amd64", "win-amd64", 64)

    with pytest.raises(SystemExit, match=r"Existing \.venv does not match --python"):
        _require_matching_venv(requested, existing)


def test_bootstrap_accepts_exact_requested_python() -> None:
    requested = PythonDetails((3, 14), "arm64", "win-arm64", 64)

    _require_matching_venv(requested, requested)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    (
        ([], ()),
        (["--skip-models"], ()),
        (["--include-research-encoder"], ("multilingual-cpu",)),
        (["--include-research-reranker"], ("reranker-multilingual-cpu",)),
        (
            ["--include-research-encoder", "--include-research-reranker"],
            ("multilingual-cpu", "reranker-multilingual-cpu"),
        ),
    ),
)
def test_bootstrap_model_selection_is_explicit(
    arguments: list[str],
    expected: tuple[str, ...],
) -> None:
    assert _research_profiles(_parse_args(arguments)) == expected


def test_bootstrap_rejects_skip_models_with_research_model() -> None:
    with pytest.raises(SystemExit) as captured:
        _parse_args(["--skip-models", "--include-research-encoder"])

    assert captured.value.code == 2
