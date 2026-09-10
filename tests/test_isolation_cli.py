from __future__ import annotations

import json
from pathlib import Path

import pytest

from polymorph.cli import _parser_worker_status, build_parser
from polymorph.isolation import SandboxError, SandboxErrorCode


def test_isolated_content_cli_defaults_to_strict_os_containment() -> None:
    args = build_parser().parse_args(["inspect", "isolated-content", "input.bin"])

    assert args.backend == "auto"
    assert args.require_containment == "os-sandbox"
    assert args.timeout == 15.0
    assert args.max_input_mib == 512


def test_isolated_content_cli_runs_explicit_process_worker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "misleading.xlsx"
    source.write_text("customer,amount\nA,1\n", encoding="utf-8")
    args = build_parser().parse_args(
        [
            "inspect",
            "isolated-content",
            str(source),
            "--backend",
            "process",
            "--require-containment",
            "process",
        ]
    )

    args.func(args)
    payload = json.loads(capsys.readouterr().out)

    assert payload["content"]["kind"] == "delimited_text"
    assert payload["content"]["path"] == "<snapshot>"
    assert payload["worker"]["scope"] == "content_inspection_only"
    assert payload["worker"]["structured_parsers_isolated"] is False
    assert payload["worker"]["success"] is True
    assert payload["worker"]["backend"] == "process"
    assert payload["worker"]["os_sandboxed"] is False
    assert payload["worker"]["snapshot"]["size_bytes"] == source.stat().st_size
    assert payload["worker"]["timing_ms"]["end_to_end"] > 0
    assert payload["worker"]["protocol_output_bytes"]["stdout"] > 0
    assert payload["worker"]["protocol_output_bytes"]["stderr"] == 0


def test_isolated_content_cli_does_not_silently_downgrade_strict_policy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    args = build_parser().parse_args(
        ["inspect", "isolated-content", str(source), "--backend", "process"]
    )

    with pytest.raises(SandboxError) as caught:
        args.func(args)

    assert caught.value.code is SandboxErrorCode.CONTAINMENT_TOO_WEAK


def test_parser_worker_benchmark_reports_repeatable_real_timings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    args = build_parser().parse_args(
        [
            "benchmark",
            "parser-worker",
            str(source),
            "--runs",
            "2",
            "--backend",
            "process",
            "--require-containment",
            "process",
        ]
    )

    args.func(args)
    payload = json.loads(capsys.readouterr().out)

    assert payload["runs"] == 2
    assert payload["success"] is True
    assert payload["consistent"] is True
    assert payload["content_kind"] == "delimited_text"
    assert payload["timing_ms"]["end_to_end"]["p50"] > 0
    assert payload["timing_ms"]["worker"]["p95"] > 0
    assert len(payload["samples"]) == 2
    assert payload["timing_ms"]["cold_end_to_end"] > 0
    assert payload["timing_ms"]["warm_end_to_end"]["p50"] > 0
    assert payload["resource_observation"]["mode"] in {
        "sampled_process_tree",
        "unavailable",
    }
    if payload["resource_observation"]["mode"] == "sampled_process_tree":
        assert payload["child_peak_rss_bytes"] > 0
        assert payload["child_cpu_seconds_max"] >= 0
        assert payload["resource_observation"]["successful_sample_count"] > 0
        assert all(sample["resource_sample_count"] > 0 for sample in payload["samples"])
    else:
        assert payload["child_peak_rss_bytes"] is None
    assert set(payload["limits"]) == {
        "wall_timeout_seconds",
        "cpu_seconds",
        "max_memory_bytes",
        "max_input_bytes",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "max_open_files",
        "max_processes",
        "max_output_file_bytes",
        "max_parser_log_bytes",
        "max_tmpfs_bytes",
    }


def test_parser_worker_benchmark_rejects_unbounded_run_count(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    args = build_parser().parse_args(
        [
            "benchmark",
            "parser-worker",
            str(source),
            "--runs",
            "101",
            "--backend",
            "process",
            "--require-containment",
            "process",
        ]
    )

    with pytest.raises(ValueError, match="--runs"):
        args.func(args)


def test_parser_worker_benchmark_writes_stable_failure_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.csv"
    output = tmp_path / "worker-failure.json"
    source.write_text("a,b\n1,2\n", encoding="utf-8")

    def fail_worker(*_args: object, **_kwargs: object) -> object:
        raise SandboxError(
            SandboxErrorCode.WORKER_TIMEOUT,
            "parser worker exceeded its wall-time budget",
            stderr_digest="ab" * 32,
        )

    monkeypatch.setattr("polymorph.cli.ParserWorkerClient.inspect_content", fail_worker)
    args = build_parser().parse_args(
        [
            "benchmark",
            "parser-worker",
            str(source),
            "--backend",
            "process",
            "--require-containment",
            "process",
            "--output",
            str(output),
        ]
    )

    with pytest.raises(SandboxError) as caught:
        args.func(args)

    assert caught.value.code is SandboxErrorCode.WORKER_TIMEOUT
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["success"] is False
    assert payload["completed_runs"] == 0
    assert payload["failed_run"] == 1
    assert payload["failure"]["reason_code"] == "worker_timeout"
    assert payload["failure"]["stderr_sha256"] == "ab" * 32
    assert payload["failure"]["diagnostic"]["category"] == "parser_containment"


def test_doctor_reports_worker_scope_and_honest_backend_capabilities() -> None:
    status = _parser_worker_status()

    assert status["scope"] == "content_inspection_only"
    assert status["structured_parsers_isolated"] is False
    assert status["default_minimum_level"] == "os_sandbox"
    backends = {item["name"]: item for item in status["backends"]}
    assert set(backends) == {"bubblewrap", "process"}
    assert backends["process"]["available"] is True
    assert "separate_process" in backends["process"]["capabilities"]
