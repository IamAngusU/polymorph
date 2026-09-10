from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_local.py"
SPEC = importlib.util.spec_from_file_location("polymorph_local_validator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validation
SPEC.loader.exec_module(validation)


@pytest.mark.parametrize("number", ["nan", "inf", "-inf", "0", "-1", "no"])
def test_limits_reject_invalid_values(number: str) -> None:
    with pytest.raises(SystemExit):
        validation.parse_args(["--timeout", number])


def test_plan_reuses_existing_tests_and_integrity_gate(tmp_path: Path) -> None:
    steps = validation.make_steps(tmp_path, validation.parse_args([]))
    assert len(steps) == 14
    assert len({step.name for step in steps}) == len(steps)
    tests = next(step for step in steps if step.name == "tests")
    assert "--strict-markers" in tests.args
    assert "--cov=polymorph" in tests.args
    for index in range(1, 4):
        run = next(step for step in steps if step.name == f"workflow-{index}")
        gate = next(step for step in steps if step.name == f"workflow-{index}-gate")
        assert run.after == ("tests",)
        assert "1000" in run.args and "100" in run.args
        assert gate.after == (run.name,)
        assert gate.args[0] == "scripts/check_workflow_performance.py"
        assert "--expected-records" in gate.args
    assert all("install" not in step.args for step in steps)
    assert all("--models" not in step.args for step in steps)


def test_listing_does_not_create_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validation, "ROOT", tmp_path)
    assert validation.main(["--list"]) == 0
    assert list(tmp_path.iterdir()) == []


def test_missing_tool_blocks_without_installing(tmp_path: Path) -> None:
    result = validation.run_step(
        validation.Step("missing", ("-c", "raise AssertionError"), ("nonexistent_test_tool_xyz",)),
        tmp_path,
        tmp_path,
        os.environ.copy(),
        5,
    )
    assert result.status == "blocked"
    assert result.returncode is None
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(("exit_code", "status"), [(0, "passed"), (3, "failed")])
def test_real_subprocess_exit_and_log_hash(tmp_path: Path, exit_code: int, status: str) -> None:
    result = validation.run_step(
        validation.Step("child", ("-c", f"print('fixture'); raise SystemExit({exit_code})")),
        tmp_path,
        tmp_path,
        os.environ.copy(),
        5,
    )
    assert result.status == status
    assert result.returncode == exit_code
    assert len(result.log_sha256) == 64
    assert (tmp_path / "child.log").read_text().strip() == "fixture"


def test_hung_command_times_out(tmp_path: Path) -> None:
    result = validation.run_step(
        validation.Step("hang", ("-c", "import time; time.sleep(30)")),
        tmp_path,
        tmp_path,
        os.environ.copy(),
        0.1,
    )
    assert result.status == "failed"
    assert result.reason == "timeout"
    assert result.seconds < 15


def test_output_flood_is_not_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validation, "MAX_LOG_BYTES", 1000)
    result = validation.run_step(
        validation.Step("flood", ("-c", "print('x' * 10000)")),
        tmp_path,
        tmp_path,
        os.environ.copy(),
        5,
    )
    assert result.status == "failed"
    assert result.reason == "log_limit"


def test_junit_distinguishes_passes_from_skips(tmp_path: Path) -> None:
    path = tmp_path / "tests.xml"
    path.write_text(
        '<testsuites><testsuite errors="0"><testcase/><testcase><skipped/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    assert validation.test_totals(path) == {
        "collected": 2,
        "passed": 1,
        "failed": 0,
        "errors": 0,
        "skipped": 1,
    }


@pytest.mark.parametrize(
    "xml",
    [
        "<testsuites/>",
        "<testsuite><testcase><skipped/></testcase></testsuite>",
        "<testsuite><testcase/><testcase><failure/></testcase></testsuite>",
        '<testsuite errors="1"><testcase/></testsuite>',
    ],
)
def test_unproven_junit_never_passes(tmp_path: Path, xml: str) -> None:
    path = tmp_path / "tests.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(ValueError):
        validation.test_totals(path)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _repository(root: Path) -> None:
    _git(root, "init")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "config", "core.hooksPath", str(root / "no-hooks"))
    _git(root, "config", "user.name", "Fixture")
    _git(root, "config", "user.email", "fixture@example.invalid")
    (root / ".gitignore").write_text(".polymorph/\n", encoding="utf-8")
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "fixture")


def test_fingerprint_detects_dirty_bytes_and_new_files(tmp_path: Path) -> None:
    _repository(tmp_path)
    before = validation.source_state(tmp_path)
    (tmp_path / "source.py").write_text("value = 2\n", encoding="utf-8")
    changed = validation.source_state(tmp_path)
    assert before["commit"] == changed["commit"]
    assert before["source_sha256"] != changed["source_sha256"]
    assert changed["dirty"] is True
    (tmp_path / "new.py").write_text("value = 3\n", encoding="utf-8")
    assert changed["source_sha256"] != validation.source_state(tmp_path)["source_sha256"]


def test_fingerprint_ignores_own_output(tmp_path: Path) -> None:
    _repository(tmp_path)
    before = validation.source_state(tmp_path)
    (tmp_path / ".polymorph").mkdir()
    (tmp_path / ".polymorph" / "summary.json").write_text("{}", encoding="utf-8")
    assert validation.source_state(tmp_path) == before


def _summary(root: Path) -> dict:
    reports = list((root / ".polymorph" / "validation").glob("*/summary.json"))
    assert len(reports) == 1
    return json.loads(reports[0].read_text(encoding="utf-8"))


def _plan(monkeypatch: pytest.MonkeyPatch, root: Path, steps: list) -> None:
    monkeypatch.setattr(validation, "ROOT", root)
    monkeypatch.setattr(validation, "make_steps", lambda output, args: steps)


def test_runner_executes_real_plan_and_keeps_logs_out_of_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repository(tmp_path)
    _plan(
        monkeypatch,
        tmp_path,
        [validation.Step("fixture", ("-c", "print('LOCAL_ONLY_CANARY')"))],
    )
    assert validation.main([]) == 0
    report = _summary(tmp_path)
    assert report["status"] == "passed"
    assert report["source_unchanged"] is True
    assert "LOCAL_ONLY_CANARY" not in json.dumps(report)
    assert str(tmp_path) not in json.dumps(report)


def test_failed_dependency_blocks_only_dependent_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repository(tmp_path)
    _plan(
        monkeypatch,
        tmp_path,
        [
            validation.Step("first", ("-c", "raise SystemExit(2)")),
            validation.Step("dependent", ("-c", "raise AssertionError"), after=("first",)),
            validation.Step("independent", ("-c", "pass")),
        ],
    )
    assert validation.main([]) == 1
    report = _summary(tmp_path)
    assert [step["status"] for step in report["steps"]] == ["failed", "blocked", "passed"]


def test_source_edit_during_execution_fails_provenance_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repository(tmp_path)
    code = "from pathlib import Path; Path('source.py').write_text('changed')"
    _plan(monkeypatch, tmp_path, [validation.Step("edit", ("-c", code))])
    assert validation.main([]) == 1
    assert _summary(tmp_path)["source_unchanged"] is False


def test_successful_pytest_exit_without_junit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repository(tmp_path)
    _plan(monkeypatch, tmp_path, [validation.Step("tests", ("-c", "pass"))])
    assert validation.main([]) == 1
    assert _summary(tmp_path)["steps"][0]["reason"] == "invalid_junit"


def test_no_git_checkout_fails_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validation, "ROOT", tmp_path)
    assert validation.main([]) == 2
    assert list(tmp_path.iterdir()) == []


def test_workflow_summary_only_copies_numeric_measurements(tmp_path: Path) -> None:
    path = tmp_path / "gate.json"
    path.write_text(
        json.dumps(
            {
                "passed": True,
                "observed": {
                    "throughput_per_second": 300,
                    "wall_seconds": 3.3,
                    "peak_rss_mib": 100,
                    "payload": "LOCAL_ONLY_CANARY",
                },
            }
        ),
        encoding="utf-8",
    )
    result = validation.workflow_metrics(path)
    assert result == {
        "throughput_per_second": 300.0,
        "wall_seconds": 3.3,
        "peak_rss_mib": 100.0,
    }
    assert "LOCAL_ONLY_CANARY" not in json.dumps(result)


@pytest.mark.parametrize("value", [True, -1, 0, float("inf"), float("nan"), "300"])
def test_invalid_workflow_metrics_cannot_pass(tmp_path: Path, value: object) -> None:
    path = tmp_path / "gate.json"
    path.write_text(
        json.dumps({"passed": True, "observed": {"throughput_per_second": value}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        validation.workflow_metrics(path)


def test_exit_zero_without_workflow_evidence_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repository(tmp_path)
    _plan(monkeypatch, tmp_path, [validation.Step("workflow-1-gate", ("-c", "pass"))])
    assert validation.main([]) == 1
    assert _summary(tmp_path)["steps"][0]["reason"] == "invalid_workflow_report"
