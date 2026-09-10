"""Run the repository's quality gates without GitHub Actions or automatic installs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import signal
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
RUNTIME_MODULES = ("cryptography", "openpyxl", "defusedxml", "sqlalchemy", "httpx", "json5")


@dataclass(frozen=True)
class Step:
    name: str
    args: tuple[str, ...]
    modules: tuple[str, ...] = ()
    after: tuple[str, ...] = ()


@dataclass(frozen=True)
class Result:
    name: str
    status: str
    seconds: float = 0.0
    returncode: int | None = None
    reason: str | None = None
    log_sha256: str | None = None


def positive_number(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive finite number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return number


def make_steps(output: Path, args: argparse.Namespace) -> list[Step]:
    paths = ("src", "tests", "scripts", "examples.py")
    steps = [
        Step("compile", ("-W", "error", "-m", "compileall", "-q", *paths)),
        Step("lint", ("-m", "ruff", "check", *paths), ("ruff",)),
        Step("format", ("-m", "ruff", "format", "--check", *paths), ("ruff",)),
        Step("types", ("-m", "mypy"), ("mypy",)),
        Step("dependencies", ("-m", "pip", "check"), ("pip",)),
        Step("example", ("examples.py",), RUNTIME_MODULES),
        Step(
            "tests",
            (
                "-W",
                "error",
                "-m",
                "pytest",
                "--strict-config",
                "--strict-markers",
                f"--junitxml={output / 'tests.xml'}",
                "--cov=polymorph",
                f"--cov-report=json:{output / 'coverage.json'}",
                "--cov-report=term",
            ),
            (*RUNTIME_MODULES, "pytest", "pytest_cov", "hypothesis", "keyring"),
        ),
        Step(
            "mapping",
            (
                "-W",
                "error",
                "-m",
                "polymorph",
                "benchmark",
                "mapping",
                "benchmarks/safety-regression.json",
                "--require-auto-precision",
                "1.0",
                "--require-automation-coverage",
                "0.70",
                "--max-unsafe-auto",
                "0",
                "--output",
                str(output / "mapping.json"),
            ),
            RUNTIME_MODULES,
        ),
    ]
    for index in range(1, args.runs + 1):
        name = f"workflow-{index}"
        report = output / f"{name}.json"
        steps.extend(
            [
                Step(
                    name,
                    (
                        "-W",
                        "error",
                        "-m",
                        "polymorph",
                        "benchmark",
                        "workflow",
                        "--records",
                        "1000",
                        "--batch-size",
                        "100",
                        "--work-dir",
                        str(output / f"{name}-state"),
                        "--output",
                        str(report),
                    ),
                    (*RUNTIME_MODULES, "psutil"),
                    ("tests",),
                ),
                Step(
                    f"{name}-gate",
                    (
                        "scripts/check_workflow_performance.py",
                        str(report),
                        "--min-throughput",
                        str(args.min_throughput),
                        "--max-wall-seconds",
                        str(args.max_wall_seconds),
                        "--max-peak-rss-mib",
                        str(args.max_peak_rss_mib),
                        "--expected-records",
                        "1000",
                        "--expected-batch-size",
                        "100",
                        "--output",
                        str(output / f"{name}-gate.json"),
                    ),
                    RUNTIME_MODULES,
                    (name,),
                ),
            ]
        )
    return steps


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        timeout=20,
    ).stdout


def source_state(root: Path) -> dict[str, object]:
    """Bind results to actual tracked and non-ignored source bytes, not just HEAD."""
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    paths = set(
        _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    )
    digest = hashlib.sha256()
    count = 0
    for name in sorted(paths - {b""}):
        # These are local state even if a developer forgot the normal ignore rule.
        parts = name.replace(b"\\", b"/").split(b"/")
        if any(part in {b".git", b".polymorph", b".venv", b"__pycache__"} for part in parts):
            continue
        path = root / os.fsdecode(name)
        digest.update(len(name).to_bytes(8, "big") + name)
        if path.is_symlink():
            digest.update(b"link\0" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            content = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    content.update(chunk)
            digest.update(b"file\0" + content.digest())
        elif not path.exists():
            digest.update(b"deleted\0")
        else:
            raise ValueError("source contains an unsupported directory or special file")
        count += 1
    return {
        "commit": head,
        "dirty": bool(_git(root, "status", "--porcelain", "--untracked-files=normal")),
        "source_sha256": digest.hexdigest(),
        "files": count,
    }


def stop_process(process: subprocess.Popen[bytes]) -> None:
    """Best-effort process-tree cleanup; this is not a sandbox boundary."""
    if os.name == "nt":
        if process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
    else:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def run_step(
    step: Step,
    root: Path,
    output: Path,
    env: dict[str, str],
    timeout: float,
) -> Result:
    missing = [name for name in step.modules if importlib.util.find_spec(name) is None]
    if missing:
        return Result(step.name, "blocked", reason="missing modules: " + ", ".join(missing))
    log = output / f"{step.name}.log"
    start = time.monotonic()
    status, reason, code = "failed", None, None
    process = None
    try:
        with log.open("xb") as handle:
            process = subprocess.Popen(
                [sys.executable, *step.args],
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name != "nt"),
            )
            while True:
                code = process.poll()
                if log.stat().st_size > MAX_LOG_BYTES:
                    reason = "log_limit"
                    break
                if code is not None:
                    status = "passed" if code == 0 else "failed"
                    break
                if time.monotonic() - start > timeout:
                    reason = "timeout"
                    break
                time.sleep(0.05)
    except KeyboardInterrupt:
        status, reason = "interrupted", "operator_interrupt"
    except OSError as exc:
        reason = type(exc).__name__
    finally:
        if process is not None:
            stop_process(process)
    log_digest = None
    if log.exists():
        with log.open("rb") as handle:
            log_digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return Result(step.name, status, time.monotonic() - start, code, reason, log_digest)


def test_totals(path: Path) -> dict[str, int]:
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("JUnit report exceeds size limit")
    tree = ET.fromstring(path.read_bytes())
    cases = list(tree.iter("testcase"))
    if not cases:
        raise ValueError("JUnit report contains no executed tests")
    counts = {"collected": len(cases), "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for case in cases:
        if case.find("error") is not None:
            counts["errors"] += 1
        elif case.find("failure") is not None:
            counts["failed"] += 1
        elif case.find("skipped") is not None:
            counts["skipped"] += 1
        else:
            counts["passed"] += 1
    # A collection error is not necessarily represented as a testcase.
    for suite in tree.iter("testsuite"):
        if int(suite.get("errors", "0")) > counts["errors"]:
            raise ValueError("JUnit reports collection errors")
    if counts["passed"] == 0 or counts["failed"] or counts["errors"]:
        raise ValueError("JUnit does not establish a successful test run")
    return counts


def workflow_metrics(path: Path) -> dict[str, float]:
    """Copy only numeric measurements into the shareable report, never raw output."""
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("workflow gate report exceeds size limit")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload["passed"] is not True:
        raise ValueError("workflow gate did not pass")
    result: dict[str, float] = {}
    for name in ("throughput_per_second", "wall_seconds", "peak_rss_mib"):
        value = payload["observed"][name]
        if type(value) not in (float, int) or not math.isfinite(value) or value <= 0:
            raise ValueError("workflow measurement must be positive and finite")
        result[name] = float(value)
    return result


def write_report(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--timeout", type=positive_number, default=900.0, help="per step seconds")
    parser.add_argument("--min-throughput", type=positive_number, default=125.0)
    parser.add_argument("--max-wall-seconds", type=positive_number, default=8.0)
    parser.add_argument("--max-peak-rss-mib", type=positive_number, default=200.0)
    parser.add_argument("--list", action="store_true", help="show gates without executing them")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if sys.version_info < (3, 11):
        print("Python 3.11 or newer is required.", file=sys.stderr)
        return 2
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = ROOT / ".polymorph" / "validation" / run_id
    steps = make_steps(output, args)
    if args.list:
        print("\n".join(step.name for step in steps))
        return 0
    try:
        before = source_state(ROOT)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Cannot bind validation to this Git checkout: {type(exc).__name__}", file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "POLYMORPH_HOME": str(output / "home"),
            "COVERAGE_FILE": str(output / ".coverage"),
            "HYPOTHESIS_STORAGE_DIRECTORY": str(output / "hypothesis"),
        }
    )
    results: list[Result] = []
    payload: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "status": "running",
        "source_before": before,
        "host": {
            "os": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "configuration": vars(args),
        "tests": None,
        "workflow_measurements": {},
        "scope": "local checkout quality, tests, mapping and SQLite workflow",
        "not_covered": [
            "other operating systems",
            "live PostgreSQL",
            "release package installation",
            "full parser OS isolation",
        ],
    }
    report = output / "summary.json"
    for step in steps:
        previous = {item.name: item.status for item in results}
        if any(previous.get(name) != "passed" for name in step.after):
            result = Result(step.name, "blocked", reason="prerequisite did not pass")
        else:
            print(f"Running {step.name} ...", flush=True)
            result = run_step(step, ROOT, output, env, args.timeout)
        if step.name == "tests" and result.status == "passed":
            try:
                payload["tests"] = test_totals(output / "tests.xml")
            except (OSError, ValueError, ET.ParseError):
                result = Result(
                    step.name,
                    "failed",
                    result.seconds,
                    result.returncode,
                    "invalid_junit",
                    result.log_sha256,
                )
        if step.name.endswith("-gate") and result.status == "passed":
            try:
                measurements = payload["workflow_measurements"]
                assert isinstance(measurements, dict)
                measurements[step.name] = workflow_metrics(output / f"{step.name}.json")
            except (OSError, ValueError, KeyError, TypeError):
                result = Result(
                    step.name,
                    "failed",
                    result.seconds,
                    result.returncode,
                    "invalid_workflow_report",
                    result.log_sha256,
                )
        results.append(result)
        payload["steps"] = [asdict(item) for item in results]
        write_report(report, payload)
        detail = f" ({result.reason})" if result.reason else ""
        print(f"{result.name}: {result.status}{detail}", flush=True)
        if result.status == "interrupted":
            break
    try:
        after = source_state(ROOT)
        payload["source_after"] = after
        stable = before == after
    except (OSError, ValueError, subprocess.SubprocessError):
        stable = False
    payload["source_unchanged"] = stable
    passed = (
        stable
        and len(results) == len(steps)
        and all(item.status == "passed" for item in results)
    )
    payload["status"] = "passed" if passed else "failed"
    write_report(report, payload)
    print(f"\n{payload['status']}: {report}")
    print("Share summary.json first. Raw logs and test reports can contain paths or test values.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
