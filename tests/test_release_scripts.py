from __future__ import annotations

import ast
import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.bootstrap import PythonDetails, _require_matching_venv
from scripts.check_sdist import (
    archive_file_paths,
    expected_release_paths,
    missing_release_paths,
)


def _write_sdist(path: Path, names: tuple[str, ...]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name in names:
            payload = name.encode("utf-8")
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
