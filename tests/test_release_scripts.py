from __future__ import annotations

import io
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
