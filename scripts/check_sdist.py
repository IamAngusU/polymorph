from __future__ import annotations

import argparse
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
ROOT_FILES = (
    "CHANGELOG.md",
    "COMMERCIAL.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "MANIFEST.in",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY.md",
    "examples.py",
    "pyproject.toml",
)


def _selected_files(directory: Path, suffixes: set[str]) -> set[Path]:
    if not directory.is_dir():
        raise FileNotFoundError(f"release source directory is missing: {directory}")
    return {
        path
        for path in directory.rglob("*")
        if path.is_file() and (path.suffix in suffixes or path.name == "py.typed")
    }


def expected_release_paths(root: Path = ROOT) -> set[str]:
    """Return every current file that MANIFEST.in promises to ship."""

    paths = {root / name for name in ROOT_FILES}
    paths.update(_selected_files(root / "benchmarks", {".json", ".md"}))
    paths.update(_selected_files(root / "docs", {".md", ".png", ".webp"}))
    paths.update(_selected_files(root / "scripts", {".py"}))
    paths.update(_selected_files(root / "tests", {".py"}))
    paths.update(_selected_files(root / "src" / "polymorph", {".py"}))
    missing_local = sorted(path for path in paths if not path.is_file())
    if missing_local:
        rendered = ", ".join(str(path) for path in missing_local)
        raise FileNotFoundError(f"required local release files are missing: {rendered}")
    return {path.relative_to(root).as_posix() for path in paths}


def archive_file_paths(sdist: Path) -> set[str]:
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()

    roots: set[str] = set()
    files: list[str] = []
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"sdist contains unsafe member path: {member.name}")
        if not path.parts:
            continue
        roots.add(path.parts[0])
        if member.isfile() and len(path.parts) > 1:
            files.append(PurePosixPath(*path.parts[1:]).as_posix())
    if len(roots) != 1:
        raise ValueError("sdist must contain exactly one top-level directory")
    if len(files) != len(set(files)):
        raise ValueError("sdist contains duplicate normalized file paths")
    return set(files)


def missing_release_paths(sdist: Path, expected: set[str]) -> list[str]:
    return sorted(expected - archive_file_paths(sdist))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that the source release is actually usable."
    )
    parser.add_argument("sdist", type=Path)
    args = parser.parse_args()

    expected = expected_release_paths()
    missing = missing_release_paths(args.sdist, expected)
    if missing:
        raise SystemExit(f"sdist is missing required files: {', '.join(missing)}")
    print(f"sdist contains all {len(expected)} current release files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
