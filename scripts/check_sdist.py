from __future__ import annotations

import argparse
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
ROOT_FILES = (
    "CHANGELOG.md",
    "COMMERCIAL.md",
    "COMMERCIAL.de.md",
    "CONTRIBUTING.md",
    "CONTRIBUTING.de.md",
    "LICENSE",
    "LICENSING.md",
    "LICENSING.de.md",
    "MANIFEST.in",
    "NOTICE",
    "README.md",
    "README.de.md",
    "SECURITY.md",
    "SECURITY.de.md",
    "THIRD_PARTY.md",
    "TRADEMARKS.md",
    "TRADEMARKS.de.md",
    "examples.py",
    "pyproject.toml",
)


def _selected_files(directory: Path, suffixes: set[str]) -> set[Path]:
    if not directory.is_dir():
        raise FileNotFoundError(f"release source directory is missing: {directory}")
    return {
        path
        for path in directory.rglob("*")
        if path.is_file() and (path.suffix in suffixes or path.name in {"py.typed", "SHA256SUMS"})
    }


def expected_release_paths(root: Path = ROOT) -> set[str]:
    """Return every current file that MANIFEST.in promises to ship."""

    paths = {root / name for name in ROOT_FILES}
    paths.update(_selected_files(root / "benchmarks", {".json", ".md"}))
    paths.update(_selected_files(root / "docs", {".md", ".png", ".svg", ".webp"}))
    paths.update(_selected_files(root / "scripts", {".py"}))
    paths.update(
        _selected_files(
            root / "tests",
            {".base64", ".csv", ".json", ".md", ".py", ".tsv", ".txt"},
        )
    )
    paths.update(_selected_files(root / "src" / "polymorph", {".py"}))
    missing_local = sorted(path for path in paths if not path.is_file())
    if missing_local:
        rendered = ", ".join(str(path) for path in missing_local)
        raise FileNotFoundError(f"required local release files are missing: {rendered}")
    return {path.relative_to(root).as_posix() for path in paths}


def _normalized_archive_files(
    members: list[tarfile.TarInfo],
) -> dict[str, tarfile.TarInfo]:
    roots: set[str] = set()
    files: dict[str, tarfile.TarInfo] = {}
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"sdist contains unsafe member path: {member.name}")
        if not path.parts:
            continue
        roots.add(path.parts[0])
        if member.isfile() and len(path.parts) > 1:
            normalized = PurePosixPath(*path.parts[1:]).as_posix()
            if normalized in files:
                raise ValueError("sdist contains duplicate normalized file paths")
            files[normalized] = member
    if len(roots) != 1:
        raise ValueError("sdist must contain exactly one top-level directory")
    return files


def archive_file_paths(sdist: Path) -> set[str]:
    with tarfile.open(sdist, "r:gz") as archive:
        return set(_normalized_archive_files(archive.getmembers()))


def missing_release_paths(sdist: Path, expected: set[str]) -> list[str]:
    return sorted(expected - archive_file_paths(sdist))


def mismatched_release_paths(
    sdist: Path,
    expected: set[str],
    *,
    root: Path = ROOT,
) -> list[str]:
    """Return packaged files whose bytes differ from the current workspace."""

    mismatched: list[str] = []
    with tarfile.open(sdist, "r:gz") as archive:
        members = _normalized_archive_files(archive.getmembers())
        for relative_path in sorted(expected & set(members)):
            local_path = root / relative_path
            member = members[relative_path]
            if member.size != local_path.stat().st_size:
                mismatched.append(relative_path)
                continue
            archived = archive.extractfile(member)
            if archived is None:
                mismatched.append(relative_path)
                continue
            with archived, local_path.open("rb") as local:
                while True:
                    archived_chunk = archived.read(64 * 1024)
                    local_chunk = local.read(64 * 1024)
                    if archived_chunk != local_chunk:
                        mismatched.append(relative_path)
                        break
                    if not archived_chunk:
                        break
    return mismatched


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
    mismatched = mismatched_release_paths(args.sdist, expected)
    if mismatched:
        raise SystemExit(
            "sdist files do not match current workspace bytes: " + ", ".join(mismatched)
        )
    print(f"sdist contains all {len(expected)} current release files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
