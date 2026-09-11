from pathlib import Path

import pytest

from scripts.check_sdist import ROOT_FILES, expected_release_paths


def _workspace(root: Path) -> None:
    for name in ROOT_FILES:
        (root / name).write_text(name, encoding="utf-8")
    for name in ("benchmarks", "docs", "knowledge", "scripts", "tests", "src/polymorph"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "docs/assets").mkdir()
    (root / "docs/assets/training.svg").write_text("<svg/>", encoding="utf-8")
    (root / "knowledge/latest.json").write_text("{}", encoding="utf-8")


def test_source_manifest_covers_knowledge_and_generated_assets(tmp_path: Path) -> None:
    _workspace(tmp_path)
    assert {"README.de.md", "knowledge/latest.json", "docs/assets/training.svg"} <= (
        expected_release_paths(tmp_path)
    )


def test_missing_german_readme_blocks_source_release(tmp_path: Path) -> None:
    _workspace(tmp_path)
    (tmp_path / "README.de.md").unlink()
    with pytest.raises(FileNotFoundError, match="README.de.md"):
        expected_release_paths(tmp_path)


def test_missing_knowledge_tree_blocks_source_release(tmp_path: Path) -> None:
    _workspace(tmp_path)
    (tmp_path / "knowledge/latest.json").unlink()
    (tmp_path / "knowledge").rmdir()
    with pytest.raises(FileNotFoundError, match="knowledge"):
        expected_release_paths(tmp_path)
