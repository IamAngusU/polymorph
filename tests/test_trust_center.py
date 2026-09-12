from __future__ import annotations

import json
from pathlib import Path

from polymorph.trust_center import main

COMMIT = "8ea3edd401a116138e41638c9c6befdadb55a082"


def _write_fixture(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _manifest() -> dict[str, object]:
    return {
        "format": "polymorph.release-evidence",
        "project": "polymorph-bridge",
        "project_version": "0.4.0a7",
        "source_commit": COMMIT,
        "source_tree_sha256": "a" * 64,
        "version": 1,
        "working_tree_clean": True,
        "artifacts": [{"name": "polymorph.whl", "sha256": "b" * 64, "size_bytes": 1234}],
    }


def _validation() -> dict[str, object]:
    snapshot = {
        "commit": COMMIT,
        "dirty": False,
        "source_sha256": "c" * 64,
    }
    return {
        "host": {"machine": "AMD64", "os": "Windows", "python": "3.11.9"},
        "not_covered": ["other operating systems", "independent audit"],
        "run_id": "test-run",
        "source_before": snapshot,
        "source_after": snapshot,
        "source_unchanged": True,
        "status": "passed",
        "tests": {"errors": 0, "failed": 0, "passed": 1246, "skipped": 8},
        "workflow_measurements": {
            "workflow-1": {
                "peak_rss_mib": 79.7,
                "throughput_per_second": 188.1,
                "wall_seconds": 5.3,
            },
            "workflow-2": {
                "peak_rss_mib": 79.8,
                "throughput_per_second": 190.6,
                "wall_seconds": 5.2,
            },
        },
    }


def test_trust_center_requires_and_publishes_commit_bound_evidence(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "release-manifest.json"
    validation = tmp_path / "validation-summary.json"
    output = tmp_path / "trust"
    _write_fixture(manifest, _manifest())
    _write_fixture(validation, _validation())

    assert main([str(manifest), str(validation), "--output", str(output)]) == 0

    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["release"]["source_commit"] == COMMIT
    assert evidence["provenance"] == {
        "external_audit": False,
        "github_actions_used": False,
        "independent": False,
        "origin": "local_maintainer_machine",
    }
    assert evidence["validation"]["workflow"]["runs"] == 2
    page = (output / "index.html").read_text(encoding="utf-8")
    assert "not an independent audit" in page
    assert str(tmp_path) not in page


def test_trust_center_rejects_commit_mismatch(tmp_path: Path) -> None:
    manifest = tmp_path / "release-manifest.json"
    validation = tmp_path / "validation-summary.json"
    output = tmp_path / "trust"
    mismatch = _validation()
    mismatch["source_after"] = {
        "commit": "d" * 40,
        "dirty": False,
        "source_sha256": "c" * 64,
    }
    _write_fixture(manifest, _manifest())
    _write_fixture(validation, mismatch)

    assert main([str(manifest), str(validation), "--output", str(output)]) == 2
    assert not output.exists()
