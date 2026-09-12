"""Create a local, shareable Polymorph evidence bundle without uploading it."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_observed(
    root: Path,
    output_dir: Path,
    history: Path,
    label: str,
    command: list[str],
) -> int:
    return subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "observe_run.py"),
            "--output",
            str(output_dir / f"{label}-resources.json"),
            "--history",
            str(history),
            "--label",
            label,
            "--",
            *command,
        ],
        cwd=root,
        check=False,
    ).returncode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--records", type=int, default=1000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument(
        "--export-public",
        action="store_true",
        help="also refresh the explicitly public longitudinal files; never commits or uploads",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.project.resolve()
    if not (root / "pyproject.toml").is_file():
        raise SystemExit(f"Not a Polymorph checkout: {root}")
    if not 1 <= args.records <= 1_000_000:
        raise SystemExit("--records must be between 1 and 1000000")
    if not 1 <= args.batch_size <= 10_000:
        raise SystemExit("--batch-size must be between 1 and 10000")

    output_dir = root / ".polymorph" / "evidence" / _stamp()
    output_dir.mkdir(parents=True, exist_ok=False)
    history = root / ".polymorph" / "metrics" / "observed-runs.jsonl"
    python = sys.executable

    workflow_report = output_dir / "workflow.json"
    workflow_state = output_dir / "workflow-state"
    workflow_code = _run_observed(
        root,
        output_dir,
        history,
        "workflow",
        [
            python,
            "-m",
            "polymorph",
            "benchmark",
            "workflow",
            "--records",
            str(args.records),
            "--batch-size",
            str(args.batch_size),
            "--work-dir",
            str(workflow_state),
            "--output",
            str(workflow_report),
        ],
    )

    mapping_report = output_dir / "mapping.json"
    mapping_code = _run_observed(
        root,
        output_dir,
        history,
        "mapping-safety",
        [
            python,
            "-m",
            "polymorph",
            "benchmark",
            "mapping",
            str(root / "benchmarks" / "safety-regression.json"),
            "--require-auto-precision",
            "1.0",
            "--max-unsafe-auto",
            "0",
            "--output",
            str(mapping_report),
        ],
    )

    metrics_script = root / "scripts" / "run_metrics.py"
    metrics_code: int | None = None
    if metrics_script.is_file():
        command = [python, str(metrics_script), "--project", str(root)]
        if args.export_public:
            command.append("--export-public")
        metrics_code = subprocess.run(command, cwd=root, check=False).returncode

    files = []
    for path in sorted(output_dir.glob("*.json")):
        files.append(
            {
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    manifest = {
        "schema": "polymorph.evidence-bundle",
        "version": 1,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "records": args.records,
        "batch_size": args.batch_size,
        "steps": {
            "workflow_exit_code": workflow_code,
            "mapping_safety_exit_code": mapping_code,
            "metrics_exit_code": metrics_code,
        },
        "files": files,
        "privacy": {
            "uploaded": False,
            "contains_payload_rows": True,
            "note": "The workflow fixture is synthetic, but review every bundle before sharing.",
        },
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Evidence bundle: {output_dir}")
    print("Nothing was uploaded.")
    return 0 if workflow_code == mapping_code == 0 and metrics_code in {None, 0} else 2


if __name__ == "__main__":
    raise SystemExit(main())
