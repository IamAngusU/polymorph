from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import subprocess
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parent.parent


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def _source_digest() -> str:
    digest = hashlib.sha256()
    for name in _git("ls-files", "-z").split("\0"):
        if not name:
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def _dependencies(project: dict[str, object]) -> list[tuple[str, str, str]]:
    declarations: list[tuple[str, str]] = [
        ("required", item) for item in project.get("dependencies", [])
    ]
    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group, items in optional.items():
            declarations.extend((f"optional:{group}", item) for item in items)
    output = []
    for scope, declaration in declarations:
        requirement = Requirement(str(declaration))
        try:
            version = importlib.metadata.version(requirement.name)
        except importlib.metadata.PackageNotFoundError:
            version = "not-installed"
        output.append((requirement.name, version, scope))
    return sorted(set(output), key=lambda item: (item[0].casefold(), item[2]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build local release manifest and CycloneDX SBOM")
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--manifest", default="dist/release-manifest.json")
    parser.add_argument("--sbom", default="dist/sbom.cdx.json")
    args = parser.parse_args()

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    commit = _git("rev-parse", "HEAD")
    tree_digest = _source_digest()
    artifacts = []
    for supplied in args.artifact:
        path = (ROOT / supplied).resolve() if not Path(supplied).is_absolute() else Path(supplied)
        artifacts.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    artifacts.sort(key=lambda item: item["path"])
    generated_at = datetime.now(UTC).isoformat()
    manifest = {
        "format": "polymorph.release-evidence",
        "version": 1,
        "project": pyproject["name"],
        "project_version": pyproject["version"],
        "source_commit": commit,
        "source_tree_sha256": tree_digest,
        "working_tree_clean": not bool(_git("status", "--porcelain")),
        "generated_at": generated_at,
        "artifacts": artifacts,
    }
    dependencies = _dependencies(pyproject)
    root_ref = f"pkg:pypi/{pyproject['name']}@{pyproject['version']}"
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, commit + tree_digest)}",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "component": {
                "type": "application",
                "name": pyproject["name"],
                "version": pyproject["version"],
                "bom-ref": root_ref,
                "purl": root_ref,
                "hashes": [{"alg": "SHA-256", "content": tree_digest}],
            },
        },
        "components": [
            {
                "type": "library",
                "name": name,
                "version": version,
                "scope": "required" if scope == "required" else "optional",
                "properties": [{"name": "polymorph:dependency-group", "value": scope}],
            }
            for name, version, scope in dependencies
        ],
    }
    for supplied, payload in ((args.manifest, manifest), (args.sbom, sbom)):
        destination = ROOT / supplied
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps({"manifest": args.manifest, "sbom": args.sbom, "artifacts": len(artifacts)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
