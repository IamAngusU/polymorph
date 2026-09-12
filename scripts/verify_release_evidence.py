from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify release artifact sizes and SHA-256 hashes")
    parser.add_argument("manifest")
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if manifest.get("format") != "polymorph.release-evidence" or manifest.get("version") != 1:
        raise ValueError("unsupported release evidence manifest")
    checked = 0
    for artifact in manifest.get("artifacts", []):
        path = ROOT / artifact["path"]
        if path.stat().st_size != artifact["size_bytes"] or _sha256(path) != artifact["sha256"]:
            raise ValueError(f"release artifact verification failed: {artifact['path']}")
        checked += 1
    print(json.dumps({"verified": True, "artifacts": checked}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
