"""Explicit local knowledge updates. No scheduler, recipe writes or automatic promotion."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from polymorph.knowledge import KnowledgeStore, fetch_latest, read_bytes, verify_pack
    from polymorph.paths import data_home

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=data_home())
    parser.add_argument("--trusted-key", type=Path, required=True,
                        help="locally approved 32-byte Ed25519 public key encoded as hex")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "verify"):
        cmd = commands.add_parser(name)
        cmd.add_argument("package", type=Path)
        if name == "install":
            cmd.add_argument("--activate", action="store_true")
    cmd = commands.add_parser("fetch")
    cmd.add_argument("--ref", default="main")
    cmd.add_argument("--activate", action="store_true")
    cmd = commands.add_parser("activate")
    cmd.add_argument("version")
    cmd.add_argument("--allow-rollback", action="store_true")
    commands.add_parser("status")
    args = parser.parse_args()
    try:
        key = bytes.fromhex(read_bytes(args.trusted_key, 256).decode("ascii").strip())
        if args.command == "verify":
            signed = verify_pack(read_bytes(args.package), key)
            result = {k: signed[k] for k in ("version", "sequence", "model_sha256", "evidence", "origin")}
        else:
            store = KnowledgeStore(args.home, key)
            if args.command in ("install", "fetch"):
                raw = read_bytes(args.package) if args.command == "install" else fetch_latest(ref=args.ref)
                result = store.install(raw, activate=args.activate)
            else:
                if args.command == "activate":
                    store.activate(args.version, allow_rollback=args.allow_rollback)
                result = store.status()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"Knowledge operation blocked: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
