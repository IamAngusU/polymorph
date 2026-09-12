from __future__ import annotations

import argparse
import json
from importlib.resources import files
from pathlib import Path

from .errors import PolymorphError
from .filesystem import atomic_write_text

UI_ASSETS = ("polymorph-review.js", "example.html", "README.md")


class UiExportError(PolymorphError):
    """Raised when packaged UI assets cannot be exported without data loss."""


def export_review_ui(output: str | Path, *, overwrite: bool = False) -> tuple[Path, ...]:
    destination = Path(output).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    existing = [destination / name for name in UI_ASSETS if (destination / name).exists()]
    if existing and not overwrite:
        raise UiExportError("review UI destination contains packaged asset names")
    package = files("polymorph").joinpath("ui")
    exported: list[Path] = []
    for name in UI_ASSETS:
        target = destination / name
        if target.is_symlink():
            raise UiExportError("review UI asset target cannot be a symbolic link")
        content = package.joinpath(name).read_text(encoding="utf-8")
        atomic_write_text(target, content)
        exported.append(target)
    return tuple(exported)


def _export(args: argparse.Namespace) -> int:
    exported = export_review_ui(args.output, overwrite=args.overwrite)
    print(
        json.dumps(
            {
                "assets": [str(path) for path in exported],
                "network_dependencies": 0,
                "status": "exported",
                "write_authority": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export Polymorph's dependency-free, framework-neutral review component."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("output")
    export.add_argument("--overwrite", action="store_true")
    export.set_defaults(func=_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
