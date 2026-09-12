from __future__ import annotations

import sys
from collections.abc import Callable


def _commands() -> dict[str, Callable[[list[str] | None], int]]:
    from .connector_builder import main as connector_main
    from .data_quality import main as quality_main
    from .review_artifacts import main as review_main
    from .sync_state import main as sync_main
    from .ui_assets import main as ui_main

    return {
        "connector": connector_main,
        "quality": quality_main,
        "review": review_main,
        "sync": sync_main,
        "ui": ui_main,
    }


def _help() -> None:
    print(
        """usage: polymorph-kit <area> [arguments]

areas:
  connector   create a fail-closed connector starter
  quality     produce a bounded metadata-only quality report
  review      finalize or validate schema-bound review evidence
  sync        inspect commit-bound recurring-run checkpoints
  ui          export the framework-neutral review component

Run `polymorph-kit <area> --help` for area-specific options.
"""
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] in {"-h", "--help"}:
        _help()
        return 0
    area = arguments.pop(0)
    command = _commands().get(area)
    if command is None:
        _help()
        raise SystemExit(f"unknown toolkit area: {area}")
    return command(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
