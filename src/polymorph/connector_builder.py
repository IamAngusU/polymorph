from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from .errors import PolymorphError

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")


class ConnectorScaffoldError(PolymorphError):
    """Raised when a connector starter cannot be created without overwriting content."""


def _identity(name: str) -> tuple[str, str, str]:
    if not _NAME.fullmatch(name):
        raise ConnectorScaffoldError(
            "connector name must contain 1..64 simple ASCII letters, digits, spaces, dots, "
            "dashes, or underscores"
        )
    words = [part for part in re.split(r"[^A-Za-z0-9]+", name) if part]
    slug = "-".join(part.casefold() for part in words)
    package = "polymorph_connector_" + "_".join(part.casefold() for part in words)
    class_name = "".join(part[:1].upper() + part[1:] for part in words) + "Source"
    return slug, package, class_name


def _files(name: str, slug: str, package: str, class_name: str) -> dict[str, str]:
    dependency = "polymorph-bridge>=0.4.0a9,<0.5"
    manifest = {
        "capabilities": {
            "incremental_read": False,
            "read_records": False,
            "schema_inspection": False,
        },
        "limitations": [
            "Starter only: no capability is claimed until its implementation and tests exist.",
            "Credentials must be resolved by the trusted host, never embedded in connector specs.",
        ],
        "name": name,
        "roles": ["source"],
        "schema": "polymorph.connector-manifest",
        "schemes": [slug],
        "version": 1,
    }
    return {
        ".gitignore": ".venv/\n__pycache__/\n*.egg-info/\ndist/\nbuild/\n",
        "connector-manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        "pyproject.toml": f'''[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[project]
name = "polymorph-connector-{slug}"
version = "0.1.0"
description = "{name} source connector for Polymorph"
requires-python = ">=3.11"
dependencies = ["{dependency}"]

[project.optional-dependencies]
test = ["pytest>=8"]

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
''',
        "README.md": f"""# {name} connector starter

This scaffold starts deliberately with every capability set to `false`. Implement the two
read methods, add fixture-based contract tests, then opt into the connector registry by following
Polymorph's `docs/CONNECTORS.md`. Do not advertise a capability before its behavior is tested.

```powershell
py -m venv .venv
.venv\\Scripts\\python -m pip install -e ".[test]"
.venv\\Scripts\\python -m pytest
```

## Security defaults

- Accept credential references, not credential values, in public connector configuration.
- Bound response bytes, records, nesting, pagination, and wall time before enabling network I/O.
- Never retry destination writes unless provider idempotency makes the retry provably safe.
- Keep customer row values out of logs, metrics, exceptions, and review artifacts.
- Add provider-specific pagination, rate-limit, token-refresh, and API-version fixtures.

No GitHub Actions workflow is generated. CI activation remains an explicit repository-owner choice.
""",
        f"src/{package}/__init__.py": f'''from .connector import {class_name}

__all__ = ["{class_name}"]
''',
        f"src/{package}/connector.py": f'''from __future__ import annotations

from collections.abc import Iterator, Mapping


class {class_name}:
    """Fill in a read-only source before registering any capability claim."""

    def __init__(self, endpoint: str, *, credential_reference: str | None = None) -> None:
        self.endpoint = endpoint
        self.credential_reference = credential_reference

    def inspect_schema(self) -> object:
        raise NotImplementedError("implement bounded schema inspection")

    def iter_records(self) -> Iterator[Mapping[str, object]]:
        raise NotImplementedError("implement bounded or streaming record reads")
        yield {{}}
''',
        "tests/test_starter.py": f"""from __future__ import annotations

import pytest

from {package} import {class_name}


def test_starter_refuses_to_claim_unimplemented_reads() -> None:
    connector = {class_name}("https://example.invalid", credential_reference="test")
    with pytest.raises(NotImplementedError, match="bounded schema"):
        connector.inspect_schema()
    with pytest.raises(NotImplementedError, match="bounded or streaming"):
        next(connector.iter_records())
""",
    }


def scaffold_connector(name: str, output: str | Path | None = None) -> Path:
    slug, package, class_name = _identity(name)
    target = Path(output or f"polymorph-connector-{slug}").expanduser()
    if not target.is_absolute():
        target = Path.cwd() / target
    target = Path(os.path.abspath(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ConnectorScaffoldError("connector scaffold destination already exists")
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=target.parent))
    try:
        for relative, content in _files(name, slug, package, class_name).items():
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def _scaffold(args: argparse.Namespace) -> int:
    path = scaffold_connector(args.name, args.output)
    print(
        json.dumps(
            {
                "actions_generated": False,
                "path": str(path),
                "status": "created",
                "type": "source_connector_starter",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a fail-closed Polymorph connector starter without CI automation."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scaffold = commands.add_parser("scaffold")
    scaffold.add_argument("name")
    scaffold.add_argument("--output")
    scaffold.set_defaults(func=_scaffold)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
