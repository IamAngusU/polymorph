from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = "Scripts" if os.name == "nt" else "bin"
SUFFIX = ".exe" if os.name == "nt" else ""
CLI = ROOT / ".venv" / BIN / f"polymorph{SUFFIX}"


def main() -> int:
    if not CLI.is_file():
        print("Run `python scripts/bootstrap.py` first.", file=sys.stderr)
        return 2
    env = os.environ.copy()
    env.setdefault("POLYMORPH_HOME", str(ROOT / ".polymorph"))
    return subprocess.run([str(CLI), *sys.argv[1:]], cwd=ROOT, env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main())
