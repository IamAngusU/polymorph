from __future__ import annotations

import json
import sys

from polymorph.data_quality import inspect_source


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python examples/quality_report.py SOURCE")
    report = inspect_source(sys.argv[1])
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
