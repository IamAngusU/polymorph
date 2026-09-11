"""Check an external training candidate without installing or activating it."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

from campaign_contract import verify_candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    runtime = Path(__file__).resolve().parents[1] / "src/polymorph/matching/lexical.py"
    try:
        feature_ast = ast.dump(ast.parse(runtime.read_text("utf-8")), include_attributes=False)
        expected = hashlib.sha256(feature_ast.encode()).hexdigest()
        report = verify_candidate(args.candidate, expected_feature_abi_sha256=expected)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"verified": False, "error_type": type(exc).__name__}))
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
