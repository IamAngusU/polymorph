from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_adversarial_multilingual_corpus_has_zero_unsafe_auto_decisions() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "polymorph",
            "benchmark",
            "mapping",
            str(ROOT / "benchmarks" / "adversarial-multilingual-v1.json"),
            "--max-unsafe-auto",
            "0",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    mapping = json.loads(completed.stdout)["mapping"]

    assert mapping["cases"] == 8
    assert mapping["auto_decisions"] == 0
    assert mapping["unsafe_auto_decisions"] == 0
    assert mapping["decision_contract_valid"] is True
