import json
from pathlib import Path

from polymorph.cli import build_parser


def test_independent_public_corpus_has_no_unsafe_auto(tmp_path) -> None:
    root = Path(__file__).parents[1]
    output = tmp_path / "report.json"
    args = build_parser().parse_args(
        [
            "benchmark",
            "mapping",
            str(root / "benchmarks" / "independent-public-multilingual-v1.json"),
            "--max-unsafe-auto",
            "0",
            "--require-suggestion-accuracy",
            "1.0",
            "--output",
            str(output),
        ]
    )

    args.func(args)
    report = json.loads(output.read_text(encoding="utf-8"))["mapping"]

    assert report["fields_scored"] == 14
    assert report["suggestion_correct"] == 14
    assert report["unsafe_auto_decisions"] == 0
