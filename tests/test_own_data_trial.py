from __future__ import annotations

import json
from pathlib import Path

from polymorph.own_data_trial import main


def test_trial_builds_metadata_only_report_without_source_values(
    tmp_path: Path,
) -> None:
    source = tmp_path / "customers.csv"
    source.write_text(
        "customer_id,amount,currency\nC-1,10.50,EUR\nC-2,20.00,USD\n",
        encoding="utf-8",
    )
    output = tmp_path / "trial"

    assert main([str(source), "--output", str(output)]) == 0

    summary = json.loads((output / "trial-summary.json").read_text(encoding="utf-8"))
    assert summary["write_authority"] is False
    assert summary["network_used"] is False
    assert summary["privacy"] == "metadata_only_no_record_values"
    assert summary["records_scanned"] == 2
    assert summary["field_count"] == 3
    rendered = "\n".join(path.read_text(encoding="utf-8") for path in sorted(output.iterdir()))
    assert "C-1" not in rendered
    assert "10.50" not in rendered
    assert str(source.resolve()) not in rendered
    assert (output / "index.html").is_file()


def test_trial_refuses_to_replace_an_existing_output(tmp_path: Path) -> None:
    source = tmp_path / "data.csv"
    source.write_text("id\n1\n", encoding="utf-8")
    output = tmp_path / "trial"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    assert main([str(source), "--output", str(output)]) == 2
    assert marker.read_text(encoding="utf-8") == "keep"
