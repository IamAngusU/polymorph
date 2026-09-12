from __future__ import annotations

import pytest

from polymorph.connectors.csv_file import CsvConnector
from polymorph.work_budget import WorkBudget


def test_csv_streaming_rewrite_is_atomic_when_late_record_is_invalid(tmp_path) -> None:
    path = tmp_path / "records.csv"
    path.write_text("id,name\n1,Ada\n", encoding="utf-8")
    original = path.read_bytes()
    connector = CsvConnector(path)

    def records():
        yield {"id": "2", "name": "Grace"}
        yield {"id": "3", "different": "blocked"}

    with pytest.raises(ValueError, match="identical fields"):
        connector.write_records(records())
    assert path.read_bytes() == original


def test_csv_generator_is_consumed_only_as_each_row_is_written(tmp_path, monkeypatch) -> None:
    path = tmp_path / "lazy.csv"
    connector = CsvConnector(path)
    consumed = 0
    written: list[int] = []

    def records():
        nonlocal consumed
        for index in range(3):
            consumed += 1
            yield {"id": str(index)}

    original = connector._reject_spreadsheet_formulas

    def observe(fieldnames, rows):
        written.append(consumed)
        assert consumed <= len(written)
        return original(fieldnames, rows)

    monkeypatch.setattr(connector, "_reject_spreadsheet_formulas", observe)
    assert connector.write_records(records()) == 3
    assert consumed == 3


def test_csv_streaming_rewrite_enforces_record_budget(tmp_path) -> None:
    path = tmp_path / "records.csv"
    connector = CsvConnector(path, work_budget=WorkBudget(max_total_records=2))

    with pytest.raises(Exception, match="max_total_records"):
        connector.write_records({"id": str(index)} for index in range(3))
    assert not path.exists()
