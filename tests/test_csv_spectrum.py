from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from polymorph.connectors.csv_file import CsvConnector

_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "csv-spectrum"
_CASES = (
    "comma_in_quotes",
    "empty",
    "empty_crlf",
    "escaped_quotes",
    "json",
    "newlines",
    "newlines_crlf",
    "quotes_and_newlines",
    "simple",
    "simple_crlf",
    "utf8",
)


def _expected_records(case: str) -> list[dict[str, object]]:
    raw: Any = json.loads((_FIXTURE_ROOT / "json" / f"{case}.json").read_text(encoding="utf-8"))
    assert isinstance(raw, list)
    assert all(isinstance(record, dict) for record in raw)

    # CsvConnector's public record contract canonicalizes an empty CSV cell to None.
    return [
        {str(key): None if value == "" else value for key, value in record.items()}
        for record in raw
    ]


def _named_records(connector: CsvConnector) -> list[dict[str, object]]:
    schema = connector.inspect_schema()
    return [
        {field.name: record[field.id] for field in schema.fields}
        for record in connector.iter_records()
    ]


@pytest.mark.parametrize("case", _CASES)
def test_csv_connector_matches_csv_spectrum_expected_results(case: str) -> None:
    connector = CsvConnector(_FIXTURE_ROOT / "csvs" / f"{case}.csv")

    assert connector.inspect_schema().metadata["delimiter"] == ","
    assert _named_records(connector) == _expected_records(case)


def test_csv_spectrum_fixture_bytes_match_pinned_sha256_manifest() -> None:
    expected_cases = set(_CASES)
    assert {path.stem for path in (_FIXTURE_ROOT / "csvs").glob("*.csv")} == expected_cases
    assert {path.stem for path in (_FIXTURE_ROOT / "json").glob("*.json")} == expected_cases

    entries = [
        line.split("  ", maxsplit=1)
        for line in (_FIXTURE_ROOT / "SHA256SUMS").read_text(encoding="ascii").splitlines()
        if line
    ]

    assert len(entries) == len(_CASES) * 2
    for expected_digest, relative_path in entries:
        fixture = _FIXTURE_ROOT / relative_path
        assert fixture.is_file()
        assert hashlib.sha256(fixture.read_bytes()).hexdigest() == expected_digest
