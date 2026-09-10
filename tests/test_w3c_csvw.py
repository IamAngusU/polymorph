from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from polymorph.connectors.csv_file import CsvConnector

_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "w3c-csvw"
_SOURCE_FILES = {
    "csv/test008.csv",
    "csv/test055.csv",
    "csv/test091.csv",
    "csv/test125.csv",
    "csv/test248.csv",
    "csv/tree-ops.tsv",
    "encoded/test009.csv.base64",
}
_TEST009_SHA256 = "696d489e33252a0e291bee583edb4fef38bd4b16ef2b03ef24b06aeeb60b43ad"

_POSITIVE_CASES: dict[
    str,
    tuple[str, tuple[str, ...], list[dict[str, object]]],
] = {
    "test008.csv": (
        ",",
        ("Book1", "Book2", "Path"),
        [
            {
                "Book1": "1",
                "Book2": "7680",
                "Path": (
                    "http://dbpedia.org/ontology/language,"
                    "http://dbpedia.org/resource/English_language,"
                    "http://dbpedia.org/ontology/language"
                ),
            },
            {
                "Book1": "1",
                "Book2": "2",
                "Path": (
                    "http://dbpedia.org/ontology/author,"
                    "http://dbpedia.org/resource/Diana_Gabaldon,"
                    "http://dbpedia.org/ontology/author"
                ),
            },
            {
                "Book1": "1",
                "Book2": "2",
                "Path": (
                    "http://dbpedia.org/ontology/country,"
                    "http://dbpedia.org/resource/United_States,"
                    "http://dbpedia.org/ontology/country"
                ),
            },
        ],
    ),
    "test055.csv": (
        ",",
        ("GID", "On Street", "Species", "Trim Cycle", "Inventory Date"),
        [
            {
                "GID": "1",
                "On Street": "ADDISON AV",
                "Species": "Celtis australis",
                "Trim Cycle": "Large Tree Routine Prune",
                "Inventory Date": "10/18/2010",
            },
            {
                "GID": "2",
                "On Street": "EMERSON ST",
                "Species": "Liquidambar styraciflua",
                "Trim Cycle": "Large Tree Routine Prune",
                "Inventory Date": "6/2/2010",
            },
        ],
    ),
    "test125.csv": (
        ",",
        ("countryCode", "latitude", "longitude", "name"),
        [
            {
                "countryCode": "AD",
                "latitude": "42.546245",
                "longitude": "1.601554",
                "name": "Andorra",
            },
            {
                "countryCode": "AE",
                "latitude": "23.424076",
                "longitude": "53.847818",
                "name": "United Arab Emirates",
            },
            {
                "countryCode": "AF",
                "latitude": None,
                "longitude": "67.709953",
                "name": "Afghanistan",
            },
        ],
    ),
    "test248.csv": (
        ",",
        ("characters", "codepoints", "nfc", "description"),
        [
            {
                "characters": "Å",
                "codepoints": "212B",
                "nfc": "00C5",
                "description": "a-with-ring",
            },
            {
                "characters": "ḍ̇",
                "codepoints": "1E0B 0323",
                "nfc": "1E0D 0307",
                "description": "combining marks",
            },
        ],
    ),
    "tree-ops.tsv": (
        "\t",
        ("GID", "On Street", "Species", "Trim Cycle", "Inventory Date"),
        [
            {
                "GID": "1",
                "On Street": "ADDISON AV",
                "Species": "Celtis australis",
                "Trim Cycle": "Large Tree Routine Prune",
                "Inventory Date": "10/18/2010",
            },
            {
                "GID": "2",
                "On Street": "EMERSON ST",
                "Species": "Liquidambar styraciflua",
                "Trim Cycle": "Large Tree Routine Prune",
                "Inventory Date": "6/2/2010",
            },
        ],
    ),
}


def _read_named_records(
    connector: CsvConnector,
) -> tuple[tuple[str, ...], str, list[dict[str, object]]]:
    schema = connector.inspect_schema()
    records = [
        {field.name: record[field.id] for field in schema.fields}
        for record in connector.iter_records()
    ]
    return (
        tuple(field.name for field in schema.fields),
        str(schema.metadata["delimiter"]),
        records,
    )


@pytest.mark.parametrize("case", tuple(_POSITIVE_CASES))
def test_csv_connector_matches_selected_w3c_csvw_records(case: str) -> None:
    expected_delimiter, expected_headers, expected_records = _POSITIVE_CASES[case]

    headers, delimiter, records = _read_named_records(CsvConnector(_FIXTURE_ROOT / "csv" / case))

    assert delimiter == expected_delimiter
    assert headers == expected_headers
    assert records == expected_records


def test_csv_connector_parses_exact_w3c_crlf_source(tmp_path: Path) -> None:
    encoded = (_FIXTURE_ROOT / "encoded" / "test009.csv.base64").read_bytes().strip()
    payload = base64.b64decode(encoded, validate=True)
    source = tmp_path / "test009.csv"
    source.write_bytes(payload)

    assert hashlib.sha256(payload).hexdigest() == _TEST009_SHA256
    assert payload.count(b"\r\n") == 4
    assert b"\n" not in payload.replace(b"\r\n", b"")

    headers, delimiter, records = _read_named_records(CsvConnector(source))
    assert delimiter == ","
    assert headers == ("GID", "On Street", "Species", "Trim Cycle", "Inventory Date")
    assert records == [
        {
            "GID": "1",
            "On Street": "ADDISON AV",
            "Species": "Celtis australis",
            "Trim Cycle": "Large Tree Routine Prune",
            "Inventory Date": "10/18/2010",
        },
        {
            "GID": "2",
            "On Street": "EMERSON ST",
            "Species": "Liquidambar styraciflua",
            "Trim Cycle": "Large Tree Routine Prune",
            "Inventory Date": "6/2/2010",
        },
        {
            "GID": "3",
            "On Street": "EMERSON ST",
            "Species": "Liquidambar styraciflua",
            "Trim Cycle": "Large Tree Routine Prune",
            "Inventory Date": "6/2/2010",
        },
    ]


def test_csv_connector_abstains_on_w3c_inconsistent_width_without_override() -> None:
    source = _FIXTURE_ROOT / "csv" / "test091.csv"

    with pytest.raises(ValueError, match="CSV dialect is too ambiguous"):
        CsvConnector(source).inspect_schema()

    headers, delimiter, records = _read_named_records(CsvConnector(source, delimiter=","))
    assert delimiter == ","
    assert headers == ("col1", "col2", "col3")
    assert records == [
        {"col1": "1", "col2": "2", "col3": "3"},
        {"col1": "1", "col2": "2", "col3": None},
        {"col1": "1", "col2": None, "col3": None},
    ]


def test_w3c_csvw_fixture_bytes_match_pinned_sha256_manifest() -> None:
    entries = {}
    for line in (_FIXTURE_ROOT / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        digest, relative_path = line.split("  ", maxsplit=1)
        entries[relative_path] = digest

    actual_sources = {
        path.relative_to(_FIXTURE_ROOT).as_posix()
        for directory in ("csv", "encoded")
        for path in (_FIXTURE_ROOT / directory).iterdir()
        if path.is_file()
    }
    assert actual_sources == _SOURCE_FILES
    assert set(entries) == _SOURCE_FILES
    for relative_path, expected_digest in entries.items():
        fixture = _FIXTURE_ROOT / relative_path
        assert fixture.is_file()
        assert hashlib.sha256(fixture.read_bytes()).hexdigest() == expected_digest
