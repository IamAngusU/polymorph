from __future__ import annotations

from polymorph.connectors.csv_file import CsvConnector
from polymorph.models.types import DataType, FieldRole, Sensitivity


def test_csv_sniffs_semicolon_and_preserves_natural_keys(tmp_path) -> None:
    path = tmp_path / "orders.csv"
    path.write_text(
        "Debitor Nr;Amount;API Token\n000042;12.50;secret-1\n000043;3.00;secret-2\n",
        encoding="utf-8",
    )
    connector = CsvConnector(path)
    schema = connector.inspect_schema()

    assert schema.metadata["delimiter"] == ";"
    assert schema.fields[0].role is FieldRole.NATURAL_KEY
    assert schema.fields[0].data_type is DataType.STRING
    assert schema.fields[2].sensitivity is Sensitivity.SECRET
    records = list(connector.iter_records())
    assert records[0]["c1"] == "000042"
    assert records[0]["c3"] == "secret-1"


def test_csv_repeated_header_is_skipped(tmp_path) -> None:
    path = tmp_path / "paged.csv"
    path.write_text("Name,Value\nA,1\nName,Value\nB,2\n", encoding="utf-8")
    records = list(CsvConnector(path).iter_records())
    assert records == [{"c1": "A", "c2": "1"}, {"c1": "B", "c2": "2"}]


def test_csv_write_rejects_shape_changes(tmp_path) -> None:
    path = tmp_path / "out.csv"
    path.write_text("a,b\n", encoding="utf-8")
    connector = CsvConnector(path)
    try:
        connector.write_records([{"a": 1, "b": 2}, {"a": 3}])
    except ValueError as exc:
        assert "identical fields" in str(exc)
    else:
        raise AssertionError("shape mismatch was not rejected")


def test_csv_can_create_new_destination(tmp_path) -> None:
    path = tmp_path / "new.csv"
    connector = CsvConnector(path)
    assert connector.write_records([{"name": "A", "value": 1}]) == 1
    assert path.read_text(encoding="utf-8-sig").startswith("name,value")
