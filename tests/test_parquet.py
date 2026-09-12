from __future__ import annotations

from datetime import date

import pytest

from polymorph.cli import _auto_source, build_parser
from polymorph.connectors.parquet import ParquetConnector
from polymorph.models.types import DataType

pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")


def test_parquet_inspection_and_streaming(tmp_path) -> None:
    path = tmp_path / "orders.parquet"
    table = pa.table(
        {
            "order_id": ["A-1", "A-2"],
            "quantity": [2, 5],
            "invoice_date": [date(2026, 1, 2), date(2026, 1, 3)],
        }
    )
    pq.write_table(table, path)

    connector = ParquetConnector(path, batch_rows=1)
    schema = connector.inspect_schema()

    assert schema.metadata["format"] == "parquet"
    assert schema.metadata["rows"] == "2"
    assert schema.by_id()["quantity"].data_type is DataType.INTEGER
    assert list(connector.iter_records()) == table.to_pylist()


def test_parquet_auto_inspection_uses_content_not_extension(tmp_path) -> None:
    path = tmp_path / "orders.bin"
    pq.write_table(pa.table({"customer_number": ["C-1"]}), path)

    report, connector = _auto_source(str(path))

    assert report.kind.value == "parquet"
    assert isinstance(connector, ParquetConnector)


def test_parquet_cli_inspection(tmp_path, capsys) -> None:
    path = tmp_path / "orders.parquet"
    pq.write_table(pa.table({"quantity": [1, 2]}), path)
    args = build_parser().parse_args(["inspect", "parquet", str(path)])

    args.func(args)

    assert '"format": "parquet"' in capsys.readouterr().out
