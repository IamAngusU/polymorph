import pytest
from openpyxl import Workbook

from polymorph.connectors.excel import ExcelConnector
from polymorph.errors import ConnectorError
from polymorph.models.types import DataType, FieldRole, Sensitivity


def test_excel_schema_and_records(tmp_path):
    path = tmp_path / "input.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["Debitor Nr", "API Token", "Netto Betrag"])
    sheet.append(["00042", "secret", 12.5])
    workbook.save(path)

    connector = ExcelConnector(path)
    schema = connector.inspect_schema()
    records = list(connector.iter_records())

    assert schema.fields[1].sensitivity is Sensitivity.SECRET
    assert schema.fields[0].role is FieldRole.NATURAL_KEY
    assert schema.fields[2].data_type is DataType.DECIMAL
    assert records[0]["c1"] == "00042"
    assert records[0]["c3"] == 12.5


def test_excel_auto_detects_header_below_title_rows(tmp_path):
    path = tmp_path / "messy.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet["A1"] = "Quarterly customer export"
    sheet.append([])
    sheet.append(["Customer Number", "Order Number", "Net Amount"])
    sheet.append([42, "A-1", 100.25])
    sheet.append([43, "A-2", 99.50])
    workbook.save(path)

    connector = ExcelConnector(path)
    layout = connector.discover_layout()
    schema = connector.inspect_schema()

    assert layout.header_row == 3
    assert [field.name for field in schema.fields] == [
        "Customer Number",
        "Order Number",
        "Net Amount",
    ]
    assert schema.fields[0].data_type is DataType.INTEGER
    assert schema.fields[2].data_type is DataType.DECIMAL


def test_excel_preserves_fixed_width_numeric_identifiers(tmp_path):
    path = tmp_path / "ids.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["Customer Number", "Name"])
    sheet.append([42, "Acme"])
    sheet["A2"].number_format = "000000"
    workbook.save(path)

    connector = ExcelConnector(path)
    record = next(iter(connector.iter_records()))
    assert record["c1"] == "000042"
    assert connector.inspect_schema().fields[0].data_type is DataType.STRING


def test_excel_skips_repeated_headers_inside_export(tmp_path):
    path = tmp_path / "paged.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["Customer Number", "Amount"])
    sheet.append(["A-1", 10])
    sheet.append(["Customer Number", "Amount"])
    sheet.append(["A-2", 20])
    workbook.save(path)

    records = list(ExcelConnector(path).iter_records())
    assert len(records) == 2
    assert [record["c1"] for record in records] == ["A-1", "A-2"]


def test_excel_marks_formula_values_as_cached_and_unproven(tmp_path):
    path = tmp_path / "formulas.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["Amount", "Tax"])
    sheet.append([100, "=A2*0.19"])
    workbook.save(path)

    schema = ExcelConnector(path).inspect_schema()

    assert schema.metadata["formula_cells_present"] == "true"
    assert schema.metadata["formula_value_source"] == "cached_workbook_value"


def test_excel_fails_closed_when_openpyxl_xml_hardening_is_disabled(tmp_path, monkeypatch) -> None:
    import polymorph.connectors.excel as excel_module

    path = tmp_path / "book.xlsx"
    workbook = Workbook()
    workbook.active.append(["id"])
    workbook.active.append([1])
    workbook.save(path)

    monkeypatch.setattr(excel_module.openpyxl, "DEFUSEDXML", False)

    with pytest.raises(ConnectorError, match="defusedxml"):
        ExcelConnector(path).inspect_schema()
