from __future__ import annotations

import zipfile

import pytest
from openpyxl import Workbook

from polymorph.cli import _normalized_database_url
from polymorph.connectors.excel import ExcelConnector
from polymorph.data_quality import DataQualityAnalyzer
from polymorph.execution import DataPlaneExecutor
from polymorph.models.mapping import MappingDecision, MappingStatus
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType
from polymorph.planning import build_plan
from polymorph.preflight import PreflightRunner


def test_excel_detects_namespace_prefixed_formula_tag(tmp_path) -> None:
    path = tmp_path / "prefixed-formula.xlsx"
    rewritten = tmp_path / "rewritten.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["quantity", "unit_price", "total"])
    sheet.append([2, 50, "=A2*B2"])
    workbook.save(path)

    namespace = b"http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    with (
        zipfile.ZipFile(path, "r") as source,
        zipfile.ZipFile(rewritten, "w", zipfile.ZIP_DEFLATED) as target,
    ):
        for info in source.infolist():
            payload = source.read(info.filename)
            if info.filename == "xl/worksheets/sheet1.xml":
                declaration = b'<worksheet xmlns="' + namespace + b'">'
                replacement = b'<worksheet xmlns="' + namespace + b'" xmlns:x="' + namespace + b'">'
                payload = payload.replace(declaration, replacement, 1)
                payload = payload.replace(b"<f>", b"<x:f>").replace(b"</f>", b"</x:f>")
            target.writestr(info, payload)
    rewritten.replace(path)

    schema = ExcelConnector(path).inspect_schema()

    assert schema.metadata["formula_cells_present"] == "true"
    assert schema.metadata["formula_value_source"] == "cached_workbook_value"


def test_csv_null_cells_remain_visible_as_empty_string_quality_findings() -> None:
    csv_schema = SchemaDescriptor(
        "csv:quality.csv",
        (FieldDescriptor("c1", "label", DataType.STRING, nullable=True),),
        metadata={"delimiter": ",", "encoding": "utf-8-sig"},
    )
    json_schema = SchemaDescriptor(
        "json:quality.json",
        (FieldDescriptor("label", "label", DataType.STRING, nullable=True),),
        metadata={"format": "json"},
    )

    csv_report = DataQualityAnalyzer(csv_schema).inspect([{"c1": None}])
    json_report = DataQualityAnalyzer(json_schema).inspect([{"label": None}])

    assert {item.code for item in csv_report.issue_groups} == {"empty_string"}
    assert not json_report.issue_groups


def test_integer_auto_route_uses_one_strict_transform_end_to_end() -> None:
    source = SchemaDescriptor(
        "csv:quantities.csv",
        (FieldDescriptor("c1", "quantity", DataType.INTEGER, nullable=False),),
        metadata={"delimiter": ",", "encoding": "utf-8-sig"},
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("quantity", "quantity", DataType.INTEGER, nullable=False),),
    )
    decision = MappingDecision("c1", "quantity", MappingStatus.AUTO, 1.0, 1.0)

    plan = build_plan(source, target, [decision])

    assert plan.rules[0].transform == "parse_integer"
    assert PreflightRunner().run([{"c1": "42"}], source, target, plan).promotable
    assert DataPlaneExecutor(source, target, plan).execute_record({"c1": "42"}) == {"quantity": 42}
    rejected = PreflightRunner().run([{"c1": "4.2"}], source, target, plan)
    assert not rejected.valid
    assert {item.code for item in rejected.findings} == {"source_transform_failed"}


def test_existing_local_sqlite_path_is_normalized_without_changing_urls(tmp_path) -> None:
    database = tmp_path / "target.sqlite3"
    database.touch()

    assert _normalized_database_url(str(database)) == f"sqlite:///{database.resolve().as_posix()}"
    assert _normalized_database_url("postgresql://localhost/example") == (
        "postgresql://localhost/example"
    )
    with pytest.raises(SystemExit, match="SQLAlchemy URL or an existing local SQLite file"):
        _normalized_database_url(str(tmp_path / "missing.sqlite3"))
