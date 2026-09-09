from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from openpyxl import Workbook

from polymorph.connectors.excel import ExcelConnector
from polymorph.connectors.json_file import JsonFileConnector
from polymorph.content import ContentInspector, ContentKind, RiskCode
from polymorph.errors import ConnectorError


def test_content_inspection_ignores_filename_for_json(tmp_path) -> None:
    path = tmp_path / "definitely-an-image.png"
    path.write_text('{"customer": "Acme"}', encoding="utf-8")

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.JSON
    assert report.safe
    assert list(JsonFileConnector(path).iter_records()) == [{"customer": "Acme"}]


def test_json5_is_selected_by_content_not_extension(tmp_path) -> None:
    path = tmp_path / "payload.dat"
    path.write_text("[{ customer: 'Acme', amount: 2, },]", encoding="utf-8")

    connector = JsonFileConnector(path)
    schema = connector.inspect_schema()

    assert schema.metadata["format"] == "json5"


def test_excel_is_detected_from_ooxml_structure_without_xlsx_suffix(tmp_path) -> None:
    original = tmp_path / "book.xlsx"
    renamed = tmp_path / "opaque-upload.bin"
    workbook = Workbook()
    workbook.active.append(["Customer", "Amount"])
    workbook.active.append(["Acme", 10])
    workbook.save(original)
    original.replace(renamed)

    report = ContentInspector().inspect(renamed)

    assert report.kind is ContentKind.XLSX
    assert ExcelConnector(renamed).inspect_schema().fields[0].name == "Customer"


def test_archive_path_traversal_is_blocking(tmp_path) -> None:
    path = tmp_path / "trap.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../escape.txt", "nope")

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert any(item.code is RiskCode.ARCHIVE_PATH_TRAVERSAL for item in report.risks)


def test_macro_enabled_office_container_is_rejected_before_openpyxl(tmp_path) -> None:
    path = tmp_path / "macro.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("xl/vbaProject.bin", b"MZfake")

    report = ContentInspector().inspect(path)
    assert any(item.code is RiskCode.OFFICE_MACRO for item in report.risks)
    with pytest.raises(ConnectorError, match="office_macro"):
        ExcelConnector(path).inspect_schema()


def test_csv_connector_rejects_binary_renamed_to_csv(tmp_path) -> None:
    from polymorph.connectors.csv_file import CsvConnector

    path = tmp_path / "trusted.csv"
    path.write_bytes(b"MZ" + b"\x00" * 100)

    with pytest.raises(ConnectorError, match="detected executable"):
        CsvConnector(path).inspect_schema()


def test_external_workbook_links_are_blocking_by_default(tmp_path) -> None:
    path = tmp_path / "linked.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("xl/externalLinks/externalLink1.xml", "<externalLink/>")

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert any(item.code is RiskCode.OFFICE_EXTERNAL_LINK for item in report.risks)


def test_high_confidence_classifier_disagreement_blocks_parser_selection(tmp_path) -> None:
    from polymorph.content import ClassifierEvidence

    class FakeClassifier:
        def classify(self, path):
            return ClassifierEvidence("test", "executable", "application/x-executable", 0.99)

    path = tmp_path / "input.json"
    path.write_text('{"id": 1}', encoding="utf-8")

    report = ContentInspector(classifier=FakeClassifier()).inspect(path)

    assert report.kind is ContentKind.JSON
    assert not report.safe
    assert any(item.code is RiskCode.CLASSIFIER_DISAGREEMENT for item in report.risks)


def test_duplicate_archive_entries_are_blocking(tmp_path) -> None:
    path = tmp_path / "duplicate.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("XL/WORKBOOK.XML", "<other/>")

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert any(item.code is RiskCode.ARCHIVE_DUPLICATE_ENTRY for item in report.risks)


def test_magika_adapter_reads_score_from_prediction_object() -> None:
    from types import SimpleNamespace

    from polymorph.content import MagikaClassifier

    class FakeMagika:
        def identify_path(self, path):
            return SimpleNamespace(
                output=SimpleNamespace(label="json", mime_type="application/json"),
                score=0.987,
            )

    classifier = MagikaClassifier.__new__(MagikaClassifier)
    classifier._magika = FakeMagika()
    evidence = classifier.classify(Path("ignored"))

    assert evidence.label == "json"
    assert evidence.score == pytest.approx(0.987)


def test_external_workbook_data_connections_are_blocking_by_default(tmp_path) -> None:
    path = tmp_path / "connected.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("xl/connections.xml", "<connections/>")

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert any(item.code is RiskCode.OFFICE_EXTERNAL_DATA for item in report.risks)
