from __future__ import annotations

import gzip
import hashlib
import math
import os
import struct
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import polymorph.content as content_module
from polymorph.content import (
    ClassifierEvidence,
    ContentInspector,
    ContentKind,
    FileTrustPolicy,
    RiskCode,
)

_INTEGER_LIMITS = (
    "max_file_bytes",
    "max_probe_bytes",
    "max_text_parse_bytes",
    "max_json5_parse_bytes",
    "max_structured_text_depth",
    "max_archive_entries",
    "max_archive_metadata_bytes",
    "max_archive_uncompressed_bytes",
    "max_archive_member_bytes",
    "max_xml_elements",
    "max_gzip_scan_bytes",
    "max_json_items",
    "max_xml_attributes_per_element",
)


def test_windows_reparse_input_is_blocked_like_a_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "junction-target.json"
    path.write_text('{"value": 1}', encoding="utf-8")
    metadata = path.lstat()
    reparse_metadata = SimpleNamespace(
        st_dev=metadata.st_dev,
        st_ino=metadata.st_ino,
        st_size=metadata.st_size,
        st_mtime_ns=metadata.st_mtime_ns,
        st_mode=metadata.st_mode,
        st_file_attributes=0x400,
    )
    monkeypatch.setattr(Path, "lstat", lambda _path: reparse_metadata)

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.UNKNOWN
    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.SYMLINK_INPUT]
    assert "reparse point" in report.risks[0].detail


def test_linked_parent_directory_is_blocked_like_a_link_input(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    (real_directory / "input.json").write_text('{"value": 1}', encoding="utf-8")
    linked_directory = tmp_path / "linked"
    try:
        linked_directory.symlink_to(real_directory, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    report = ContentInspector().inspect(linked_directory / "input.json")

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.SYMLINK_INPUT]
    assert "parent" in report.risks[0].detail


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink and dot-dot traversal semantics")
def test_linked_parent_before_dotdot_cannot_bypass_link_gate(tmp_path: Path) -> None:
    lexical_directory = tmp_path / "lexical"
    lexical_directory.mkdir()
    target_parent = tmp_path / "target"
    target_child = target_parent / "child"
    target_child.mkdir(parents=True)
    (target_parent / "input.json").write_text('{"value": 1}', encoding="utf-8")
    linked_directory = lexical_directory / "jump"
    try:
        linked_directory.symlink_to(target_child, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    report = ContentInspector().inspect(linked_directory / ".." / "input.json")

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.SYMLINK_INPUT]
    assert "parent" in report.risks[0].detail


def _write_forced_zip64(path: Path, *names: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "content")

    payload = path.read_bytes()
    eocd_offset = payload.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    end_record = struct.unpack_from("<4s4H2LH", payload, eocd_offset)
    zip64_record = struct.pack(
        "<4sQ2H2L4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        end_record[3],
        end_record[4],
        end_record[5],
        end_record[6],
    )
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd_offset, 1)
    path.write_bytes(payload[:eocd_offset] + zip64_record + locator + payload[eocd_offset:])


@pytest.mark.parametrize("name", _INTEGER_LIMITS)
@pytest.mark.parametrize("value", (True, False, 0, -1, 1.5, "1", None))
def test_file_trust_policy_requires_positive_integer_limits(name: str, value: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        FileTrustPolicy(**{name: value})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    (True, False, 0.0, -1.0, math.inf, -math.inf, math.nan, "200", None),
)
def test_file_trust_policy_requires_finite_positive_compression_ratio(value: object) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        FileTrustPolicy(max_compression_ratio=value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    (True, False, -0.01, 1.01, math.inf, -math.inf, math.nan, "0.9", None),
)
def test_file_trust_policy_requires_unit_interval_classifier_threshold(value: object) -> None:
    with pytest.raises(ValueError, match="between zero and one"):
        FileTrustPolicy(classifier_disagreement_threshold=value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "name",
    (
        "allow_office_macros",
        "allow_office_external_links",
        "allow_symlink_inputs",
        "classifier_disagreement_is_blocking",
    ),
)
@pytest.mark.parametrize("value", (0, 1, "false", None))
def test_file_trust_policy_requires_real_booleans(name: str, value: object) -> None:
    with pytest.raises(ValueError, match="must be a boolean"):
        FileTrustPolicy(**{name: value})  # type: ignore[arg-type]


def test_file_trust_policy_accepts_finite_boundary_values() -> None:
    lower = FileTrustPolicy(
        max_compression_ratio=0.01,
        classifier_disagreement_threshold=0.0,
    )
    upper = FileTrustPolicy(classifier_disagreement_threshold=1.0)

    assert lower.classifier_disagreement_threshold == 0.0
    assert upper.classifier_disagreement_threshold == 1.0


def test_file_trust_policy_preserves_original_positional_field_order() -> None:
    policy = FileTrustPolicy(
        100,
        101,
        102,
        103,
        104,
        105,
        106.0,
        True,
        False,
        True,
        0.75,
        False,
    )

    assert policy.max_archive_entries == 103
    assert policy.max_compression_ratio == 106.0
    assert policy.allow_office_macros is True
    assert policy.classifier_disagreement_threshold == 0.75
    assert policy.classifier_disagreement_is_blocking is False
    assert policy.max_json5_parse_bytes == 64 * 1024


@pytest.mark.parametrize(
    "name",
    ("max_compression_ratio", "classifier_disagreement_threshold"),
)
def test_file_trust_policy_rejects_integers_too_large_for_float(name: str) -> None:
    with pytest.raises(ValueError, match="finite"):
        FileTrustPolicy(**{name: 10**10000})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "payload",
    (
        "[" * 160 + "0" + "]" * 160,
        "/* JSON5 */ " + "[" * 160 + "'value'" + "]" * 160,
    ),
)
def test_deep_json_like_input_is_blocked_before_recursive_parsers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    path = tmp_path / "deep.data"
    path.write_text(payload, encoding="utf-8")

    def parser_must_not_run(_text: str) -> object:
        raise AssertionError("recursive parser was invoked before the nesting gate")

    monkeypatch.setattr(content_module.json, "loads", parser_must_not_run)
    monkeypatch.setattr(content_module.json5, "loads", parser_must_not_run)

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.TEXT
    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.JSON_NESTING_TOO_DEEP]


def test_json_nesting_scan_ignores_strings_and_json5_comments(tmp_path: Path) -> None:
    path = tmp_path / "shallow.json5"
    path.write_text(
        "/* [[[ ignored ]]] */ {value: '[[[ also ignored ]]]'}",
        encoding="utf-8",
    )

    report = ContentInspector(FileTrustPolicy(max_structured_text_depth=1)).inspect(path)

    assert report.kind is ContentKind.JSON5
    assert report.safe


def test_json_item_budget_blocks_wide_input_before_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "wide.json"
    path.write_text("[{}, {}, {}]", encoding="utf-8")

    def parser_must_not_run(_text: str) -> object:
        raise AssertionError("recursive parser was invoked before the item gate")

    monkeypatch.setattr(content_module.json, "loads", parser_must_not_run)
    monkeypatch.setattr(content_module.json5, "loads", parser_must_not_run)

    report = ContentInspector(FileTrustPolicy(max_json_items=2)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.JSON_TOO_MANY_ITEMS]


@pytest.mark.parametrize("line_terminator", (" ", " "))
def test_json5_line_terminators_end_comments_for_nesting_gate(
    tmp_path: Path,
    line_terminator: str,
) -> None:
    path = tmp_path / "deep-comment.json5"
    path.write_text(
        f"{{// comment{line_terminator}value: [[0]]}}",
        encoding="utf-8",
    )

    report = ContentInspector(FileTrustPolicy(max_structured_text_depth=1)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.JSON_NESTING_TOO_DEEP]


def test_json5_above_inspector_limit_is_not_parsed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "large.json5"
    path.write_text("{value: '" + ("x" * 70_000) + "'}", encoding="utf-8")

    def json5_must_not_run(_text: str) -> object:
        raise AssertionError("JSON5 parser ran above its byte limit")

    monkeypatch.setattr(content_module.json5, "loads", json5_must_not_run)
    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.TEXT
    assert report.safe
    assert report.signals == ("JSON-like content exceeds the configured JSON5 parse limit",)


def test_strict_json_above_json5_limit_is_still_confirmed(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    path.write_text('{"value":"' + ("x" * 70_000) + '"}', encoding="utf-8")

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.JSON
    assert report.safe


@pytest.mark.parametrize(
    "score",
    (
        math.nan,
        math.inf,
        -0.1,
        1.1,
        True,
        pytest.param(10**10000, id="huge-int"),
    ),
)
def test_invalid_classifier_score_is_a_blocking_risk(tmp_path: Path, score: object) -> None:
    class InvalidClassifier:
        def classify(self, _path: Path) -> ClassifierEvidence:
            return ClassifierEvidence("test", "executable", score=score)  # type: ignore[arg-type]

    path = tmp_path / "input.json"
    path.write_text('{"value": 1}', encoding="utf-8")

    report = ContentInspector(classifier=InvalidClassifier()).inspect(path)

    assert not report.safe
    assert report.classifier is not None
    assert report.classifier.score is None
    assert [risk.code for risk in report.risks] == [RiskCode.CLASSIFIER_DISAGREEMENT]
    assert "invalid classifier evidence was ignored" in report.signals


def test_leading_html_fragment_does_not_make_markdown_xml(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    path.write_text("<p>badge</p>\n\n# Heading\n", encoding="utf-8")

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.TEXT
    assert report.safe


def test_well_formed_xml_requires_safe_full_parse(tmp_path: Path) -> None:
    path = tmp_path / "input.data"
    path.write_text("<root><value>1</value></root>", encoding="utf-8")

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.XML
    assert report.safe
    assert report.signals == ("safe streaming XML parser accepted content",)


def test_deep_xml_is_blocked_by_streaming_depth_gate(tmp_path: Path) -> None:
    path = tmp_path / "deep.xml"
    path.write_text("<x>" * 160 + "value" + "</x>" * 160, encoding="utf-8")

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.TEXT
    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.XML_NESTING_TOO_DEEP]


def test_xml_element_count_is_bounded_without_building_a_tree(tmp_path: Path) -> None:
    path = tmp_path / "many-elements.xml"
    path.write_text("<root>" + ("<x/>" * 4) + "</root>", encoding="utf-8")

    report = ContentInspector(FileTrustPolicy(max_xml_elements=4)).inspect(path)

    assert report.kind is ContentKind.TEXT
    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.XML_TOO_MANY_ELEMENTS]


def test_xml_attribute_count_is_bounded_before_sax_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "many-attributes.xml"
    path.write_text('<root a="1" b="2" c="3"/>', encoding="utf-8")

    def sax_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("SAX parser ran above the attribute limit")

    monkeypatch.setattr(content_module.defused_sax, "parse", sax_must_not_run)
    report = ContentInspector(FileTrustPolicy(max_xml_attributes_per_element=2)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.XML_TOO_MANY_ATTRIBUTES]


def test_xml_attribute_gate_does_not_depend_on_python_isalpha(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "unicode-tag.xml"
    path.write_text('<℮ a="1" b="2" c="3"/>', encoding="utf-8")

    def sax_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("SAX parser materialized attributes before the lexical gate")

    monkeypatch.setattr(content_module.defused_sax, "parse", sax_must_not_run)
    report = ContentInspector(FileTrustPolicy(max_xml_attributes_per_element=2)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.XML_TOO_MANY_ATTRIBUTES]


def test_xml_attribute_scan_ignores_processing_instruction_text(tmp_path: Path) -> None:
    path = tmp_path / "processing-instruction.xml"
    path.write_text(
        '<?pretty output="> <fake a=1 b=2 c=3>"?><root/>',
        encoding="utf-8",
    )

    report = ContentInspector(FileTrustPolicy(max_xml_attributes_per_element=2)).inspect(path)

    assert report.safe
    assert report.kind is ContentKind.XML


def test_xml_dtd_is_not_classified_as_safely_parsed_xml(tmp_path: Path) -> None:
    path = tmp_path / "entity.xml"
    path.write_text(
        '<!DOCTYPE root [<!ENTITY value "blocked">]><root>&value;</root>',
        encoding="utf-8",
    )

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.TEXT
    assert "safe streaming XML parser accepted content" not in report.signals


def test_gzip_footer_ratio_is_blocking(tmp_path: Path) -> None:
    path = tmp_path / "compressed.data"
    path.write_bytes(gzip.compress(b"0" * (4 * 1024 * 1024), compresslevel=9))

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.GZIP
    assert not report.safe
    assert any(risk.code is RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO for risk in report.risks)


def test_gzip_forged_isize_cannot_hide_oversized_member(tmp_path: Path) -> None:
    path = tmp_path / "forged-size.gz"
    payload = bytearray(gzip.compress(b"0" * (4 * 1024 * 1024), compresslevel=9))
    struct.pack_into("<L", payload, len(payload) - 4, 0)
    path.write_bytes(payload)

    report = ContentInspector(
        FileTrustPolicy(
            max_archive_member_bytes=1024 * 1024,
            max_archive_uncompressed_bytes=8 * 1024 * 1024,
            max_compression_ratio=1_000_000,
        )
    ).inspect(path)

    assert not report.safe
    assert any(risk.code is RiskCode.ARCHIVE_MEMBER_TOO_LARGE for risk in report.risks)


def test_gzip_concatenated_members_count_toward_aggregate_limit(tmp_path: Path) -> None:
    path = tmp_path / "many-members.gz"
    member = gzip.compress(b"0" * (1024 * 1024), compresslevel=1)
    path.write_bytes(member * 6)

    report = ContentInspector(
        FileTrustPolicy(
            max_archive_member_bytes=2 * 1024 * 1024,
            max_archive_uncompressed_bytes=2 * 1024 * 1024,
            max_compression_ratio=1_000_000,
        )
    ).inspect(path)

    assert not report.safe
    assert any(risk.code is RiskCode.ARCHIVE_TOO_LARGE for risk in report.risks)


def test_gzip_concatenated_members_respect_archive_entry_limit(tmp_path: Path) -> None:
    path = tmp_path / "too-many-members.gz"
    member = gzip.compress(b"", compresslevel=1)
    path.write_bytes(member * 2)

    report = ContentInspector(FileTrustPolicy(max_archive_entries=1)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.ARCHIVE_TOO_MANY_ENTRIES]


def test_gzip_zero_padding_cannot_dilute_aggregate_ratio(tmp_path: Path) -> None:
    path = tmp_path / "padded-ratio.gz"
    member = gzip.compress(b"0" * (600 * 1024), compresslevel=9)
    path.write_bytes(member + (b"\x00" * (100 * 1024)) + member)

    report = ContentInspector(FileTrustPolicy(max_compression_ratio=20)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO]


def test_gzip_compressible_prefix_uses_complete_member_ratio(tmp_path: Path) -> None:
    path = tmp_path / "mixed-ratio.gz"
    incompressible = hashlib.shake_256(b"polymorph-gzip-ratio").digest(4 * 1024 * 1024)
    path.write_bytes(gzip.compress((b"0" * (1024 * 1024)) + incompressible, compresslevel=9))

    report = ContentInspector().inspect(path)

    assert report.safe
    assert report.kind is ContentKind.GZIP


def test_gzip_aggregate_ratio_uses_complete_stream(tmp_path: Path) -> None:
    path = tmp_path / "mixed-members.gz"
    small_bomb = gzip.compress(b"0" * (600 * 1024), compresslevel=9)
    incompressible = hashlib.shake_256(b"polymorph-gzip-aggregate").digest(4 * 1024 * 1024)
    path.write_bytes(small_bomb + small_bomb + gzip.compress(incompressible, compresslevel=9))

    report = ContentInspector().inspect(path)

    assert report.safe
    assert report.kind is ContentKind.GZIP


def test_gzip_padding_does_not_create_false_isize_evidence(tmp_path: Path) -> None:
    path = tmp_path / "trailing-padding.gz"
    path.write_bytes(gzip.compress(b"hello world") + (b"\x00" * 16))

    report = ContentInspector().inspect(path)

    assert report.safe
    assert not any("footer reports" in signal for signal in report.signals)
    assert any(signal.startswith("validated 1 gzip member") for signal in report.signals)


def test_gzip_trailing_garbage_is_not_misreported_as_an_extra_member(tmp_path: Path) -> None:
    path = tmp_path / "trailing-garbage.gz"
    path.write_bytes(gzip.compress(b"ordinary payload") + b"not-a-member")

    report = ContentInspector(FileTrustPolicy(max_archive_entries=1)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.MALFORMED_ARCHIVE]


def test_gzip_malformed_extra_field_is_blocked(tmp_path: Path) -> None:
    path = tmp_path / "malformed-extra.gz"
    path.write_bytes(b"\x1f\x8b\x08\x04" + b"\x00" * 6 + b"\xff\xff" + b"\x00" * 8)

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert any(risk.code is RiskCode.MALFORMED_ARCHIVE for risk in report.risks)


def test_valid_gzip_is_stream_validated(tmp_path: Path) -> None:
    path = tmp_path / "normal.gz"
    path.write_bytes(gzip.compress(b"ordinary payload"))

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.GZIP
    assert report.safe
    assert any(signal.startswith("validated 1 gzip member") for signal in report.signals)


def test_gzip_scan_budget_blocks_before_decompression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "above-scan-budget.gz"
    path.write_bytes(gzip.compress(b"ordinary payload" * 20, compresslevel=1))
    assert path.stat().st_size > 20

    def decompressor_must_not_start(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("gzip decompressor started above its input budget")

    monkeypatch.setattr(content_module.zlib, "decompressobj", decompressor_must_not_start)
    report = ContentInspector(FileTrustPolicy(max_gzip_scan_bytes=20)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.ARCHIVE_SCAN_BUDGET_EXCEEDED]


def test_archive_entry_limit_is_checked_before_zipfile_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "entries.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("first.txt", "")
        archive.writestr("second.txt", "")

    def zipfile_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ZipFile was constructed before the EOCD entry limit")

    monkeypatch.setattr(content_module.zipfile, "ZipFile", zipfile_must_not_run)

    report = ContentInspector(FileTrustPolicy(max_archive_entries=1)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.ARCHIVE_TOO_MANY_ENTRIES]


def test_archive_metadata_limit_is_checked_before_zipfile_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "metadata.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("entry.txt", "")

    def zipfile_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ZipFile was constructed before the EOCD metadata limit")

    monkeypatch.setattr(content_module.zipfile, "ZipFile", zipfile_must_not_run)

    report = ContentInspector(FileTrustPolicy(max_archive_metadata_bytes=1)).inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.ARCHIVE_METADATA_TOO_LARGE]


def test_zip64_metadata_disagreement_is_blocked_before_zipfile_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "contradictory-zip64.zip"
    _write_forced_zip64(path, "first.txt", "second.txt")
    payload = bytearray(path.read_bytes())
    eocd_offset = payload.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    struct.pack_into("<2H2L", payload, eocd_offset + 8, 1, 1, 1, 0)
    path.write_bytes(payload)

    def zipfile_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ZipFile was constructed after contradictory ZIP64 metadata")

    monkeypatch.setattr(content_module.zipfile, "ZipFile", zipfile_must_not_run)

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.MALFORMED_ARCHIVE]


def test_zip64_with_prepended_data_uses_physical_end_record(tmp_path: Path) -> None:
    path = tmp_path / "prepended-zip64.zip"
    _write_forced_zip64(path, "entry.txt")
    payload = bytearray(path.read_bytes())
    eocd_offset = payload.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    struct.pack_into(
        "<2H2L",
        payload,
        eocd_offset + 8,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    )
    prefix = b"PK\x03\x04prepended-data-before-the-real-archive"
    path.write_bytes(prefix + payload)

    with zipfile.ZipFile(path) as archive:
        assert archive.namelist() == ["entry.txt"]

    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.ZIP
    assert report.safe
    assert not report.risks


def test_underreported_zip_entries_are_blocked_before_zipfile_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "underreported.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("first.txt", "")
        archive.writestr("second.txt", "")

    payload = bytearray(path.read_bytes())
    eocd_offset = payload.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    struct.pack_into("<2H", payload, eocd_offset + 8, 1, 1)
    path.write_bytes(payload)

    def zipfile_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ZipFile was constructed after an underreported entry count")

    monkeypatch.setattr(content_module.zipfile, "ZipFile", zipfile_must_not_run)
    report = ContentInspector(FileTrustPolicy(max_archive_entries=1)).inspect(path)

    assert not report.safe
    assert {risk.code for risk in report.risks} == {
        RiskCode.MALFORMED_ARCHIVE,
        RiskCode.ARCHIVE_TOO_MANY_ENTRIES,
    }


def test_underreported_zip64_entries_are_streamed_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "underreported-zip64.zip"
    _write_forced_zip64(path, "first.txt", "second.txt")
    payload = bytearray(path.read_bytes())
    zip64_offset = payload.find(b"PK\x06\x06")
    eocd_offset = payload.rfind(b"PK\x05\x06")
    assert zip64_offset >= 0
    assert eocd_offset >= 0
    struct.pack_into("<2Q", payload, zip64_offset + 24, 1, 1)
    struct.pack_into(
        "<2H2L",
        payload,
        eocd_offset + 8,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
    )
    path.write_bytes(payload)

    def zipfile_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ZipFile was constructed after ZIP64 underreported its entry count")

    monkeypatch.setattr(content_module.zipfile, "ZipFile", zipfile_must_not_run)
    report = ContentInspector(FileTrustPolicy(max_archive_entries=1)).inspect(path)

    assert not report.safe
    assert {risk.code for risk in report.risks} == {
        RiskCode.MALFORMED_ARCHIVE,
        RiskCode.ARCHIVE_TOO_MANY_ENTRIES,
    }


def test_eocd_signature_inside_comment_is_rejected_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("fake.txt", "")
    source_payload = source.read_bytes()
    source_eocd = source_payload.rfind(b"PK\x05\x06")
    source_directory = source_payload[source_payload.find(b"PK\x01\x02") : source_eocd]

    path = tmp_path / "ambiguous-comment.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("real.txt", "")
    payload = bytearray(path.read_bytes())
    real_eocd = payload.rfind(b"PK\x05\x06")
    assert real_eocd >= 0
    fake_directory = source_directory + source_directory
    fake_eocd = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        2,
        2,
        len(fake_directory),
        0,
        0,
    )
    comment = fake_directory + fake_eocd + b"X"
    struct.pack_into("<H", payload, real_eocd + 20, len(comment))
    path.write_bytes(payload + comment)

    def zipfile_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ZipFile was constructed after an ambiguous EOCD")

    monkeypatch.setattr(content_module.zipfile, "ZipFile", zipfile_must_not_run)
    report = ContentInspector().inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.MALFORMED_ARCHIVE]


def test_structurally_valid_fake_eocd_inside_comment_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("fake.txt", "")
    source_payload = source.read_bytes()
    source_eocd = source_payload.rfind(b"PK\x05\x06")
    source_directory = source_payload[source_payload.find(b"PK\x01\x02") : source_eocd]

    path = tmp_path / "valid-looking-fake-eocd.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("real.txt", "")
    payload = bytearray(path.read_bytes())
    real_eocd = payload.rfind(b"PK\x05\x06")
    assert real_eocd >= 0
    fake_directory = source_directory + source_directory
    fake_eocd = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        2,
        2,
        len(fake_directory),
        0,
        0,
    )
    comment = fake_directory + fake_eocd
    struct.pack_into("<H", payload, real_eocd + 20, len(comment))
    path.write_bytes(payload + comment)

    def zipfile_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("ZipFile was constructed after an ambiguous valid EOCD")

    monkeypatch.setattr(content_module.zipfile, "ZipFile", zipfile_must_not_run)
    report = ContentInspector().inspect(path)

    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.MALFORMED_ARCHIVE]


def test_archive_member_risks_are_aggregated_by_code(tmp_path: Path) -> None:
    path = tmp_path / "many-risks.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for index in range(100):
            archive.writestr(f"../escape-{index}.txt", "blocked")

    report = ContentInspector().inspect(path)
    traversal = [risk for risk in report.risks if risk.code is RiskCode.ARCHIVE_PATH_TRAVERSAL]

    assert len(traversal) == 1
    assert "100 occurrences total" in traversal[0].detail
    assert len(traversal[0].detail) <= 512


def test_aggregate_archive_ratio_blocks_many_subthreshold_members(tmp_path: Path) -> None:
    path = tmp_path / "aggregate-bomb.zip"
    payload = b"0" * (600 * 1024)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("first.bin", payload)
        archive.writestr("second.bin", payload)

    report = ContentInspector().inspect(path)
    ratio_risks = [
        risk for risk in report.risks if risk.code is RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO
    ]

    assert not report.safe
    assert len(ratio_risks) == 1
    assert "aggregate archive compression ratio" in ratio_risks[0].detail


@pytest.mark.parametrize(
    ("first", "second"),
    (
        ("a/b.txt", "a//b.txt"),
        ("a/b.txt", "a/./b.txt"),
        ("a/../b.txt", "b.txt"),
        ("name", "name."),
        ("é.txt", "é.txt"),
    ),
)
def test_archive_extraction_aliases_are_duplicate_entries(
    tmp_path: Path,
    first: str,
    second: str,
) -> None:
    path = tmp_path / "aliases.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(first, "first")
        archive.writestr(second, "second")

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert any(risk.code is RiskCode.ARCHIVE_DUPLICATE_ENTRY for risk in report.risks)


def test_archive_collision_key_normalizes_windows_separator() -> None:
    assert ContentInspector._archive_path_collision_key(
        "a\\b.txt"
    ) == ContentInspector._archive_path_collision_key("a/b.txt")


@pytest.mark.parametrize(
    "name",
    (
        "CON",
        "CONIN$",
        "CONOUT$.txt",
        "CON .txt",
        "COM1 .log",
        "file:stream",
        "a/./b.txt",
        "a//b.txt",
        "name. ",
        "C:/payload.txt",
    ),
)
def test_windows_unsafe_archive_names_are_blocked(tmp_path: Path, name: str) -> None:
    path = tmp_path / "unsafe-name.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, "blocked")

    report = ContentInspector().inspect(path)

    assert not report.safe
    assert any(risk.code is RiskCode.ARCHIVE_PATH_TRAVERSAL for risk in report.risks)


def test_archive_risk_detail_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "long-risk.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../" + "x" * 2000, "blocked")

    report = ContentInspector().inspect(path)
    traversal = next(risk for risk in report.risks if risk.code is RiskCode.ARCHIVE_PATH_TRAVERSAL)

    assert len(traversal.detail) <= 512
    assert traversal.detail.endswith("... [truncated]")


def test_archive_risk_count_survives_detail_truncation(tmp_path: Path) -> None:
    path = tmp_path / "long-aggregate.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../" + "a" * 1000, "blocked")
        archive.writestr("../" + "b" * 1000, "blocked")

    report = ContentInspector().inspect(path)
    traversal = next(risk for risk in report.risks if risk.code is RiskCode.ARCHIVE_PATH_TRAVERSAL)

    assert len(traversal.detail) <= 512
    assert traversal.detail.startswith("2 occurrences total")


def test_blocking_file_size_stops_structured_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "oversized.json"
    path.write_text('{"value": 1}', encoding="utf-8")

    def parser_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("structured parser ran for an oversized input")

    monkeypatch.setattr(content_module.json, "loads", parser_must_not_run)
    monkeypatch.setattr(content_module.json5, "loads", parser_must_not_run)
    monkeypatch.setattr(content_module.zipfile, "ZipFile", parser_must_not_run)

    report = ContentInspector(FileTrustPolicy(max_file_bytes=1)).inspect(path)

    assert report.kind is ContentKind.UNKNOWN
    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.FILE_TOO_LARGE]


def test_non_regular_input_stops_structured_inspection(tmp_path: Path) -> None:
    report = ContentInspector().inspect(tmp_path)

    assert report.kind is ContentKind.UNKNOWN
    assert not report.safe
    assert [risk.code for risk in report.risks] == [RiskCode.NON_REGULAR_INPUT]
