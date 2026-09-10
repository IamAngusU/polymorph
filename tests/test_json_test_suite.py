from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from polymorph.connectors.json_file import JsonFileConnector
from polymorph.content import ContentInspector, ContentKind
from polymorph.errors import ConnectorError

_FIXTURES = Path(__file__).parent / "fixtures" / "json-test-suite"

_STRICT_VALID = (
    "y_array_heterogeneous.json",
    "y_number_real_fraction_exponent.json",
    "y_object_basic.json",
    "y_object_duplicated_key.json",
    "y_object_empty_key.json",
    "y_object_escaped_null_in_key.json",
    "y_object_extreme_numbers.json",
    "y_object_string_unicode.json",
    "y_string_allowed_escapes.json",
    "y_string_utf8.json",
)

_RECORD_SHAPED = (
    "y_object_basic.json",
    "y_object_empty_key.json",
    "y_object_escaped_null_in_key.json",
    "y_object_extreme_numbers.json",
    "y_object_string_unicode.json",
)

_VALID_BUT_NOT_RECORD_SHAPED = (
    "y_array_heterogeneous.json",
    "y_number_real_fraction_exponent.json",
    "y_string_allowed_escapes.json",
    "y_string_utf8.json",
)

_STRICT_INVALID = (
    "n_array_incomplete.json",
    "n_number_0.3e.json",
    "n_number_with_leading_zero.json",
    "n_string_incomplete_escape.json",
    "n_string_invalid_backslash_esc.json",
    "n_string_invalid_unicode_escape.json",
    "n_structure_uescaped_LF_before_string.json",
    "n_structure_unclosed_object.json",
)


def _fixture(name: str) -> Path:
    return _FIXTURES / name


def test_vendored_json_test_suite_manifest_matches_every_fixture() -> None:
    lines = (_FIXTURES / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    entries = [line.split("  ", 1) for line in lines if line]
    expected = {name: digest for digest, name in entries}

    assert len(entries) == len(expected)
    assert set(expected) == {path.name for path in _FIXTURES.glob("*.json")}
    for name, digest in expected.items():
        assert len(digest) == 64
        assert hashlib.sha256(_fixture(name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("name", _STRICT_VALID)
def test_json_test_suite_valid_syntax_reaches_strict_json_content_boundary(name: str) -> None:
    report = ContentInspector().inspect(_fixture(name))

    assert report.safe
    assert report.kind is ContentKind.JSON


@pytest.mark.parametrize("name", _RECORD_SHAPED)
def test_json_test_suite_record_shaped_values_reach_connector_records(name: str) -> None:
    records = list(JsonFileConnector(_fixture(name)).iter_records())

    assert records
    assert all(isinstance(record, dict) for record in records)


@pytest.mark.parametrize("name", _VALID_BUT_NOT_RECORD_SHAPED)
def test_json_test_suite_valid_non_record_roots_stop_at_record_boundary(name: str) -> None:
    with pytest.raises(ValueError, match="JSON root must be an object or an array of objects"):
        list(JsonFileConnector(_fixture(name)).iter_records())


def test_json_test_suite_duplicate_keys_stop_at_connector_policy_boundary() -> None:
    path = _fixture("y_object_duplicated_key.json")
    report = ContentInspector().inspect(path)

    assert report.kind is ContentKind.JSON
    with pytest.raises(ValueError, match="duplicate key 'a'"):
        list(JsonFileConnector(path).iter_records())


@pytest.mark.parametrize("name", _STRICT_INVALID)
def test_json_test_suite_invalid_syntax_never_becomes_strict_json_or_records(name: str) -> None:
    path = _fixture(name)
    report = ContentInspector().inspect(path)

    assert report.kind is not ContentKind.JSON
    with pytest.raises((ConnectorError, ValueError)):
        list(JsonFileConnector(path).iter_records())


def test_json_test_suite_non_finite_number_stops_at_value_policy_boundary() -> None:
    path = _fixture("n_number_NaN.json")
    report = ContentInspector().inspect(path)

    assert report.kind is not ContentKind.JSON
    with pytest.raises(ValueError, match="non-finite number"):
        list(JsonFileConnector(path).iter_records())


def test_json_test_suite_implementation_defined_depth_is_observation_only() -> None:
    path = _fixture("i_structure_500_nested_arrays.json")
    report = ContentInspector().inspect(path)
    content_outcome = "/".join(
        (
            report.kind.value,
            "safe" if report.safe else "blocked",
            ",".join(risk.code.value for risk in report.risks) or "no-risk",
        )
    )
    try:
        records = list(JsonFileConnector(path).iter_records())
    except (ConnectorError, ValueError) as exc:
        connector_outcome = f"rejected:{type(exc).__name__}"
    else:
        connector_outcome = f"accepted:{len(records)}-records"

    # The upstream i_ prefix forbids an accept/reject conformance verdict. Compare
    # both Polymorph boundaries, but assert only that each returned a bounded outcome.
    observations = {
        "content_inspector": content_outcome,
        "json_connector": connector_outcome,
    }
    assert all(observations.values())
