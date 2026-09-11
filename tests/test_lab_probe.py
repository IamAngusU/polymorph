from __future__ import annotations

import copy
import importlib.util
import json
import math
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "lab_probe.py"
SPEC = importlib.util.spec_from_file_location("polymorph_lab_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def _request(operation="facts", items=None):
    return {
        "protocol": probe.PROTOCOL,
        "request_id": "request-1",
        "operation": operation,
        "items": [] if items is None else items,
    }


def _schema(identifier="source", kind="integer"):
    return {
        "id": identifier,
        "fields": [{"id": identifier, "name": "quantity", "data_type": kind}],
        "relations": [],
    }


def test_probe_uses_actual_matcher_without_receiving_labels(tmp_path):
    item = {"id": "case-1", "source_schema": _schema(), "target_schema": _schema("target")}
    request = _request("map", [item])
    before = copy.deepcopy(request)
    reply = probe.handle(request, tmp_path)
    assert reply["oracle_received"] is False
    assert reply["training_performed"] is False
    assert reply["os_sandboxed"] is False
    assert reply["items"][0]["result"][0]["target_field_id"] == "target"
    assert reply["items"][0]["result"][0]["status"] == "auto"
    assert request == before


def test_probe_unknown_type_cannot_authorize_auto(tmp_path):
    item = {
        "id": "case-1",
        "source_schema": _schema(kind="unknown"),
        "target_schema": _schema("target"),
    }
    reply = probe.handle(_request("map", [item]), tmp_path)
    assert reply["items"][0]["result"][0]["status"] != "auto"


@pytest.mark.parametrize("extra", ["expected", "oracle", "labels", "training", "target_url"])
def test_probe_rejects_answer_or_authority_fields(tmp_path, extra):
    request = _request()
    request[extra] = {"answer": "quantity"}
    with pytest.raises(probe.InvalidRequest):
        probe.handle(request, tmp_path)


def test_probe_rejects_labels_inside_mapping_item(tmp_path):
    item = {
        "id": "x", "source_schema": _schema(),
        "target_schema": _schema("target"), "expected": [],
    }
    with pytest.raises(probe.InvalidRequest):
        probe.handle(_request("map", [item]), tmp_path)


@pytest.mark.parametrize("operation", ["train", "write", "exec", None])
def test_probe_cannot_train_write_or_execute_arbitrary_commands(tmp_path, operation):
    with pytest.raises(probe.InvalidRequest):
        probe.handle(_request(operation), tmp_path)


def test_probe_facts_is_empty_operation(tmp_path):
    with pytest.raises(probe.InvalidRequest):
        probe.handle(_request("facts", [{"id": "x"}]), tmp_path)
    out = probe.handle(_request(), tmp_path)
    assert out["items"] == []
    assert out["facts"]["model_profile"] == "none"


def test_probe_duplicate_case_rejected(tmp_path):
    item = {"id": "x", "transform": "trim", "value": " x "}
    with pytest.raises(probe.InvalidRequest):
        probe.handle(_request("transform", [item, item]), tmp_path)


def test_probe_duplicate_json_key_rejected():
    with pytest.raises(probe.InvalidRequest):
        json.loads('{"a":1,"a":2}', object_pairs_hook=probe._pairs)


@pytest.mark.parametrize("value", [True, 0, -1, 1.0, None, 1001])
def test_probe_integer_budgets_are_strict(value):
    with pytest.raises(probe.InvalidRequest):
        probe._int(value, 1000)


def test_probe_field_budget():
    data = _schema()
    data["fields"] = data["fields"] * 129
    with pytest.raises(probe.InvalidRequest):
        probe._schema(data)


def test_probe_descriptor_rejects_embedded_labels():
    data = _schema()
    data["fields"][0]["expected_target"] = "answer"
    with pytest.raises(probe.InvalidRequest):
        probe._schema(data)


@pytest.mark.parametrize("relative", ["../escape", "/tmp/input", "C:/input", "a\\b"])
def test_probe_path_boundary(tmp_path, relative):
    with pytest.raises(probe.InvalidRequest):
        probe._input_path(tmp_path, relative, 1024)


def test_probe_oversized_file_rejected_before_parser(tmp_path):
    (tmp_path / "a").write_bytes(b"abc")
    with pytest.raises(probe.InvalidRequest):
        probe._input_path(tmp_path, "a", 2)


def test_probe_symlink_rejected(tmp_path):
    (tmp_path / "source").write_text("a")
    try:
        (tmp_path / "link").symlink_to(tmp_path / "source")
    except (OSError, NotImplementedError):
        pytest.skip("platform cannot create test symlinks")
    with pytest.raises(probe.InvalidRequest):
        probe._input_path(tmp_path, "link", 1024)


def test_probe_typed_values_preserve_distinctions():
    assert probe._typed(True) != probe._typed(1)
    assert probe._typed(42) != probe._typed("42")
    assert probe._typed(Decimal("1.20")) == ["decimal", "1.20"]
    assert probe._typed(date(2026, 1, 1)) == ["date", "2026-01-01"]
    assert probe._typed(datetime(2026, 1, 1)) == ["datetime", "2026-01-01T00:00:00"]
    assert probe._typed(b"\x00\xff") == ["bytes", "00ff"]


@pytest.mark.parametrize("number", [math.nan, math.inf, -math.inf])
def test_probe_typed_output_rejects_nonfinite(number):
    with pytest.raises(ValueError):
        probe._typed(number)


def test_probe_actual_transform_and_rejection(tmp_path):
    items = [
        {
            "id": "de", "transform": "parse_decimal", "value": "1.234,56",
            "parameters": {"decimal_separator": ",", "thousands_separator": "."},
        },
        {"id": "bad", "transform": "parse_decimal", "value": "invalid"},
        {"id": "text", "transform": "trim", "value": "  Grüße 東京  "},
    ]
    reply = probe.handle(_request("transform", items), tmp_path)
    a, b, c = reply["items"]
    assert a["result"] == ["decimal", "1234.56"]
    assert b["status"] == "rejected"
    assert "invalid" not in json.dumps(b)
    assert c["result"] == ["string", "Grüße 東京"]
    assert all(x["operation_wall_ms"] >= 0 and x["operation_cpu_ms"] >= 0 for x in reply["items"])


def test_probe_receives_no_actual_secret_provider_or_destination(tmp_path):
    with pytest.raises(probe.InvalidRequest):
        item = {
            "id": "a", "transform": "copy",
            "value": "synthetic", "password_ref": "production",
        }
        probe.handle(_request("transform", [item]), tmp_path)


def test_probe_does_not_hide_nonfinite_transform_output_as_target_rejection(tmp_path):
    item = {"id": "nan", "transform": "parse_decimal", "value": "NaN"}
    out = probe.handle(_request("transform", [item]), tmp_path)
    # The transform currently returns Decimal NaN. The evidence codec rejects it,
    # but that rejection is NOT evidence that the transform itself rejected input.
    assert out["items"][0]["status"] == "target_error"
    assert out["items"][0]["error_type"] == "ObservationError"


@pytest.mark.parametrize("raw", [b'{"v":1e9999}', b'[' * 40 + b'0' + b']' * 40])
def test_probe_request_structure_limits(raw):
    with pytest.raises(probe.InvalidRequest):
        probe._request(raw)
