from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import json
import math
import platform
import stat
import sys
import time
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

PROTOCOL = "angusu.bridge.lab-probe/1"
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 128
MAX_FIELDS = 128
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LOGICAL_OUTPUT_BYTES = 512 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]


class InvalidRequest(ValueError):
    """The external laboratory sent a request outside the read-only contract."""


class ObservationError(ValueError):
    """The target returned output that cannot satisfy the observation contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise InvalidRequest("duplicate key")
        out[key] = value
    return out


def _constant(value: str) -> Any:
    raise InvalidRequest("non-finite JSON")


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - keys:
        raise InvalidRequest("unexpected object fields")
    return value


def _text(value: Any, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise InvalidRequest("invalid text")
    return value


def _int(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise InvalidRequest("invalid integer limit")
    return value


def _schema(value: Any) -> Any:
    from polymorph.models.schema import (
        FieldDescriptor,
        LookupKeyDescriptor,
        RelationDescriptor,
        SchemaDescriptor,
    )
    from polymorph.models.types import DataType, FieldRole, Sensitivity

    obj = _object(value, {"id", "fields", "relations"})
    raw = obj.get("fields")
    if not isinstance(raw, list) or len(raw) > MAX_FIELDS:
        raise InvalidRequest("invalid field list")
    fields = []
    for raw_field in raw:
        field = _object(
            raw_field,
            {
                "id", "name", "data_type", "nullable", "sensitivity",
                "role", "aliases", "description",
            },
        )
        aliases = field.get("aliases", [])
        if (
            not isinstance(aliases, list)
            or len(aliases) > 32
            or type(field.get("nullable", True)) is not bool
        ):
            raise InvalidRequest("invalid field metadata")
        fields.append(
            FieldDescriptor(
                id=_text(field.get("id")),
                name=_text(field.get("name")),
                data_type=DataType(field.get("data_type", "unknown")),
                nullable=field.get("nullable", True),
                sensitivity=Sensitivity(field.get("sensitivity", "internal")),
                role=FieldRole(field.get("role", "value")),
                aliases=tuple(_text(alias) for alias in aliases),
                description=(
                    _text(field["description"]) if field.get("description") is not None else None
                ),
            )
        )
    raw_relations = obj.get("relations", [])
    if not isinstance(raw_relations, list) or len(raw_relations) > MAX_FIELDS:
        raise InvalidRequest("invalid relations")
    relations = []
    for raw_relation in raw_relations:
        relation = _object(
            raw_relation, {"source_field_id", "target_container", "target_field", "lookup_keys"}
        )
        keys = relation.get("lookup_keys", [])
        if not isinstance(keys, list) or len(keys) > 32:
            raise InvalidRequest("invalid lookup keys")
        lookups = []
        for raw_key in keys:
            key = _object(raw_key, {"name", "data_type"})
            lookups.append(
                LookupKeyDescriptor(
                    _text(key.get("name")), DataType(key.get("data_type", "unknown"))
                )
            )
        relations.append(
            RelationDescriptor(
                _text(relation.get("source_field_id")),
                _text(relation.get("target_container")),
                _text(relation.get("target_field")),
                lookup_keys=tuple(lookups),
            )
        )
    return SchemaDescriptor(_text(obj.get("id")), tuple(fields), tuple(relations))


def _typed(value: Any, depth: int = 0) -> Any:
    """Evidence codec: no coercion between bool, number, text, null or binary."""
    if depth > 64:
        raise ObservationError("typed output exceeds depth budget")
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["boolean", value]
    if type(value) is int:
        return ["integer", str(value)]
    if type(value) is str:
        return ["string", value]
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ObservationError("non-finite output")
        return ["decimal", str(value)]
    if type(value) is float:
        if not math.isfinite(value):
            raise ObservationError("non-finite output")
        return ["float", value.hex()]
    if isinstance(value, datetime):
        return ["datetime", value.isoformat()]
    if isinstance(value, date):
        return ["date", value.isoformat()]
    if isinstance(value, bytes):
        return ["bytes", value.hex()]
    if isinstance(value, (list, tuple)):
        return ["array", [_typed(item, depth + 1) for item in value]]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return ["object", [[key, _typed(value[key], depth + 1)] for key in sorted(value)]]
    raise ObservationError("unsupported output type")


def _input_path(root: Path, relative: Any, maximum: int) -> Path:
    relative = _text(relative, 1024)
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative or ":" in relative:
        raise InvalidRequest("invalid input path")
    candidate = root.absolute() / path
    for part in (candidate, *candidate.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise InvalidRequest("linked input is not accepted")
    if not candidate.resolve().is_relative_to(root.resolve()) or not candidate.is_file():
        raise InvalidRequest("input is not a regular file inside the input root")
    if candidate.stat().st_size > maximum:
        raise InvalidRequest("input exceeds byte limit")
    return candidate


def _parse(item: dict[str, Any], root: Path) -> dict[str, Any]:
    item = _object(
        item, {"id", "format", "relative_path", "max_rows", "max_input_bytes", "max_output_bytes"}
    )
    maximum = _int(item.get("max_input_bytes"), MAX_FILE_BYTES)
    max_rows = _int(item.get("max_rows"), 1_000_001)
    max_output = _int(item.get("max_output_bytes"), MAX_LOGICAL_OUTPUT_BYTES)
    path = _input_path(root, item.get("relative_path"), maximum)
    fmt = item.get("format")
    if fmt in ("csv", "tsv"):
        from polymorph.connectors.csv_file import CsvConnector

        connector: Any = CsvConnector(path)
    elif fmt in ("json", "json5"):
        from polymorph.connectors.json_file import JsonFileConnector

        connector = JsonFileConnector(path)
    elif fmt == "xlsx":
        from polymorph.connectors.excel import ExcelConnector

        connector = ExcelConnector(path)
    else:
        raise InvalidRequest("unsupported fixture format")
    # Keep the real connector's content detection and safety policies enabled.
    source_schema = connector.inspect_schema()
    names = {field.id: field.name for field in source_schema.fields}
    if len(set(names.values())) != len(names):
        raise ObservationError("ambiguous returned field names")
    hasher = hashlib.sha256()
    count = size = 0
    for record in connector.iter_records():
        count += 1
        if count > max_rows:
            raise ObservationError("row limit exceeded")
        if set(record) - set(names):
            raise ObservationError("record outside returned schema")
        raw = _canonical(_typed({names[key]: value for key, value in record.items()}))
        size += len(raw)
        if len(raw) > 1024 * 1024 or size > max_output:
            raise ObservationError("logical output limit exceeded")
        hasher.update(len(raw).to_bytes(8, "big"))
        hasher.update(raw)
    return {
        "row_count": count,
        "ordered_typed_sha256": hasher.hexdigest(),
        "encoding": "typed-row/1",
    }


def _execute(operation: str, item: dict[str, Any], root: Path) -> Any:
    if operation == "map":
        from polymorph.matching.hybrid import HybridMatcher

        item = _object(item, {"id", "source_schema", "target_schema"})
        source = _schema(item.get("source_schema"))
        target = _schema(item.get("target_schema"))
        return [
            {
                "source_field_id": decision.source_field_id,
                "target_field_id": decision.target_field_id,
                "status": decision.status.value,
                "score": decision.score,
                "margin": decision.margin,
            }
            for decision in HybridMatcher().propose(source, target)
        ]
    if operation == "parse":
        return _parse(item, root)
    if operation == "transform":
        from polymorph.transforms import apply_transform

        item = _object(item, {"id", "transform", "value", "parameters"})
        if item.get("transform") not in ("copy", "trim", "parse_decimal", "parse_datetime"):
            raise InvalidRequest("unsupported transform")
        parameters = item.get("parameters", {})
        if not isinstance(parameters, dict) or len(parameters) > 8:
            raise InvalidRequest("invalid parameters")
        parameters = {_text(key, 128): _text(value, 128) for key, value in parameters.items()}
        return _typed(apply_transform(item["transform"], item.get("value"), parameters))
    raise InvalidRequest("unsupported operation")


def facts() -> dict[str, Any]:
    import polymorph

    packages = {}
    for name in (
        "SQLAlchemy", "cryptography", "openpyxl", "defusedxml", "json5",
        "numpy", "onnxruntime", "psutil", "clevercsv", "magika",
    ):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "polymorph": polymorph.__version__,
        "packages": packages,
        "model_profile": "none",
        "probe_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def handle(payload: Any, root: Path) -> dict[str, Any]:
    obj = _object(payload, {"protocol", "request_id", "operation", "items"})
    if obj.get("protocol") != PROTOCOL:
        raise InvalidRequest("unsupported protocol")
    request_id = _text(obj.get("request_id"), 128)
    operation = obj.get("operation")
    if operation not in ("map", "parse", "transform", "facts"):
        raise InvalidRequest("unsupported operation")
    items = obj.get("items", [])
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise InvalidRequest("invalid items")
    if operation == "facts" and items:
        raise InvalidRequest("facts accepts no items")
    output = []
    identities = set()
    from polymorph.errors import PolymorphError

    for item in items:
        if not isinstance(item, dict):
            raise InvalidRequest("invalid item")
        identity = _text(item.get("id"), 128)
        if identity in identities:
            raise InvalidRequest("duplicate case identity")
        identities.add(identity)
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        try:
            result = _execute(operation, item, root)
            value = {"id": identity, "status": "ok", "result": result}
        except InvalidRequest:
            raise
        except ObservationError as exc:
            # Probe-side rejection must never masquerade as the target rejecting an input.
            value = {"id": identity, "status": "target_error", "error_type": type(exc).__name__}
        except (PolymorphError, ValueError) as exc:
            value = {"id": identity, "status": "rejected", "error_type": type(exc).__name__}
        except Exception as exc:
            value = {"id": identity, "status": "target_error", "error_type": type(exc).__name__}
        value.update(
            operation_wall_ms=(time.perf_counter_ns() - wall) / 1e6,
            operation_cpu_ms=(time.process_time_ns() - cpu) / 1e6,
        )
        output.append(value)
    return {
        "protocol": PROTOCOL,
        "request_id": request_id,
        "operation": operation,
        "facts": facts(),
        "items": output,
        "oracle_received": False,
        "scope": "read_only_synthetic_lab_probe",
        "training_performed": False,
        "os_sandboxed": False,
    }


def _request(raw: bytes) -> Any:
    if len(raw) > MAX_REQUEST_BYTES:
        raise InvalidRequest("request too large")
    obj = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    stack = [(obj, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 200_000:
            raise InvalidRequest("request structure budget exceeded")
        if isinstance(current, dict):
            stack.extend((value, depth + 1) for value in current.values())
        elif isinstance(current, list):
            stack.extend((value, depth + 1) for value in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise InvalidRequest("non-finite JSON")
    return obj


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only, label-free local laboratory probe.")
    parser.add_argument("--input-root", type=Path, required=True)
    args = parser.parse_args()
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        obj = _request(raw)
        # Keep incidental library prints outside the wire channel.
        with contextlib.redirect_stdout(sys.stderr):
            output = handle(obj, args.input_root)
        data = _canonical(output)
        if len(data) > MAX_REQUEST_BYTES:
            raise InvalidRequest("response too large")
        sys.stdout.buffer.write(data + b"\n")
        return 0
    except Exception as exc:
        sys.stdout.buffer.write(
            _canonical(
                {"protocol": PROTOCOL, "status": "probe_error", "error_type": type(exc).__name__}
            ) + b"\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
