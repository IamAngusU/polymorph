from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from pathlib import Path

import json5

from polymorph.classification import classify_field_name, infer_role
from polymorph.errors import ConnectorWriteError, WriteOutcome
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.filesystem import atomic_write_text
from polymorph.content import ContentInspector, ContentKind

from .base import ConnectorCapabilities, DeliveryContext
from .inference import merge_types, runtime_type


class JsonFileConnector:
    capabilities = ConnectorCapabilities(read_schema=True, read_records=True, write_records=True)

    def __init__(
        self,
        path: str | Path,
        *,
        sensitivity_overrides: Mapping[str, Sensitivity] | None = None,
        max_file_bytes: int = 64 * 1024 * 1024,
        schema_sample_records: int = 1024,
    ) -> None:
        self.path = Path(path)
        self.sensitivity_overrides = dict(sensitivity_overrides or {})
        self.max_file_bytes = max_file_bytes
        self.schema_sample_records = max(1, schema_sample_records)
        self._cache: list[dict[str, object]] | None = None
        self._format_cache: str | None = None
        self._content_inspector = ContentInspector()

    @staticmethod
    def _validate_value(value: object) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("JSON source contains a non-finite number")
        if isinstance(value, list):
            for item in value:
                JsonFileConnector._validate_value(item)
        elif isinstance(value, dict):
            for item in value.values():
                JsonFileConnector._validate_value(item)

    def _load(self) -> list[dict[str, object]]:
        if self._cache is not None:
            return self._cache
        size = self.path.stat().st_size
        if size > self.max_file_bytes:
            raise ValueError("JSON source exceeds configured file size limit")
        self._content_inspector.require(
            self.path,
            allowed={ContentKind.JSON, ContentKind.JSON5, ContentKind.TEXT, ContentKind.DELIMITED_TEXT},
            purpose="JSON connector",
        )
        raw = self.path.read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("JSON source must be UTF-8 text") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            try:
                data = json5.loads(text)
            except (ValueError, TypeError) as exc:
                raise ValueError("input is neither valid JSON nor accepted JSON5") from exc
            self._format_cache = "json5"
        else:
            self._format_cache = "json"
        self._validate_value(data)
        if isinstance(data, dict):
            records = [data]
        elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
            records = list(data)
        else:
            raise ValueError("JSON root must be an object or an array of objects")
        self._cache = records
        return records

    def inspect_schema(self) -> SchemaDescriptor:
        records = self._load()
        sample = records[: self.schema_sample_records]
        keys = sorted({str(key) for record in sample for key in record})
        fields = []
        for key in keys:
            values = [record.get(key) for record in sample]
            fields.append(
                FieldDescriptor(
                    id=key,
                    name=key,
                    data_type=merge_types(
                        [runtime_type(value) for value in values if value is not None]
                    ),
                    nullable=any(value is None for value in values),
                    sensitivity=self.sensitivity_overrides.get(key, classify_field_name(key)),
                    role=infer_role(key),
                )
            )
        return SchemaDescriptor(
            id=f"json:{self.path.name}",
            fields=tuple(fields),
            metadata={"path": self.path.name, "format": self._format_cache or "json"},
        )

    def iter_records(self) -> Iterable[Mapping[str, object]]:
        yield from self._load()

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        materialized = [dict(record) for record in records]
        self._validate_value(materialized)
        encoded = json.dumps(
            materialized,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        if len(encoded.encode("utf-8")) > self.max_file_bytes:
            raise ValueError("JSON destination exceeds configured file size limit")
        try:
            atomic_write_text(self.path, encoded + "\n")
        except OSError as exc:
            raise ConnectorWriteError(
                "JSON destination write did not commit",
                outcome=WriteOutcome.NOT_COMMITTED,
            ) from exc
        self._cache = materialized
        return len(materialized)
