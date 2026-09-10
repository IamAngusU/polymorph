from __future__ import annotations

import json
import math
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

import json5

from polymorph.classification import classify_field_name, infer_role
from polymorph.content import (
    ContentInspector,
    ContentKind,
    FileIdentity,
    FileTrustPolicy,
    require_matching_file_identity,
)
from polymorph.errors import ConnectorError, ConnectorWriteError, WriteOutcome
from polymorph.filesystem import atomic_write_text, exclusive_path_lock
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity

from .base import ConnectorCapabilities, DeliveryContext
from .inference import merge_types, runtime_type


def _object_without_duplicate_keys(
    pairs: Iterable[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"JSON object contains duplicate key {key!r}")
        output[key] = value
    return output


class JsonFileConnector:
    capabilities = ConnectorCapabilities(
        read_schema=True,
        read_records=True,
        write_records=True,
        transactional_write=True,
    )

    def __init__(
        self,
        path: str | Path,
        *,
        sensitivity_overrides: Mapping[str, Sensitivity] | None = None,
        max_file_bytes: int = 64 * 1024 * 1024,
        max_json5_parse_bytes: int = 64 * 1024,
        max_structured_text_depth: int = 128,
        max_json_items: int = 100_000,
        schema_sample_records: int = 1024,
        write_lock_timeout: float = 30.0,
        expected_source_identity: FileIdentity | None = None,
    ) -> None:
        self.path = Path(path)
        self.sensitivity_overrides = dict(sensitivity_overrides or {})
        for name, value in {
            "max_file_bytes": max_file_bytes,
            "max_json5_parse_bytes": max_json5_parse_bytes,
            "max_structured_text_depth": max_structured_text_depth,
            "max_json_items": max_json_items,
        }.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.max_file_bytes = max_file_bytes
        self.max_json5_parse_bytes = max_json5_parse_bytes
        self.max_structured_text_depth = max_structured_text_depth
        self.max_json_items = max_json_items
        self.schema_sample_records = max(1, schema_sample_records)
        if not math.isfinite(write_lock_timeout) or write_lock_timeout < 0:
            raise ValueError("JSON write lock timeout must be a finite non-negative number")
        self.write_lock_timeout = write_lock_timeout
        self._cache: list[dict[str, object]] | None = None
        self._format_cache: str | None = None
        self._content_inspector = ContentInspector(
            FileTrustPolicy(
                max_file_bytes=max_file_bytes,
                max_json5_parse_bytes=max_json5_parse_bytes,
                max_structured_text_depth=max_structured_text_depth,
                max_json_items=max_json_items,
            )
        )
        self._trusted_identity: FileIdentity | None = None
        self._expected_source_identity = expected_source_identity

    def _reset_cached_source(self) -> None:
        self._cache = None
        self._format_cache = None
        self._trusted_identity = None

    def _ensure_source_safe(self) -> FileIdentity:
        if self._trusted_identity is None:
            report = self._content_inspector.require(
                self.path,
                allowed={
                    ContentKind.JSON,
                    ContentKind.JSON5,
                    ContentKind.TEXT,
                    ContentKind.DELIMITED_TEXT,
                },
                purpose="JSON connector",
            )
            if (
                self._expected_source_identity is not None
                and report.identity != self._expected_source_identity
            ):
                raise ConnectorError(
                    "JSON connector rejected input changed after accepted content inspection"
                )
            self._trusted_identity = report.identity
        return self._trusted_identity

    @contextmanager
    def _open_verified_binary(self) -> Iterator[BinaryIO]:
        expected = self._ensure_source_safe()
        try:
            handle = self.path.open("rb")
        except OSError as exc:
            raise ConnectorError("JSON connector could not open the inspected input") from exc
        try:
            require_matching_file_identity(handle, expected, purpose="JSON connector")
            try:
                yield handle
            finally:
                require_matching_file_identity(handle, expected, purpose="JSON connector")
        finally:
            handle.close()

    def _verify_cached_source(self) -> None:
        with self._open_verified_binary():
            pass

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
            self._verify_cached_source()
            return self._cache
        identity = self._ensure_source_safe()
        if identity.size_bytes > self.max_file_bytes:
            raise ValueError("JSON source exceeds configured file size limit")
        with self._open_verified_binary() as handle:
            raw = handle.read(self.max_file_bytes + 1)
        if len(raw) > self.max_file_bytes:
            raise ValueError("JSON source exceeds configured file size limit")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("JSON source must be UTF-8 text") from exc
        depth_exceeded, items_exceeded = ContentInspector._json_like_limits_exceeded(
            text,
            max_depth=self.max_structured_text_depth,
            max_items=self.max_json_items,
        )
        if depth_exceeded:
            raise ValueError(
                "JSON source exceeds the configured nesting depth "
                f"of {self.max_structured_text_depth}"
            )
        if items_exceeded:
            raise ValueError(
                "JSON source exceeds the configured item limit "
                f"of {self.max_json_items} members and array items"
            )
        try:
            data = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
        except RecursionError:
            raise ValueError("JSON source exceeds the configured nesting depth") from None
        except json.JSONDecodeError:
            if len(raw) > self.max_json5_parse_bytes:
                raise ValueError(
                    "JSON5 source exceeds the configured parse size limit "
                    f"of {self.max_json5_parse_bytes} bytes"
                ) from None
            try:
                data = json5.loads(text, object_pairs_hook=_object_without_duplicate_keys)
            except RecursionError:
                raise ValueError("JSON5 source exceeds the configured nesting depth") from None
            except (ValueError, TypeError) as exc:
                raise ValueError("input is neither valid JSON nor accepted JSON5") from exc
            self._format_cache = "json5"
        else:
            self._format_cache = "json"
        try:
            self._validate_value(data)
        except RecursionError:
            raise ValueError("JSON source exceeds the configured nesting depth") from None
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
        if not materialized:
            return 0

        try:
            with exclusive_path_lock(self.path, timeout_seconds=self.write_lock_timeout):
                # A destination is intentionally mutable. Rebind all parsed state to the
                # latest committed file only after this writer owns the path lock.
                self._reset_cached_source()
                existing: list[dict[str, object]] = []
                target_existed = self.path.exists()
                if target_existed:
                    identity = self._ensure_source_safe()
                    if identity.size_bytes:
                        existing = [dict(record) for record in self._load()]
                combined = [*existing, *materialized]
                expected_fields = set(combined[0])
                if unreal := [
                    index for index, record in enumerate(combined) if set(record) != expected_fields
                ]:
                    raise ValueError(
                        "JSON destination records must have identical fields; "
                        f"mismatch at record {unreal[0]}"
                    )
                encoded = json.dumps(
                    combined,
                    indent=2,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                if len(encoded.encode("utf-8")) > self.max_file_bytes:
                    raise ValueError("JSON destination exceeds configured file size limit")
                if target_existed:
                    self._verify_cached_source()
                atomic_write_text(
                    self.path,
                    encoded + "\n",
                    overwrite=target_existed,
                )
        except (OSError, ConnectorError) as exc:
            raise ConnectorWriteError(
                "JSON destination write did not commit",
                outcome=WriteOutcome.NOT_COMMITTED,
            ) from exc
        self._reset_cached_source()
        return len(materialized)
