from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

from polymorph.classification import classify_field_name, infer_role
from polymorph.content import (
    ContentInspector,
    ContentKind,
    FileIdentity,
    require_matching_file_identity,
)
from polymorph.errors import ConnectorError
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity

from .base import ConnectorCapabilities

MAX_PARQUET_COLUMNS = 4096
MAX_PARQUET_BATCH_ROWS = 10_000


def _pyarrow() -> tuple[Any, Any]:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ConnectorError(
            'Parquet support requires the optional extra: pip install "polymorph-bridge[parquet]"'
        ) from exc
    return pa, pq


def _data_type(pa: Any, arrow_type: Any) -> DataType:
    if pa.types.is_dictionary(arrow_type):
        return _data_type(pa, arrow_type.value_type)
    if pa.types.is_boolean(arrow_type):
        return DataType.BOOLEAN
    if pa.types.is_integer(arrow_type):
        return DataType.INTEGER
    if pa.types.is_floating(arrow_type) or pa.types.is_decimal(arrow_type):
        return DataType.DECIMAL
    if pa.types.is_date(arrow_type):
        return DataType.DATE
    if pa.types.is_timestamp(arrow_type):
        return DataType.DATETIME
    if pa.types.is_binary(arrow_type) or pa.types.is_fixed_size_binary(arrow_type):
        return DataType.BINARY
    if pa.types.is_string(arrow_type) or pa.types.is_large_string(arrow_type):
        return DataType.STRING
    if (
        pa.types.is_struct(arrow_type)
        or pa.types.is_list(arrow_type)
        or pa.types.is_large_list(arrow_type)
    ):
        return DataType.JSON
    return DataType.UNKNOWN


class ParquetConnector:
    """Bounded, read-only Parquet source behind the content-first trust gate."""

    capabilities = ConnectorCapabilities(read_schema=True, read_records=True)

    def __init__(
        self,
        path: str | Path,
        *,
        columns: Sequence[str] | None = None,
        batch_rows: int = 1024,
        sensitivity_overrides: Mapping[str, Sensitivity] | None = None,
        expected_source_identity: FileIdentity | None = None,
    ) -> None:
        if isinstance(batch_rows, bool) or not 1 <= batch_rows <= MAX_PARQUET_BATCH_ROWS:
            raise ValueError(f"Parquet batch_rows must be between 1 and {MAX_PARQUET_BATCH_ROWS}")
        selected = tuple(columns) if columns is not None else None
        if selected is not None and (
            not selected
            or len(selected) > MAX_PARQUET_COLUMNS
            or any(not isinstance(item, str) or not item or "\x00" in item for item in selected)
            or len(set(selected)) != len(selected)
        ):
            raise ValueError("Parquet columns must be unique non-empty bounded strings")
        self.path = Path(path)
        self.columns = selected
        self.batch_rows = batch_rows
        self.sensitivity_overrides = dict(sensitivity_overrides or {})
        self._expected_source_identity = expected_source_identity
        self._trusted_identity: FileIdentity | None = None
        self._content_inspector = ContentInspector()

    def _ensure_source_safe(self) -> FileIdentity:
        if self._trusted_identity is None:
            report = self._content_inspector.require(
                self.path,
                allowed={ContentKind.PARQUET},
                purpose="Parquet connector",
            )
            if (
                self._expected_source_identity is not None
                and report.identity != self._expected_source_identity
            ):
                raise ConnectorError(
                    "Parquet connector rejected input changed after accepted content inspection"
                )
            self._trusted_identity = report.identity
        return self._trusted_identity

    @contextmanager
    def _open_verified(self) -> Iterator[BinaryIO]:
        expected = self._ensure_source_safe()
        try:
            handle = self.path.open("rb")
        except OSError as exc:
            raise ConnectorError("Parquet connector could not open the inspected input") from exc
        try:
            require_matching_file_identity(handle, expected, purpose="Parquet connector")
            yield handle
            require_matching_file_identity(handle, expected, purpose="Parquet connector")
        finally:
            handle.close()

    def _file(self, handle: BinaryIO) -> Any:
        _, pq = _pyarrow()
        try:
            parquet_file = pq.ParquetFile(handle)
        except Exception as exc:
            raise ConnectorError("Parquet metadata could not be parsed safely") from exc
        if len(parquet_file.schema_arrow) > MAX_PARQUET_COLUMNS:
            raise ConnectorError("Parquet schema exceeds the column limit")
        names = parquet_file.schema_arrow.names
        if len(set(names)) != len(names):
            raise ConnectorError("Parquet schema contains duplicate column names")
        if self.columns is not None:
            missing = sorted(set(self.columns) - set(names))
            if missing:
                raise ConnectorError(f"Parquet selected columns are missing: {', '.join(missing)}")
        return parquet_file

    def inspect_schema(self) -> SchemaDescriptor:
        pa, _ = _pyarrow()
        with self._open_verified() as handle:
            parquet_file = self._file(handle)
            arrow_schema = parquet_file.schema_arrow
            selected = set(self.columns) if self.columns is not None else None
            fields = tuple(
                FieldDescriptor(
                    id=field.name,
                    name=field.name,
                    data_type=_data_type(pa, field.type),
                    nullable=field.nullable,
                    sensitivity=self.sensitivity_overrides.get(
                        field.name, classify_field_name(field.name)
                    ),
                    role=infer_role(field.name),
                )
                for field in arrow_schema
                if selected is None or field.name in selected
            )
            return SchemaDescriptor(
                id=f"parquet:{self.path.name}",
                fields=fields,
                metadata={
                    "format": "parquet",
                    "rows": str(parquet_file.metadata.num_rows),
                    "row_groups": str(parquet_file.metadata.num_row_groups),
                },
            )

    def iter_records(self) -> Iterable[Mapping[str, object]]:
        with self._open_verified() as handle:
            parquet_file = self._file(handle)
            try:
                for batch in parquet_file.iter_batches(
                    batch_size=self.batch_rows,
                    columns=list(self.columns) if self.columns is not None else None,
                ):
                    yield from batch.to_pylist()
            except Exception as exc:
                raise ConnectorError("Parquet records could not be streamed safely") from exc
