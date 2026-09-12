from __future__ import annotations

import csv
import io
import math
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from itertools import chain
from pathlib import Path
from typing import Literal, TextIO

from polymorph.classification import classify_field_name, infer_role
from polymorph.content import (
    ContentInspector,
    ContentKind,
    FileIdentity,
    require_matching_file_identity,
)
from polymorph.errors import ConnectorError, ConnectorWriteError, WriteOutcome
from polymorph.filesystem import atomic_text_writer, exclusive_path_lock
from polymorph.matching.deterministic import normalize_name
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.work_budget import WorkBudget, WorkBudgetExceeded, WorkMeter

from .base import ConnectorCapabilities, DeliveryContext
from .inference import merge_types, textual_type


def _dialect_from_parts(
    delimiter: str, quotechar: str | None = '"', escapechar: str | None = None
) -> csv.Dialect:
    quoting: Literal[0, 1, 2, 3] = csv.QUOTE_MINIMAL if quotechar else csv.QUOTE_NONE

    class Candidate(csv.Dialect):
        lineterminator = "\n"
        doublequote = True
        skipinitialspace = False
        strict = False

    Candidate.delimiter = delimiter
    Candidate.quotechar = quotechar
    Candidate.escapechar = escapechar
    Candidate.quoting = quoting
    return Candidate()


def _dialect_score(sample: str, dialect: csv.Dialect) -> float:
    try:
        rows = [
            row
            for row in list(csv.reader(io.StringIO(sample), dialect))[:80]
            if row and any(value.strip() for value in row)
        ]
    except (csv.Error, UnicodeError):
        return 0.0
    if not rows:
        return 0.0
    widths = [len(row) for row in rows]
    mode_width, mode_count = Counter(widths).most_common(1)[0]
    consistency = mode_count / len(widths)
    if len(rows) == 1:
        return 0.62 if mode_width > 1 else 0.0
    if mode_width == 1:
        # A true one-column file has no observable delimiter. Treat comma as a stable
        # convention but do not claim dialect evidence that does not exist.
        return 0.58 if dialect.delimiter == "," and consistency == 1.0 else 0.30
    density = sum(sum(bool(value.strip()) for value in row) / len(row) for row in rows) / len(rows)
    return 0.82 * consistency + 0.12 * min(mode_width, 8) / 8 + 0.06 * density


def _candidate_key(dialect: csv.Dialect) -> tuple[str, str | None, str | None, int]:
    return dialect.delimiter, dialect.quotechar, dialect.escapechar, dialect.quoting


def _parse_signature(sample: str, dialect: csv.Dialect) -> tuple[tuple[str, ...], ...] | None:
    """Return the observed parse, so equivalent detector output does not look ambiguous."""

    try:
        return tuple(tuple(row) for row in list(csv.reader(io.StringIO(sample), dialect))[:80])
    except (csv.Error, UnicodeError):
        return None


class CsvConnector:
    """Streaming CSV/TSV source and destination with conservative local inference."""

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
        encoding: str = "utf-8-sig",
        delimiter: str | None = None,
        sensitivity_overrides: Mapping[str, Sensitivity] | None = None,
        type_sample_rows: int = 256,
        skip_repeated_headers: bool = True,
        allow_spreadsheet_formulas: bool = False,
        write_lock_timeout: float = 30.0,
        expected_source_identity: FileIdentity | None = None,
        work_budget: WorkBudget | None = None,
    ) -> None:
        self.path = Path(path)
        self.encoding = encoding
        self.delimiter = delimiter
        self.sensitivity_overrides = dict(sensitivity_overrides or {})
        self.type_sample_rows = max(1, type_sample_rows)
        self.skip_repeated_headers = skip_repeated_headers
        self.allow_spreadsheet_formulas = allow_spreadsheet_formulas
        if not math.isfinite(write_lock_timeout) or write_lock_timeout < 0:
            raise ValueError("CSV write lock timeout must be a finite non-negative number")
        self.write_lock_timeout = write_lock_timeout
        self._schema_cache: SchemaDescriptor | None = None
        self._dialect_cache: csv.Dialect | None = None
        self._headers_cache: tuple[str, ...] | None = None
        self._content_inspector = ContentInspector()
        self._trusted_identity: FileIdentity | None = None
        self._expected_source_identity = expected_source_identity
        self.work_budget = work_budget or WorkBudget()

    def _reset_cached_source(self) -> None:
        self._schema_cache = None
        self._dialect_cache = None
        self._headers_cache = None
        self._trusted_identity = None

    @staticmethod
    def _looks_like_spreadsheet_formula(value: object) -> bool:
        if not isinstance(value, str):
            return False
        candidate = value.lstrip(" \t\r\n")
        return bool(candidate) and candidate[0] in "=+-@"

    def _reject_spreadsheet_formulas(
        self,
        fieldnames: Iterable[object],
        rows: Iterable[Mapping[str, object]],
    ) -> None:
        if self.allow_spreadsheet_formulas:
            return
        values = [*fieldnames, *(value for row in rows for value in row.values())]
        if any(self._looks_like_spreadsheet_formula(value) for value in values):
            raise ConnectorWriteError(
                "CSV destination rejected a spreadsheet formula-like value",
                outcome=WriteOutcome.NOT_COMMITTED,
            )

    def _ensure_source_safe(self) -> FileIdentity:
        if self._trusted_identity is None:
            report = self._content_inspector.require(
                self.path,
                allowed={ContentKind.EMPTY, ContentKind.TEXT, ContentKind.DELIMITED_TEXT},
                purpose="CSV connector",
            )
            if (
                self._expected_source_identity is not None
                and report.identity != self._expected_source_identity
            ):
                raise ConnectorError(
                    "CSV connector rejected input changed after accepted content inspection"
                )
            self._trusted_identity = report.identity
        return self._trusted_identity

    @contextmanager
    def _open_verified_text(self) -> Iterator[TextIO]:
        expected = self._ensure_source_safe()
        try:
            handle = self.path.open("r", encoding=self.encoding, newline="")
        except OSError as exc:
            raise ConnectorError("CSV connector could not open the inspected input") from exc
        try:
            require_matching_file_identity(handle, expected, purpose="CSV connector")
            try:
                yield handle
            finally:
                require_matching_file_identity(handle, expected, purpose="CSV connector")
        finally:
            handle.close()

    def _verify_cached_source(self) -> None:
        with self._open_verified_text():
            pass

    def _dialect(self) -> csv.Dialect:
        if self._dialect_cache is not None:
            return self._dialect_cache
        if not self.path.exists():
            if self.delimiter is None:
                self._dialect_cache = csv.excel()
                return self._dialect_cache
            sample = ""
        else:
            with self._open_verified_text() as handle:
                sample = handle.read(64 * 1024)
        if "\x00" in sample:
            raise ValueError("CSV input contains NUL bytes")
        if self.delimiter is not None:
            if len(self.delimiter) != 1 or self.delimiter in {"\r", "\n", '"'}:
                raise ValueError("CSV delimiter must be one safe character")
            self._dialect_cache = _dialect_from_parts(self.delimiter)
            return self._dialect_cache
        if not sample:
            self._dialect_cache = csv.excel()
            return self._dialect_cache

        candidates: dict[tuple[str, str | None, str | None, int], csv.Dialect] = {}
        for delimiter in (",", ";", "\t", "|"):
            candidate = _dialect_from_parts(delimiter)
            candidates[_candidate_key(candidate)] = candidate
        try:
            sniffed_type = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            pass
        else:
            sniffed = sniffed_type()
            candidates[_candidate_key(sniffed)] = sniffed

        # CleverCSV is an optional extra. Its output is another candidate in the
        # deterministic ensemble, not a parser-selection authority.
        try:
            import clevercsv
        except ImportError:
            clever = None
        else:
            try:
                clever = clevercsv.Sniffer().sniff(sample)
            except Exception:
                clever = None
        clever_delimiter = getattr(clever, "delimiter", None)
        if isinstance(clever_delimiter, str) and clever_delimiter in {",", ";", "\t", "|"}:
            quote = getattr(clever, "quotechar", None) or None
            escape = getattr(clever, "escapechar", None) or None
            converted = _dialect_from_parts(clever_delimiter, quote, escape)
            candidates[_candidate_key(converted)] = converted

        ranked = sorted(
            ((_dialect_score(sample, candidate), candidate) for candidate in candidates.values()),
            key=lambda item: item[0],
            reverse=True,
        )
        if not ranked or ranked[0][0] < 0.55:
            raise ValueError("CSV dialect is too ambiguous for automatic parsing")
        if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < 0.015:
            # Identical one-column interpretations are harmless; a multi-column tie is not.
            top_width = len(next(csv.reader(io.StringIO(sample), ranked[0][1]), []))
            parses_differ = _parse_signature(sample, ranked[0][1]) != _parse_signature(
                sample, ranked[1][1]
            )
            if top_width > 1 and parses_differ:
                raise ValueError("CSV dialect candidates are too close; configure a delimiter")
        self._dialect_cache = ranked[0][1]
        return self._dialect_cache

    @staticmethod
    def _dedupe_headers(row: list[str]) -> tuple[str, ...]:
        seen: Counter[str] = Counter()
        output: list[str] = []
        for index, raw in enumerate(row, start=1):
            name = raw.strip() or f"column_{index}"
            seen[name] += 1
            if seen[name] > 1:
                name = f"{name} [{seen[name]}]"
            output.append(name)
        if not output:
            raise ValueError("CSV input does not contain a header row")
        return tuple(output)

    def _headers(self) -> tuple[str, ...]:
        if self._headers_cache is not None:
            return self._headers_cache
        dialect = self._dialect()
        with self._open_verified_text() as handle:
            reader = csv.reader(handle, dialect)
            try:
                row = next(reader)
            except StopIteration as exc:
                raise ValueError("CSV input is empty") from exc
        self._headers_cache = self._dedupe_headers(row)
        return self._headers_cache

    @staticmethod
    def _is_repeated_header(row: list[str], headers: tuple[str, ...]) -> bool:
        comparable = 0
        matches = 0
        for value, header in zip(row, headers, strict=False):
            if not value.strip():
                continue
            comparable += 1
            if normalize_name(value) == normalize_name(header.split(" [", 1)[0]):
                matches += 1
        return comparable >= 2 and matches / comparable >= 0.8

    def _rows(self) -> Iterable[list[str]]:
        headers = self._headers()
        dialect = self._dialect()
        with self._open_verified_text() as handle:
            reader = csv.reader(handle, dialect)
            next(reader, None)
            for row in reader:
                if not row or not any(value.strip() for value in row):
                    continue
                if len(row) > len(headers):
                    raise ValueError("CSV row contains more columns than the header")
                padded = row + [""] * (len(headers) - len(row))
                if self.skip_repeated_headers and self._is_repeated_header(padded, headers):
                    continue
                yield padded

    def inspect_schema(self) -> SchemaDescriptor:
        if self._schema_cache is not None:
            self._verify_cached_source()
            return self._schema_cache
        headers = self._headers()
        samples: list[list[str]] = [[] for _ in headers]
        nulls = [False for _ in headers]
        sampled = 0
        for row in self._rows():
            sampled += 1
            for index, value in enumerate(row):
                if not value.strip():
                    nulls[index] = True
                else:
                    samples[index].append(value)
            if sampled >= self.type_sample_rows:
                break

        fields = []
        for index, name in enumerate(headers, start=1):
            role = infer_role(name)
            observed = [textual_type(value, role=role) for value in samples[index - 1]]
            fields.append(
                FieldDescriptor(
                    id=f"c{index}",
                    name=name,
                    data_type=merge_types(observed),
                    nullable=nulls[index - 1] or sampled == 0,
                    sensitivity=self.sensitivity_overrides.get(name, classify_field_name(name)),
                    role=role,
                )
            )
        dialect = self._dialect()
        schema = SchemaDescriptor(
            id=f"csv:{self.path.name}",
            fields=tuple(fields),
            metadata={
                "path": self.path.name,
                "encoding": self.encoding,
                "delimiter": dialect.delimiter,
            },
        )
        self._schema_cache = schema
        return schema

    def iter_records(self) -> Iterable[Mapping[str, object]]:
        headers = self._headers()
        for row in self._rows():
            yield {
                f"c{index}": (value if value != "" else None)
                for index, value in enumerate(row[: len(headers)], start=1)
            }

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        iterator = iter(records)
        try:
            first = dict(next(iterator))
        except StopIteration:
            return 0
        meter = WorkMeter(self.work_budget)
        meter.consume_records()
        meter.validate_structure(first)
        keys = list(first)
        if not keys:
            raise ValueError("CSV destination record has no fields")
        self._reject_spreadsheet_formulas(keys, (first,))

        try:
            with exclusive_path_lock(self.path, timeout_seconds=self.write_lock_timeout):
                # A destination is intentionally mutable. Once this writer owns the path lock,
                # inspect the latest committed snapshot instead of trusting a startup cache.
                self._reset_cached_source()
                fieldnames = keys
                target_existed = self.path.exists()
                has_existing_content = False
                positional: list[str] | None = None
                if target_existed:
                    identity = self._ensure_source_safe()
                    if identity.size_bytes:
                        has_existing_content = True
                        headers = list(self._headers())
                        positional = [f"c{index}" for index in range(1, len(headers) + 1)]
                        if keys != positional and set(keys) != set(headers):
                            raise ValueError(
                                "CSV destination fields do not match the existing header"
                            )
                        fieldnames = headers
                dialect = self._dialect()
                count = 0
                with atomic_text_writer(
                    self.path,
                    encoding=self.encoding,
                    overwrite=target_existed,
                ) as output:
                    last_character = ""
                    if has_existing_content:
                        with self._open_verified_text() as source:
                            while chunk := source.read(1024 * 1024):
                                output.write(chunk)
                                last_character = chunk[-1]
                        if last_character not in {"\n", "\r"}:
                            output.write(dialect.lineterminator)
                    writer = csv.DictWriter(output, fieldnames=fieldnames, dialect=dialect)
                    if not has_existing_content:
                        writer.writeheader()

                    pending: Iterable[Mapping[str, object]] = chain((first,), iterator)
                    for source_row in pending:
                        row = dict(source_row)
                        if set(row) != set(keys):
                            raise ValueError("CSV destination records must have identical fields")
                        meter.consume_records(0 if count == 0 else 1)
                        meter.validate_structure(row)
                        if positional is not None and keys == positional:
                            row = dict(
                                zip(
                                    fieldnames,
                                    (row[key] for key in positional),
                                    strict=True,
                                )
                            )
                        self._reject_spreadsheet_formulas(fieldnames, (row,))
                        writer.writerow(row)
                        count += 1
                    if target_existed:
                        self._verify_cached_source()
        except WorkBudgetExceeded as exc:
            raise ConnectorWriteError(
                str(exc),
                outcome=WriteOutcome.NOT_COMMITTED,
            ) from exc
        except (OSError, ConnectorError) as exc:
            raise ConnectorWriteError(
                "CSV destination write did not commit",
                outcome=WriteOutcome.NOT_COMMITTED,
            ) from exc
        self._reset_cached_source()
        return count
