from __future__ import annotations

import csv
import io
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path

from polymorph.classification import classify_field_name, infer_role
from polymorph.content import ContentInspector, ContentKind
from polymorph.matching.deterministic import normalize_name
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.errors import ConnectorWriteError, WriteOutcome
from polymorph.filesystem import atomic_write_text

from .base import ConnectorCapabilities, DeliveryContext
from .inference import merge_types, textual_type


def _dialect_from_parts(
    delimiter: str, quotechar: str | None = '"', escapechar: str | None = None
) -> csv.Dialect:
    quoting = csv.QUOTE_MINIMAL if quotechar else csv.QUOTE_NONE

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
    if len(rows) < 2:
        return 0.0
    widths = [len(row) for row in rows]
    mode_width, mode_count = Counter(widths).most_common(1)[0]
    consistency = mode_count / len(widths)
    if mode_width == 1:
        # A true one-column file has no observable delimiter. Treat comma as a stable
        # convention but do not claim dialect evidence that does not exist.
        return 0.58 if dialect.delimiter == "," and consistency == 1.0 else 0.30
    density = sum(sum(bool(value.strip()) for value in row) / len(row) for row in rows) / len(rows)
    return 0.82 * consistency + 0.12 * min(mode_width, 8) / 8 + 0.06 * density


def _candidate_key(dialect: csv.Dialect) -> tuple[str, str | None, str | None, int]:
    return dialect.delimiter, dialect.quotechar, dialect.escapechar, dialect.quoting


class CsvConnector:
    """Streaming CSV/TSV source and destination with conservative local inference."""

    capabilities = ConnectorCapabilities(read_schema=True, read_records=True, write_records=True)

    def __init__(
        self,
        path: str | Path,
        *,
        encoding: str = "utf-8-sig",
        delimiter: str | None = None,
        sensitivity_overrides: Mapping[str, Sensitivity] | None = None,
        type_sample_rows: int = 256,
        skip_repeated_headers: bool = True,
    ) -> None:
        self.path = Path(path)
        self.encoding = encoding
        self.delimiter = delimiter
        self.sensitivity_overrides = dict(sensitivity_overrides or {})
        self.type_sample_rows = max(1, type_sample_rows)
        self.skip_repeated_headers = skip_repeated_headers
        self._schema_cache: SchemaDescriptor | None = None
        self._dialect_cache: csv.Dialect | None = None
        self._headers_cache: tuple[str, ...] | None = None
        self._content_inspector = ContentInspector()
        self._content_checked = False


    def _ensure_source_safe(self) -> None:
        if self._content_checked or not self.path.exists() or self.path.stat().st_size == 0:
            return
        self._content_inspector.require(
            self.path,
            allowed={ContentKind.TEXT, ContentKind.DELIMITED_TEXT},
            purpose="CSV connector",
        )
        self._content_checked = True

    def _dialect(self) -> csv.Dialect:
        if self._dialect_cache is not None:
            return self._dialect_cache
        if not self.path.exists():
            if self.delimiter is None:
                self._dialect_cache = csv.excel
                return self._dialect_cache
            sample = ""
        else:
            self._ensure_source_safe()
            with self.path.open("r", encoding=self.encoding, newline="") as handle:
                sample = handle.read(64 * 1024)
        if "\x00" in sample:
            raise ValueError("CSV input contains NUL bytes")
        if self.delimiter is not None:
            if len(self.delimiter) != 1 or self.delimiter in {"\r", "\n", '"'}:
                raise ValueError("CSV delimiter must be one safe character")
            self._dialect_cache = _dialect_from_parts(self.delimiter)
            return self._dialect_cache

        candidates: dict[tuple[str, str | None, str | None, int], csv.Dialect] = {}
        for delimiter in (",", ";", "\t", "|"):
            candidate = _dialect_from_parts(delimiter)
            candidates[_candidate_key(candidate)] = candidate
        try:
            sniffed = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            pass
        else:
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
        if clever is not None and getattr(clever, "delimiter", None) in {",", ";", "\t", "|"}:
            quote = getattr(clever, "quotechar", None) or None
            escape = getattr(clever, "escapechar", None) or None
            converted = _dialect_from_parts(clever.delimiter, quote, escape)
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
            if top_width > 1 and _candidate_key(ranked[0][1]) != _candidate_key(ranked[1][1]):
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
        with self.path.open("r", encoding=self.encoding, newline="") as handle:
            reader = csv.reader(handle, self._dialect())
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
        with self.path.open("r", encoding=self.encoding, newline="") as handle:
            reader = csv.reader(handle, self._dialect())
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
                    container=self.path.name,
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
        rows = [dict(item) for item in records]
        if not rows:
            return 0
        keys = list(rows[0])
        if not keys:
            raise ValueError("CSV destination record has no fields")
        if any(set(row) != set(keys) for row in rows):
            raise ValueError("CSV destination records must have identical fields")
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=keys, dialect=self._dialect())
        writer.writeheader()
        writer.writerows(rows)
        try:
            atomic_write_text(self.path, buffer.getvalue(), encoding=self.encoding)
        except OSError as exc:
            raise ConnectorWriteError(
                "CSV destination write did not commit",
                outcome=WriteOutcome.NOT_COMMITTED,
            ) from exc
        return len(rows)
