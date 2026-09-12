from __future__ import annotations

import argparse
import hashlib
import json
import math
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .connector_registry import default_connector_registry
from .errors import PolymorphError
from .filesystem import atomic_write_text
from .models.schema import SchemaDescriptor
from .serialization import schema_to_dict


class DataQualityError(PolymorphError):
    """Raised when a bounded quality inspection or explicit repair plan is invalid."""


class IssueSeverity(StrEnum):
    INFO = "info"
    REVIEW = "review"
    ERROR = "error"


class CleaningAction(StrEnum):
    NORMALIZE_UNICODE_NFC = "normalize_unicode_nfc"
    TRIM_WHITESPACE = "trim_whitespace"
    EMPTY_TO_NULL = "empty_to_null"


@dataclass(frozen=True, slots=True)
class QualityLimits:
    max_records: int = 100_000
    max_samples_per_group: int = 8
    max_groups: int = 4096

    def __post_init__(self) -> None:
        if not 1 <= self.max_records <= 10_000_000:
            raise DataQualityError("max_records must be between 1 and 10,000,000")
        if not 0 <= self.max_samples_per_group <= 100:
            raise DataQualityError("max_samples_per_group must be between 0 and 100")
        if not 1 <= self.max_groups <= 8192:
            raise DataQualityError("max_groups must be between 1 and 8,192")


@dataclass(frozen=True, slots=True)
class QualityIssueGroup:
    code: str
    field: str
    severity: IssueSeverity
    count: int
    record_samples: tuple[int, ...]
    suggested_action: str

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "count": self.count,
            "field": self.field,
            "record_samples": list(self.record_samples),
            "severity": self.severity.value,
            "suggested_action": self.suggested_action,
        }


@dataclass(frozen=True, slots=True)
class QualityReport:
    schema_fingerprint: str
    records_scanned: int
    complete: bool
    issue_groups: tuple[QualityIssueGroup, ...]
    dropped_issue_groups: int
    generated_at: str

    @property
    def issue_count(self) -> int:
        return sum(group.count for group in self.issue_groups)

    def to_dict(self) -> dict[str, object]:
        return {
            "complete": self.complete,
            "dropped_issue_groups": self.dropped_issue_groups,
            "generated_at": self.generated_at,
            "issue_count": self.issue_count,
            "issue_groups": [group.to_dict() for group in self.issue_groups],
            "privacy": "metadata_only_no_record_values",
            "records_scanned": self.records_scanned,
            "schema": "polymorph.quality-report",
            "schema_fingerprint": self.schema_fingerprint,
            "version": 1,
        }


@dataclass(slots=True)
class _IssueAccumulator:
    severity: IssueSeverity
    suggested_action: str
    count: int
    samples: list[int]


def _canonical_schema(schema: object) -> tuple[dict[str, Any], str]:
    if isinstance(schema, SchemaDescriptor):
        raw = schema_to_dict(schema)
        fingerprint = schema.fingerprint()
    elif callable(serializer := getattr(schema, "to_dict", None)):
        raw = serializer()
        fingerprint = ""
    elif isinstance(schema, Mapping):
        raw = dict(schema)
        fingerprint = ""
    else:
        raise DataQualityError("schema must expose to_dict() or be a mapping")
    if not isinstance(raw, dict):
        raise DataQualityError("schema serialization must be an object")
    encoded = json.dumps(
        raw,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fingerprinter = getattr(schema, "fingerprint", None)
    if not fingerprint and callable(fingerprinter):
        fingerprint = str(fingerprinter())
    elif not fingerprint:
        fingerprint = hashlib.sha256(encoded).hexdigest()
    if len(fingerprint) != 64:
        fingerprint = hashlib.sha256(encoded).hexdigest()
    return raw, fingerprint


def _field_profiles(schema: Mapping[str, Any]) -> tuple[dict[str, bool], bool]:
    fields = schema.get("fields")
    if not isinstance(fields, list):
        return {}, False
    result: dict[str, bool] = {}
    for raw in fields:
        if not isinstance(raw, Mapping):
            continue
        candidate = raw.get("id") or raw.get("name") or raw.get("field_id") or raw.get("path")
        if not isinstance(candidate, str) or not candidate or len(candidate) > 256:
            continue
        nullable = raw.get("nullable", True)
        if "required" in raw:
            nullable = not bool(raw["required"])
        result[candidate] = bool(nullable)
    return result, bool(result)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class DataQualityAnalyzer:
    """Inspect records incrementally and retain only bounded, value-free issue metadata."""

    def __init__(self, schema: object, limits: QualityLimits | None = None) -> None:
        self._schema, self.schema_fingerprint = _canonical_schema(schema)
        self._fields, self._has_field_contract = _field_profiles(self._schema)
        self.limits = limits or QualityLimits()

    def inspect(self, records: Iterable[Mapping[str, object]]) -> QualityReport:
        groups: dict[tuple[str, str], _IssueAccumulator] = {}
        dropped_groups = 0
        records_scanned = 0
        complete = True

        def add(
            code: str,
            field: str,
            severity: IssueSeverity,
            suggested_action: str,
            record_number: int,
        ) -> None:
            nonlocal dropped_groups
            key = (code, field)
            state = groups.get(key)
            if state is None:
                if len(groups) >= self.limits.max_groups:
                    dropped_groups += 1
                    return
                state = _IssueAccumulator(severity, suggested_action, 0, [])
                groups[key] = state
            state.count += 1
            if len(state.samples) < self.limits.max_samples_per_group:
                state.samples.append(record_number)

        for record_number, record in enumerate(records, start=1):
            if record_number > self.limits.max_records:
                complete = False
                break
            records_scanned = record_number
            if not isinstance(record, Mapping):
                add(
                    "record_not_mapping",
                    "<record>",
                    IssueSeverity.ERROR,
                    "reject_or_reparse_record",
                    record_number,
                )
                continue
            if self._has_field_contract:
                for field, nullable in self._fields.items():
                    if field not in record:
                        if not nullable:
                            add(
                                "missing_required_field",
                                field,
                                IssueSeverity.ERROR,
                                "supply_value_or_correct_mapping",
                                record_number,
                            )
                    elif record[field] is None and not nullable:
                        add(
                            "null_in_required_field",
                            field,
                            IssueSeverity.ERROR,
                            "supply_value_or_reject_record",
                            record_number,
                        )
                for field in record:
                    if field not in self._fields:
                        add(
                            "unexpected_field",
                            str(field)[:256],
                            IssueSeverity.REVIEW,
                            "map_or_explicitly_drop_field",
                            record_number,
                        )
            for field, value in record.items():
                field_name = str(field)[:256]
                if isinstance(value, str):
                    if value and value != value.strip():
                        add(
                            "outer_whitespace",
                            field_name,
                            IssueSeverity.REVIEW,
                            CleaningAction.TRIM_WHITESPACE.value,
                            record_number,
                        )
                    if value == "":
                        add(
                            "empty_string",
                            field_name,
                            IssueSeverity.REVIEW,
                            CleaningAction.EMPTY_TO_NULL.value,
                            record_number,
                        )
                    if any(
                        ord(character) < 32 and character not in "\t\n\r" for character in value
                    ):
                        add(
                            "embedded_control_character",
                            field_name,
                            IssueSeverity.ERROR,
                            "reject_or_explicitly_repair",
                            record_number,
                        )
                    if not unicodedata.is_normalized("NFC", value):
                        add(
                            "non_normalized_unicode",
                            field_name,
                            IssueSeverity.INFO,
                            CleaningAction.NORMALIZE_UNICODE_NFC.value,
                            record_number,
                        )
                elif isinstance(value, float) and not math.isfinite(value):
                    add(
                        "non_finite_number",
                        field_name,
                        IssueSeverity.ERROR,
                        "reject_or_replace_with_reviewed_value",
                        record_number,
                    )

        rendered = tuple(
            QualityIssueGroup(
                code=code,
                field=field,
                severity=state.severity,
                count=state.count,
                record_samples=tuple(state.samples),
                suggested_action=state.suggested_action,
            )
            for (code, field), state in sorted(groups.items())
        )
        return QualityReport(
            schema_fingerprint=self.schema_fingerprint,
            records_scanned=records_scanned,
            complete=complete,
            issue_groups=rendered,
            dropped_issue_groups=dropped_groups,
            generated_at=_utc_now(),
        )


@dataclass(frozen=True, slots=True)
class CleaningRule:
    field: str
    action: CleaningAction

    def __post_init__(self) -> None:
        if not self.field or len(self.field) > 256:
            raise DataQualityError("cleaning rule field must contain 1..256 characters")


@dataclass(frozen=True, slots=True)
class CleaningPlan:
    """A schema-bound, operator-reviewed set of deterministic record repairs."""

    schema_fingerprint: str
    reviewed_by: str
    rules: tuple[CleaningRule, ...]

    def __post_init__(self) -> None:
        if len(self.schema_fingerprint) != 64:
            raise DataQualityError("cleaning plan requires a SHA-256 schema fingerprint")
        if not self.reviewed_by or len(self.reviewed_by) > 256:
            raise DataQualityError("cleaning plan requires a bounded reviewer label")
        if not self.rules or len(self.rules) > 4096:
            raise DataQualityError("cleaning plan must contain 1..4,096 rules")
        identities = [(rule.field, rule.action) for rule in self.rules]
        if len(identities) != len(set(identities)):
            raise DataQualityError("cleaning plan contains a duplicate rule")

    def validate_schema(self, schema: object) -> None:
        _, current = _canonical_schema(schema)
        if current != self.schema_fingerprint:
            raise DataQualityError("cleaning plan is stale for the current source schema")

    def apply_record(self, record: Mapping[str, object]) -> dict[str, object]:
        cleaned = dict(record)
        for rule in self.rules:
            if rule.field not in cleaned:
                continue
            value = cleaned[rule.field]
            if rule.action is CleaningAction.NORMALIZE_UNICODE_NFC and isinstance(value, str):
                cleaned[rule.field] = unicodedata.normalize("NFC", value)
            elif rule.action is CleaningAction.TRIM_WHITESPACE and isinstance(value, str):
                cleaned[rule.field] = value.strip()
            elif rule.action is CleaningAction.EMPTY_TO_NULL and value == "":
                cleaned[rule.field] = None
        return cleaned

    def apply(self, records: Iterable[Mapping[str, object]]) -> Iterator[dict[str, object]]:
        for record in records:
            yield self.apply_record(record)

    def to_dict(self) -> dict[str, object]:
        return {
            "privacy": "schema_metadata_only_no_record_values",
            "reviewed_by": self.reviewed_by,
            "rules": [{"action": rule.action.value, "field": rule.field} for rule in self.rules],
            "schema": "polymorph.cleaning-plan",
            "schema_fingerprint": self.schema_fingerprint,
            "version": 1,
        }


def inspect_source(
    source_spec: str,
    *,
    limits: QualityLimits | None = None,
) -> QualityReport:
    registry = default_connector_registry()
    connector = registry.resolve_file_source(Path(source_spec)).connector
    schema = connector.inspect_schema()
    analyzer = DataQualityAnalyzer(schema, limits)
    return analyzer.inspect(connector.iter_records())


def _inspect(args: argparse.Namespace) -> int:
    report = inspect_source(
        args.source,
        limits=QualityLimits(
            max_records=args.max_records,
            max_samples_per_group=args.max_samples,
            max_groups=args.max_groups,
        ),
    )
    rendered = json.dumps(report.to_dict(), indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    if args.output:
        atomic_write_text(Path(args.output), rendered, private=True)
    else:
        print(rendered, end="")
    return 0 if report.complete else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stream a source into a bounded, record-value-free quality report."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("source", help="source path or registered connector specification")
    inspect.add_argument("--max-records", type=int, default=100_000)
    inspect.add_argument("--max-samples", type=int, default=8)
    inspect.add_argument("--max-groups", type=int, default=4096)
    inspect.add_argument("--output")
    inspect.set_defaults(func=_inspect)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
