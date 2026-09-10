from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from .errors import IntegrityError
from .filesystem import exclusive_path_lock

_SCHEMA_VERSION = 1
_MAX_EVENT_BYTES = 4096
MAX_COMPACT_EVENT_BYTES = 1024
MIN_EVENT_STREAM_BYTES = _MAX_EVENT_BYTES
DEFAULT_EVENT_STREAM_BYTES = 64 * 1024 * 1024
MAX_EVENT_STREAM_BYTES = 1024 * 1024 * 1024
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_MACHINE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "run_id",
        "correlation_id",
        "timestamp",
        "component",
        "event_type",
        "status",
        "reason_code",
        "duration_ms",
        "item_count",
    }
)
_DELIVERY_EVENT_TYPES = frozenset({"delivery", "replay", "force_replay"})
_DELIVERY_SUCCESS_STATUSES = frozenset({"delivered", "duplicate"})
_DELIVERY_FAILURE_STATUSES = frozenset({"ambiguous", "quarantined"})
WORKFLOW_STAGE_COMPONENTS = (
    "fixture_generation",
    "destination_setup",
    "content_inspection",
    "source_schema_inspection",
    "target_schema_inspection",
    "mapping_and_plan",
    "full_preflight",
    "security_and_state_setup",
    "source_record_read",
    "source_seal_and_outbox_stage",
    "outbox_reload_and_relay_enqueue",
    "relay_lease",
    "destination_delivery",
    "acknowledgements",
    "destination_audit_outcome_check",
    "destination_operational_event_check",
    "end_to_end_verification",
    "workflow_internal",
    "resource_cleanup",
)
_WORKFLOW_STAGE_COMPONENTS = frozenset(WORKFLOW_STAGE_COMPONENTS)


class EventWriteStatus(StrEnum):
    DISABLED = "disabled"
    RECORDED = "recorded"
    APPEND_FAILED = "append_failed"


def new_trace_id() -> str:
    """Return a random opaque 128-bit identifier safe for operational correlation."""

    return secrets.token_hex(16)


def _validate_trace_id(value: str, label: str) -> str:
    if not _TRACE_ID.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 128-bit hexadecimal identifier")
    return value


def _validate_machine_code(value: str, label: str) -> str:
    if not _MACHINE_CODE.fullmatch(value):
        raise ValueError(f"{label} must be a short machine-readable identifier")
    return value


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("operational event timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise IntegrityError("operational event JSON contains a duplicate field")
        payload[key] = value
    return payload


@dataclass(frozen=True, slots=True)
class OperationalEvent:
    event_id: str
    run_id: str
    correlation_id: str
    timestamp: datetime
    component: str
    event_type: str
    status: str
    reason_code: str | None = None
    duration_ms: float | None = None
    item_count: int | None = None

    def as_dict(self) -> dict[str, object]:
        _validate_trace_id(self.event_id, "event_id")
        _validate_trace_id(self.run_id, "run_id")
        _validate_trace_id(self.correlation_id, "correlation_id")
        _validate_machine_code(self.component, "component")
        _validate_machine_code(self.event_type, "event_type")
        _validate_machine_code(self.status, "status")
        if self.reason_code is not None:
            _validate_machine_code(self.reason_code, "reason_code")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, (int, float))
            or not math.isfinite(self.duration_ms)
            or self.duration_ms < 0
        ):
            raise ValueError("duration_ms must be a finite non-negative number")
        if self.item_count is not None and (
            isinstance(self.item_count, bool)
            or not isinstance(self.item_count, int)
            or not 0 <= self.item_count <= (1 << 63) - 1
        ):
            raise ValueError("item_count must be a non-negative 64-bit integer")
        return {
            "schema_version": _SCHEMA_VERSION,
            "event_id": self.event_id,
            "run_id": self.run_id,
            "correlation_id": self.correlation_id,
            "timestamp": _utc_timestamp(self.timestamp),
            "component": self.component,
            "event_type": self.event_type,
            "status": self.status,
            "reason_code": self.reason_code,
            "duration_ms": self.duration_ms,
            "item_count": self.item_count,
        }

    @classmethod
    def from_dict(cls, payload: object) -> OperationalEvent:
        if not isinstance(payload, dict) or set(payload) != _EVENT_FIELDS:
            raise IntegrityError("operational event has an invalid field set")
        schema_version = payload.get("schema_version")
        if isinstance(schema_version, bool) or schema_version != _SCHEMA_VERSION:
            raise IntegrityError("operational event schema version is unsupported")
        timestamp_value = payload.get("timestamp")
        if not isinstance(timestamp_value, str) or len(timestamp_value) > 64:
            raise IntegrityError("operational event timestamp is invalid")
        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError as exc:
            raise IntegrityError("operational event timestamp is invalid") from exc
        values = {
            name: payload.get(name)
            for name in (
                "event_id",
                "run_id",
                "correlation_id",
                "component",
                "event_type",
                "status",
            )
        }
        if any(not isinstance(value, str) for value in values.values()):
            raise IntegrityError("operational event contains a non-string identifier")
        reason_code = payload.get("reason_code")
        if reason_code is not None and not isinstance(reason_code, str):
            raise IntegrityError("operational event reason_code is invalid")
        duration_ms = payload.get("duration_ms")
        if duration_ms is not None and (
            isinstance(duration_ms, bool) or not isinstance(duration_ms, (int, float))
        ):
            raise IntegrityError("operational event duration_ms is invalid")
        item_count = payload.get("item_count")
        if item_count is not None and (
            isinstance(item_count, bool) or not isinstance(item_count, int)
        ):
            raise IntegrityError("operational event item_count is invalid")
        try:
            event = cls(
                event_id=str(values["event_id"]),
                run_id=str(values["run_id"]),
                correlation_id=str(values["correlation_id"]),
                timestamp=timestamp,
                component=str(values["component"]),
                event_type=str(values["event_type"]),
                status=str(values["status"]),
                reason_code=reason_code,
                duration_ms=float(duration_ms) if duration_ms is not None else None,
                item_count=item_count,
            )
            event.as_dict()
        except (OverflowError, ValueError) as exc:
            raise IntegrityError("operational event field validation failed") from exc
        return event


def _event_contract_valid(event: OperationalEvent) -> bool:
    """Validate the component, event type and status combinations emitted by the product."""

    if event.event_type == "workflow_started":
        return (
            event.component == "workflow_benchmark"
            and event.status == "started"
            and event.reason_code is None
            and event.item_count is not None
        )
    if event.event_type == "workflow_completed":
        return (
            event.component == "workflow_benchmark"
            and event.status in {"passed", "failed"}
            and ((event.status == "passed") == (event.reason_code is None))
            and event.item_count is not None
        )
    if event.event_type == "batch_completed":
        return (
            event.component == "workflow_benchmark"
            and event.status == "passed"
            and event.reason_code is None
            and event.item_count is not None
            and event.item_count > 0
        )
    if event.event_type == "stage_summary":
        return (
            event.component in _WORKFLOW_STAGE_COMPONENTS
            and event.status in {"passed", "failed"}
            and ((event.status == "passed") == (event.reason_code is None))
            and event.item_count is not None
            and event.duration_ms is not None
        )
    if event.event_type in _DELIVERY_EVENT_TYPES:
        return (
            event.component == "destination_runtime"
            and (
                (event.status in _DELIVERY_SUCCESS_STATUSES and event.reason_code is None)
                or (event.status in _DELIVERY_FAILURE_STATUSES and event.reason_code is not None)
            )
            and event.item_count == 1
        )
    return False


@dataclass(frozen=True, slots=True)
class EventStreamSummary:
    run_id: str | None
    events: int
    components: dict[str, int]
    event_types: dict[str, int]
    statuses: dict[str, int]
    reasons: dict[str, int]
    first_timestamp: str | None
    last_timestamp: str | None
    first_event_type: str | None
    last_event_type: str | None
    workflow_lifecycle_valid: bool | None
    event_ids_unique: bool
    duplicate_event_ids: int
    event_contract_valid: bool
    workflow_counts_valid: bool | None

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "events": self.events,
            "components": self.components,
            "event_types": self.event_types,
            "statuses": self.statuses,
            "reasons": self.reasons,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "first_event_type": self.first_event_type,
            "last_event_type": self.last_event_type,
            "workflow_lifecycle_valid": self.workflow_lifecycle_valid,
            "event_ids_unique": self.event_ids_unique,
            "duplicate_event_ids": self.duplicate_event_ids,
            "event_contract_valid": self.event_contract_valid,
            "workflow_counts_valid": self.workflow_counts_valid,
        }


class EventStream:
    """Durable payload-free JSONL event stream for local operational diagnostics.

    Cooperative writers are serialized across threads and processes. Every complete event is
    flushed with ``fsync`` before ``emit`` returns. Individual lines and total stream bytes are
    bounded. This is an operational log, not a signed or hash-chained security audit trail.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        run_id: str | None = None,
        clock: Callable[[], datetime] | None = None,
        lock_timeout_seconds: float = 10.0,
        max_stream_bytes: int = DEFAULT_EVENT_STREAM_BYTES,
    ) -> None:
        if not math.isfinite(lock_timeout_seconds) or lock_timeout_seconds < 0:
            raise ValueError("event stream lock timeout must be finite and non-negative")
        if isinstance(max_stream_bytes, bool) or not isinstance(max_stream_bytes, int):
            raise TypeError("event stream size limit must be an integer")
        if not MIN_EVENT_STREAM_BYTES <= max_stream_bytes <= MAX_EVENT_STREAM_BYTES:
            raise ValueError(
                "event stream size limit must be between "
                f"{MIN_EVENT_STREAM_BYTES} and {MAX_EVENT_STREAM_BYTES} bytes"
            )
        self.path = Path(path)
        self.run_id = _validate_trace_id(
            run_id if run_id is not None else new_trace_id(),
            "run_id",
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock_timeout_seconds = lock_timeout_seconds
        self._max_stream_bytes = max_stream_bytes
        self._validated_state: tuple[int, int, int, int] | None = None

    def correlation_id(self, key: str) -> str:
        """Derive a run-scoped opaque ID without persisting the identifying input."""

        if not key or len(key) > 1024 or not key.isprintable():
            raise ValueError("correlation key must be bounded printable text")
        material = bytes.fromhex(self.run_id) + b"\x00" + key.encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:32]

    def emit(
        self,
        *,
        component: str,
        event_type: str,
        status: str,
        correlation_id: str | None = None,
        reason_code: str | None = None,
        duration_ms: float | None = None,
        item_count: int | None = None,
    ) -> OperationalEvent:
        event = OperationalEvent(
            event_id=new_trace_id(),
            run_id=self.run_id,
            correlation_id=correlation_id if correlation_id is not None else new_trace_id(),
            timestamp=self._clock(),
            component=component,
            event_type=event_type,
            status=status,
            reason_code=reason_code,
            duration_ms=duration_ms,
            item_count=item_count,
        )
        self.append(event)
        return event

    def append(self, event: OperationalEvent) -> None:
        if event.run_id != self.run_id:
            raise ValueError("event run_id does not match this stream writer")
        encoded = (
            json.dumps(
                event.as_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            + b"\n"
        )
        if len(encoded) > MAX_COMPACT_EVENT_BYTES:
            raise ValueError("operational event exceeds the compact writer size limit")
        if len(encoded) > _MAX_EVENT_BYTES:
            raise ValueError("operational event exceeds the bounded line size")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with exclusive_path_lock(self.path, timeout_seconds=self._lock_timeout_seconds):
            descriptor = self._open_for_append()
            try:
                current = os.fstat(descriptor)
                if current.st_size + len(encoded) > self._max_stream_bytes:
                    raise ValueError("operational event stream reached its configured size limit")
                remaining = memoryview(encoded)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("operational event append made no progress")
                    remaining = remaining[written:]
                os.fsync(descriptor)
                current = os.fstat(descriptor)
                self._validated_state = (
                    current.st_dev,
                    current.st_ino,
                    current.st_size,
                    current.st_mtime_ns,
                )
            finally:
                os.close(descriptor)

    def _open_for_append(self) -> int:
        flags = os.O_CREAT | os.O_RDWR | os.O_APPEND
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            linked = self.path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(linked.st_mode)
                or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            ):
                raise IntegrityError("operational event path is not a stable regular file")
            if opened.st_size > self._max_stream_bytes:
                raise IntegrityError("operational event stream exceeds its configured size limit")
            state = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            if opened.st_size:
                os.lseek(descriptor, -1, os.SEEK_END)
                if os.read(descriptor, 1) != b"\n":
                    raise IntegrityError("operational event stream has an incomplete tail")
                if self._validated_state != state:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    with os.fdopen(os.dup(descriptor), "rb") as handle:
                        for _ in self._iter_handle(handle):
                            pass
            self._validated_state = state
            if os.name == "posix":
                os.chmod(descriptor, 0o600)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _iter_handle(handle: BinaryIO) -> Iterator[OperationalEvent]:
        line_number = 0
        while encoded := handle.readline(_MAX_EVENT_BYTES + 1):
            line_number += 1
            if len(encoded) > _MAX_EVENT_BYTES:
                raise IntegrityError(f"operational event line {line_number} exceeds the size limit")
            if not encoded.endswith(b"\n"):
                raise IntegrityError("operational event stream has an incomplete tail")
            try:
                payload = json.loads(encoded, object_pairs_hook=_object_without_duplicate_keys)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise IntegrityError(
                    f"operational event line {line_number} is invalid JSON"
                ) from exc
            yield OperationalEvent.from_dict(payload)

    def _open_for_read(self) -> int:
        try:
            linked = self.path.lstat()
        except FileNotFoundError:
            raise
        if not stat.S_ISREG(linked.st_mode):
            raise IntegrityError("operational event path is not a regular file")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                linked.st_dev,
                linked.st_ino,
            ):
                raise IntegrityError("operational event path is not a stable regular file")
            if opened.st_size > self._max_stream_bytes:
                raise IntegrityError("operational event stream exceeds its configured size limit")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def read(self) -> tuple[OperationalEvent, ...]:
        with exclusive_path_lock(self.path, timeout_seconds=self._lock_timeout_seconds):
            try:
                descriptor = self._open_for_read()
            except FileNotFoundError:
                return ()
            with os.fdopen(descriptor, "rb") as handle:
                return tuple(self._iter_handle(handle))

    def summary(self, *, run_id: str | None = None) -> EventStreamSummary:
        selected_run_id = _validate_trace_id(run_id, "run_id") if run_id is not None else None
        components: Counter[str] = Counter()
        event_types: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        reasons: Counter[str] = Counter()
        event_count = 0
        first_timestamp = None
        last_timestamp = None
        first_event_type = None
        last_event_type = None
        lifecycle_valid = selected_run_id is not None
        workflow_correlation_id = None
        workflow_completed = False
        seen_event_ids: set[str] = set()
        duplicate_event_ids = 0
        event_contract_valid = True
        requested_items = None
        completed_items = None
        completion_status = None
        successful_deliveries = 0
        completed_batch_items = 0
        batch_counts_complete = True
        with exclusive_path_lock(self.path, timeout_seconds=self._lock_timeout_seconds):
            try:
                descriptor = self._open_for_read()
            except FileNotFoundError:
                descriptor = None
            if descriptor is not None:
                with os.fdopen(descriptor, "rb") as handle:
                    for event in self._iter_handle(handle):
                        if event.event_id in seen_event_ids:
                            duplicate_event_ids += 1
                        else:
                            seen_event_ids.add(event.event_id)
                        if not _event_contract_valid(event):
                            event_contract_valid = False
                        if selected_run_id is not None and event.run_id != selected_run_id:
                            continue
                        if first_event_type is None:
                            first_event_type = event.event_type
                        last_event_type = event.event_type
                        if selected_run_id is not None:
                            if workflow_completed:
                                lifecycle_valid = False
                            if event.event_type == "workflow_started":
                                requested_items = event.item_count
                                if (
                                    event_count != 0
                                    or event.component != "workflow_benchmark"
                                    or event.status != "started"
                                    or workflow_correlation_id is not None
                                ):
                                    lifecycle_valid = False
                                workflow_correlation_id = event.correlation_id
                            elif event.event_type == "workflow_completed":
                                completed_items = event.item_count
                                completion_status = event.status
                                if (
                                    event_types.get("workflow_started", 0) != 1
                                    or event.component != "workflow_benchmark"
                                    or event.status not in {"passed", "failed"}
                                    or event.correlation_id != workflow_correlation_id
                                ):
                                    lifecycle_valid = False
                                workflow_completed = True
                        if (
                            event.event_type in _DELIVERY_EVENT_TYPES
                            and event.status in _DELIVERY_SUCCESS_STATUSES
                        ):
                            successful_deliveries += 1
                        if event.event_type == "batch_completed":
                            if event.item_count is None:
                                batch_counts_complete = False
                            else:
                                completed_batch_items += event.item_count
                        timestamp = _utc_timestamp(event.timestamp)
                        if first_timestamp is None:
                            first_timestamp = timestamp
                        last_timestamp = timestamp
                        event_count += 1
                        components[event.component] += 1
                        event_types[event.event_type] += 1
                        statuses[event.status] += 1
                        if event.reason_code is not None:
                            reasons[event.reason_code] += 1
        if selected_run_id is not None:
            lifecycle_valid = bool(
                lifecycle_valid
                and event_count
                and event_types.get("workflow_started", 0) == 1
                and event_types.get("workflow_completed", 0) == 1
                and first_event_type == "workflow_started"
                and last_event_type == "workflow_completed"
            )
        workflow_counts_valid: bool | None = None
        if selected_run_id is not None and lifecycle_valid:
            workflow_counts_valid = True
            if completed_items != successful_deliveries:
                workflow_counts_valid = False
            if completion_status == "passed":
                if requested_items != completed_items:
                    workflow_counts_valid = False
                if not batch_counts_complete or completed_batch_items != successful_deliveries:
                    workflow_counts_valid = False
        return EventStreamSummary(
            run_id=selected_run_id,
            events=event_count,
            components=dict(sorted(components.items())),
            event_types=dict(sorted(event_types.items())),
            statuses=dict(sorted(statuses.items())),
            reasons=dict(sorted(reasons.items())),
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
            first_event_type=first_event_type,
            last_event_type=last_event_type,
            workflow_lifecycle_valid=lifecycle_valid,
            event_ids_unique=duplicate_event_ids == 0,
            duplicate_event_ids=duplicate_event_ids,
            event_contract_valid=event_contract_valid and duplicate_event_ids == 0,
            workflow_counts_valid=workflow_counts_valid,
        )
