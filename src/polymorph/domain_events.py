from __future__ import annotations

import asyncio
import json
import math
import re
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Protocol, TypeAlias

EVENT_CONTRACT_VERSION = 1
MAX_EVENT_PARAMETERS = 32
MAX_EVENT_PARAMETER_TEXT = 256
MAX_EVENT_FAILURE_RECORDS = 128

EventParameter: TypeAlias = str | int | float | bool | None
EventHandler: TypeAlias = Callable[["PolymorphEvent"], None]

_MACHINE_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


def _require_machine_key(value: str, *, label: str) -> str:
    if not isinstance(value, str) or _MACHINE_KEY.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lower-case bounded machine key")
    return value


def _require_bounded_text(value: str, *, label: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isprintable()
        or value != value.strip()
    ):
        raise ValueError(f"{label} must be non-empty bounded printable text")
    return value


class EventSeverity(StrEnum):
    INFO = "info"
    REVIEW = "review"
    WARNING = "warning"
    ERROR = "error"


class PresentationHint(StrEnum):
    INLINE = "inline"
    TOAST = "toast"
    BANNER = "banner"
    DIALOG = "dialog"
    BACKGROUND = "background"
    INCIDENT = "incident"


class RetryPolicy(StrEnum):
    SAFE_AFTER_FIX = "safe_after_fix"
    AFTER_REVIEW = "after_review"
    AFTER_RECONCILIATION = "after_reconciliation"
    NEVER_BLIND = "never_blind_retry"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class EventScope:
    stage: str
    connector_id: str | None = None
    source_field_id: str | None = None
    target_field_id: str | None = None

    def __post_init__(self) -> None:
        _require_machine_key(self.stage, label="event scope stage")
        for label, value in (
            ("connector id", self.connector_id),
            ("source field id", self.source_field_id),
            ("target field id", self.target_field_id),
        ):
            if value is not None:
                _require_bounded_text(value, label=label, maximum=128)

    def as_dict(self) -> dict[str, str]:
        payload = {"stage": self.stage}
        if self.connector_id is not None:
            payload["connector_id"] = self.connector_id
        if self.source_field_id is not None:
            payload["source_field_id"] = self.source_field_id
        if self.target_field_id is not None:
            payload["target_field_id"] = self.target_field_id
        return payload


@dataclass(frozen=True, slots=True)
class PolymorphEvent:
    event_type: str
    severity: EventSeverity
    message_key: str
    default_message: str
    next_action: str
    retry_policy: RetryPolicy
    presentation_hint: PresentationHint
    run_id: str
    correlation_id: str
    scope: EventScope
    reason_code: str | None = None
    parameters: Mapping[str, EventParameter] = field(default_factory=dict)
    schema_version: int = EVENT_CONTRACT_VERSION
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.schema_version != EVENT_CONTRACT_VERSION:
            raise ValueError("unsupported domain event contract version")
        _require_machine_key(self.event_type, label="event type")
        _require_machine_key(self.message_key, label="message key")
        _require_bounded_text(self.default_message, label="default message", maximum=1024)
        _require_bounded_text(self.next_action, label="next action", maximum=1024)
        _require_bounded_text(self.run_id, label="run id", maximum=128)
        _require_bounded_text(self.correlation_id, label="correlation id", maximum=128)
        _require_bounded_text(self.event_id, label="event id", maximum=128)
        if self.reason_code is not None:
            _require_machine_key(self.reason_code, label="reason code")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("domain event timestamp must be timezone-aware")
        if len(self.parameters) > MAX_EVENT_PARAMETERS:
            raise ValueError("domain event has too many parameters")
        normalized: dict[str, EventParameter] = {}
        for key, value in self.parameters.items():
            _require_machine_key(key, label="event parameter key")
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError("domain event parameters must be scalar metadata")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("domain event numeric parameters must be finite")
            if isinstance(value, str):
                _require_bounded_text(
                    value,
                    label="event parameter text",
                    maximum=MAX_EVENT_PARAMETER_TEXT,
                )
            normalized[key] = value
        object.__setattr__(self, "parameters", MappingProxyType(normalized))

    @classmethod
    def create(
        cls,
        event_type: str,
        *,
        severity: EventSeverity,
        default_message: str,
        next_action: str,
        retry_policy: RetryPolicy,
        presentation_hint: PresentationHint,
        run_id: str,
        correlation_id: str,
        scope: EventScope,
        reason_code: str | None = None,
        parameters: Mapping[str, EventParameter] | None = None,
    ) -> PolymorphEvent:
        return cls(
            event_type=event_type,
            severity=severity,
            message_key=event_type,
            default_message=default_message,
            next_action=next_action,
            retry_policy=retry_policy,
            presentation_hint=presentation_hint,
            run_id=run_id,
            correlation_id=correlation_id,
            scope=scope,
            reason_code=reason_code,
            parameters=parameters or {},
        )

    def localized_message(self, locale: str = "en") -> str:
        return message_for(
            self.message_key,
            locale=locale,
            parameters=self.parameters,
            default=self.default_message,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "reason_code": self.reason_code,
            "scope": self.scope.as_dict(),
            "message_key": self.message_key,
            "default_message": self.default_message,
            "parameters": dict(self.parameters),
            "next_action": self.next_action,
            "retry_policy": self.retry_policy.value,
            "presentation_hint": self.presentation_hint.value,
            "run_id": self.run_id,
            "correlation_id": self.correlation_id,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        }


class _SafeFormatParameters(dict[str, EventParameter]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


@lru_cache(maxsize=2)
def _message_catalog(locale: str) -> dict[str, str]:
    language = locale.casefold().replace("_", "-").split("-", 1)[0]
    if language not in {"de", "en"}:
        language = "en"
    text = (
        resources.files("polymorph")
        .joinpath("data")
        .joinpath(f"messages.{language}.json")
        .read_text(encoding="utf-8")
    )
    payload = json.loads(text)
    if not isinstance(payload, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in payload.items()
    ):
        raise ValueError("invalid packaged domain event message catalog")
    return dict(payload)


def message_for(
    message_key: str,
    *,
    locale: str = "en",
    parameters: Mapping[str, EventParameter] | None = None,
    default: str | None = None,
) -> str:
    _require_machine_key(message_key, label="message key")
    template = _message_catalog(locale).get(message_key, default or message_key)
    return template.format_map(_SafeFormatParameters(parameters or {}))


class EventSink(Protocol):
    def emit(self, event: PolymorphEvent) -> None: ...


@dataclass(slots=True)
class CallbackEventSink:
    callback: EventHandler

    def emit(self, event: PolymorphEvent) -> None:
        self.callback(event)


class EventSinkError(RuntimeError):
    pass


class CompositeEventSink:
    def __init__(self, sinks: Sequence[EventSink]) -> None:
        self._sinks = tuple(sinks)

    def emit(self, event: PolymorphEvent) -> None:
        failures = 0
        for sink in self._sinks:
            try:
                sink.emit(event)
            except Exception:
                failures += 1
        if failures:
            raise EventSinkError(f"{failures} domain event sink(s) failed")


class AsyncQueueEventSink:
    def __init__(self, *, maxsize: int = 256) -> None:
        if isinstance(maxsize, bool) or not isinstance(maxsize, int) or maxsize <= 0:
            raise ValueError("event queue maxsize must be a positive integer")
        self._queue: asyncio.Queue[PolymorphEvent] = asyncio.Queue(maxsize=maxsize)

    def emit(self, event: PolymorphEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull as exc:
            raise EventSinkError("bounded domain event queue is full") from exc

    async def get(self) -> PolymorphEvent:
        return await self._queue.get()

    def get_nowait(self) -> PolymorphEvent:
        return self._queue.get_nowait()

    @property
    def pending(self) -> int:
        return self._queue.qsize()


@dataclass(frozen=True, slots=True)
class EventDeliveryFailure:
    event_id: str
    consumer: str
    error_type: str


class EventDispatcher:
    """Best-effort product events that can never change destination write semantics."""

    def __init__(
        self,
        sinks: Iterable[EventSink] = (),
        *,
        max_failure_records: int = MAX_EVENT_FAILURE_RECORDS,
    ) -> None:
        if (
            isinstance(max_failure_records, bool)
            or not isinstance(max_failure_records, int)
            or max_failure_records <= 0
        ):
            raise ValueError("event failure record limit must be a positive integer")
        self._sinks = list(sinks)
        self._handlers: dict[str, list[EventHandler]] = {}
        self._failures: list[EventDeliveryFailure] = []
        self._failure_count = 0
        self._max_failure_records = max_failure_records

    def add_sink(self, sink: EventSink) -> EventDispatcher:
        self._sinks.append(sink)
        return self

    def on(self, event_type: str, handler: EventHandler) -> EventDispatcher:
        if event_type != "*":
            _require_machine_key(event_type, label="event subscription")
        self._handlers.setdefault(event_type, []).append(handler)
        return self

    def emit(self, event: PolymorphEvent) -> None:
        for sink in tuple(self._sinks):
            self._deliver(event, type(sink).__name__, sink.emit)
        for key in (event.event_type, "*"):
            for handler in tuple(self._handlers.get(key, ())):
                name = getattr(handler, "__qualname__", type(handler).__name__)
                self._deliver(event, name, handler)

    def _deliver(
        self,
        event: PolymorphEvent,
        consumer: str,
        callback: EventHandler,
    ) -> None:
        try:
            callback(event)
        except Exception as exc:
            self._failure_count += 1
            if len(self._failures) < self._max_failure_records:
                self._failures.append(
                    EventDeliveryFailure(
                        event_id=event.event_id,
                        consumer=consumer[:128],
                        error_type=type(exc).__name__,
                    )
                )

    @property
    def failures(self) -> tuple[EventDeliveryFailure, ...]:
        return tuple(self._failures)

    @property
    def failure_count(self) -> int:
        return self._failure_count
