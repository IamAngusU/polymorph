from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from .errors import PolymorphError

Transform = Callable[[object, Mapping[str, str]], object]


class TransformStage(StrEnum):
    SOURCE = "source"
    DESTINATION = "destination"
    TRANSPORT = "transport"


@dataclass(frozen=True, slots=True)
class TransformSpec:
    name: str
    stage: TransformStage
    function: Transform | None = None


def _copy(value: object, _: Mapping[str, str]) -> object:
    return value


def _trim(value: object, _: Mapping[str, str]) -> object:
    return value.strip() if isinstance(value, str) else value


def _parse_decimal(value: object, params: Mapping[str, str]) -> Decimal | None:
    if value is None or value == "":
        return None
    if isinstance(value, Decimal):
        return value
    text = str(value).strip()
    decimal_sep = params.get("decimal_separator", ".")
    thousands_sep = params.get("thousands_separator", ",")
    if thousands_sep:
        text = text.replace(thousands_sep, "")
    if decimal_sep != ".":
        text = text.replace(decimal_sep, ".")
    try:
        return Decimal(text)
    except InvalidOperation as exc:
        raise PolymorphError("decimal parsing failed") from exc


def _parse_datetime(value: object, params: Mapping[str, str]) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    fmt = params.get("format")
    if fmt:
        return datetime.strptime(str(value), fmt)
    return datetime.fromisoformat(str(value))


TRANSFORMS: dict[str, Transform] = {
    "copy": _copy,
    "trim": _trim,
    "parse_decimal": _parse_decimal,
    "parse_datetime": _parse_datetime,
}

TRANSFORM_SPECS: dict[str, TransformSpec] = {
    **{
        name: TransformSpec(name=name, stage=TransformStage.SOURCE, function=fn)
        for name, fn in TRANSFORMS.items()
    },
    "opaque_forward": TransformSpec("opaque_forward", TransformStage.TRANSPORT),
    "lookup_foreign_key": TransformSpec("lookup_foreign_key", TransformStage.DESTINATION),
}


def transform_stage(name: str) -> TransformStage:
    try:
        return TRANSFORM_SPECS[name].stage
    except KeyError as exc:
        raise PolymorphError(f"unknown transform: {name}") from exc


def is_known_transform(name: str) -> bool:
    return name in TRANSFORM_SPECS


def apply_transform(
    name: str,
    value: object,
    parameters: Mapping[str, str] | None = None,
) -> object:
    try:
        spec = TRANSFORM_SPECS[name]
    except KeyError as exc:
        raise PolymorphError(f"unknown transform: {name}") from exc
    if spec.stage is not TransformStage.SOURCE or spec.function is None:
        raise PolymorphError(f"transform {name} cannot execute at the source stage")
    return spec.function(value, parameters or {})
