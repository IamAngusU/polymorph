from __future__ import annotations

import math
import re
import uuid
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from polymorph.models.types import DataType, FieldRole

_INTEGER = re.compile(r"^[+-]?(?:0|[1-9][0-9]*)$")
_DECIMAL = re.compile(
    r"^[+-]?(?:[0-9]+\.[0-9]+|[0-9]+[eE][+-]?[0-9]+|[0-9]+\.[0-9]+[eE][+-]?[0-9]+)$"
)


def runtime_type(value: object) -> DataType:
    if isinstance(value, bool):
        return DataType.BOOLEAN
    if isinstance(value, datetime):
        return DataType.DATETIME
    if isinstance(value, date):
        return DataType.DATE
    if isinstance(value, int):
        return DataType.INTEGER
    if isinstance(value, (float, Decimal)):
        return DataType.DECIMAL
    if isinstance(value, bytes):
        return DataType.BINARY
    if isinstance(value, (dict, list)):
        return DataType.JSON
    if isinstance(value, uuid.UUID):
        return DataType.UUID
    if isinstance(value, str):
        return DataType.STRING
    return DataType.UNKNOWN


def merge_types(types: list[DataType]) -> DataType:
    known = [item for item in types if item is not DataType.UNKNOWN]
    if not known:
        return DataType.UNKNOWN
    distinct = set(known)
    if len(distinct) == 1:
        return known[0]
    if distinct <= {DataType.INTEGER, DataType.DECIMAL}:
        return DataType.DECIMAL
    if distinct <= {DataType.DATE, DataType.DATETIME}:
        return DataType.DATETIME
    if DataType.STRING in distinct:
        return DataType.STRING
    return DataType.UNKNOWN


def textual_type(value: str, *, role: FieldRole = FieldRole.VALUE) -> DataType:
    """Infer metadata from text without changing the value.

    Natural keys are deliberately kept as strings. Converting identifiers such as 000042
    to integers would destroy information even when every sampled value consists of digits.
    """

    text = value.strip()
    if not text:
        return DataType.UNKNOWN
    if role in {FieldRole.NATURAL_KEY, FieldRole.CREDENTIAL}:
        return DataType.STRING
    lowered = text.casefold()
    if lowered in {"true", "false"}:
        return DataType.BOOLEAN
    try:
        uuid.UUID(text)
    except (ValueError, AttributeError):
        pass
    else:
        return DataType.UUID
    if _INTEGER.fullmatch(text):
        return DataType.INTEGER
    if _DECIMAL.fullmatch(text):
        try:
            number = Decimal(text)
        except InvalidOperation:
            pass
        else:
            if number.is_finite():
                return DataType.DECIMAL
    # ISO-only temporal inference avoids locale guesses such as 03/04/2026.
    try:
        parsed_datetime = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed_datetime = None
    if parsed_datetime is not None and ("T" in text or " " in text):
        return DataType.DATETIME
    try:
        date.fromisoformat(text)
    except ValueError:
        return DataType.STRING
    return DataType.DATE


def finite_json_number(value: object) -> bool:
    return not isinstance(value, float) or math.isfinite(value)
