from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DataType(StrEnum):
    UNKNOWN = "unknown"
    STRING = "string"
    INTEGER = "integer"
    DECIMAL = "decimal"
    BOOLEAN = "boolean"
    DATE = "date"
    DATETIME = "datetime"
    UUID = "uuid"
    BINARY = "binary"
    JSON = "json"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PERSONAL = "personal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    OPAQUE = "opaque"


_SENSITIVITY_RANK = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.PERSONAL: 2,
    Sensitivity.CONFIDENTIAL: 3,
    Sensitivity.SECRET: 4,
    Sensitivity.OPAQUE: 5,
}


def sensitivity_route_safe(source: Sensitivity, target: Sensitivity) -> bool:
    """Return whether a destination classification avoids an information downgrade."""

    return _SENSITIVITY_RANK[target] >= _SENSITIVITY_RANK[source]


class FieldRole(StrEnum):
    VALUE = "value"
    PRIMARY_KEY = "primary_key"
    FOREIGN_KEY = "foreign_key"
    NATURAL_KEY = "natural_key"
    CREDENTIAL = "credential"


def runtime_type_satisfies(actual: DataType, target: DataType) -> bool:
    """Mirror the destination runtime's non-coercing value type contract."""

    if target is DataType.UNKNOWN:
        return True
    return actual is target or (actual is DataType.INTEGER and target is DataType.DECIMAL)


def automatic_copy_type_safe(source: DataType, target: DataType) -> bool:
    """Return whether declared types justify an automatic direct-copy decision."""

    return source is not DataType.UNKNOWN and runtime_type_satisfies(source, target)


@dataclass(frozen=True, slots=True)
class FieldPolicy:
    sensitivity: Sensitivity
    transformable: bool

    @classmethod
    def for_sensitivity(cls, sensitivity: Sensitivity) -> FieldPolicy:
        return cls(
            sensitivity=sensitivity,
            transformable=sensitivity not in {Sensitivity.SECRET, Sensitivity.OPAQUE},
        )
