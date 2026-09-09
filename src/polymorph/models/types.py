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


class FieldRole(StrEnum):
    VALUE = "value"
    PRIMARY_KEY = "primary_key"
    FOREIGN_KEY = "foreign_key"
    NATURAL_KEY = "natural_key"
    CREDENTIAL = "credential"


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
