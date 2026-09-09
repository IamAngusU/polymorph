from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType


class MappingStatus(StrEnum):
    AUTO = "auto"
    REVIEW = "review"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class MappingCandidate:
    source_field_id: str
    target_field_id: str
    score: float
    deterministic_score: float
    semantic_score: float | None = None
    reasons: tuple[str, ...] = ()
    reranker_score: float | None = None


@dataclass(frozen=True, slots=True)
class MappingDecision:
    source_field_id: str
    target_field_id: str | None
    status: MappingStatus
    score: float
    margin: float
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MappingRule:
    source_field_id: str
    target_field_id: str
    transform: str = "copy"
    parameters: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, value in (
            ("source field id", self.source_field_id),
            ("target field id", self.target_field_id),
            ("transform", self.transform),
        ):
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                raise ValueError(f"{label} must be a non-empty string without NUL")
        normalized = {str(key): str(value) for key, value in self.parameters.items()}
        object.__setattr__(self, "parameters", MappingProxyType(normalized))

    def canonical_dict(self) -> dict[str, object]:
        return {
            "source_field_id": self.source_field_id,
            "target_field_id": self.target_field_id,
            "transform": self.transform,
            "parameters": dict(sorted(self.parameters.items())),
        }


@dataclass(frozen=True, slots=True)
class MappingPlan:
    id: str
    source_schema_id: str
    target_schema_id: str
    source_fingerprint: str
    target_fingerprint: str
    rules: tuple[MappingRule, ...]
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))
        if not self.id or not self.source_schema_id or not self.target_schema_id:
            raise ValueError("plan and schema ids must be non-empty")
        if self.version < 1:
            raise ValueError("plan version must be at least 1")
        created_at = self.created_at
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError("plan created_at must be timezone-aware")
        object.__setattr__(self, "created_at", created_at.astimezone(UTC))

    def canonical_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "source_schema_id": self.source_schema_id,
            "target_schema_id": self.target_schema_id,
            "source_fingerprint": self.source_fingerprint,
            "target_fingerprint": self.target_fingerprint,
            "rules": [item.canonical_dict() for item in self.rules],
            "version": self.version,
            "created_at": self.created_at.isoformat(),
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
