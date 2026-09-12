"""Policy contracts for a payload-free metadata trust boundary.

This module intentionally does not parse or rewrite file formats. Format adapters
must produce value-free observations and a sanitizer must return a provenance
receipt. Active content and probabilistic content classification are separate
boundaries.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

_MACHINE_KEY = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")


class MetadataCategory(StrEnum):
    TECHNICAL_REQUIRED = "technical_required"
    COLOR_PROFILE = "color_profile"
    ORIENTATION = "orientation"
    LOCATION = "location"
    DEVICE_IDENTIFIER = "device_identifier"
    PERSON_IDENTITY = "person_identity"
    COPYRIGHT = "copyright"
    CAPTURE_TIME = "capture_time"
    DOCUMENT_TIME = "document_time"
    EDITOR_HISTORY = "editor_history"
    COMMENT = "comment"
    DOCUMENT_IDENTIFIER = "document_identifier"
    EMBEDDED_THUMBNAIL = "embedded_thumbnail"
    UNKNOWN = "unknown"


class MetadataEvidenceClass(StrEnum):
    REQUIRED = "required"
    SAFE = "safe"
    SENSITIVE = "sensitive"
    AMBIGUOUS = "ambiguous"


class MetadataAction(StrEnum):
    PRESERVE = "preserve"
    STRIP = "strip"
    REVIEW = "review"
    BLOCK = "block"


class MetadataDecisionStatus(StrEnum):
    PASSED = "passed"
    SANITIZE = "sanitize"
    REVIEW = "review"
    BLOCKED = "blocked"


class ArtifactIntegrityState(StrEnum):
    UNSIGNED = "unsigned"
    SIGNED = "signed"
    UNKNOWN = "unknown"


class RemovalImpact(StrEnum):
    NONE = "none"
    REPRESENTATION = "representation"
    RENDERING = "rendering"
    SIGNATURE = "signature"
    UNKNOWN = "unknown"


_EVIDENCE_CLASSES: Mapping[MetadataCategory, MetadataEvidenceClass] = MappingProxyType(
    {
        MetadataCategory.TECHNICAL_REQUIRED: MetadataEvidenceClass.REQUIRED,
        MetadataCategory.COLOR_PROFILE: MetadataEvidenceClass.REQUIRED,
        MetadataCategory.ORIENTATION: MetadataEvidenceClass.REQUIRED,
        MetadataCategory.LOCATION: MetadataEvidenceClass.SENSITIVE,
        MetadataCategory.DEVICE_IDENTIFIER: MetadataEvidenceClass.SENSITIVE,
        MetadataCategory.PERSON_IDENTITY: MetadataEvidenceClass.SENSITIVE,
        MetadataCategory.COPYRIGHT: MetadataEvidenceClass.AMBIGUOUS,
        MetadataCategory.CAPTURE_TIME: MetadataEvidenceClass.AMBIGUOUS,
        MetadataCategory.DOCUMENT_TIME: MetadataEvidenceClass.AMBIGUOUS,
        MetadataCategory.EDITOR_HISTORY: MetadataEvidenceClass.SENSITIVE,
        MetadataCategory.COMMENT: MetadataEvidenceClass.SENSITIVE,
        MetadataCategory.DOCUMENT_IDENTIFIER: MetadataEvidenceClass.SENSITIVE,
        MetadataCategory.EMBEDDED_THUMBNAIL: MetadataEvidenceClass.SENSITIVE,
        MetadataCategory.UNKNOWN: MetadataEvidenceClass.AMBIGUOUS,
    }
)


def _require_machine_key(value: str, *, label: str) -> None:
    if not isinstance(value, str) or not _MACHINE_KEY.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase machine key")


def _require_digest(value: str, *, label: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")


@dataclass(frozen=True, slots=True)
class MetadataObservation:
    """Value-free evidence that a metadata class is present in an artifact."""

    key: str
    category: MetadataCategory
    occurrences: int = 1
    encoded_bytes: int | None = None
    removal_impact: RemovalImpact = RemovalImpact.UNKNOWN

    def __post_init__(self) -> None:
        _require_machine_key(self.key, label="metadata observation key")
        if not isinstance(self.category, MetadataCategory):
            raise ValueError("metadata category must be a MetadataCategory")
        if not isinstance(self.removal_impact, RemovalImpact):
            raise ValueError("metadata removal impact must be a RemovalImpact")
        if (
            isinstance(self.occurrences, bool)
            or not isinstance(self.occurrences, int)
            or self.occurrences <= 0
        ):
            raise ValueError("metadata occurrence count must be a positive integer")
        if self.encoded_bytes is not None and (
            isinstance(self.encoded_bytes, bool)
            or not isinstance(self.encoded_bytes, int)
            or self.encoded_bytes < 0
        ):
            raise ValueError("metadata encoded bytes must be a non-negative integer")

    @property
    def evidence_class(self) -> MetadataEvidenceClass:
        return _EVIDENCE_CLASSES[self.category]

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "category": self.category.value,
            "evidence_class": self.evidence_class.value,
            "occurrences": self.occurrences,
            "encoded_bytes": self.encoded_bytes,
            "removal_impact": self.removal_impact.value,
        }


@dataclass(frozen=True, slots=True)
class MetadataInventory:
    source_digest: str
    artifact_kind: str
    integrity_state: ArtifactIntegrityState
    observations: tuple[MetadataObservation, ...] = ()
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported metadata inventory schema version")
        _require_digest(self.source_digest, label="source digest")
        _require_machine_key(self.artifact_kind, label="artifact kind")
        if not isinstance(self.integrity_state, ArtifactIntegrityState):
            raise ValueError("integrity state must be an ArtifactIntegrityState")
        if not isinstance(self.observations, tuple) or not all(
            isinstance(item, MetadataObservation) for item in self.observations
        ):
            raise ValueError("metadata observations must be a tuple of MetadataObservation")
        if len(self.observations) > 4096:
            raise ValueError("metadata inventory has too many observations")
        keys = [observation.key for observation in self.observations]
        if len(keys) != len(set(keys)):
            raise ValueError("metadata inventory contains duplicate observation keys")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_digest": self.source_digest,
            "artifact_kind": self.artifact_kind,
            "integrity_state": self.integrity_state.value,
            "observations": [item.as_dict() for item in self.observations],
        }


@dataclass(frozen=True, slots=True)
class MetadataPolicy:
    name: str
    version: str
    default_action: MetadataAction
    category_actions: Mapping[MetadataCategory, MetadataAction] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_machine_key(self.name, label="metadata policy name")
        _require_machine_key(self.version, label="metadata policy version")
        if not isinstance(self.default_action, MetadataAction):
            raise ValueError("metadata default action must be a MetadataAction")
        normalized: dict[MetadataCategory, MetadataAction] = {}
        for category, action in self.category_actions.items():
            if not isinstance(category, MetadataCategory):
                raise ValueError("metadata policy category must be a MetadataCategory")
            if not isinstance(action, MetadataAction):
                raise ValueError("metadata policy action must be a MetadataAction")
            normalized[category] = action
        object.__setattr__(self, "category_actions", MappingProxyType(normalized))

    def action_for(self, observation: MetadataObservation) -> MetadataAction:
        return self.category_actions.get(observation.category, self.default_action)

    @classmethod
    def preserve(cls) -> MetadataPolicy:
        return cls(
            name="preserve",
            version="v1",
            default_action=MetadataAction.PRESERVE,
        )

    @classmethod
    def privacy(cls) -> MetadataPolicy:
        return cls(
            name="privacy",
            version="v1",
            default_action=MetadataAction.REVIEW,
            category_actions={
                MetadataCategory.TECHNICAL_REQUIRED: MetadataAction.PRESERVE,
                MetadataCategory.COLOR_PROFILE: MetadataAction.PRESERVE,
                MetadataCategory.ORIENTATION: MetadataAction.PRESERVE,
                MetadataCategory.LOCATION: MetadataAction.STRIP,
                MetadataCategory.DEVICE_IDENTIFIER: MetadataAction.STRIP,
                MetadataCategory.PERSON_IDENTITY: MetadataAction.STRIP,
                MetadataCategory.COPYRIGHT: MetadataAction.REVIEW,
                MetadataCategory.CAPTURE_TIME: MetadataAction.REVIEW,
                MetadataCategory.DOCUMENT_TIME: MetadataAction.REVIEW,
                MetadataCategory.EDITOR_HISTORY: MetadataAction.STRIP,
                MetadataCategory.COMMENT: MetadataAction.STRIP,
                MetadataCategory.DOCUMENT_IDENTIFIER: MetadataAction.STRIP,
                MetadataCategory.EMBEDDED_THUMBNAIL: MetadataAction.STRIP,
                MetadataCategory.UNKNOWN: MetadataAction.REVIEW,
            },
        )

    @classmethod
    def strict(cls) -> MetadataPolicy:
        return cls(
            name="strict",
            version="v1",
            default_action=MetadataAction.REVIEW,
            category_actions={
                MetadataCategory.TECHNICAL_REQUIRED: MetadataAction.PRESERVE,
                MetadataCategory.COLOR_PROFILE: MetadataAction.PRESERVE,
                MetadataCategory.ORIENTATION: MetadataAction.PRESERVE,
                MetadataCategory.LOCATION: MetadataAction.STRIP,
                MetadataCategory.DEVICE_IDENTIFIER: MetadataAction.STRIP,
                MetadataCategory.PERSON_IDENTITY: MetadataAction.STRIP,
                MetadataCategory.COPYRIGHT: MetadataAction.STRIP,
                MetadataCategory.CAPTURE_TIME: MetadataAction.STRIP,
                MetadataCategory.DOCUMENT_TIME: MetadataAction.STRIP,
                MetadataCategory.EDITOR_HISTORY: MetadataAction.STRIP,
                MetadataCategory.COMMENT: MetadataAction.STRIP,
                MetadataCategory.DOCUMENT_IDENTIFIER: MetadataAction.STRIP,
                MetadataCategory.EMBEDDED_THUMBNAIL: MetadataAction.STRIP,
                MetadataCategory.UNKNOWN: MetadataAction.REVIEW,
            },
        )


@dataclass(frozen=True, slots=True)
class MetadataItemDecision:
    observation: MetadataObservation
    action: MetadataAction

    def as_dict(self) -> dict[str, object]:
        return {**self.observation.as_dict(), "action": self.action.value}


@dataclass(frozen=True, slots=True)
class MetadataEvaluation:
    inventory: MetadataInventory
    policy_name: str
    policy_version: str
    status: MetadataDecisionStatus
    reason_code: str
    decisions: tuple[MetadataItemDecision, ...]
    schema_version: int = 1

    @property
    def strip_keys(self) -> tuple[str, ...]:
        return tuple(
            decision.observation.key
            for decision in self.decisions
            if decision.action is MetadataAction.STRIP
        )

    @property
    def preserve_keys(self) -> tuple[str, ...]:
        return tuple(
            decision.observation.key
            for decision in self.decisions
            if decision.action is MetadataAction.PRESERVE
        )

    def as_dict(self) -> dict[str, object]:
        counts = {action.value: 0 for action in MetadataAction}
        for decision in self.decisions:
            counts[decision.action.value] += 1
        return {
            "schema_version": self.schema_version,
            "source_digest": self.inventory.source_digest,
            "artifact_kind": self.inventory.artifact_kind,
            "integrity_state": self.inventory.integrity_state.value,
            "policy": {"name": self.policy_name, "version": self.policy_version},
            "status": self.status.value,
            "reason_code": self.reason_code,
            "counts": counts,
            "decisions": [decision.as_dict() for decision in self.decisions],
        }


class MetadataFirewall:
    """Evaluate metadata crossing a trust boundary without inspecting values."""

    def evaluate(
        self,
        inventory: MetadataInventory,
        policy: MetadataPolicy,
    ) -> MetadataEvaluation:
        decisions = tuple(
            MetadataItemDecision(observation, policy.action_for(observation))
            for observation in inventory.observations
        )
        has_strip = any(item.action is MetadataAction.STRIP for item in decisions)
        has_review = any(item.action is MetadataAction.REVIEW for item in decisions)
        has_block = any(item.action is MetadataAction.BLOCK for item in decisions)

        if has_block:
            status = MetadataDecisionStatus.BLOCKED
            reason_code = "metadata_policy_blocked"
        elif has_strip and inventory.integrity_state is ArtifactIntegrityState.SIGNED:
            status = MetadataDecisionStatus.BLOCKED
            reason_code = "signed_source_sanitization_would_invalidate_signature"
        elif has_strip and inventory.integrity_state is ArtifactIntegrityState.UNKNOWN:
            status = MetadataDecisionStatus.REVIEW
            reason_code = "source_signature_state_unknown"
        elif has_review:
            status = MetadataDecisionStatus.REVIEW
            reason_code = "metadata_review_required"
        elif has_strip:
            status = MetadataDecisionStatus.SANITIZE
            reason_code = "metadata_sanitization_required"
        else:
            status = MetadataDecisionStatus.PASSED
            reason_code = "metadata_policy_passed"

        return MetadataEvaluation(
            inventory=inventory,
            policy_name=policy.name,
            policy_version=policy.version,
            status=status,
            reason_code=reason_code,
            decisions=decisions,
        )


@dataclass(frozen=True, slots=True)
class MetadataSanitizationReceipt:
    source_digest: str
    output_digest: str
    policy_name: str
    policy_version: str
    removed_keys: tuple[str, ...]
    preserved_keys: tuple[str, ...]
    content_representation_preserved: bool
    rendered_content_may_change: bool
    source_signature_invalidated: bool = False
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported sanitization receipt schema version")
        _require_digest(self.source_digest, label="source digest")
        _require_digest(self.output_digest, label="output digest")
        _require_machine_key(self.policy_name, label="metadata policy name")
        _require_machine_key(self.policy_version, label="metadata policy version")
        for key in (*self.removed_keys, *self.preserved_keys):
            _require_machine_key(key, label="receipt metadata key")
        if set(self.removed_keys) & set(self.preserved_keys):
            raise ValueError("metadata key cannot be both removed and preserved")
        if self.removed_keys and self.source_digest == self.output_digest:
            raise ValueError("removed metadata requires a distinct output digest")
        if self.source_signature_invalidated:
            raise ValueError("Polymorph receipts cannot approve an invalidated source signature")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "transform": "metadata_sanitize",
            "policy": {"name": self.policy_name, "version": self.policy_version},
            "source_digest": self.source_digest,
            "output_digest": self.output_digest,
            "removed_keys": list(self.removed_keys),
            "preserved_keys": list(self.preserved_keys),
            "content_representation_preserved": self.content_representation_preserved,
            "rendered_content_may_change": self.rendered_content_may_change,
            "source_signature_invalidated": self.source_signature_invalidated,
        }


def build_sanitization_receipt(
    evaluation: MetadataEvaluation,
    *,
    output_digest: str,
    content_representation_preserved: bool,
    rendered_content_may_change: bool,
) -> MetadataSanitizationReceipt:
    if evaluation.status is not MetadataDecisionStatus.SANITIZE:
        raise ValueError("only an approved sanitize evaluation can produce a receipt")
    return MetadataSanitizationReceipt(
        source_digest=evaluation.inventory.source_digest,
        output_digest=output_digest,
        policy_name=evaluation.policy_name,
        policy_version=evaluation.policy_version,
        removed_keys=evaluation.strip_keys,
        preserved_keys=evaluation.preserve_keys,
        content_representation_preserved=content_representation_preserved,
        rendered_content_may_change=rendered_content_may_change,
    )


class MetadataInspector(Protocol):
    """Format adapter that emits no metadata values."""

    def inspect_metadata(self, source: Path) -> MetadataInventory: ...


class MetadataSanitizer(Protocol):
    """Format adapter that applies an already-approved evaluation."""

    def sanitize_metadata(
        self,
        source: Path,
        destination: Path,
        evaluation: MetadataEvaluation,
    ) -> MetadataSanitizationReceipt: ...


def observations_for_categories(
    pairs: Sequence[tuple[str, MetadataCategory]],
) -> tuple[MetadataObservation, ...]:
    """Small adapter helper that still makes raw metadata values unrepresentable."""

    return tuple(MetadataObservation(key, category) for key, category in pairs)
