from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import re
import stat
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .errors import PolymorphError
from .filesystem import atomic_write_text, exclusive_path_lock

REVIEW_ARTIFACT_SCHEMA = "polymorph.review-artifact"
REVIEW_DRAFT_SCHEMA = "polymorph.review-draft"
REVIEW_ARTIFACT_VERSION = 1
MAX_REVIEW_ARTIFACT_BYTES = 1024 * 1024
MAX_REVIEW_DECISIONS = 4096
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_DISPOSITIONS = frozenset({"accepted", "corrected", "abstained"})


class ReviewArtifactError(PolymorphError):
    """Raised when portable review evidence is malformed, stale, or incomplete."""


class ReviewableSession(Protocol):
    def prepare(self) -> object: ...

    def review_mapping(
        self,
        source_field: str,
        target_field: str,
        *,
        reviewed_by: str,
    ) -> object: ...


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _bounded_text(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReviewArtifactError(f"{name} must be a non-empty string of at most {maximum} chars")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ReviewArtifactError(f"{name} contains control characters")
    return value


def _fingerprint(name: str, value: object) -> str:
    text = _bounded_text(name, value, 64)
    if not _FINGERPRINT.fullmatch(text):
        raise ReviewArtifactError(f"{name} must be a lowercase SHA-256 fingerprint")
    return text


def _timestamp(name: str, value: object) -> str:
    text = _bounded_text(name, value, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReviewArtifactError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ReviewArtifactError(f"{name} must include a timezone")
    return text


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewArtifactError("review JSON contains a duplicate key")
        result[key] = value
    return result


def _canonical(payload: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReviewArtifactError("review artifact is not canonical JSON") from exc


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    source_field: str
    target_field: str | None
    disposition: str

    def __post_init__(self) -> None:
        _bounded_text("source_field", self.source_field, 256)
        if self.target_field is not None:
            _bounded_text("target_field", self.target_field, 256)
        if self.disposition not in _DISPOSITIONS:
            raise ReviewArtifactError("unsupported review disposition")
        if self.disposition == "abstained" and self.target_field is not None:
            raise ReviewArtifactError("an abstained decision cannot select a target field")
        if self.disposition != "abstained" and self.target_field is None:
            raise ReviewArtifactError("accepted and corrected decisions require a target field")

    def to_dict(self) -> dict[str, object]:
        return {
            "disposition": self.disposition,
            "source_field": self.source_field,
            "target_field": self.target_field,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> ReviewDecision:
        allowed = {"source_field", "target_field", "disposition", "suggested_target"}
        if set(payload) - allowed:
            raise ReviewArtifactError("review decision contains unsupported properties")
        return cls(
            source_field=_bounded_text("source_field", payload.get("source_field"), 256),
            target_field=(
                None
                if payload.get("target_field") is None
                else _bounded_text("target_field", payload.get("target_field"), 256)
            ),
            disposition=_bounded_text("disposition", payload.get("disposition"), 16),
        )


@dataclass(frozen=True, slots=True)
class ReviewArtifact:
    artifact_id: str
    source_schema_fingerprint: str
    destination_schema_fingerprint: str
    reviewed_by: str
    created_at: str
    decisions: tuple[ReviewDecision, ...]

    def __post_init__(self) -> None:
        _bounded_text("artifact_id", self.artifact_id, 64)
        _fingerprint("source_schema_fingerprint", self.source_schema_fingerprint)
        _fingerprint("destination_schema_fingerprint", self.destination_schema_fingerprint)
        _bounded_text("reviewed_by", self.reviewed_by, 256)
        _timestamp("created_at", self.created_at)
        if not self.decisions or len(self.decisions) > MAX_REVIEW_DECISIONS:
            raise ReviewArtifactError(
                f"review artifact must contain 1..{MAX_REVIEW_DECISIONS} decisions"
            )
        sources: set[str] = set()
        targets: set[str] = set()
        for decision in self.decisions:
            if decision.source_field in sources:
                raise ReviewArtifactError("review artifact maps a source field more than once")
            sources.add(decision.source_field)
            if decision.target_field is not None:
                if decision.target_field in targets:
                    raise ReviewArtifactError("review artifact maps a target field more than once")
                targets.add(decision.target_field)

    def _body(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "created_at": self.created_at,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "destination_schema_fingerprint": self.destination_schema_fingerprint,
            "privacy": "schema_metadata_only_no_record_values",
            "reviewed_by": self.reviewed_by,
            "schema": REVIEW_ARTIFACT_SCHEMA,
            "source_schema_fingerprint": self.source_schema_fingerprint,
            "version": REVIEW_ARTIFACT_VERSION,
        }

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(_canonical(self._body())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {**self._body(), "content_sha256": self.content_sha256}

    def validate_route(self, source_fingerprint: str, destination_fingerprint: str) -> None:
        if self.source_schema_fingerprint != _fingerprint(
            "source_schema_fingerprint", source_fingerprint
        ):
            raise ReviewArtifactError("review artifact is stale for the current source schema")
        if self.destination_schema_fingerprint != _fingerprint(
            "destination_schema_fingerprint", destination_fingerprint
        ):
            raise ReviewArtifactError("review artifact is stale for the current destination schema")

    def require_complete(self) -> None:
        if any(decision.disposition == "abstained" for decision in self.decisions):
            raise ReviewArtifactError("review artifact still contains abstained decisions")

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        if target.is_symlink():
            raise ReviewArtifactError("review artifact target cannot be a symbolic link")
        text = json.dumps(self.to_dict(), indent=2, ensure_ascii=True, sort_keys=True) + "\n"
        with exclusive_path_lock(target):
            atomic_write_text(target, text, private=True)
        return target

    @classmethod
    def from_review_draft(cls, payload: Mapping[str, object]) -> ReviewArtifact:
        allowed = {
            "schema",
            "version",
            "session_id",
            "source_schema_fingerprint",
            "destination_schema_fingerprint",
            "reviewed_by",
            "reviewed_at",
            "decisions",
            "privacy",
        }
        if set(payload) - allowed:
            raise ReviewArtifactError("review draft contains unsupported properties")
        if payload.get("schema") != REVIEW_DRAFT_SCHEMA or payload.get("version") != 1:
            raise ReviewArtifactError("unsupported review draft schema")
        raw_decisions = payload.get("decisions")
        if not isinstance(raw_decisions, list):
            raise ReviewArtifactError("review draft decisions must be an array")
        decisions = tuple(
            ReviewDecision.from_dict(item)
            if isinstance(item, Mapping)
            else (_raise_decision_type())
            for item in raw_decisions
        )
        reviewed_at = payload.get("reviewed_at")
        return cls(
            artifact_id=uuid.uuid4().hex,
            source_schema_fingerprint=_fingerprint(
                "source_schema_fingerprint", payload.get("source_schema_fingerprint")
            ),
            destination_schema_fingerprint=_fingerprint(
                "destination_schema_fingerprint", payload.get("destination_schema_fingerprint")
            ),
            reviewed_by=_bounded_text("reviewed_by", payload.get("reviewed_by"), 256),
            created_at=_now() if reviewed_at is None else _timestamp("reviewed_at", reviewed_at),
            decisions=decisions,
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> ReviewArtifact:
        expected = {
            "artifact_id",
            "created_at",
            "decisions",
            "destination_schema_fingerprint",
            "privacy",
            "reviewed_by",
            "schema",
            "source_schema_fingerprint",
            "version",
            "content_sha256",
        }
        if set(payload) != expected:
            raise ReviewArtifactError("review artifact properties do not match version 1")
        if payload.get("schema") != REVIEW_ARTIFACT_SCHEMA or payload.get("version") != 1:
            raise ReviewArtifactError("unsupported review artifact schema")
        if payload.get("privacy") != "schema_metadata_only_no_record_values":
            raise ReviewArtifactError("review artifact privacy declaration is invalid")
        raw_decisions = payload.get("decisions")
        if not isinstance(raw_decisions, list):
            raise ReviewArtifactError("review artifact decisions must be an array")
        decisions = tuple(
            ReviewDecision.from_dict(item)
            if isinstance(item, Mapping)
            else (_raise_decision_type())
            for item in raw_decisions
        )
        artifact = cls(
            artifact_id=_bounded_text("artifact_id", payload.get("artifact_id"), 64),
            source_schema_fingerprint=_fingerprint(
                "source_schema_fingerprint", payload.get("source_schema_fingerprint")
            ),
            destination_schema_fingerprint=_fingerprint(
                "destination_schema_fingerprint", payload.get("destination_schema_fingerprint")
            ),
            reviewed_by=_bounded_text("reviewed_by", payload.get("reviewed_by"), 256),
            created_at=_timestamp("created_at", payload.get("created_at")),
            decisions=decisions,
        )
        supplied = _fingerprint("content_sha256", payload.get("content_sha256"))
        if not hmac.compare_digest(supplied, artifact.content_sha256):
            raise ReviewArtifactError("review artifact content digest does not match")
        return artifact

    @classmethod
    def load(cls, path: str | Path) -> ReviewArtifact:
        source = Path(path)
        try:
            metadata = source.lstat()
        except OSError as exc:
            raise ReviewArtifactError("review artifact cannot be opened") from exc
        if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ReviewArtifactError("review artifact must be a regular non-symlink file")
        if metadata.st_size > MAX_REVIEW_ARTIFACT_BYTES:
            raise ReviewArtifactError("review artifact exceeds the local size limit")
        try:
            raw = source.read_text(encoding="utf-8")
            payload = json.loads(raw, object_pairs_hook=_strict_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReviewArtifactError("review artifact is not valid UTF-8 JSON") from exc
        if not isinstance(payload, Mapping):
            raise ReviewArtifactError("review artifact root must be an object")
        return cls.from_dict(payload)


def _raise_decision_type() -> ReviewDecision:
    raise ReviewArtifactError("review decision must be an object")


def _preparation_payload(preparation: object) -> Mapping[str, object]:
    if isinstance(preparation, Mapping):
        return preparation
    serializer = getattr(preparation, "as_dict", None)
    if not callable(serializer):
        serializer = getattr(preparation, "to_dict", None)
    if not callable(serializer):
        raise ReviewArtifactError("session preparation does not expose structured evidence")
    payload = serializer()
    if not isinstance(payload, Mapping):
        raise ReviewArtifactError("session preparation evidence is malformed")
    return payload


def _preparation_fingerprints(preparation: object) -> tuple[str, str]:
    payload = _preparation_payload(preparation)
    source = payload.get("source_schema_fingerprint") or payload.get("source_fingerprint")
    destination = payload.get("destination_schema_fingerprint") or payload.get(
        "target_schema_fingerprint"
    )
    return _fingerprint("source_schema_fingerprint", source), _fingerprint(
        "destination_schema_fingerprint", destination
    )


def review_model_from_preparation(preparation: object) -> dict[str, object]:
    """Build the bounded, record-value-free JSON model consumed by the review component."""

    payload = _preparation_payload(preparation)
    source_fingerprint, destination_fingerprint = _preparation_fingerprints(payload)
    destination_schema = payload.get("destination_schema")
    raw_decisions = payload.get("decisions")
    if not isinstance(destination_schema, Mapping) or not isinstance(raw_decisions, list):
        raise ReviewArtifactError("preparation lacks destination schema or mapping decisions")
    raw_fields = destination_schema.get("fields")
    if not isinstance(raw_fields, list) or len(raw_fields) > MAX_REVIEW_DECISIONS:
        raise ReviewArtifactError("destination schema fields exceed the review UI contract")
    target_fields: list[str] = []
    for raw_field in raw_fields:
        if not isinstance(raw_field, Mapping):
            raise ReviewArtifactError("destination schema field is malformed")
        target_fields.append(_bounded_text("target field id", raw_field.get("id"), 256))

    suggestions: list[dict[str, object]] = []
    for raw_decision in raw_decisions:
        if not isinstance(raw_decision, Mapping):
            raise ReviewArtifactError("mapping decision is malformed")
        status = _bounded_text("mapping status", raw_decision.get("status"), 16)
        if status == "auto":
            continue
        source_field = _bounded_text("source field id", raw_decision.get("source_field_id"), 256)
        target_value = raw_decision.get("target_field_id")
        target_field = (
            None if target_value is None else _bounded_text("target field id", target_value, 256)
        )
        raw_reasons = raw_decision.get("reasons", [])
        if not isinstance(raw_reasons, list) or len(raw_reasons) > 32:
            raise ReviewArtifactError("mapping reasons exceed the review UI contract")
        reasons = [_bounded_text("mapping reason", reason, 512) for reason in raw_reasons]
        score_value = raw_decision.get("score", 0.0)
        if (
            isinstance(score_value, bool)
            or not isinstance(score_value, (int, float))
            or not math.isfinite(float(score_value))
        ):
            raise ReviewArtifactError("mapping score is malformed")
        evidence_class = (
            "no_supported_match"
            if status == "blocked"
            else "multiple_signals"
            if len(reasons) > 1
            else "single_signal"
            if reasons
            else "unclassified"
        )
        suggestions.append(
            {
                "authority": "none",
                "confidence": max(0.0, min(1.0, float(score_value))),
                "decision_status": status,
                "evidence_class": evidence_class,
                "reasons": reasons,
                "source_field": source_field,
                "target_field": target_field,
            }
        )
    if len(suggestions) > MAX_REVIEW_DECISIONS:
        raise ReviewArtifactError("mapping decisions exceed the review UI contract")
    run_id = payload.get("run_id")
    return {
        "destination_schema_fingerprint": destination_fingerprint,
        "privacy": "schema_metadata_only_no_record_values",
        "schema": "polymorph.review-ui-model",
        "session_id": _bounded_text("run_id", run_id, 256),
        "source_schema_fingerprint": source_fingerprint,
        "suggestions": suggestions,
        "target_fields": target_fields,
        "version": 1,
        "write_authority": False,
    }


def apply_review_artifact(session: ReviewableSession, artifact: ReviewArtifact) -> object:
    """Apply schema-bound review choices without granting the artifact write authority."""

    preparation = session.prepare()
    source, destination = _preparation_fingerprints(preparation)
    artifact.validate_route(source, destination)
    artifact.require_complete()
    for decision in artifact.decisions:
        if decision.target_field is None:
            raise ReviewArtifactError("complete review decision unexpectedly has no target")
        session.review_mapping(
            decision.source_field,
            decision.target_field,
            reviewed_by=artifact.reviewed_by,
        )
    return session.prepare()


def _load_json(path: str) -> Mapping[str, object]:
    source = Path(path)
    if source.stat().st_size > MAX_REVIEW_ARTIFACT_BYTES:
        raise ReviewArtifactError("review draft exceeds the local size limit")
    payload = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    if not isinstance(payload, Mapping):
        raise ReviewArtifactError("review draft root must be an object")
    return payload


def _finalize(args: argparse.Namespace) -> int:
    artifact = ReviewArtifact.from_review_draft(_load_json(args.draft))
    artifact.save(args.output)
    print(json.dumps(artifact.to_dict(), indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def _validate(args: argparse.Namespace) -> int:
    artifact = ReviewArtifact.load(args.artifact)
    if args.source_fingerprint and args.destination_fingerprint:
        artifact.validate_route(args.source_fingerprint, args.destination_fingerprint)
    print(
        json.dumps(
            {
                "artifact_id": artifact.artifact_id,
                "content_sha256": artifact.content_sha256,
                "decisions": len(artifact.decisions),
                "status": "valid",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _model(args: argparse.Namespace) -> int:
    model = review_model_from_preparation(_load_json(args.preparation))
    review_items = model["suggestions"]
    if not isinstance(review_items, list):
        raise ReviewArtifactError("generated review model contains malformed suggestions")
    rendered = json.dumps(model, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    atomic_write_text(args.output, rendered, private=True)
    print(
        json.dumps(
            {
                "output": str(Path(args.output)),
                "review_items": len(review_items),
                "status": "created",
                "write_authority": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Finalize and validate portable, schema-bound Polymorph review evidence."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    finalize = commands.add_parser("finalize", help="turn a UI review draft into an artifact")
    finalize.add_argument("draft")
    finalize.add_argument("--output", required=True)
    finalize.set_defaults(func=_finalize)
    model = commands.add_parser("model", help="derive a review UI model from preparation JSON")
    model.add_argument("preparation")
    model.add_argument("--output", required=True)
    model.set_defaults(func=_model)
    validate = commands.add_parser("validate", help="validate an artifact and its digest")
    validate.add_argument("artifact")
    validate.add_argument("--source-fingerprint")
    validate.add_argument("--destination-fingerprint")
    validate.set_defaults(func=_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_fingerprint = getattr(args, "source_fingerprint", None)
    destination_fingerprint = getattr(args, "destination_fingerprint", None)
    if bool(source_fingerprint) != bool(destination_fingerprint):
        raise SystemExit("both route fingerprints are required when either is supplied")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
