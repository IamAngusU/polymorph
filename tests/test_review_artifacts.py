from __future__ import annotations

import json

import pytest

from polymorph.review_artifacts import (
    ReviewArtifact,
    ReviewArtifactError,
    apply_review_artifact,
)


def _draft() -> dict[str, object]:
    return {
        "schema": "polymorph.review-draft",
        "version": 1,
        "session_id": "session-1",
        "source_schema_fingerprint": "a" * 64,
        "destination_schema_fingerprint": "b" * 64,
        "reviewed_by": "finance-team",
        "reviewed_at": "2026-09-12T12:00:00Z",
        "decisions": [
            {
                "source_field": "Bruttobetrag",
                "target_field": "invoice_total",
                "disposition": "corrected",
            }
        ],
        "privacy": "schema_metadata_only_no_record_values",
    }


def test_review_artifact_round_trip_is_schema_bound_and_value_free(tmp_path) -> None:
    artifact = ReviewArtifact.from_review_draft(_draft())
    path = artifact.save(tmp_path / "review.json")
    loaded = ReviewArtifact.load(path)

    loaded.validate_route("a" * 64, "b" * 64)
    assert loaded.content_sha256 == artifact.content_sha256
    rendered = path.read_text(encoding="utf-8")
    assert "row_values" not in rendered
    assert "invoice_total" in rendered


def test_review_artifact_rejects_tampering_and_stale_schema(tmp_path) -> None:
    artifact = ReviewArtifact.from_review_draft(_draft())
    payload = artifact.to_dict()
    payload["reviewed_by"] = "attacker"
    path = tmp_path / "review.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReviewArtifactError, match="digest"):
        ReviewArtifact.load(path)
    with pytest.raises(ReviewArtifactError, match="stale"):
        artifact.validate_route("c" * 64, "b" * 64)


def test_apply_review_artifact_does_not_execute_write() -> None:
    artifact = ReviewArtifact.from_review_draft(_draft())

    class Preparation:
        def to_dict(self) -> dict[str, str]:
            return {
                "source_schema_fingerprint": "a" * 64,
                "destination_schema_fingerprint": "b" * 64,
            }

    class Session:
        def __init__(self) -> None:
            self.reviews: list[tuple[str, str]] = []
            self.executed = False

        def prepare(self) -> Preparation:
            return Preparation()

        def review_mapping(self, source: str, target: str) -> None:
            self.reviews.append((source, target))

    session = Session()
    apply_review_artifact(session, artifact)
    assert session.reviews == [("Bruttobetrag", "invoice_total")]
    assert session.executed is False
