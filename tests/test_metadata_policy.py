from __future__ import annotations

import pytest

from polymorph.metadata_policy import (
    ArtifactIntegrityState,
    MetadataCategory,
    MetadataDecisionStatus,
    MetadataFirewall,
    MetadataInventory,
    MetadataObservation,
    MetadataPolicy,
    MetadataSourceChangedError,
    RemovalImpact,
    build_sanitization_receipt,
    require_source_digest,
)

SOURCE_DIGEST = "sha256:" + ("a" * 64)
OUTPUT_DIGEST = "sha256:" + ("b" * 64)


def _inventory(
    *observations: MetadataObservation,
    integrity: ArtifactIntegrityState = ArtifactIntegrityState.UNSIGNED,
) -> MetadataInventory:
    return MetadataInventory(
        source_digest=SOURCE_DIGEST,
        artifact_kind="image.jpeg",
        integrity_state=integrity,
        observations=observations,
    )


def test_privacy_policy_preserves_rendering_metadata_and_strips_location() -> None:
    inventory = _inventory(
        MetadataObservation("image.orientation", MetadataCategory.ORIENTATION),
        MetadataObservation("image.icc-profile", MetadataCategory.COLOR_PROFILE),
        MetadataObservation(
            "image.gps", MetadataCategory.LOCATION, removal_impact=RemovalImpact.NONE
        ),
        MetadataObservation(
            "image.camera-serial",
            MetadataCategory.DEVICE_IDENTIFIER,
            removal_impact=RemovalImpact.NONE,
        ),
    )

    result = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    assert result.status is MetadataDecisionStatus.SANITIZE
    assert result.strip_keys == ("image.gps", "image.camera-serial")
    assert result.preserve_keys == ("image.orientation", "image.icc-profile")


def test_ambiguous_business_metadata_requires_review() -> None:
    inventory = _inventory(
        MetadataObservation("image.capture-time", MetadataCategory.CAPTURE_TIME),
    )

    result = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    assert result.status is MetadataDecisionStatus.REVIEW
    assert result.reason_code == "metadata_review_required"


def test_signed_source_blocks_a_policy_that_would_strip_metadata() -> None:
    inventory = _inventory(
        MetadataObservation(
            "document.author",
            MetadataCategory.PERSON_IDENTITY,
            removal_impact=RemovalImpact.NONE,
        ),
        integrity=ArtifactIntegrityState.SIGNED,
    )

    result = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    assert result.status is MetadataDecisionStatus.BLOCKED
    assert result.reason_code == "signed_source_sanitization_would_invalidate_signature"


def test_unknown_signature_state_requires_review_before_mutation() -> None:
    inventory = _inventory(
        MetadataObservation(
            "document.author",
            MetadataCategory.PERSON_IDENTITY,
            removal_impact=RemovalImpact.NONE,
        ),
        integrity=ArtifactIntegrityState.UNKNOWN,
    )

    result = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    assert result.status is MetadataDecisionStatus.REVIEW
    assert result.reason_code == "source_signature_state_unknown"


def test_preserve_policy_accepts_signed_source_without_mutation() -> None:
    inventory = _inventory(
        MetadataObservation("document.author", MetadataCategory.PERSON_IDENTITY),
        integrity=ArtifactIntegrityState.SIGNED,
    )

    result = MetadataFirewall().evaluate(inventory, MetadataPolicy.preserve())

    assert result.status is MetadataDecisionStatus.PASSED


def test_receipt_contains_only_value_free_provenance() -> None:
    inventory = _inventory(
        MetadataObservation(
            "image.gps",
            MetadataCategory.LOCATION,
            encoded_bytes=96,
            removal_impact=RemovalImpact.NONE,
        ),
    )
    evaluation = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    receipt = build_sanitization_receipt(
        evaluation,
        output_digest=OUTPUT_DIGEST,
        content_representation_preserved=True,
        rendered_content_may_change=False,
    )

    assert receipt.as_dict()["removed_keys"] == ["image.gps"]
    assert "value" not in repr(receipt.as_dict())


def test_receipt_rejects_claimed_removal_without_byte_change() -> None:
    inventory = _inventory(
        MetadataObservation(
            "image.gps", MetadataCategory.LOCATION, removal_impact=RemovalImpact.NONE
        ),
    )
    evaluation = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    with pytest.raises(ValueError, match="distinct output digest"):
        build_sanitization_receipt(
            evaluation,
            output_digest=SOURCE_DIGEST,
            content_representation_preserved=True,
            rendered_content_may_change=False,
        )


@pytest.mark.parametrize(
    ("impact", "status", "reason_code"),
    (
        (
            RemovalImpact.RENDERING,
            MetadataDecisionStatus.REVIEW,
            "metadata_removal_impact_requires_review",
        ),
        (
            RemovalImpact.UNKNOWN,
            MetadataDecisionStatus.REVIEW,
            "metadata_removal_impact_requires_review",
        ),
        (
            RemovalImpact.SIGNATURE,
            MetadataDecisionStatus.BLOCKED,
            "metadata_removal_would_invalidate_signature",
        ),
    ),
)
def test_removal_impact_has_policy_authority(
    impact: RemovalImpact,
    status: MetadataDecisionStatus,
    reason_code: str,
) -> None:
    inventory = _inventory(
        MetadataObservation("image.gps", MetadataCategory.LOCATION, removal_impact=impact)
    )

    result = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    assert result.status is status
    assert result.reason_code == reason_code


def test_representation_impact_cannot_claim_representation_preserved() -> None:
    inventory = _inventory(
        MetadataObservation(
            "image.editor-history",
            MetadataCategory.EDITOR_HISTORY,
            removal_impact=RemovalImpact.REPRESENTATION,
        )
    )
    evaluation = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    with pytest.raises(ValueError, match="representation-preserved"):
        build_sanitization_receipt(
            evaluation,
            output_digest=OUTPUT_DIGEST,
            content_representation_preserved=True,
            rendered_content_may_change=False,
        )


def test_source_digest_guard_rejects_replaced_content(tmp_path) -> None:
    source = tmp_path / "photo.jpg"
    source.write_bytes(b"inspected bytes")
    expected = "sha256:" + __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    assert require_source_digest(source, expected) == expected

    source.write_bytes(b"replaced bytes")

    with pytest.raises(MetadataSourceChangedError, match="digest"):
        require_source_digest(source, expected)
