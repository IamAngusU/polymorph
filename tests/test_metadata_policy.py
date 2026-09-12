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
    build_sanitization_receipt,
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
        MetadataObservation("image.gps", MetadataCategory.LOCATION),
        MetadataObservation("image.camera-serial", MetadataCategory.DEVICE_IDENTIFIER),
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
        MetadataObservation("document.author", MetadataCategory.PERSON_IDENTITY),
        integrity=ArtifactIntegrityState.SIGNED,
    )

    result = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    assert result.status is MetadataDecisionStatus.BLOCKED
    assert result.reason_code == "signed_source_sanitization_would_invalidate_signature"


def test_unknown_signature_state_requires_review_before_mutation() -> None:
    inventory = _inventory(
        MetadataObservation("document.author", MetadataCategory.PERSON_IDENTITY),
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
        MetadataObservation("image.gps", MetadataCategory.LOCATION, encoded_bytes=96),
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
        MetadataObservation("image.gps", MetadataCategory.LOCATION),
    )
    evaluation = MetadataFirewall().evaluate(inventory, MetadataPolicy.privacy())

    with pytest.raises(ValueError, match="distinct output digest"):
        build_sanitization_receipt(
            evaluation,
            output_digest=SOURCE_DIGEST,
            content_representation_preserved=True,
            rendered_content_may_change=False,
        )
