from __future__ import annotations

import hashlib
import json

import pytest

from polymorph.matching.lexical import (
    DIMENSIONS,
    FEATURE_VERSION,
    FORMAT,
    LearnedRanker,
    baseline_weights,
    field_text,
)


def _artifact(tmp_path, **changes):
    payload = {
        "format": FORMAT,
        "feature_version": FEATURE_VERSION,
        "dimensions": DIMENSIONS,
        "weights": baseline_weights(),
    }
    payload.update(changes)
    path = tmp_path / "model.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_lexical_artifact_roundtrip(tmp_path):
    path, checksum = _artifact(tmp_path)

    ranker = LearnedRanker.load(path, expected_sha256=checksum)

    assert ranker.artifact_sha256 == checksum


@pytest.mark.parametrize(
    "changes",
    [
        {"dimensions": True},
        {"feature_version": "future"},
        {"format": "pickle"},
        {"extra": "command"},
        {"weights": [True] * DIMENSIONS},
        {"weights": [float("nan")] * DIMENSIONS},
        {"weights": []},
    ],
)
def test_invalid_lexical_models_are_rejected(tmp_path, changes):
    path, checksum = _artifact(tmp_path, **changes)

    with pytest.raises(ValueError):
        LearnedRanker.load(path, expected_sha256=checksum)


def test_lexical_artifact_mutation_is_rejected(tmp_path):
    path, checksum = _artifact(tmp_path)
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(ValueError, match="checksum"):
        LearnedRanker.load(path, expected_sha256=checksum)


def test_lexical_artifact_requires_explicit_pin(tmp_path):
    path, _ = _artifact(tmp_path)

    with pytest.raises(ValueError):
        LearnedRanker.load(path, expected_sha256="")


def test_untrusted_ids_and_values_are_not_features():
    first = {"name": "customer", "id": "truth", "values": ["secret"]}
    second = {"name": "customer", "id": "different"}

    assert field_text(first) == field_text(second)


def test_lexical_output_never_authorizes():
    result = LearnedRanker.baseline().rank_fields(
        {"name": "customer"}, [{"id": "a", "name": "customer"}]
    )

    assert result[0]["authority"] == "advisory_only"
    assert "status" not in result[0]


def test_lexical_weights_are_frozen():
    weights = baseline_weights()
    ranker = LearnedRanker(weights)
    weights[0] = 555

    assert ranker.weights[0] != 555


def test_lexical_candidate_limit():
    with pytest.raises(ValueError):
        LearnedRanker.baseline().scores("query", ["candidate"] * 129)


def test_linked_lexical_artifact_is_rejected(tmp_path):
    path, checksum = _artifact(tmp_path)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(ValueError):
        LearnedRanker.load(link, expected_sha256=checksum)
