from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from polymorph.matching.learned import AdvisoryRanker, features


def _save(path: Path, payload: object) -> str:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_advisor_model_roundtrip_is_hash_bound(tmp_path: Path) -> None:
    path = tmp_path / "ranker.json"
    original = AdvisoryRanker()
    sha = _save(path, original.as_dict())
    loaded = AdvisoryRanker.load(path, expected_sha256=sha)
    assert loaded.as_dict() == original.as_dict()
    with pytest.raises(ValueError):
        AdvisoryRanker.load(path, expected_sha256="0" * 64)


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), 1001.0])
def test_nonfinite_boolean_or_unbounded_weights_are_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        AdvisoryRanker({"exact": value})  # type: ignore[dict-item]


def test_model_document_cannot_change_authority(tmp_path: Path) -> None:
    path = tmp_path / "ranker.json"
    doc = AdvisoryRanker().as_dict()
    doc["authority"] = "automatic"
    sha = _save(path, doc)
    with pytest.raises(ValueError):
        AdvisoryRanker.load(path, expected_sha256=sha)
    doc = AdvisoryRanker().as_dict()
    doc["minimum_margin"] = 0
    sha = _save(path, doc)
    with pytest.raises(ValueError):
        AdvisoryRanker.load(path, expected_sha256=sha)


def test_normalized_feature_identity_and_bounded_scores() -> None:
    assert features("name: CUSTOMER NUMBER", "name: customer number") == features(
        "name: customer number", "name: CUSTOMER NUMBER"
    )
    scores = AdvisoryRanker().scores("name: customer number", ["name: invoice date", "name: customer number"])
    assert 0 <= scores[0] < scores[1] <= 1


@pytest.mark.parametrize("text", ["bad\x00text", "x" * 4097])
def test_descriptor_input_is_bounded(text: str) -> None:
    with pytest.raises(ValueError):
        AdvisoryRanker().scores(text, ["target"])


def test_candidate_limit_and_immutable_weights() -> None:
    advisor = AdvisoryRanker()
    with pytest.raises(ValueError):
        advisor.scores("source", ["target"] * 257)
    with pytest.raises(TypeError):
        advisor.weights["exact"] = 0  # type: ignore[index]


@pytest.mark.parametrize("case", ["unknown_type", "nullable", "sensitivity"])
def test_full_matcher_keeps_automatic_contract_boundary(case: str) -> None:
    from polymorph.matching.hybrid import HybridMatcher
    from polymorph.models.mapping import MappingStatus
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType, Sensitivity

    source = FieldDescriptor(
        "source",
        "customer number",
        DataType.UNKNOWN if case == "unknown_type" else DataType.STRING,
        nullable=case == "nullable",
        sensitivity=Sensitivity.SECRET if case == "sensitivity" else Sensitivity.INTERNAL,
    )
    target = FieldDescriptor("target", "customer number", DataType.STRING, nullable=False)
    model = HybridMatcher(reranker=AdvisoryRanker({"exact": 999.0, "length": 999.0}))
    decision = model.decide(source, SchemaDescriptor("target", (target,)))
    assert decision.status is not MappingStatus.AUTO
