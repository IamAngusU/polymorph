from __future__ import annotations

import hashlib
import json

import pytest

from polymorph.errors import IntegrityError
from polymorph.matching import semantic
from polymorph.matching.semantic import (
    ModelArtifact,
    ModelProfile,
    _claim_install_destination,
    _convert_sentencepiece_ids,
    _pad_token_sequences,
    _truncate_pair,
    load_profile_encoder,
    verify_installed_profile,
)


def test_model_profile_detects_local_asset_tampering(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("polymorph.matching.semantic._platform_key", lambda: "x86_64")
    model = tmp_path / "onnx/model.onnx"
    model.parent.mkdir()
    model.write_bytes(b"model")
    tokenizer = tmp_path / "tokenizer.json"
    tokenizer.write_text("{}", encoding="utf-8")

    model_hash = hashlib.sha256(b"model").hexdigest()
    token_hash = hashlib.sha256(b"{}").hexdigest()
    profile = ModelProfile(
        name="test",
        repo_id="owner/model",
        revision="abc123",
        artifacts={
            "x86_64": ModelArtifact("onnx/model.onnx", model_hash),
            "fallback": ModelArtifact("onnx/model.onnx", model_hash),
        },
        tokenizer_files=("tokenizer.json",),
        asset_sha256={"tokenizer.json": token_hash},
    )
    (tmp_path / "polymorph-model-manifest.json").write_text(
        json.dumps(
            {
                "profile": "test",
                "repo_id": "owner/model",
                "revision": "abc123",
                "platform": "x86_64",
                "files": {"onnx/model.onnx": model_hash, "tokenizer.json": token_hash},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "polymorph-model-owner.json").write_text(
        json.dumps(
            {
                "profile": "test",
                "repo_id": "owner/model",
                "revision": "abc123",
            }
        ),
        encoding="utf-8",
    )
    assert verify_installed_profile(profile, tmp_path) == model
    tokenizer.write_text('{"changed": true}', encoding="utf-8")
    with pytest.raises(IntegrityError, match="tokenizer.json"):
        verify_installed_profile(profile, tmp_path)

    manifest_path = tmp_path / "polymorph-model-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["tokenizer.json"] = hashlib.sha256(tokenizer.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(IntegrityError, match="pinned checksum.*tokenizer.json"):
        verify_installed_profile(profile, tmp_path)


def _profile() -> ModelProfile:
    digest = hashlib.sha256(b"model").hexdigest()
    return ModelProfile(
        name="test",
        repo_id="owner/model",
        revision="abc123",
        artifacts={"x86_64": ModelArtifact("model.onnx", digest)},
        tokenizer_files=("tokenizer.model",),
        asset_sha256={"tokenizer.model": digest},
    )


def test_model_install_destination_refuses_unowned_content(tmp_path) -> None:
    destination = tmp_path / "models"
    destination.mkdir()
    (destination / "config.json").write_text("do not replace", encoding="utf-8")

    with pytest.raises(IntegrityError, match="non-empty"):
        _claim_install_destination(_profile(), destination)

    assert (destination / "config.json").read_text(encoding="utf-8") == "do not replace"


def test_model_install_destination_is_owned_by_one_exact_profile(tmp_path) -> None:
    destination = tmp_path / "models"
    profile = _profile()
    _claim_install_destination(profile, destination)

    other = ModelProfile(
        name="other",
        repo_id=profile.repo_id,
        revision=profile.revision,
        artifacts=profile.artifacts,
        tokenizer_files=profile.tokenizer_files,
        asset_sha256=profile.asset_sha256,
    )
    with pytest.raises(IntegrityError, match="another profile"):
        _claim_install_destination(other, destination)


def test_model_ownership_metadata_rejects_duplicate_keys(tmp_path) -> None:
    destination = tmp_path / "models"
    profile = _profile()
    _claim_install_destination(profile, destination)
    (destination / "polymorph-model-owner.json").write_text(
        '{"profile":"test","profile":"test","repo_id":"owner/model","revision":"abc123"}',
        encoding="utf-8",
    )

    with pytest.raises(IntegrityError, match="ownership marker is invalid"):
        _claim_install_destination(profile, destination)


def test_xlmr_sentencepiece_id_conversion_truncation_and_padding() -> None:
    assert _convert_sentencepiece_ids([0, 3, 7]) == [3, 4, 8]
    left = [10, 11, 12, 13]
    right = [20, 21, 22, 23]
    _truncate_pair(left, right, 5)
    assert left == [10, 11, 12]
    assert right == [20, 21]
    ids, masks = _pad_token_sequences([[0, 8, 2], [0, 2]])
    assert ids == [[0, 8, 2], [0, 2, 1]]
    assert masks == [[1, 1, 1], [1, 1, 0]]


def test_profile_encoder_verifies_now_and_allocates_only_on_first_use(
    tmp_path, monkeypatch
) -> None:
    profile = _profile()
    model_path = tmp_path / "model.onnx"
    constructions: list[tuple[object, ...]] = []

    class FakeEncoder:
        def __init__(self, *args: object) -> None:
            constructions.append(args)

        def similarities(self, query: str, candidates) -> list[float]:
            return [0.5 for _ in candidates]

        def similarity(self, left: str, right: str) -> float:
            return 0.5

    monkeypatch.setattr(semantic, "verify_installed_profile", lambda *_: model_path)
    monkeypatch.setattr(semantic, "OnnxSentenceEncoder", FakeEncoder)

    encoder = load_profile_encoder(profile, tmp_path)
    assert constructions == []
    assert encoder.similarities("source", ["target"]) == [0.5]
    assert len(constructions) == 1
