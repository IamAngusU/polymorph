from __future__ import annotations

import json

import pytest

from polymorph.errors import IntegrityError
from polymorph.matching.semantic import ModelArtifact, ModelProfile, verify_installed_profile


def test_model_profile_detects_local_asset_tampering(tmp_path, monkeypatch) -> None:
    profile = ModelProfile(
        name="test",
        repo_id="owner/model",
        revision="abc123",
        artifacts={"x86_64": ModelArtifact("onnx/model.onnx", ""), "fallback": ModelArtifact("onnx/model.onnx", "")},
        tokenizer_files=("tokenizer.json",),
    )
    monkeypatch.setattr("polymorph.matching.semantic._platform_key", lambda: "x86_64")
    model = tmp_path / "onnx/model.onnx"
    model.parent.mkdir()
    model.write_bytes(b"model")
    tokenizer = tmp_path / "tokenizer.json"
    tokenizer.write_text("{}", encoding="utf-8")

    import hashlib
    model_hash = hashlib.sha256(b"model").hexdigest()
    token_hash = hashlib.sha256(b"{}").hexdigest()
    profile = ModelProfile(
        name="test",
        repo_id="owner/model",
        revision="abc123",
        artifacts={"x86_64": ModelArtifact("onnx/model.onnx", model_hash), "fallback": ModelArtifact("onnx/model.onnx", model_hash)},
        tokenizer_files=("tokenizer.json",),
    )
    (tmp_path / "polymorph-model-manifest.json").write_text(
        json.dumps({
            "profile": "test",
            "repo_id": "owner/model",
            "revision": "abc123",
            "platform": "x86_64",
            "files": {"onnx/model.onnx": model_hash, "tokenizer.json": token_hash},
        }),
        encoding="utf-8",
    )
    assert verify_installed_profile(profile, tmp_path) == model
    tokenizer.write_text('{"changed": true}', encoding="utf-8")
    with pytest.raises(IntegrityError, match="tokenizer.json"):
        verify_installed_profile(profile, tmp_path)
