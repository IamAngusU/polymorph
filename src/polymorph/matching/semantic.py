from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from polymorph.errors import IntegrityError, PolymorphError


@dataclass(frozen=True, slots=True)
class ModelArtifact:
    filename: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ModelProfile:
    name: str
    repo_id: str
    revision: str
    artifacts: dict[str, ModelArtifact]
    tokenizer_files: tuple[str, ...]


MULTILINGUAL_CPU = ModelProfile(
    name="multilingual-cpu",
    repo_id="sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    revision="e8f8c211226b894fcb81acc59f3b34ba3efd5f42",
    artifacts={
        "x86_64": ModelArtifact(
            "onnx/model_quint8_avx2.onnx",
            "98a01d88b7de996cdea58c32ca71208c09968d143798814b2ea09d3439dc334f",
        ),
        "arm64": ModelArtifact(
            "onnx/model_qint8_arm64.onnx",
            "783fea82d71a58179b830a4dbd2d58447e640609e98eedf9ffa12622d375a672",
        ),
        "fallback": ModelArtifact(
            "onnx/model.onnx",
            "10f7a088420252b26caf819236ca2c9d2987afd0fc06fec7553b542a5655a05a",
        ),
    },
    tokenizer_files=(
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "config.json",
    ),
)

RERANKER_MULTILINGUAL_CPU = ModelProfile(
    name="reranker-multilingual-cpu",
    repo_id="cross-encoder/mmarco-mMiniLMv2-L12-H384-v1",
    revision="1427fd652930e4ba29e8149678df786c240d8825",
    artifacts={
        "x86_64": ModelArtifact(
            "onnx/model_quint8_avx2.onnx",
            "6c2513767fb63d008a4377bef7a7a3555433d9436342bb53e35a3a72ffc52d4b",
        ),
        "arm64": ModelArtifact(
            "onnx/model_qint8_arm64.onnx",
            "1825907d6c1a9001ff78124780bbde20a614a8c3df3b63409cf3c72c6fe5c8b4",
        ),
    },
    tokenizer_files=(
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "config.json",
    ),
)



def _platform_key() -> str:
    machine = platform.machine().lower()
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    return "fallback"


def _artifact_for_profile(profile: ModelProfile) -> ModelArtifact:
    key = _platform_key()
    artifact = profile.artifacts.get(key) or profile.artifacts.get("fallback")
    if artifact is None:
        raise PolymorphError(
            f"model profile {profile.name!r} has no artifact for platform {platform.machine()!r}"
        )
    return artifact


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


_MANIFEST_NAME = "polymorph-model-manifest.json"


def _required_files(profile: ModelProfile, artifact: ModelArtifact) -> tuple[str, ...]:
    return (artifact.filename, *profile.tokenizer_files)


def _write_manifest(
    profile: ModelProfile,
    destination: Path,
    artifact: ModelArtifact,
) -> None:
    files: dict[str, str] = {}
    for relative in _required_files(profile, artifact):
        path = destination / relative
        if not path.is_file():
            raise IntegrityError(f"semantic model asset is missing: {relative}")
        files[relative] = _sha256(path)
    payload = {
        "profile": profile.name,
        "repo_id": profile.repo_id,
        "revision": profile.revision,
        "platform": _platform_key(),
        "files": files,
    }
    (destination / _MANIFEST_NAME).write_text(
        json.dumps(payload, sort_keys=True, indent=2),
        encoding="utf-8",
    )


def verify_installed_profile(profile: ModelProfile, destination: Path) -> Path:
    artifact = _artifact_for_profile(profile)
    manifest_path = destination / _MANIFEST_NAME
    if not manifest_path.is_file():
        raise IntegrityError("semantic model manifest is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError("semantic model manifest is invalid") from exc
    if (
        manifest.get("profile") != profile.name
        or manifest.get("repo_id") != profile.repo_id
        or manifest.get("revision") != profile.revision
    ):
        raise IntegrityError("semantic model manifest does not match the configured profile")
    hashes = manifest.get("files")
    if not isinstance(hashes, dict):
        raise IntegrityError("semantic model manifest does not contain file hashes")
    for relative in _required_files(profile, artifact):
        expected = hashes.get(relative)
        path = destination / relative
        if not isinstance(expected, str) or not path.is_file() or _sha256(path) != expected:
            raise IntegrityError(f"semantic model asset integrity check failed: {relative}")
    if _sha256(destination / artifact.filename) != artifact.sha256:
        raise IntegrityError("semantic model checksum mismatch")
    return destination / artifact.filename


def install_profile(profile: ModelProfile, destination: Path) -> Path:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise PolymorphError("semantic extras are required to install a model profile") from exc

    artifact = _artifact_for_profile(profile)
    destination.mkdir(parents=True, exist_ok=True)
    allow = list(_required_files(profile, artifact))
    snapshot_path = Path(
        snapshot_download(
            repo_id=profile.repo_id,
            revision=profile.revision,
            allow_patterns=allow,
            local_dir=destination,
        )
    )
    model_path = snapshot_path / artifact.filename
    actual = _sha256(model_path)
    if actual != artifact.sha256:
        model_path.unlink(missing_ok=True)
        raise IntegrityError("semantic model checksum mismatch")
    _write_manifest(profile, snapshot_path, artifact)
    return verify_installed_profile(profile, snapshot_path)


def load_profile_encoder(profile: ModelProfile, destination: Path) -> "OnnxSentenceEncoder":
    model_path = verify_installed_profile(profile, destination)
    tokenizer_path = destination / "tokenizer.json"
    return OnnxSentenceEncoder(model_path, tokenizer_path)


def load_profile_reranker(
    profile: ModelProfile, destination: Path
) -> "OnnxCrossEncoderReranker":
    model_path = verify_installed_profile(profile, destination)
    tokenizer_path = destination / "tokenizer.json"
    return OnnxCrossEncoderReranker(model_path, tokenizer_path)


class OnnxSentenceEncoder:
    """Local descriptor encoder.

    The interface accepts descriptor strings only. It deliberately has no API for records,
    connector credentials or opaque payloads.
    """

    def __init__(self, model_path: Path, tokenizer_path: Path, max_length: int = 128) -> None:
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise PolymorphError("semantic extras are required to load the ONNX encoder") from exc

        self._np = np
        self._session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._tokenizer.enable_truncation(max_length=max_length)
        self._tokenizer.enable_padding()
        self._inputs = {item.name for item in self._session.get_inputs()}

    def _encode_batch(self, texts: Sequence[str]):
        np = self._np
        encoded = self._tokenizer.encode_batch(list(texts))
        input_ids = np.asarray([item.ids for item in encoded], dtype=np.int64)
        attention_mask = np.asarray([item.attention_mask for item in encoded], dtype=np.int64)
        inputs = {"input_ids": input_ids, "attention_mask": attention_mask}
        if "token_type_ids" in self._inputs:
            inputs["token_type_ids"] = np.zeros_like(input_ids)

        output = self._session.run(None, {k: v for k, v in inputs.items() if k in self._inputs})[0]
        mask = attention_mask[..., None].astype(output.dtype)
        summed = (output * mask).sum(axis=1)
        counts = np.clip(mask.sum(axis=1), 1e-9, None)
        pooled = summed / counts
        norms = np.linalg.norm(pooled, axis=1, keepdims=True)
        return pooled / np.clip(norms, 1e-12, None)

    def similarities(self, query: str, candidates: Sequence[str]) -> list[float]:
        if not candidates:
            return []
        vectors = self._encode_batch([query, *candidates])
        query_vector = vectors[0]
        return [float(self._np.dot(query_vector, vector)) for vector in vectors[1:]]

    def similarity(self, left: str, right: str) -> float:
        return self.similarities(left, [right])[0]


class OnnxCrossEncoderReranker:
    """CPU-only descriptor-pair reranker used only for ambiguous top-k candidates."""

    def __init__(self, model_path: Path, tokenizer_path: Path, max_length: int = 192) -> None:
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise PolymorphError("semantic extras are required to load the ONNX reranker") from exc

        self._np = np
        self._session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._tokenizer.enable_truncation(max_length=max_length)
        self._tokenizer.enable_padding()
        self._inputs = {item.name for item in self._session.get_inputs()}

    def scores(self, query: str, candidates: Sequence[str]) -> list[float]:
        if not candidates:
            return []
        np = self._np
        encoded = self._tokenizer.encode_batch([(query, candidate) for candidate in candidates])
        input_ids = np.asarray([item.ids for item in encoded], dtype=np.int64)
        attention_mask = np.asarray([item.attention_mask for item in encoded], dtype=np.int64)
        inputs = {"input_ids": input_ids, "attention_mask": attention_mask}
        if "token_type_ids" in self._inputs:
            inputs["token_type_ids"] = np.asarray(
                [item.type_ids for item in encoded], dtype=np.int64
            )
        raw = self._session.run(
            None, {key: value for key, value in inputs.items() if key in self._inputs}
        )[0]
        logits = np.asarray(raw, dtype=np.float64).reshape(len(candidates), -1)[:, 0]
        # A sigmoid gives a bounded evidence score. It is not treated as calibrated
        # probability anywhere in the policy layer.
        logits = np.clip(logits, -40.0, 40.0)
        bounded = 1.0 / (1.0 + np.exp(-logits))
        return [float(value) for value in bounded]
