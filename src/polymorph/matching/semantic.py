from __future__ import annotations

import hashlib
import json
import platform
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from polymorph.errors import IntegrityError, PolymorphError
from polymorph.filesystem import atomic_write_text, exclusive_path_lock


@dataclass(frozen=True, slots=True)
class ModelArtifact:
    filename: str
    sha256: str

    def __post_init__(self) -> None:
        _validate_asset_path(self.filename)
        _validate_sha256(self.sha256)


@dataclass(frozen=True, slots=True)
class ModelProfile:
    name: str
    repo_id: str
    revision: str
    artifacts: dict[str, ModelArtifact]
    tokenizer_files: tuple[str, ...]
    asset_sha256: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.repo_id or not self.revision:
            raise ValueError("model profile identity must be non-empty")
        if not self.artifacts:
            raise ValueError("model profile requires at least one architecture artifact")
        missing = set(self.tokenizer_files) - set(self.asset_sha256)
        if missing:
            raise ValueError(f"model profile has unpinned runtime assets: {sorted(missing)!r}")
        for relative in self.tokenizer_files:
            _validate_asset_path(relative)
            _validate_sha256(self.asset_sha256[relative])


def _validate_asset_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("model asset path must be a safe relative POSIX path")


def _validate_sha256(value: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("model asset SHA-256 must be a lowercase hexadecimal digest")


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
        "sentencepiece.bpe.model",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "config.json",
    ),
    asset_sha256={
        "config.json": "6300193cb75e01cf80c96decef7187dfb33094d97cc1490b7ead6ff134476e4e",
        "special_tokens_map.json": (
            "378eb3bf733eb16e65792d7e3fda5b8a4631387ca04d2015199c4d4f22ae554d"
        ),
        "sentencepiece.bpe.model": (
            "cfc8146abe2a0488e9e2a0c56de7952f7c11ab059eca145a0a727afce0db2865"
        ),
        "tokenizer_config.json": (
            "5036ea374ffedd706e3bef33e2e0d6953cb868ef8a490e76e32ba0faa37a6b9b"
        ),
    },
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
        "sentencepiece.bpe.model",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "config.json",
    ),
    asset_sha256={
        "config.json": "cc2cfe51aa3fd759d21d21acf5dfd6994aa67a3c9210636d22e143699d336c77",
        "special_tokens_map.json": (
            "378eb3bf733eb16e65792d7e3fda5b8a4631387ca04d2015199c4d4f22ae554d"
        ),
        "sentencepiece.bpe.model": (
            "cfc8146abe2a0488e9e2a0c56de7952f7c11ab059eca145a0a727afce0db2865"
        ),
        "tokenizer_config.json": (
            "e7fbfbfa6347b4e414c1cee50d142e2c2f9a895dad68b068ae83a8b564c3837e"
        ),
    },
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
_OWNER_NAME = "polymorph-model-owner.json"
_TOKENIZER_NAME = "sentencepiece.bpe.model"
_METADATA_SIZE_LIMIT = 64 * 1024


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
        actual = _sha256(path)
        pinned = (
            artifact.sha256 if relative == artifact.filename else profile.asset_sha256.get(relative)
        )
        if pinned is None or actual != pinned:
            raise IntegrityError(f"semantic model asset checksum mismatch: {relative}")
        files[relative] = actual
    payload = {
        "profile": profile.name,
        "repo_id": profile.repo_id,
        "revision": profile.revision,
        "platform": _platform_key(),
        "files": files,
    }
    atomic_write_text(
        destination / _MANIFEST_NAME,
        json.dumps(payload, sort_keys=True, indent=2),
    )


def _profile_identity(profile: ModelProfile) -> dict[str, str]:
    return {
        "profile": profile.name,
        "repo_id": profile.repo_id,
        "revision": profile.revision,
    }


def _read_identity(path: Path, *, label: str) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> object:
        raise ValueError(f"non-finite number {value!r}")

    try:
        if path.stat().st_size > _METADATA_SIZE_LIMIT:
            raise IntegrityError(f"semantic model {label} exceeds the size limit")
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise IntegrityError(f"semantic model {label} is invalid") from exc
    if not isinstance(payload, dict):
        raise IntegrityError(f"semantic model {label} is invalid")
    return payload


def _identity_matches(profile: ModelProfile, payload: dict[str, object]) -> bool:
    return all(payload.get(key) == value for key, value in _profile_identity(profile).items())


def _verify_owner(profile: ModelProfile, destination: Path) -> None:
    owner_path = destination / _OWNER_NAME
    if not owner_path.is_file():
        raise IntegrityError("semantic model ownership marker is missing")
    if not _identity_matches(profile, _read_identity(owner_path, label="ownership marker")):
        raise IntegrityError("semantic model ownership marker belongs to another profile")


def _claim_install_destination(profile: ModelProfile, destination: Path) -> None:
    if destination.is_symlink():
        raise IntegrityError("semantic model destination must not be a symbolic link")
    destination.mkdir(parents=True, exist_ok=True)
    owner_path = destination / _OWNER_NAME
    if owner_path.exists():
        _verify_owner(profile, destination)
        return

    entries = list(destination.iterdir())
    if entries:
        # Profiles installed before the ownership marker existed can be migrated only when
        # their existing manifest identifies this exact pinned profile.
        manifest_path = destination / _MANIFEST_NAME
        if not manifest_path.is_file() or not _identity_matches(
            profile,
            _read_identity(manifest_path, label="manifest"),
        ):
            raise IntegrityError(
                "semantic model destination is non-empty and is not owned by this profile"
            )
    atomic_write_text(
        owner_path,
        json.dumps(_profile_identity(profile), sort_keys=True, indent=2),
        overwrite=False,
        private=True,
    )


def verify_installed_profile(profile: ModelProfile, destination: Path) -> Path:
    _verify_owner(profile, destination)
    artifact = _artifact_for_profile(profile)
    manifest_path = destination / _MANIFEST_NAME
    if not manifest_path.is_file():
        raise IntegrityError("semantic model manifest is missing")
    manifest = _read_identity(manifest_path, label="manifest")
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
        pinned = (
            artifact.sha256 if relative == artifact.filename else profile.asset_sha256.get(relative)
        )
        if pinned is None or expected != pinned:
            raise IntegrityError(f"semantic model pinned checksum mismatch: {relative}")
    return destination / artifact.filename


def install_profile(profile: ModelProfile, destination: Path) -> Path:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise PolymorphError("semantic extras are required to install a model profile") from exc

    destination = destination.expanduser().resolve(strict=False)
    artifact = _artifact_for_profile(profile)
    with exclusive_path_lock(destination, timeout_seconds=30.0):
        _claim_install_destination(profile, destination)
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


def load_profile_encoder(profile: ModelProfile, destination: Path) -> LazyOnnxSentenceEncoder:
    verify_installed_profile(profile, destination)
    return LazyOnnxSentenceEncoder(profile, destination)


def load_profile_reranker(profile: ModelProfile, destination: Path) -> LazyOnnxCrossEncoderReranker:
    verify_installed_profile(profile, destination)
    return LazyOnnxCrossEncoderReranker(profile, destination)


def _convert_sentencepiece_ids(piece_ids: Sequence[int]) -> list[int]:
    # XLM-R reserves Fairseq ids 0..3. SentencePiece id 0 is unknown and normal pieces
    # start at 3, so normal pieces are shifted by one.
    return [3 if piece_id == 0 else piece_id + 1 for piece_id in piece_ids]


def _truncate_pair(left: list[int], right: list[int], token_budget: int) -> None:
    while len(left) + len(right) > token_budget:
        if len(left) > len(right):
            left.pop()
        else:
            right.pop()


def _pad_token_sequences(sequences: Sequence[list[int]]) -> tuple[list[list[int]], list[list[int]]]:
    if not sequences:
        return [], []
    width = max(len(sequence) for sequence in sequences)
    input_ids: list[list[int]] = []
    attention_masks: list[list[int]] = []
    for sequence in sequences:
        padding = width - len(sequence)
        input_ids.append([*sequence, *([1] * padding)])
        attention_masks.append([*([1] * len(sequence)), *([0] * padding)])
    return input_ids, attention_masks


class _SentencePieceTokenizer:
    """Small XLM-R tokenizer adapter without the 250k-token JSON expansion."""

    def __init__(self, path: Path) -> None:
        try:
            import sentencepiece as sentencepiece
        except ImportError as exc:
            raise PolymorphError("semantic extras are required to load the tokenizer") from exc
        try:
            processor = sentencepiece.SentencePieceProcessor(model_file=str(path))
        except (OSError, RuntimeError) as exc:
            raise IntegrityError("semantic tokenizer asset could not be loaded") from exc
        if (
            processor.unk_id() != 0
            or processor.bos_id() != 1
            or processor.eos_id() != 2
            or processor.vocab_size() != 250_000
        ):
            raise IntegrityError("semantic tokenizer is not the expected XLM-R vocabulary")
        self._processor = processor

    def _pieces(self, text: str) -> list[int]:
        encoded = self._processor.encode(text, out_type=int)
        if not isinstance(encoded, list) or not all(isinstance(item, int) for item in encoded):
            raise IntegrityError("semantic tokenizer returned an invalid token sequence")
        return _convert_sentencepiece_ids(encoded)

    def encode_texts(
        self,
        texts: Sequence[str],
        *,
        max_length: int,
    ) -> tuple[list[list[int]], list[list[int]]]:
        if max_length < 2:
            raise ValueError("encoder maximum length must be at least 2")
        sequences = [[0, *self._pieces(text)[: max_length - 2], 2] for text in texts]
        return _pad_token_sequences(sequences)

    def encode_pairs(
        self,
        pairs: Sequence[tuple[str, str]],
        *,
        max_length: int,
    ) -> tuple[list[list[int]], list[list[int]]]:
        if max_length < 4:
            raise ValueError("reranker maximum length must be at least 4")
        sequences: list[list[int]] = []
        for left_text, right_text in pairs:
            left = self._pieces(left_text)
            right = self._pieces(right_text)
            _truncate_pair(left, right, max_length - 4)
            sequences.append([0, *left, 2, 2, *right, 2])
        return _pad_token_sequences(sequences)


class OnnxSentenceEncoder:
    """Local descriptor encoder.

    The interface accepts descriptor strings only. It deliberately has no API for records,
    connector credentials or opaque payloads.
    """

    def __init__(self, model_path: Path, tokenizer_path: Path, max_length: int = 128) -> None:
        if max_length < 2:
            raise ValueError("encoder max_length must be at least 2")
        try:
            import numpy as np
            import onnxruntime as ort
        except ImportError as exc:
            raise PolymorphError("semantic extras are required to load the ONNX encoder") from exc

        self._np = np
        options = ort.SessionOptions()
        # This saves roughly 18 MiB of steady RSS on the reference Windows CPU for a small
        # latency tradeoff. Other optimizer and prepacking defaults are behavior-sensitive.
        options.enable_cpu_mem_arena = False
        self._session = ort.InferenceSession(
            str(model_path),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
        self._tokenizer = _SentencePieceTokenizer(tokenizer_path)
        self._max_length = max_length
        self._inputs = {item.name for item in self._session.get_inputs()}

    def _encode_batch(self, texts: Sequence[str]) -> Any:
        np = self._np
        ids, masks = self._tokenizer.encode_texts(texts, max_length=self._max_length)
        input_ids = np.asarray(ids, dtype=np.int64)
        attention_mask = np.asarray(masks, dtype=np.int64)
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
        if max_length < 4:
            raise ValueError("reranker max_length must be at least 4")
        try:
            import numpy as np
            import onnxruntime as ort
        except ImportError as exc:
            raise PolymorphError("semantic extras are required to load the ONNX reranker") from exc

        self._np = np
        self._session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        self._tokenizer = _SentencePieceTokenizer(tokenizer_path)
        self._max_length = max_length
        self._inputs = {item.name for item in self._session.get_inputs()}

    def scores(self, query: str, candidates: Sequence[str]) -> list[float]:
        if not candidates:
            return []
        np = self._np
        ids, masks = self._tokenizer.encode_pairs(
            [(query, candidate) for candidate in candidates],
            max_length=self._max_length,
        )
        input_ids = np.asarray(ids, dtype=np.int64)
        attention_mask = np.asarray(masks, dtype=np.int64)
        inputs = {"input_ids": input_ids, "attention_mask": attention_mask}
        if "token_type_ids" in self._inputs:
            inputs["token_type_ids"] = np.zeros_like(input_ids)
        raw = self._session.run(
            None, {key: value for key, value in inputs.items() if key in self._inputs}
        )[0]
        logits = np.asarray(raw, dtype=np.float64).reshape(len(candidates), -1)[:, 0]
        # A sigmoid gives a bounded evidence score. It is not treated as calibrated
        # probability anywhere in the policy layer.
        logits = np.clip(logits, -40.0, 40.0)
        bounded = 1.0 / (1.0 + np.exp(-logits))
        return [float(value) for value in bounded]


class LazyOnnxSentenceEncoder:
    """Verify now, allocate the encoder only when ambiguous evidence needs it."""

    def __init__(self, profile: ModelProfile, destination: Path) -> None:
        self._profile = profile
        self._destination = destination.expanduser().resolve(strict=False)
        self._delegate: OnnxSentenceEncoder | None = None
        self._lock = threading.Lock()

    def _loaded(self) -> OnnxSentenceEncoder:
        if self._delegate is not None:
            return self._delegate
        with self._lock:
            if self._delegate is None:
                model_path = verify_installed_profile(self._profile, self._destination)
                self._delegate = OnnxSentenceEncoder(
                    model_path,
                    self._destination / _TOKENIZER_NAME,
                )
            return self._delegate

    def similarities(self, query: str, candidates: Sequence[str]) -> list[float]:
        if not candidates:
            return []
        return self._loaded().similarities(query, candidates)

    def similarity(self, left: str, right: str) -> float:
        return self._loaded().similarity(left, right)


class LazyOnnxCrossEncoderReranker:
    """Verify now, allocate the reranker only for a genuinely ambiguous top-k."""

    def __init__(self, profile: ModelProfile, destination: Path) -> None:
        self._profile = profile
        self._destination = destination.expanduser().resolve(strict=False)
        self._delegate: OnnxCrossEncoderReranker | None = None
        self._lock = threading.Lock()

    def _loaded(self) -> OnnxCrossEncoderReranker:
        if self._delegate is not None:
            return self._delegate
        with self._lock:
            if self._delegate is None:
                model_path = verify_installed_profile(self._profile, self._destination)
                self._delegate = OnnxCrossEncoderReranker(
                    model_path,
                    self._destination / _TOKENIZER_NAME,
                )
            return self._delegate

    def scores(self, query: str, candidates: Sequence[str]) -> list[float]:
        if not candidates:
            return []
        return self._loaded().scores(query, candidates)
