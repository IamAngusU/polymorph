"""Opt-in, data-only lexical ranker. Its scores never authorize a write."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

FORMAT = "angusu.bridge.lexical-ranker/1"
FEATURE_VERSION = "token-cross/1"
DIMENSIONS = 16384
MAX_BYTES = 2 * 1024 * 1024
MAX_TEXT = 1024
MAX_CANDIDATES = 128


def _index(text: str) -> int:
    raw = hashlib.blake2s(text.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(raw, "big") % DIMENSIONS


def normalize(text: str) -> str:
    if not isinstance(text, str) or len(text) > MAX_TEXT or "\x00" in text:
        raise ValueError("ranker text exceeds its contract")
    text = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text)
    return " ".join(re.findall(r"\w+", unicodedata.normalize("NFKC", text).casefold()))


def field_text(field: Mapping[str, Any]) -> str:
    """Use declared descriptors only, never cell values, field IDs, or labels."""
    name = field.get("name")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ValueError("ranker requires a bounded field name")
    aliases = field.get("aliases", [])
    if not isinstance(aliases, (list, tuple)) or len(aliases) > 16:
        raise ValueError("ranker aliases exceed their contract")
    if any(not isinstance(value, str) or len(value) > 128 for value in aliases):
        raise ValueError("ranker alias is invalid")
    description = field.get("description") or ""
    if not isinstance(description, str) or len(description) > 512:
        raise ValueError("ranker description is invalid")
    text = " | ".join([name, *aliases, description])
    if len(text) > MAX_TEXT:
        raise ValueError("ranker descriptor exceeds its contract")
    normalize(text)
    return text


def features(query: str, candidate: str) -> dict[int, float]:
    q, c = normalize(query), normalize(candidate)
    query_tokens = sorted(set(q.split()))[:24]
    candidate_tokens = sorted(set(c.split()))[:24]
    output: dict[int, float] = {}

    def add(name: str, value: float = 1.0) -> None:
        index = _index(name)
        output[index] = output.get(index, 0.0) + value

    add("bias")
    add("exact", float(bool(q) and q == c))
    add("edit", SequenceMatcher(None, q, c, autojunk=False).ratio())
    union = set(query_tokens) | set(candidate_tokens)
    add("overlap", len(set(query_tokens) & set(candidate_tokens)) / max(1, len(union)))
    add("length", min(len(q), len(c)) / max(1, len(q), len(c)))
    for left in query_tokens:
        for right in candidate_tokens:
            add(
                "pair:" + left + "\x1f" + right,
                1 / math.sqrt(max(1, len(query_tokens) * len(candidate_tokens))),
            )
    for size in (2, 3):
        query_parts = {q[index : index + size] for index in range(max(0, len(q) - size + 1))}
        candidate_parts = {c[index : index + size] for index in range(max(0, len(c) - size + 1))}
        add(
            "char" + str(size),
            len(query_parts & candidate_parts) / max(1, len(query_parts | candidate_parts)),
        )
    return output


def baseline_weights() -> list[float]:
    weights = [0.0] * DIMENSIONS
    for name, weight in (
        ("bias", -2.0),
        ("exact", 2.0),
        ("edit", 1.0),
        ("overlap", 1.0),
        ("char2", 0.5),
        ("char3", 0.5),
    ):
        weights[_index(name)] += weight
    return weights


def dot(weights: Sequence[float], vector: Mapping[int, float]) -> float:
    return sum(weights[index] * value for index, value in vector.items())


def sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-50.0, min(50.0, value))))


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in items:
        if key in output:
            raise ValueError("duplicate ranker artifact key")
        output[key] = value
    return output


def _reject_constant(_: str) -> Any:
    raise ValueError("nonfinite ranker value")


@dataclass(frozen=True, slots=True)
class LearnedRanker:
    weights: tuple[float, ...]
    artifact_sha256: str = "baseline"

    def __post_init__(self) -> None:
        object.__setattr__(self, "weights", tuple(self.weights))
        if len(self.weights) != DIMENSIONS or any(
            type(value) not in (int, float) or not math.isfinite(value) or abs(value) > 1e4
            for value in self.weights
        ):
            raise ValueError("invalid ranker weights")

    @classmethod
    def baseline(cls) -> LearnedRanker:
        return cls(tuple(baseline_weights()))

    @classmethod
    def load(cls, path: str | Path, *, expected_sha256: str) -> LearnedRanker:
        if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
            raise ValueError("an explicitly trusted SHA-256 is required")
        path = Path(path).absolute()
        for component in (path, *path.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("linked ranker artifacts are not accepted")
        if not path.is_file():
            raise ValueError("ranker artifact must be a regular file")
        with path.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("ranker artifact exceeds byte budget")
        observed = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(observed, expected_sha256):
            raise ValueError("ranker artifact checksum mismatch")
        try:
            payload = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_reject_constant)
        except (ValueError, RecursionError, UnicodeError) as exc:
            raise ValueError("invalid ranker artifact") from exc
        allowed = {"format", "feature_version", "dimensions", "weights"}
        if not isinstance(payload, dict) or set(payload) != allowed:
            raise ValueError("unsupported ranker artifact fields")
        if (
            payload["format"] != FORMAT
            or payload["feature_version"] != FEATURE_VERSION
            or type(payload["dimensions"]) is not int
            or payload["dimensions"] != DIMENSIONS
        ):
            raise ValueError("unsupported ranker artifact version")
        if not isinstance(payload["weights"], list):
            raise ValueError("weights must be an array")
        return cls(tuple(payload["weights"]), observed)

    def scores(self, query: str, candidates: Sequence[str]) -> list[float]:
        if isinstance(candidates, str) or len(candidates) > MAX_CANDIDATES:
            raise ValueError("ranker candidate budget exceeded")
        return [sigmoid(dot(self.weights, features(query, item))) for item in candidates]

    def rank_fields(
        self, source: Mapping[str, Any], candidates: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        if len(candidates) > MAX_CANDIDATES:
            raise ValueError("ranker candidate budget exceeded")
        identities = [item.get("id") for item in candidates]
        if any(
            not isinstance(identity, str) or not identity or len(identity) > 128
            for identity in identities
        ) or len(set(identities)) != len(identities):
            raise ValueError("candidate identities must be unique bounded strings")
        scores = self.scores(
            field_text(source), [field_text(candidate) for candidate in candidates]
        )
        results = [
            {
                "target_field_id": identity,
                "rank_score": score,
                "authority": "advisory_only",
            }
            for identity, score in zip(identities, scores, strict=True)
        ]
        return sorted(results, key=lambda item: (-item["rank_score"], item["target_field_id"]))
