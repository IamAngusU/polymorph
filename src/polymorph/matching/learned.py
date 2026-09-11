"""Portable, data-only learned ranking. Scores never grant write authority."""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

FORMAT = "angusu.bridge.advisory-ranker/1"
FEATURE_VERSION = "bounded-token-cross/1"
MAX_MODEL_BYTES = 16 * 1024 * 1024
MAX_WEIGHTS = 100_000
MAX_TEXT = 4096
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_HEX = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_WEIGHTS = {"exact": 1.6, "tokens": 1.2, "trigrams": 1.6, "length": 0.2}


def _name(text: str) -> str:
    if not isinstance(text, str) or len(text) > MAX_TEXT or "\x00" in text:
        raise ValueError("descriptor must be bounded text without NUL")
    # Compatible with FieldDescriptor.semantic_text, not a record-value classifier.
    name = text.split(";", 1)[0]
    if name.startswith("name: "):
        name = name[6:]
    name = unicodedata.normalize("NFKC", _CAMEL.sub(" ", name)).casefold()
    return " ".join(re.findall(r"[^\W_]+", name, re.UNICODE))[:512]


def features(query: str, candidate: str) -> dict[str, float]:
    left, right = _name(query), _name(candidate)
    a, b = set(left.split()[:24]), set(right.split()[:24])
    ac = {left[i : i + 3] for i in range(min(256, max(0, len(left) - 2)))}
    bc = {right[i : i + 3] for i in range(min(256, max(0, len(right) - 2)))}
    out = {
        "exact": float(bool(left) and left == right),
        "tokens": len(a & b) / max(1, len(a | b)),
        "trigrams": len(ac & bc) / max(1, len(ac | bc)),
        "length": min(len(left), len(right)) / max(1, len(left), len(right)),
    }
    scale = 1.0 / math.sqrt(max(1, len(a) * len(b)))
    for x in sorted(a):
        for y in sorted(b):
            key = "x" + hashlib.sha256((x + "\0" + y).encode()).hexdigest()[:24]
            out[key] = out.get(key, 0.0) + scale
    return out


def sigmoid(value: float) -> float:
    value = max(-50.0, min(50.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate model field")
        result[key] = value
    return result


class AdvisoryRanker:
    """Small CPU ranker implementing the existing Reranker.scores protocol.

    A loaded artifact is ranking evidence. It does not edit schemas, recipes,
    thresholds, permissions, or deterministic AUTO prerequisites.
    """

    def __init__(self, weights: Mapping[str, float] | None = None) -> None:
        raw = dict(DEFAULT_WEIGHTS if weights is None else weights)
        if len(raw) > MAX_WEIGHTS:
            raise ValueError("model exceeds feature budget")
        for key, value in raw.items():
            if not isinstance(key, str) or (
                key not in DEFAULT_WEIGHTS and not re.fullmatch(r"x[0-9a-f]{24}", key)
            ):
                raise ValueError("unsupported model feature")
            if type(value) not in (int, float) or not math.isfinite(value) or abs(value) > 1000:
                raise ValueError("invalid model weight")
        self.weights: Mapping[str, float] = MappingProxyType(raw)

    def scores(self, query: str, candidates: Sequence[str]) -> list[float]:
        if isinstance(candidates, (str, bytes)) or len(candidates) > 256:
            raise ValueError("candidate count exceeds budget")
        # Bounded scores are not calibrated correctness probabilities.
        return [
            sigmoid(sum(self.weights.get(k, 0.0) * v for k, v in features(query, c).items()))
            for c in candidates
        ]

    def as_dict(self) -> dict[str, object]:
        return {
            "format": FORMAT,
            "feature_version": FEATURE_VERSION,
            "authority": "advisory_only",
            "weights": dict(sorted(self.weights.items())),
        }

    @classmethod
    def load(cls, path: str | Path, *, expected_sha256: str) -> AdvisoryRanker:
        if not isinstance(expected_sha256, str) or not _HEX.fullmatch(expected_sha256):
            raise ValueError("an independently approved SHA-256 is required")
        p = Path(path).absolute()
        for component in (p, *p.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("linked model paths are not accepted")
        if not p.is_file():
            raise ValueError("model must be a regular file")
        with p.open("rb") as stream:
            raw = stream.read(MAX_MODEL_BYTES + 1)
        if len(raw) > MAX_MODEL_BYTES or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError("model integrity or byte budget check failed")
        try:
            obj = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, RecursionError, UnicodeError) as exc:
            raise ValueError("invalid model document") from exc
        if (
            not isinstance(obj, dict)
            or set(obj) != {"format", "feature_version", "authority", "weights"}
            or obj.get("format") != FORMAT
            or obj.get("feature_version") != FEATURE_VERSION
            or obj.get("authority") != "advisory_only"
            or not isinstance(obj.get("weights"), dict)
        ):
            raise ValueError("unsupported model contract")
        return cls(obj["weights"])
