"""Validate a data-only campaign candidate. Validation is not release approval."""
from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

FORMAT = "angusu.lab.candidate-export/1"
MODEL_FORMAT = "angusu.bridge.lexical-ranker/1"
FILES = {"model.json", "evidence.json", "evaluation.json"}
MAX_BYTES = 4 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
EVIDENCE_KEYS = {
    "authority",
    "automatic_activation",
    "best_epoch",
    "best_updates",
    "campaign_id",
    "checkpoint",
    "corpus_id",
    "created_at",
    "dataset_sha256",
    "feature_abi_sha256",
    "format",
    "holdout_evaluations",
    "model_sha256",
    "origin",
    "runtime_sha256",
    "saved_at",
    "status",
    "trainer_sha256",
    "training_source_groups",
    "unique_train_comparisons",
    "unique_train_queries",
    "updates",
}
EVALUATION_KEYS = {
    "baseline",
    "candidate",
    "dataset_sha256",
    "format",
    "independent_customer_sources",
    "model_sha256",
    "paired_improvements",
    "paired_regressions",
    "production_gate_passed",
    "queries",
    "scope",
    "split",
    "timestamp",
}


def read(path: Path, maximum: int = MAX_BYTES) -> bytes:
    for part in (path.absolute(), *path.absolute().parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked candidate path")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("candidate input must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("candidate byte budget exceeded")
    return raw


def document(raw: bytes) -> dict[str, Any]:
    def unique(items: list) -> dict:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate candidate field")
            result[key] = value
        return result
    def reject(_: str) -> None:
        raise ValueError("nonfinite candidate value")
    try:
        obj = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid candidate JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("candidate object required")
    return obj


def count(value: Any, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 10**12:
        raise ValueError("invalid candidate counter")
    return value


def fingerprint(value: Any) -> str:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("invalid candidate fingerprint")
    return value


def _metric(value: Any) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"queries", "correct_top1", "top1_accuracy", "mrr", "families"}
    ):
        raise ValueError("invalid candidate metric fields")
    n, correct = count(value["queries"], 1), count(value["correct_top1"])
    if correct > n:
        raise ValueError("correct count exceeds query count")
    for name in ("top1_accuracy", "mrr"):
        x = value[name]
        if type(x) not in (int, float) or not math.isfinite(x) or not 0 <= x <= 1:
            raise ValueError("invalid candidate metric")
    if not math.isclose(value["top1_accuracy"], correct / n, abs_tol=1e-12):
        raise ValueError("candidate accuracy disagrees with counts")
    if value["mrr"] + 1e-12 < value["top1_accuracy"]:
        raise ValueError("candidate ranking metrics disagree")
    families = value["families"]
    if not isinstance(families, dict) or len(families) > 32:
        raise ValueError("invalid candidate families")
    total = passed = 0
    for name, row in families.items():
        if (
            not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name)
            or not isinstance(row, dict)
            or set(row) != {"correct", "total"}
        ):
            raise ValueError("invalid candidate family metric")
        t, c = count(row["total"], 1), count(row["correct"])
        if c > t:
            raise ValueError("invalid family counts")
        total += t
        passed += c
    if total != n or passed != correct:
        raise ValueError("family metrics do not account for every query")
    return value


def verify_candidate(
    root: Path,
    *,
    expected_runtime_sha256: str | None = None,
    expected_feature_abi_sha256: str | None = None,
) -> dict[str, Any]:
    """Check four exact files and cross-file identities without importing their code.

    A matching SHA-256 is integrity evidence, not truth of a training claim. Actual
    candidate selection and signing require a separate authorized local publisher.
    """
    manifest_raw = read(root / "manifest.json", 65536)
    manifest = document(manifest_raw)
    if set(manifest) != {"format", "files", "authority", "approved_for_publication"}:
        raise ValueError("invalid candidate manifest fields")
    if (
        manifest["format"] != FORMAT
        or manifest["authority"] != "advisory_only"
        or manifest["approved_for_publication"] is not False
    ):
        raise ValueError("candidate cannot grant publication or write authority")
    if not isinstance(manifest["files"], dict) or set(manifest["files"]) != FILES:
        raise ValueError("candidate file allowlist mismatch")
    if {p.name for p in root.iterdir()} != FILES | {"manifest.json"}:
        raise ValueError("unexpected candidate files")
    raw = {name: read(root / name) for name in FILES}
    for name, content in raw.items():
        if hashlib.sha256(content).hexdigest() != fingerprint(manifest["files"][name]):
            raise ValueError("candidate checksum mismatch")
    model, evidence, evaluation = (
        document(raw[name]) for name in ("model.json", "evidence.json", "evaluation.json")
    )
    if (
        set(model) != {"format", "feature_version", "dimensions", "weights"}
        or model["format"] != MODEL_FORMAT
        or model["feature_version"] != "token-cross/1"
        or type(model["dimensions"]) is not int
        or model["dimensions"] != 16384
    ):
        raise ValueError("unsupported candidate model contract")
    weights = model["weights"]
    if (
        not isinstance(weights, list)
        or len(weights) != 16384
        or any(
            type(v) not in (int, float) or not math.isfinite(v) or abs(v) > 1e4
            for v in weights
        )
    ):
        raise ValueError("invalid candidate weights")
    if set(evidence) != EVIDENCE_KEYS or evidence["format"] != "angusu.lab.campaign-candidate/1":
        raise ValueError("unsupported candidate evidence")
    if (
        evidence["authority"] != "advisory_only"
        or evidence["origin"] != "synthetic_ground_truth"
        or evidence["automatic_activation"] is not False
        or evidence["status"] != "candidate_not_approved"
    ):
        raise ValueError("unapproved candidate scope")
    if (
        not isinstance(evidence["campaign_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", evidence["campaign_id"])
    ):
        raise ValueError("invalid campaign identity")
    for value in (evidence["created_at"], evidence["saved_at"], evaluation.get("timestamp")):
        if (
            not isinstance(value, str)
            or len(value) > 40
            or datetime.fromisoformat(value).utcoffset() != timedelta(0)
        ):
            raise ValueError("candidate timestamp must be bounded UTC text")
    for key in (
        "model_sha256",
        "corpus_id",
        "dataset_sha256",
        "runtime_sha256",
        "feature_abi_sha256",
        "trainer_sha256",
    ):
        fingerprint(evidence[key])
    for key in (
        "checkpoint",
        "updates",
        "best_updates",
        "best_epoch",
        "unique_train_queries",
        "unique_train_comparisons",
        "training_source_groups",
    ):
        count(evidence[key], 1)
    count(evidence["holdout_evaluations"])
    if evidence["best_updates"] > evidence["updates"]:
        raise ValueError("selected weights cannot precede nonexistent updates")
    if evidence["model_sha256"] != manifest["files"]["model.json"]:
        raise ValueError("candidate model identity mismatch")
    if (
        expected_runtime_sha256 is not None
        and evidence["runtime_sha256"] != fingerprint(expected_runtime_sha256)
    ):
        raise ValueError("candidate feature implementation is incompatible")
    if (
        expected_feature_abi_sha256 is not None
        and evidence["feature_abi_sha256"] != fingerprint(expected_feature_abi_sha256)
    ):
        raise ValueError("candidate feature ABI is incompatible")
    if (
        set(evaluation) != EVALUATION_KEYS
        or evaluation["format"] != "angusu.lab.campaign-evaluation/1"
    ):
        raise ValueError("unsupported candidate evaluation")
    if (
        evaluation["production_gate_passed"] is not False
        or evaluation["independent_customer_sources"] != 0
        or type(evaluation["independent_customer_sources"]) is not int
        or evaluation["scope"] != "synthetic_ranker_vs_own_untrained_baseline"
    ):
        raise ValueError("unproven production claim")
    if (
        evaluation["split"] not in ("validation", "holdout")
        or evaluation["model_sha256"] != evidence["model_sha256"]
        or evaluation["dataset_sha256"] != evidence["dataset_sha256"]
    ):
        raise ValueError("evaluation identity mismatch")
    n = count(evaluation["queries"], 1)
    a, b = _metric(evaluation["baseline"]), _metric(evaluation["candidate"])
    gains, losses = (
        count(evaluation["paired_improvements"]),
        count(evaluation["paired_regressions"]),
    )
    if (
        a["queries"] != n
        or b["queries"] != n
        or b["correct_top1"] - a["correct_top1"] != gains - losses
        or gains > n - a["correct_top1"]
        or losses > a["correct_top1"]
    ):
        raise ValueError("inconsistent paired evaluation")
    return {
        "format": "angusu.lab.candidate-verification/1",
        "verified": True,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "model_sha256": evidence["model_sha256"],
        "evidence": evidence,
        "evaluation": evaluation,
        "automatic_activation": False,
        "publication_approved": False,
    }
