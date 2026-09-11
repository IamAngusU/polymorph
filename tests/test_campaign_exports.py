"""Contract fixtures test the judge, not product accuracy or training quality."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "campaign_contract", ROOT / "scripts/campaign_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, allow_nan=False).encode("utf-8")


class CampaignExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        model = {
            "format": "angusu.bridge.lexical-ranker/1",
            "feature_version": "token-cross/1",
            "dimensions": 16384,
            "weights": [0.0] * 16384,
        }
        model_hash = hashlib.sha256(encoded(model)).hexdigest()
        evidence = {
            "format": "angusu.lab.campaign-candidate/1",
            "campaign_id": "a" * 32,
            "created_at": "2026-09-11T10:00:00+00:00",
            "saved_at": "2026-09-11T10:01:00+00:00",
            "checkpoint": 3,
            "updates": 100,
            "best_updates": 80,
            "best_epoch": 1,
            "dataset_sha256": "1" * 64,
            "unique_train_queries": 4,
            "unique_train_comparisons": 12,
            "training_source_groups": 2,
            "runtime_sha256": "2" * 64,
            "feature_abi_sha256": "3" * 64,
            "trainer_sha256": "4" * 64,
            "holdout_evaluations": 0,
            "authority": "advisory_only",
            "origin": "synthetic_ground_truth",
            "model_sha256": model_hash,
            "corpus_id": "5" * 64,
            "status": "candidate_not_approved",
            "automatic_activation": False,
        }
        evaluation = {
            "format": "angusu.lab.campaign-evaluation/1",
            "model_sha256": model_hash,
            "split": "validation",
            "queries": 2,
            "timestamp": "2026-09-11T10:01:00+00:00",
            "dataset_sha256": "1" * 64,
            "baseline": {
                "queries": 2, "correct_top1": 1, "top1_accuracy": 0.5,
                "mrr": 0.75, "families": {"alias": {"correct": 1, "total": 2}},
            },
            "candidate": {
                "queries": 2, "correct_top1": 2, "top1_accuracy": 1.0,
                "mrr": 1.0, "families": {"alias": {"correct": 2, "total": 2}},
            },
            "paired_improvements": 1,
            "paired_regressions": 0,
            "scope": "synthetic_ranker_vs_own_untrained_baseline",
            "production_gate_passed": False,
            "independent_customer_sources": 0,
        }
        for name, data in (
            ("model.json", model), ("evidence.json", evidence),
            ("evaluation.json", evaluation),
        ):
            (self.root / name).write_bytes(encoded(data))
        self.manifest()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def manifest(self) -> None:
        value = {
            "format": "angusu.lab.candidate-export/1",
            "files": {
                name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                for name in contract.FILES
            },
            "authority": "advisory_only",
            "approved_for_publication": False,
        }
        (self.root / "manifest.json").write_bytes(encoded(value))

    def change(self, name: str, key: str, value: object) -> None:
        path = self.root / name
        data = json.loads(path.read_bytes())
        data[key] = value
        path.write_bytes(encoded(data))
        self.manifest()

    def test_valid_contract_is_not_approval(self) -> None:
        value = contract.verify_candidate(self.root)
        self.assertTrue(value["verified"])
        self.assertFalse(value["publication_approved"])
        self.assertFalse(value["automatic_activation"])

    def test_additional_file_is_rejected(self) -> None:
        (self.root / "private.env").write_text("not for export")
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_hash_mismatch_is_rejected(self) -> None:
        (self.root / "model.json").write_text("{}")
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_duplicate_json_key_is_rejected(self) -> None:
        (self.root / "manifest.json").write_text('{"files":{},"files":{}}')
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_bool_is_not_a_training_count(self) -> None:
        self.change("evidence.json", "unique_train_queries", True)
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_future_updates_cannot_be_selected(self) -> None:
        self.change("evidence.json", "best_updates", 101)
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_false_production_claim_is_rejected(self) -> None:
        self.change("evaluation.json", "production_gate_passed", True)
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_training_split_is_not_evaluation(self) -> None:
        self.change("evaluation.json", "split", "train")
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_paired_counts_must_balance(self) -> None:
        self.change("evaluation.json", "paired_improvements", 0)
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_model_runtime_incompatible(self) -> None:
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root, expected_feature_abi_sha256="f" * 64)

    def test_nonfinite_weights_rejected(self) -> None:
        path = self.root / "model.json"
        data = json.loads(path.read_bytes())
        data["weights"][0] = float("inf")
        path.write_text(json.dumps(data))
        self.manifest()
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_file_path_cannot_escape(self) -> None:
        path = self.root / "manifest.json"
        data = json.loads(path.read_bytes())
        data["files"]["../model.json"] = data["files"].pop("model.json")
        path.write_bytes(encoded(data))
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_extra_evidence_field_is_rejected(self) -> None:
        self.change("evidence.json", "private_path", "do not copy")
        with self.assertRaises(ValueError):
            contract.verify_candidate(self.root)

    def test_matching_feature_abi_is_supported(self) -> None:
        value = contract.verify_candidate(self.root, expected_feature_abi_sha256="3" * 64)
        self.assertTrue(value["verified"])


if __name__ == "__main__":
    unittest.main()
