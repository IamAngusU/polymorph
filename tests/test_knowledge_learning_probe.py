from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _field(identity: str, name: str) -> dict[str, object]:
    return {
        "id": identity,
        "name": name,
        "data_type": "string",
        "nullable": False,
        "sensitivity": "internal",
        "role": "value",
        "aliases": [],
    }


def test_learning_probe_keeps_authority_read_only(tmp_path):
    root = Path(__file__).resolve().parents[1]
    request = {
        "protocol": "angusu.bridge.learning-probe/1",
        "request_id": "test-request",
        "operation": "map",
        "items": [
            {
                "id": "case-1",
                "source_schema": {
                    "id": "source",
                    "fields": [_field("source-email", "customer_email")],
                },
                "target_schema": {
                    "id": "target",
                    "fields": [_field("target-email", "customer_email")],
                },
            }
        ],
    }

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(root / "scripts" / "knowledge_learning_probe.py"),
            "--input-root",
            str(tmp_path),
        ],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        cwd=root,
        timeout=30,
        check=False,
    )
    response = json.loads(completed.stdout)

    assert completed.returncode == 0
    assert response["authority"] == "unchanged_deterministic_policy"
    assert response["recommendations"] == "advisory_only"
    assert response["writes_performed"] is False
    assert response["training_performed"] is False
    assert response["oracle_received"] is False
    assert response["model_sha256"] == "baseline"
    assert response["items"][0]["recommendations"][0]["requires_review"] is True
    assert response["items"][0]["recommendations"][0]["ranking"][0]["authority"] == "advisory_only"
