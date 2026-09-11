from __future__ import annotations

import base64
import copy
import importlib.util
import json
import sqlite3
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from polymorph import knowledge as k

NOW = datetime.now(UTC)
KEY = Ed25519PrivateKey.generate()
PUBLIC = KEY.public_key().public_bytes_raw()


def package(sequence=1, version=None, change=None):
    model = k.canonical({"format": k.MODEL_FORMAT, "feature_version": k.FEATURE_VERSION,
                         "dimensions": 16384, "weights": [0.0] * 16384})
    signed = {
        "format": k.FORMAT, "version": version or f"v{sequence}", "sequence": sequence,
        "publisher_key_id": k.sha256(PUBLIC), "created_at": (NOW-timedelta(hours=1)).isoformat(),
        "expires_at": (NOW+timedelta(days=30)).isoformat(), "authority": "advisory_only",
        "origin": "synthetic_lab", "model_b64": base64.b64encode(model).decode(),
        "model_sha256": k.sha256(model),
        "evidence": {"corpus_sha256": "a"*64, "training_sha256": "b"*64,
            "evaluation_sha256": "c"*64,
            "runtime_sha256": k.sha256((Path(k.__file__).parent/"matching/lexical.py").read_bytes()),
            "unique_train_queries": 4, "unique_train_comparisons": 10, "training_source_groups": 2,
            "weight_updates": 20, "holdout_queries": 3, "holdout_correct": 3,
            "baseline_correct": 2, "paired_regressions": 0, "independent_customer_sources": 0},
    }
    if change:
        change(signed)
    return k.canonical({"signed": signed,
        "signature": base64.b64encode(KEY.sign(k.DOMAIN+k.canonical(signed))).decode()})


def test_roundtrip_and_local_recipes_untouched(tmp_path):
    (tmp_path/"recipes.sqlite").write_bytes(b"private recipe sentinel")
    (tmp_path/"local-model.json").write_bytes(b"private model sentinel")
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package(1))
    assert store.active_ranker() is None
    store.activate("v1")
    assert len(store.active_ranker().weights) == 16384
    store.install(package(2), activate=True)
    assert store.status()["active"] == "v2"
    assert len(store.status()["versions"]) == 2
    assert (tmp_path/"recipes.sqlite").read_bytes() == b"private recipe sentinel"
    assert (tmp_path/"local-model.json").read_bytes() == b"private model sentinel"


def test_bad_update_preserves_selection(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package(), activate=True)
    tampered = json.loads(package(2))
    tampered["signed"]["sequence"] = 500
    with pytest.raises(ValueError, match="signature"):
        store.install(k.canonical(tampered), activate=True)
    assert store.status()["active"] == "v1"


def test_unknown_key_rejected():
    with pytest.raises(ValueError, match="signature"):
        k.verify_pack(package(), Ed25519PrivateKey.generate().public_key().public_bytes_raw())


@pytest.mark.parametrize("key,value", [
    ("authority", "auto"), ("format", "bad"), ("version", "../local"), ("sequence", True),
    ("sequence", 0), ("model_sha256", "0"*64), ("origin", "production_upload"),
    ("publisher_key_id", "0"*64), ("created_at", (NOW+timedelta(days=1)).isoformat()),
    ("expires_at", (NOW-timedelta(seconds=1)).isoformat()),
    ("expires_at", (NOW+timedelta(days=400)).isoformat()),
    ("created_at", "2026-09-01T00:00:00"),
])
def test_signed_invalid_contract_rejected(key, value):
    with pytest.raises(ValueError):
        k.verify_pack(package(change=lambda x: x.update({key:value})), PUBLIC)


@pytest.mark.parametrize("metric,value", [("unique_train_queries", True), ("holdout_correct",4),
    ("unique_train_comparisons",-1), ("weight_updates",1.5), ("runtime_sha256","bad")])
def test_invalid_evidence_rejected(metric,value):
    with pytest.raises(ValueError):
        k.verify_pack(package(change=lambda x: x["evidence"].update({metric:value})), PUBLIC)


def test_stale_update_and_explicit_rollback(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package(), activate=True)
    store.install(package(2), activate=True)
    with pytest.raises(ValueError, match="stale"):
        store.install(package())
    with pytest.raises(ValueError, match="allow-rollback"):
        store.activate("v1")
    store.activate("v1", allow_rollback=True)
    assert store.status()["highest_seen_sequence"] == 2
    assert store.status()["active"] == "v1"


def test_same_sequence_fork_and_version_reuse(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package())
    for raw in (package(1,"other"), package(2,"v1")):
        with pytest.raises(ValueError, match="fork"):
            store.install(raw)
    store.install(package())
    assert len(store.status()["versions"]) == 1


def test_wrong_runtime_cannot_replace_active(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package(), activate=True)
    with pytest.raises(ValueError, match="incompatible"):
        store.install(package(2,change=lambda x:x["evidence"].update(runtime_sha256="0"*64)),activate=True)
    assert store.status()["active"] == "v1"


def test_publisher_change_is_not_implicit(tmp_path):
    k.KnowledgeStore(tmp_path, PUBLIC)
    with pytest.raises(ValueError, match="migration"):
        k.KnowledgeStore(tmp_path, Ed25519PrivateKey.generate().public_key().public_bytes_raw())


def test_tampered_stored_package_fails_closed(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package(), activate=True)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE packages SET raw=?",(b"{}",))
    with pytest.raises(ValueError, match="changed"):
        store.active_ranker()


def test_transaction_failure_rolls_back_all_update_state(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package(), activate=True)
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TRIGGER no_update BEFORE UPDATE ON state BEGIN SELECT RAISE(ABORT, 'stop'); END")
    with pytest.raises(sqlite3.Error):
        store.install(package(2),activate=True)
    assert store.status()["active"] == "v1"
    assert len(store.status()["versions"]) == 1


def test_concurrent_same_package_is_idempotent(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    raw = package()
    errors=[]
    def run():
        try:
            store.install(raw,activate=True)
        except Exception as exc:
            errors.append(exc)
    threads=[threading.Thread(target=run) for _ in range(4)]
    for t in threads:t.start()
    for t in threads:t.join()
    assert errors == []
    assert len(store.status()["versions"]) == 1


def test_size_and_duplicate_keys():
    with pytest.raises(ValueError):k.document(b'x'*(k.MAX_PACK_BYTES+1))
    with pytest.raises(ValueError):k.document(b'{"x":1,"x":2}')
    with pytest.raises(ValueError):k.document(b'{"x":NaN}')


def test_store_budget_preserves_existing(tmp_path,monkeypatch):
    store=k.KnowledgeStore(tmp_path,PUBLIC);store.install(package(),activate=True)
    monkeypatch.setattr(k,"MAX_STORE_BYTES",1)
    with pytest.raises(ValueError,match="budget"):
        store.install(package(2),activate=True)
    assert store.status()["active"]=="v1"


def test_symlink_path_rejected(tmp_path):
    real=tmp_path/"real";real.mkdir();link=tmp_path/"link"
    try:link.symlink_to(real,target_is_directory=True)
    except OSError:pytest.skip("symlink unavailable")
    with pytest.raises(ValueError,match="linked"):k.KnowledgeStore(link,PUBLIC)


def test_latest_discovery_is_not_signature_trust(monkeypatch):
    raw=package();ptr={"format":"angusu.bridge.knowledge-pointer/1","package":"packs/v1.json", "sha256":k.sha256(raw),"sequence":1}
    monkeypatch.setattr(k,"_download",lambda url,maximum: k.canonical(ptr) if url.endswith('latest.json') else raw)
    assert k.fetch_latest()==raw
    ptr["package"]="../publisher.key"
    with pytest.raises(ValueError):k.fetch_latest()


def test_missing_latest_is_honest(monkeypatch):
    monkeypatch.setattr(k,"_download",lambda *args:k.canonical({"package":None}))
    with pytest.raises(ValueError,match="no general"):k.fetch_latest()
    with pytest.raises(ValueError):k.fetch_latest(ref="../../secret")


@pytest.mark.parametrize("value",[True, float("inf"), 10**1000, {}, "1"])
def test_model_bad_weights(value):
    obj={"format":k.MODEL_FORMAT,"feature_version":k.FEATURE_VERSION,"dimensions":16384,"weights":[0]*16384}
    obj["weights"][0]=value
    with pytest.raises(ValueError):k.model_document(k.canonical(obj))


def test_legacy_ranker_format_is_not_misread():
    with pytest.raises(ValueError):k.model_document(k.canonical({"format":"angusu.bridge.advisory-ranker/1","weights":{}}))


def test_silent_state_update_is_not_success(tmp_path):
    store = k.KnowledgeStore(tmp_path, PUBLIC)
    store.install(package(), activate=True)
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TRIGGER ignore_state BEFORE UPDATE ON state BEGIN SELECT RAISE(IGNORE); END")
    with pytest.raises(ValueError, match="postcondition"):
        store.install(package(2), activate=True)
    assert store.status()["active"] == "v1"
    assert len(store.status()["versions"]) == 1
