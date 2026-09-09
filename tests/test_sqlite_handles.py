from __future__ import annotations

from pathlib import Path

from polymorph.audit import AuditLog
from polymorph.ledger import DeliveryLedger
from polymorph.recipes import RecipeStore
from polymorph.relay import RelayPolicy, SealedRelayQueue
from polymorph.spool import SealedSpool


def test_sqlite_stores_release_files_after_operations(tmp_path: Path) -> None:
    paths = {
        "audit": tmp_path / "audit.db",
        "ledger": tmp_path / "ledger.db",
        "recipes": tmp_path / "recipes.db",
        "relay": tmp_path / "relay.db",
        "spool": tmp_path / "spool.db",
    }

    audit = AuditLog(paths["audit"])
    assert audit.verify() == 0
    assert audit.export_jsonl() == ""

    DeliveryLedger(paths["ledger"])

    recipes = RecipeStore(paths["recipes"])
    assert recipes.list() == []

    relay = SealedRelayQueue(paths["relay"], RelayPolicy(()))
    assert relay.depth() == 0

    spool = SealedSpool(paths["spool"])
    assert spool.list_entries() == ()

    # Windows refuses both operations while any SQLite connection still owns the file.
    for path in paths.values():
        moved = path.with_suffix(".moved")
        path.replace(moved)
        moved.unlink()
