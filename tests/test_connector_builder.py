from __future__ import annotations

import json

import pytest

from polymorph.connector_builder import ConnectorScaffoldError, scaffold_connector


def test_connector_scaffold_is_compilable_fail_closed_and_has_no_actions(tmp_path) -> None:
    target = scaffold_connector("Acme CRM", tmp_path / "acme")
    connector = target / "src" / "polymorph_connector_acme_crm" / "connector.py"
    compile(connector.read_text(encoding="utf-8"), str(connector), "exec")
    manifest = json.loads((target / "connector-manifest.json").read_text(encoding="utf-8"))
    assert manifest["capabilities"] == {
        "incremental_read": False,
        "read_records": False,
        "schema_inspection": False,
    }
    assert not (target / ".github").exists()


def test_connector_scaffold_never_overwrites(tmp_path) -> None:
    target = tmp_path / "existing"
    target.mkdir()
    (target / "important.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ConnectorScaffoldError, match="already exists"):
        scaffold_connector("Acme", target)
    assert (target / "important.txt").read_text(encoding="utf-8") == "keep"
