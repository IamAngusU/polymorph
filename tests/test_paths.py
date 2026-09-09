from __future__ import annotations

import os
from pathlib import Path

from polymorph.paths import data_home


def test_data_home_prefers_product_environment_variable(monkeypatch, tmp_path) -> None:
    preferred = tmp_path / "polymorph"
    legacy = tmp_path / "legacy"
    monkeypatch.setenv("POLYMORPH_HOME", str(preferred))
    monkeypatch.setenv("ANGUSU_BRIDGE_HOME", str(legacy))

    assert data_home() == preferred


def test_data_home_keeps_legacy_environment_alias(monkeypatch, tmp_path) -> None:
    legacy = tmp_path / "legacy"
    monkeypatch.delenv("POLYMORPH_HOME", raising=False)
    monkeypatch.setenv("ANGUSU_BRIDGE_HOME", str(legacy))

    assert data_home() == Path(legacy)


def test_data_home_reuses_legacy_default_until_product_directory_exists(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("POLYMORPH_HOME", raising=False)
    monkeypatch.delenv("ANGUSU_BRIDGE_HOME", raising=False)
    if os.name == "nt":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        legacy = tmp_path / "Angusu" / "Bridge"
        preferred = tmp_path / "Polymorph"
    else:
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        legacy = tmp_path / "angusu-bridge"
        preferred = tmp_path / "polymorph"

    legacy.mkdir(parents=True)
    assert data_home() == legacy

    preferred.mkdir()
    assert data_home() == preferred
