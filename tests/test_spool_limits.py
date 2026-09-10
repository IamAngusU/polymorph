from pathlib import Path

import pytest

from polymorph.spool import SealedSpool


@pytest.mark.parametrize("limit", [True, False, 0, -1, 10_001, 1.5, "1"])
def test_spool_rejects_unbounded_list_limits(tmp_path: Path, limit: object) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")

    with pytest.raises(ValueError, match="outside supported range"):
        spool.list_entries(limit=limit)  # type: ignore[arg-type]


def test_spool_accepts_minimum_bounded_list_limit(tmp_path: Path) -> None:
    spool = SealedSpool(tmp_path / "spool.sqlite3")

    assert spool.list_entries(limit=1) == ()
