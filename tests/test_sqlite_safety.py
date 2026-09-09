from __future__ import annotations

import sqlite3

import pytest

from polymorph.sqlite_safety import (
    configure_sqlite_durability,
    selected_journal_mode,
    sqlite_wal_is_safe,
)


@pytest.mark.parametrize(
    ("version", "safe"),
    (
        ((3, 44, 5), False),
        ((3, 44, 6), True),
        ((3, 45, 1), False),
        ((3, 49, 9), False),
        ((3, 50, 6), False),
        ((3, 50, 7), True),
        ((3, 51, 2), False),
        ((3, 51, 3), True),
        ((3, 52, 0), True),
        ((4, 0, 0), True),
    ),
)
def test_wal_reset_fix_version_policy(version, safe) -> None:
    assert sqlite_wal_is_safe(version) is safe


def test_configured_journal_mode_matches_runtime_policy(tmp_path) -> None:
    with sqlite3.connect(tmp_path / "state.sqlite") as connection:
        actual = configure_sqlite_durability(connection)
        synchronous = connection.execute("PRAGMA synchronous").fetchone()

    assert actual == selected_journal_mode()
    assert synchronous is not None
    assert synchronous[0] == 2
