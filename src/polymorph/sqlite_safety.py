from __future__ import annotations

import sqlite3
from collections.abc import Sequence


def sqlite_wal_is_safe(version: Sequence[int] | None = None) -> bool:
    """Return whether the SQLite runtime contains the 2026 WAL-reset race fix."""

    current = tuple(version or sqlite3.sqlite_version_info)
    if len(current) < 3 or current[0] != 3:
        return current >= (4, 0, 0)
    _, minor, patch = current[:3]
    if minor == 44:
        return patch >= 6
    if minor == 50:
        return patch >= 7
    if minor == 51:
        return patch >= 3
    return minor >= 52


def selected_journal_mode(version: Sequence[int] | None = None) -> str:
    return "wal" if sqlite_wal_is_safe(version) else "delete"


def configure_sqlite_durability(connection: sqlite3.Connection) -> str:
    """Select a crash-safe journal policy and require full synchronous durability."""

    requested = selected_journal_mode()
    row = connection.execute("PRAGMA journal_mode").fetchone()
    actual = str(row[0]).casefold() if row is not None else ""
    if actual != requested:
        row = connection.execute(f"PRAGMA journal_mode = {requested}").fetchone()
        actual = str(row[0]).casefold() if row is not None else ""
    if actual != requested:
        raise RuntimeError(
            f"SQLite refused required journal mode {requested!r}; active mode is {actual!r}"
        )
    connection.execute("PRAGMA synchronous = FULL")
    return actual
