from __future__ import annotations

import math
import sqlite3
from collections import Counter
from collections.abc import Callable, Hashable, Mapping, Sequence
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import Column, Table, UniqueConstraint, select, tuple_
from sqlalchemy.engine import Connection, CursorResult, Engine, Transaction

from polymorph.errors import ConnectorWriteError, WriteOutcome

# Bound SQL parameters even on older SQLite builds. Rows are read back in chunks,
# but all inserts, verification queries and the final commit share one transaction.
_READBACK_PARAMETERS = 500
_MAX_VALUE_DEPTH = 64


class _UnprovenWrite(Exception):
    """Internal, payload-free rejection before commit."""


def _value_token(value: object, *, depth: int = 0) -> Hashable:
    """Compare round-tripped values without Python's bool/int equality shortcut.

    Integer-to-decimal widening is lossless and agrees with the runtime contract.
    Tokens never leave the destination process and are never logged or persisted.
    """
    if depth > _MAX_VALUE_DEPTH:
        raise _UnprovenWrite("database value exceeds the comparison depth limit")
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("number", Decimal(value))
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise _UnprovenWrite("database value is not finite")
        return ("number", value)
    if type(value) is float:
        if not math.isfinite(value):
            raise _UnprovenWrite("database value is not finite")
        return ("number", Decimal(str(value)))
    if type(value) is str:
        return ("text", value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return ("bytes", bytes(value))
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            return ("datetime-naive", value.isoformat())
        return ("datetime-utc", value.astimezone(UTC).isoformat())
    if isinstance(value, date):
        return ("date", value)
    if isinstance(value, UUID):
        return ("uuid", value)
    if isinstance(value, Mapping):
        if not all(type(key) is str for key in value):
            raise _UnprovenWrite("database object contains a non-string key")
        return (
            "object",
            frozenset((key, _value_token(item, depth=depth + 1)) for key, item in value.items()),
        )
    if isinstance(value, (list, tuple)):
        return ("array", tuple(_value_token(item, depth=depth + 1) for item in value))
    raise _UnprovenWrite("database value type cannot be verified")


def _row_token(row: Mapping[str, object], names: Sequence[str]) -> tuple[Hashable, ...]:
    return tuple(_value_token(row[name]) for name in names)


def _provided_identity(table: Table, rows: Sequence[Mapping[str, object]]) -> tuple[str, ...]:
    candidates = [tuple(column.name for column in table.primary_key.columns)]
    candidates.extend(
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    )
    for index in table.indexes:
        if not index.unique or any(name.endswith("_where") for name in index.dialect_kwargs):
            continue
        if all(isinstance(expression, Column) for expression in index.expressions):
            candidates.append(tuple(column.name for column in index.columns))
    for names in candidates:
        if names and all(all(row.get(name) is not None for name in names) for row in rows):
            return names
    return ()


def _verify_rows(
    connection: Connection,
    table: Table,
    expected: Counter[tuple[Hashable, ...]],
    expected_count: int,
    identity_names: tuple[str, ...],
    identities: Sequence[tuple[object, ...]],
    supplied_names: tuple[str, ...],
) -> None:
    if len(identities) != expected_count or any(
        len(key) != len(identity_names) or any(value is None for value in key)
        for key in identities
    ):
        raise _UnprovenWrite("database did not return complete row identities")
    identity_tokens = {tuple(_value_token(value) for value in key) for key in identities}
    if len(identity_tokens) != len(identities):
        raise _UnprovenWrite("database returned duplicate row identities")
    names = tuple(dict.fromkeys((*identity_names, *supplied_names)))
    observed: Counter[tuple[Hashable, ...]] = Counter()
    observed_identities: set[tuple[Hashable, ...]] = set()
    columns = [table.c[name] for name in identity_names]
    chunk_size = max(1, _READBACK_PARAMETERS // len(columns))
    for start in range(0, len(identities), chunk_size):
        chunk = identities[start : start + chunk_size]
        predicate = (
            columns[0].in_([key[0] for key in chunk])
            if len(columns) == 1
            else tuple_(*columns).in_(chunk)
        )
        statement = (
            select(*(table.c[name] for name in names)).where(predicate).limit(len(chunk) + 1)
        )
        with connection.execute(statement) as result:
            returned = result.mappings().fetchmany(len(chunk) + 1)
        if len(returned) != len(chunk):
            raise _UnprovenWrite("database read-back did not prove every inserted row")
        for row in returned:
            values: dict[str, object] = {name: row[name] for name in names}
            key = _row_token(values, identity_names)
            if key not in identity_tokens or key in observed_identities:
                raise _UnprovenWrite("database read-back returned an unexpected row identity")
            observed_identities.add(key)
            observed[_row_token(values, supplied_names)] += 1
    if observed_identities != identity_tokens or observed != expected:
        raise _UnprovenWrite("database read-back differs from the supplied values")


def _rollback_outcome(transaction: Transaction, *, transactional_write: bool) -> WriteOutcome:
    try:
        transaction.rollback()
    except Exception:
        return WriteOutcome.UNKNOWN
    return WriteOutcome.NOT_COMMITTED if transactional_write else WriteOutcome.UNKNOWN


def write_verified_rows(
    engine: Engine,
    table: Table,
    rows: list[dict[str, object]],
    *,
    transactional_write: bool,
    proves_rowcount: Callable[..., bool],
) -> int:
    """Verify supplied values inside the insert transaction before acknowledging commit.

    A rowcount proves neither existence nor final values after triggers. RETURNING is used
    only to obtain generated primary keys, never as the final value proof. This does not
    guarantee that another transaction cannot change a row after this transaction commits.
    """
    if not rows:
        return 0
    try:
        allowed = set(table.columns.keys())
        if any(type(name) is not str for row in rows for name in row):
            raise _UnprovenWrite("database column names must be strings")
        names = tuple(sorted(rows[0]))
        if not set(names) <= allowed or any(set(row) != set(names) for row in rows):
            raise _UnprovenWrite("database rows must have the same known column set")
        # Freeze expectations before any database callback or driver can mutate the input.
        expected = Counter(_row_token(row, names) for row in rows)
        expected_count = len(rows)
        identity_names = _provided_identity(table, rows)
        provided_identities = [tuple(row[name] for name in identity_names) for row in rows]
        generated_identity = not identity_names
        if generated_identity:
            identity_names = tuple(column.name for column in table.primary_key.columns)
            if not identity_names:
                raise _UnprovenWrite("database write requires a primary or supplied unique key")
            if any(
                name in names and row[name] is None for row in rows for name in identity_names
            ):
                raise _UnprovenWrite("database write contains an explicit null primary key")
            if len(rows) > 1 and not engine.dialect.insert_executemany_returning:
                raise _UnprovenWrite("database driver cannot prove generated batch identities")
    except _UnprovenWrite as exc:
        raise ConnectorWriteError(str(exc), outcome=WriteOutcome.NOT_COMMITTED) from None

    connection: Connection | None = None
    transaction: Transaction | None = None
    try:
        try:
            connection = engine.connect()
            transaction = connection.begin()
        except Exception:
            raise ConnectorWriteError(
                "database transaction could not start", outcome=WriteOutcome.NOT_COMMITTED
            ) from None
        try:
            driver = connection.connection.driver_connection
            if getattr(driver, "autocommit", False) is True or (
                isinstance(driver, sqlite3.Connection)
                and driver.isolation_level is None
                and not driver.in_transaction
            ):
                raise _UnprovenWrite("database write requires a real transaction")
            statement = table.insert()
            returning = generated_identity and len(rows) > 1
            if returning:
                statement = statement.returning(*(table.c[name] for name in identity_names))
            result: CursorResult[Any] = connection.execute(
                statement, rows if len(rows) > 1 else rows[0]
            )
            try:
                if returning:
                    identities = [tuple(row) for row in result.fetchmany(len(rows) + 1)]
                    if len(identities) != len(rows):
                        raise _UnprovenWrite("database did not return every inserted identity")
                else:
                    if not proves_rowcount(
                        result, expected_count=len(rows), is_multirow=len(rows) > 1
                    ):
                        raise _UnprovenWrite("database did not prove the exact affected row count")
                    if generated_identity:
                        identities = [tuple(result.inserted_primary_key)]
                    else:
                        identities = provided_identities
            finally:
                result.close()
            if connection.dialect.name == "postgresql":
                # Run pending deferred constraint triggers before the read-back, not at COMMIT.
                connection.exec_driver_sql("SET CONSTRAINTS ALL IMMEDIATE")
            _verify_rows(
                connection, table, expected, expected_count, identity_names, identities, names
            )
        except Exception as exc:
            outcome = _rollback_outcome(transaction, transactional_write=transactional_write)
            message = (
                str(exc)
                if isinstance(exc, _UnprovenWrite)
                else "database write postcondition was not proven"
            )
            raise ConnectorWriteError(message, outcome=outcome) from None
        try:
            transaction.commit()
        except Exception:
            raise ConnectorWriteError(
                "database commit outcome is unknown", outcome=WriteOutcome.UNKNOWN
            ) from None
        return expected_count
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                # A cleanup failure cannot negate a confirmed commit or turn it into a retry.
                pass
