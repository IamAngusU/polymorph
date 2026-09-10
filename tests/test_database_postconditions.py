from __future__ import annotations

from collections.abc import Iterator
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    String,
    Table,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.engine import Connection, RootTransaction

from polymorph.connectors.base import BatchWriteItem, DeliveryContext
from polymorph.connectors.database import DatabaseConnector
from polymorph.errors import ConnectorWriteError, WriteOutcome


@pytest.fixture
def database(tmp_path: Path) -> Iterator[DatabaseConnector]:
    connector = DatabaseConnector(f"sqlite:///{tmp_path / 'proof.sqlite'}", "records")
    table = Table(
        "records",
        MetaData(),
        Column("id", Integer, primary_key=True),
        Column("reference", String, unique=True, nullable=False),
        Column("value", String),
        Column("state", String, server_default=text("'new'")),
    )
    table.create(connector.engine)
    connector._table()
    try:
        yield connector
    finally:
        connector.close()


def _write(connector: DatabaseConnector, mode: str, rows: list[dict[str, object]]) -> int:
    if mode == "scalar":
        return connector.write_records(rows)
    return connector.write_batch(
        tuple(
            BatchWriteItem(
                values=row,
                context=DeliveryContext("proof", str(i), f"{i:064x}", f"{i + 1:064x}"),
                wire_bytes=256,
            )
            for i, row in enumerate(rows)
        )
    )


def _all_rows(connector: DatabaseConnector) -> list[dict[str, object]]:
    return list(connector.iter_records())


@pytest.mark.parametrize("mode", ["scalar", "batch"])
@pytest.mark.parametrize("operation", ["delete", "rewrite", "rewrite_previous"])
def test_after_trigger_cannot_hide_a_missing_or_changed_write(
    database: DatabaseConnector, mode: str, operation: str
) -> None:
    body = {
        "delete": "DELETE FROM records WHERE id = NEW.id;",
        "rewrite": "UPDATE records SET value = 'changed' WHERE id = NEW.id;",
        "rewrite_previous": "UPDATE records SET value = 'changed' WHERE reference = 'first';",
    }[operation]
    with database.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER corrupt AFTER INSERT ON records "
            "WHEN NEW.reference = 'second' BEGIN " + body + " END"
        )
    with pytest.raises(ConnectorWriteError) as caught:
        _write(
            database,
            mode,
            [{"reference": "first", "value": "one"}, {"reference": "second", "value": "two"}],
        )
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert _all_rows(database) == []


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_proof_checks_values_per_explicit_identity(database: DatabaseConnector, mode: str) -> None:
    with database.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER swap AFTER INSERT ON records WHEN NEW.id = 2 BEGIN "
            "UPDATE records SET value = CASE id WHEN 1 THEN 'two' ELSE 'one' END; END"
        )
    with pytest.raises(ConnectorWriteError):
        _write(
            database,
            mode,
            [
                {"id": 1, "reference": "first", "value": "one"},
                {"id": 2, "reference": "second", "value": "two"},
            ],
        )
    assert _all_rows(database) == []


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_unmapped_generated_column_may_be_filled_by_trigger(
    database: DatabaseConnector, mode: str
) -> None:
    with database.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER enrich AFTER INSERT ON records BEGIN "
            "UPDATE records SET state = 'enriched' WHERE id = NEW.id; END"
        )
    assert _write(database, mode, [{"reference": "first", "value": "one"}]) == 1
    assert _all_rows(database)[0]["state"] == "enriched"


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_heterogeneous_rows_are_not_silently_projected_to_first_row(
    database: DatabaseConnector, mode: str
) -> None:
    with pytest.raises(ConnectorWriteError) as caught:
        _write(database, mode, [{"reference": "first"}, {"reference": "second", "value": "keep"}])
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert _all_rows(database) == []


@pytest.mark.parametrize("mode", ["scalar", "batch"])
@pytest.mark.parametrize("reported", [0, True, 1.0, None, -1])
def test_existing_rowcount_gate_is_preserved(
    database: DatabaseConnector, monkeypatch: pytest.MonkeyPatch, mode: str, reported: object
) -> None:
    original = Connection.execute

    def execute(self, statement, *args, **kwargs):
        result = original(self, statement, *args, **kwargs)
        if getattr(statement, "is_insert", False):
            result.rowcount = reported
        return result

    monkeypatch.setattr(Connection, "execute", execute)
    with pytest.raises(ConnectorWriteError) as caught:
        _write(database, mode, [{"reference": "first", "value": "one"}])
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert _all_rows(database) == []


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_readback_failure_rolls_back_without_exposing_payload(
    database: DatabaseConnector, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    original = Connection.execute
    canary = "private-test-value-should-not-appear"

    def execute(self, statement, *args, **kwargs):
        if getattr(statement, "is_select", False):
            raise RuntimeError(canary)
        return original(self, statement, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Connection, "execute", execute)
        with pytest.raises(ConnectorWriteError) as caught:
            _write(database, mode, [{"reference": "first", "value": canary}])
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert canary not in str(caught.value)
    assert caught.value.__suppress_context__
    assert _all_rows(database) == []


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_commit_ack_loss_remains_unknown(
    database: DatabaseConnector, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    original = RootTransaction.commit

    def commit(self):
        original(self)
        raise OSError("simulated lost commit acknowledgement")

    with monkeypatch.context() as patch:
        patch.setattr(RootTransaction, "commit", commit)
        with pytest.raises(ConnectorWriteError) as caught:
            _write(database, mode, [{"reference": "first", "value": "one"}])
    assert caught.value.outcome is WriteOutcome.UNKNOWN
    assert len(_all_rows(database)) == 1


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_close_error_does_not_undo_confirmed_commit(
    database: DatabaseConnector, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    original = Connection.close

    def close(self):
        original(self)
        raise OSError("simulated close error")

    with monkeypatch.context() as patch:
        patch.setattr(Connection, "close", close)
        assert _write(database, mode, [{"reference": "first", "value": "one"}]) == 1
    assert len(_all_rows(database)) == 1


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_rollback_failure_is_not_retry_safe(
    database: DatabaseConnector, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    original = RootTransaction.rollback
    with database.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER corrupt AFTER INSERT ON records BEGIN "
            "DELETE FROM records WHERE id = NEW.id; END"
        )

    def rollback(self):
        original(self)
        raise OSError("simulated rollback acknowledgement loss")

    with monkeypatch.context() as patch:
        patch.setattr(RootTransaction, "rollback", rollback)
        with pytest.raises(ConnectorWriteError) as caught:
            _write(database, mode, [{"reference": "first", "value": "one"}])
    assert caught.value.outcome is WriteOutcome.UNKNOWN


@pytest.mark.parametrize("count", [1, 3])
@pytest.mark.parametrize("corrupt", [False, True])
def test_generated_primary_keys_are_read_back(tmp_path: Path, count: int, corrupt: bool) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'generated.sqlite'}", "records") as connector:
        Table(
            "records", MetaData(), Column("id", Integer, primary_key=True), Column("value", String)
        ).create(connector.engine)
        if corrupt:
            with connector.engine.begin() as connection:
                connection.exec_driver_sql(
                    "CREATE TRIGGER corrupt AFTER INSERT ON records BEGIN "
                    "DELETE FROM records WHERE id = NEW.id; END"
                )
            with pytest.raises(ConnectorWriteError) as caught:
                _write(connector, "batch", [{"value": "same"} for _ in range(count)])
            assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
            assert _all_rows(connector) == []
        else:
            assert _write(connector, "batch", [{"value": "same"} for _ in range(count)]) == count
            assert len(_all_rows(connector)) == count


def test_composite_key_proof(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'composite.sqlite'}", "records") as connector:
        Table(
            "records",
            MetaData(),
            Column("tenant", String, primary_key=True),
            Column("number", Integer, primary_key=True),
            Column("value", String),
        ).create(connector.engine)
        rows = [
            {"tenant": "a", "number": 1, "value": "x"},
            {"tenant": "b", "number": 1, "value": "y"},
        ]
        assert _write(connector, "batch", rows) == 2
        assert len(_all_rows(connector)) == 2


def test_unique_identity_without_primary_key(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'unique.sqlite'}", "records") as connector:
        Table(
            "records",
            MetaData(),
            Column("a", String),
            Column("b", Integer),
            Column("value", String),
            UniqueConstraint("a", "b"),
        ).create(connector.engine)
        assert _write(connector, "batch", [{"a": "x", "b": 1, "value": "v"}]) == 1


def test_unkeyed_table_is_rejected_without_inserting(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'unkeyed.sqlite'}", "records") as connector:
        Table("records", MetaData(), Column("value", String)).create(connector.engine)
        with pytest.raises(ConnectorWriteError) as caught:
            _write(connector, "scalar", [{"value": "unprovable"}])
        assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
        assert _all_rows(connector) == []


def test_partial_unique_index_is_not_a_proof_key(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'partial.sqlite'}", "records") as connector:
        Table("records", MetaData(), Column("value", String), Column("active", Integer)).create(
            connector.engine
        )
        with connector.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE UNIQUE INDEX active_value ON records(value) WHERE active = 1"
            )
        with pytest.raises(ConnectorWriteError):
            _write(connector, "scalar", [{"value": "unprovable", "active": 0}])
        assert _all_rows(connector) == []


def test_large_readback_is_chunked_but_single_transaction(database: DatabaseConnector) -> None:
    counts = {"begin": 0, "commit": 0, "select": 0}

    def begin(connection):
        counts["begin"] += 1

    def commit(connection):
        counts["commit"] += 1

    def execute(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            counts["select"] += 1
            assert len(parameters) <= 502

    event.listen(database.engine, "begin", begin)
    event.listen(database.engine, "commit", commit)
    event.listen(database.engine, "before_cursor_execute", execute)
    rows = [{"reference": str(i), "value": "v"} for i in range(1000)]
    try:
        assert _write(database, "batch", rows) == 1000
    finally:
        event.remove(database.engine, "begin", begin)
        event.remove(database.engine, "commit", commit)
        event.remove(database.engine, "before_cursor_execute", execute)
    assert counts == {"begin": 1, "commit": 1, "select": 2}


def test_native_value_roundtrip(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'native.sqlite'}", "records") as connector:
        Table(
            "records",
            MetaData(),
            Column("id", Integer, primary_key=True),
            Column("amount", Numeric(12, 2)),
            Column("flag", Boolean),
            Column("day", Date),
            Column("stamp", DateTime),
            Column("data", JSON),
            Column("secret", LargeBinary),
        ).create(connector.engine)
        row: dict[str, object] = {
            "id": 1,
            "amount": Decimal("1234.50"),
            "flag": True,
            "day": date(2026, 9, 11),
            "stamp": datetime(2026, 9, 11, 10, 11, 12),
            "data": {"x": [1, True, None]},
            "secret": b"\x00\xff\x01",
        }
        assert _write(connector, "batch", [row]) == 1


def test_json_bool_is_not_numeric_one(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'json.sqlite'}", "records") as connector:
        Table(
            "records", MetaData(), Column("id", Integer, primary_key=True), Column("data", JSON)
        ).create(connector.engine)
        with connector.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TRIGGER corrupt AFTER INSERT ON records BEGIN "
                "UPDATE records SET data = '{\"flag\": 1}' WHERE id = NEW.id; END"
            )
        with pytest.raises(ConnectorWriteError):
            _write(connector, "batch", [{"id": 1, "data": {"flag": True}}])
        assert _all_rows(connector) == []


def test_lossy_decimal_rounding_is_rejected(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'decimal.sqlite'}", "records") as connector:
        Table(
            "records",
            MetaData(),
            Column("id", Integer, primary_key=True),
            Column("value", Numeric(12, 2)),
        ).create(connector.engine)
        with pytest.raises(ConnectorWriteError):
            _write(connector, "batch", [{"id": 1, "value": Decimal("1.234")}])
        assert _all_rows(connector) == []


def test_exact_integer_to_decimal_widening_is_allowed(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'widen.sqlite'}", "records") as connector:
        Table(
            "records",
            MetaData(),
            Column("id", Integer, primary_key=True),
            Column("value", Numeric(12, 2)),
        ).create(connector.engine)
        assert _write(connector, "batch", [{"id": 1, "value": 42}]) == 1


def test_expected_json_values_are_frozen_before_driver_callbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'mutation.sqlite'}", "records") as connector:
        Table(
            "records", MetaData(), Column("id", Integer, primary_key=True), Column("data", JSON)
        ).create(connector.engine)
        connector._table()
        payload = {"value": "approved"}
        original = Connection.execute

        def execute(self, statement, *args, **kwargs):
            if getattr(statement, "is_insert", False):
                payload["value"] = "changed-after-validation"
            return original(self, statement, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(Connection, "execute", execute)
            with pytest.raises(ConnectorWriteError) as caught:
                _write(connector, "batch", [{"id": 1, "data": payload}])
        assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
        assert _all_rows(connector) == []


def test_generated_identity_order_does_not_determine_row_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.engine import CursorResult

    with DatabaseConnector(f"sqlite:///{tmp_path / 'order.sqlite'}", "records") as connector:
        Table(
            "records", MetaData(), Column("id", Integer, primary_key=True), Column("value", String)
        ).create(connector.engine)
        original = CursorResult.fetchmany

        def fetchmany(self, size=None):
            rows = original(self, size)
            if self.is_insert:
                return list(reversed(rows))
            return rows

        with monkeypatch.context() as patch:
            patch.setattr(CursorResult, "fetchmany", fetchmany)
            assert _write(connector, "batch", [{"value": "a"}, {"value": "b"}]) == 2
        assert sorted(row["value"] for row in _all_rows(connector)) == ["a", "b"]


def test_generated_batch_rejects_duplicate_returned_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.engine import CursorResult

    with DatabaseConnector(f"sqlite:///{tmp_path / 'duplicate.sqlite'}", "records") as connector:
        Table(
            "records", MetaData(), Column("id", Integer, primary_key=True), Column("value", String)
        ).create(connector.engine)
        original = CursorResult.fetchmany

        def fetchmany(self, size=None):
            rows = original(self, size)
            return [rows[0]] * len(rows) if self.is_insert and rows else rows

        with monkeypatch.context() as patch:
            patch.setattr(CursorResult, "fetchmany", fetchmany)
            with pytest.raises(ConnectorWriteError) as caught:
                _write(connector, "batch", [{"value": "same"}, {"value": "same"}])
        assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
        assert _all_rows(connector) == []


def test_generated_batch_requires_driver_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'no-returning.sqlite'}", "records") as connector:
        Table(
            "records", MetaData(), Column("id", Integer, primary_key=True), Column("value", String)
        ).create(connector.engine)
        monkeypatch.setattr(connector.engine.dialect, "insert_executemany_returning", False)
        with pytest.raises(ConnectorWriteError) as caught:
            _write(connector, "batch", [{"value": "a"}, {"value": "b"}])
        assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
        assert _all_rows(connector) == []


@pytest.mark.parametrize("mode", ["scalar", "batch"])
def test_autocommit_cannot_invalidate_rollback_contract(
    database: DatabaseConnector, mode: str
) -> None:
    database.engine = database.engine.execution_options(isolation_level="AUTOCOMMIT")
    with pytest.raises(ConnectorWriteError) as caught:
        _write(database, mode, [{"reference": "first", "value": "one"}])
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert _all_rows(database) == []


def test_scalar_iterable_is_bounded_before_any_insert(database: DatabaseConnector) -> None:
    consumed = 0

    def rows():
        nonlocal consumed
        while True:
            consumed += 1
            if consumed > 1001:
                raise AssertionError("unbounded iterable consumed beyond its budget")
            yield {"reference": str(consumed), "value": "one"}

    with pytest.raises(ConnectorWriteError) as caught:
        database.write_records(rows())
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert consumed == 1001
    assert _all_rows(database) == []


def test_begin_failure_closes_connection(
    database: DatabaseConnector, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_close = Connection.close
    closed = 0

    def begin(self):
        raise OSError("transaction-start-secret")

    def close(self):
        nonlocal closed
        closed += 1
        original_close(self)

    with monkeypatch.context() as patch:
        patch.setattr(Connection, "begin", begin)
        patch.setattr(Connection, "close", close)
        with pytest.raises(ConnectorWriteError) as caught:
            _write(database, "scalar", [{"reference": "first", "value": "one"}])
    assert closed == 1
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert "secret" not in str(caught.value)
    assert _all_rows(database) == []


def test_postgresql_forces_deferred_triggers_before_readback(
    database: DatabaseConnector, monkeypatch: pytest.MonkeyPatch
) -> None:
    # This checks sequencing only, not a live PostgreSQL server or its driver.
    events = []
    original = Connection.execute

    def execute(self, statement, *args, **kwargs):
        if getattr(statement, "is_insert", False):
            events.append("insert")
        elif getattr(statement, "is_select", False):
            events.append("readback")
        return original(self, statement, *args, **kwargs)

    def exec_driver_sql(self, statement, *args, **kwargs):
        assert statement == "SET CONSTRAINTS ALL IMMEDIATE"
        events.append("deferred-check")

    with monkeypatch.context() as patch:
        patch.setattr(database.engine.dialect, "name", "postgresql")
        patch.setattr(Connection, "execute", execute)
        patch.setattr(Connection, "exec_driver_sql", exec_driver_sql)
        assert _write(database, "scalar", [{"reference": "first", "value": "one"}]) == 1
    assert events == ["insert", "deferred-check", "readback"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), Decimal("NaN")])
def test_nonfinite_values_fail_before_insert(database: DatabaseConnector, value: object) -> None:
    with pytest.raises(ConnectorWriteError) as caught:
        _write(database, "scalar", [{"reference": "first", "value": value}])
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert _all_rows(database) == []


def test_nested_json_comparison_budget_is_bounded(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'depth.sqlite'}", "records") as connector:
        Table(
            "records", MetaData(), Column("id", Integer, primary_key=True), Column("data", JSON)
        ).create(connector.engine)
        nested: object = None
        for _ in range(66):
            nested = [nested]
        with pytest.raises(ConnectorWriteError) as caught:
            _write(connector, "scalar", [{"id": 1, "data": nested}])
        assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
        assert _all_rows(connector) == []


def test_generated_composite_identity_can_include_supplied_part(tmp_path: Path) -> None:
    with DatabaseConnector(f"sqlite:///{tmp_path / 'mixed-key.sqlite'}", "records") as connector:
        Table(
            "records",
            MetaData(),
            Column("tenant", String, primary_key=True),
            Column("number", Integer, primary_key=True, server_default=text("42")),
            Column("value", String),
        ).create(connector.engine)
        assert _write(connector, "batch", [{"tenant": "a", "value": "x"}]) == 1
        assert _all_rows(connector) == [{"tenant": "a", "number": 42, "value": "x"}]
