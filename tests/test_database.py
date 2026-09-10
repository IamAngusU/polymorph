from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import (
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
    select,
    text,
)
from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
from sqlalchemy.dialects.postgresql.psycopg2 import PGDialect_psycopg2
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite
from sqlalchemy.engine import Connection
from sqlalchemy.engine.interfaces import Dialect

import polymorph.connectors.database as database_module
from polymorph.connectors.base import (
    AtomicBatchCapabilities,
    BatchWriteItem,
    DeliveryContext,
)
from polymorph.connectors.database import DatabaseConnector
from polymorph.errors import ConnectorError, ConnectorWriteError, WriteOutcome
from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.mapping import MappingStatus
from polymorph.models.schema import FieldDescriptor
from polymorph.models.types import DataType, FieldRole


def _batch_item(index: int, *, wire_bytes: int = 128) -> BatchWriteItem:
    return BatchWriteItem(
        values={"reference": f"order-{index}", "quantity": index},
        context=DeliveryContext(
            transfer_id="transfer-1",
            record_id=f"record-{index}",
            record_digest=f"{index:064x}",
            idempotency_key=f"{index + 1:064x}",
        ),
        wire_bytes=wire_bytes,
    )


def test_database_introspection_includes_foreign_key(tmp_path: Path) -> None:
    path = tmp_path / "test.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table("customers", metadata, Column("id", Integer, primary_key=True), Column("name", String))
    Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("customer_id", Integer, ForeignKey("customers.id"), nullable=False),
    )
    metadata.create_all(engine)

    schema = DatabaseConnector(url, "orders").inspect_schema()
    roles = {field.id: field.role for field in schema.fields}

    assert roles["id"] is FieldRole.PRIMARY_KEY
    assert roles["customer_id"] is FieldRole.FOREIGN_KEY
    assert schema.by_id()["id"].destination_generated
    assert not schema.by_id()["customer_id"].destination_generated
    assert schema.relations[0].target_container == "customers"


def test_database_introspection_marks_server_defaults_as_destination_generated(
    tmp_path: Path,
) -> None:
    path = tmp_path / "defaults.sqlite"
    engine = create_engine(f"sqlite:///{path}")
    metadata = MetaData()
    Table(
        "events",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("state", String, nullable=False, server_default=text("'new'")),
        Column("required", String, nullable=False),
    )
    metadata.create_all(engine)

    schema = DatabaseConnector(f"sqlite:///{path}", "events").inspect_schema()

    assert schema.by_id()["id"].destination_generated
    assert schema.by_id()["state"].destination_generated
    assert not schema.by_id()["required"].destination_generated


def test_database_secret_column_is_classified(tmp_path: Path) -> None:
    path = tmp_path / "secret.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "integrations",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("api_token", String),
    )
    metadata.create_all(engine)

    schema = DatabaseConnector(url, "integrations").inspect_schema()
    sensitivity = {field.id: field.sensitivity.value for field in schema.fields}
    assert sensitivity["api_token"] == "secret"


def test_unique_business_key_is_exposed_as_fk_lookup_alias(tmp_path: Path) -> None:
    path = tmp_path / "lookup-schema.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "customers",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("external_customer_number", String, nullable=False, unique=True),
    )
    Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("customer_id", Integer, ForeignKey("customers.id"), nullable=False),
    )
    metadata.create_all(engine)

    schema = DatabaseConnector(url, "orders").inspect_schema()
    customer_id = schema.by_id()["customer_id"]
    relation = schema.relation_for_source_field("customer_id")

    assert "external_customer_number" in customer_id.aliases
    assert relation is not None
    assert relation.lookup_key_names == ("external_customer_number",)
    assert relation.lookup_key("external_customer_number").data_type is DataType.STRING


def test_reflected_lookup_type_blocks_incompatible_natural_key_auto(tmp_path: Path) -> None:
    path = tmp_path / "typed-lookup-schema.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "customers",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("external_customer_number", Integer, nullable=False, unique=True),
    )
    Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("customer_id", Integer, ForeignKey("customers.id"), nullable=False),
    )
    metadata.create_all(engine)

    schema = DatabaseConnector(url, "orders").inspect_schema()
    relation = schema.relation_for_source_field("customer_id")
    source = FieldDescriptor(
        "customer_number",
        "external customer number",
        DataType.JSON,
        role=FieldRole.NATURAL_KEY,
    )

    assert relation is not None
    lookup_key = relation.lookup_key("external_customer_number")
    assert lookup_key is not None
    assert lookup_key.data_type is DataType.INTEGER
    assert HybridMatcher().decide(source, schema).status is not MappingStatus.AUTO


def test_partial_unique_index_is_not_exposed_as_global_fk_lookup_key(tmp_path: Path) -> None:
    path = tmp_path / "partial-unique-lookup.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "customers",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("external_number", String, nullable=False),
        Column("email", String, nullable=False),
        Column("active", Integer, nullable=False),
    )
    Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("customer_id", Integer, ForeignKey("customers.id"), nullable=False),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE UNIQUE INDEX uq_customers_email ON customers (email)"))
        connection.execute(
            text(
                "CREATE UNIQUE INDEX uq_active_external_number "
                "ON customers (external_number) WHERE active = 1"
            )
        )

    schema = DatabaseConnector(url, "orders").inspect_schema()
    relation = schema.relation_for_source_field("customer_id")

    assert relation is not None
    assert relation.lookup_key_names == ("email",)
    assert relation.lookup_key("email").data_type is DataType.STRING
    assert "external_number" not in schema.by_id()["customer_id"].aliases


@pytest.mark.parametrize(
    "reflected_index",
    [
        {"name": "uq_unresolved", "column_names": [None, "email"], "unique": True},
        {
            "name": "uq_expression",
            "column_names": ["email"],
            "expressions": ["lower(email)"],
            "unique": True,
        },
    ],
)
def test_unresolved_or_expression_unique_index_is_not_a_lookup_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reflected_index: dict[str, object],
) -> None:
    path = tmp_path / "unsafe-index-reflection.sqlite"
    engine = create_engine(f"sqlite:///{path}")
    metadata = MetaData()
    Table(
        "customers",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("email", String, nullable=False),
    )
    metadata.create_all(engine)
    inspector = inspect(engine)
    monkeypatch.setattr(
        inspector,
        "get_indexes",
        lambda table, schema=None: [reflected_index],
    )

    assert DatabaseConnector._unique_columns(inspector, "customers", None) == ("id",)


def test_composite_foreign_key_is_not_advertised_as_single_column_lookup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "composite-lookup.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "customers",
        metadata,
        Column("tenant_id", Integer, primary_key=True),
        Column("external_number", String, primary_key=True),
    )
    Table(
        "orders",
        metadata,
        Column("customer_tenant_id", Integer, nullable=False),
        Column("customer_external_number", String, nullable=False),
        ForeignKeyConstraint(
            ["customer_tenant_id", "customer_external_number"],
            ["customers.tenant_id", "customers.external_number"],
        ),
    )
    metadata.create_all(engine)

    schema = DatabaseConnector(url, "orders").inspect_schema()
    source = FieldDescriptor(
        "source_customer",
        "external number",
        DataType.STRING,
        role=FieldRole.NATURAL_KEY,
    )

    assert schema.relation_for_source_field("customer_tenant_id") is None
    assert schema.relation_for_source_field("customer_external_number") is None
    assert "external_number" not in schema.by_id()["customer_tenant_id"].aliases
    assert HybridMatcher().decide(source, schema).status is not MappingStatus.AUTO


def test_composite_parent_primary_key_columns_are_not_individually_unique(
    tmp_path: Path,
) -> None:
    path = tmp_path / "composite-parent-key.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "customers",
        metadata,
        Column("tenant_id", Integer, primary_key=True),
        Column("external_number", String, primary_key=True),
        Column("id", Integer, nullable=False, unique=True),
    )
    Table(
        "orders",
        metadata,
        Column("customer_id", Integer, ForeignKey("customers.id"), nullable=False),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        schema = connector.inspect_schema()
        relation = schema.relation_for_source_field("customer_id")

        assert relation is not None
        assert relation.lookup_keys == ()
        assert "tenant_id" not in schema.by_id()["customer_id"].aliases
        assert "external_number" not in schema.by_id()["customer_id"].aliases
        with pytest.raises(ConnectorError, match="not uniquely constrained"):
            connector.resolve_foreign_key(
                target_field_id="customer_id",
                match_column="external_number",
                value="C-42",
            )


def test_database_connector_context_manager_releases_sqlite_file(tmp_path: Path) -> None:
    import sqlite3
    from contextlib import closing

    path = tmp_path / "lifecycle.sqlite"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")

    with DatabaseConnector(f"sqlite:///{path}", "items") as connector:
        assert connector.inspect_schema().id == "db:items"
        assert connector.capabilities.transactional_write
        assert connector.engine.hide_parameters

    moved = tmp_path / "released.sqlite"
    path.replace(moved)
    assert moved.exists()


def test_database_connector_write_records_persists_rows(tmp_path: Path) -> None:
    path = tmp_path / "write-success.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
        Column("quantity", Integer, nullable=False),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        assert (
            connector.write_records(
                [
                    {"reference": "order-1", "quantity": 2},
                    {"reference": "order-2", "quantity": 5},
                ]
            )
            == 2
        )
        reflected_table = connector._table()
        assert connector._table() is reflected_table

    with engine.connect() as connection:
        rows = connection.execute(
            select(orders.c.reference, orders.c.quantity).order_by(orders.c.reference)
        ).all()
    assert [tuple(row) for row in rows] == [("order-1", 2), ("order-2", 5)]


def test_database_connector_constraint_error_rolls_back_all_rows(tmp_path: Path) -> None:
    path = tmp_path / "write-constraint.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
    )
    metadata.create_all(engine)

    with (
        DatabaseConnector(url, "orders") as connector,
        pytest.raises(ConnectorWriteError) as caught,
    ):
        connector.write_records(
            [
                {"reference": "duplicate"},
                {"reference": "duplicate"},
            ]
        )

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


@pytest.mark.parametrize("reported_rowcount", (0, True, 1.0, None, -1))
def test_database_scalar_write_rejects_unproven_rowcount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported_rowcount: object,
) -> None:
    path = tmp_path / "scalar-unproven-rowcount.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        connector._table()
        connector.capabilities = replace(
            connector.capabilities,
            atomic_batch_write=None,
        )
        original_execute = Connection.execute

        def execute_with_unproven_rowcount(self, statement, *args, **kwargs):
            result = original_execute(self, statement, *args, **kwargs)
            if getattr(statement, "is_insert", False):
                result.rowcount = reported_rowcount
            return result

        monkeypatch.setattr(Connection, "execute", execute_with_unproven_rowcount)
        with pytest.raises(ConnectorWriteError) as caught:
            connector.write_records([{"reference": "not-delivered"}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


@pytest.mark.parametrize("reported_rowcount", (0, True, 2.0, None, -1))
def test_database_multi_write_rejects_unproven_rowcount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported_rowcount: object,
) -> None:
    path = tmp_path / "multi-unproven-rowcount.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        connector._table()
        connector.capabilities = replace(
            connector.capabilities,
            atomic_batch_write=None,
        )
        original_execute = Connection.execute

        def execute_with_unproven_rowcount(self, statement, *args, **kwargs):
            result = original_execute(self, statement, *args, **kwargs)
            if getattr(statement, "is_insert", False):
                result.rowcount = reported_rowcount
            return result

        monkeypatch.setattr(Connection, "execute", execute_with_unproven_rowcount)
        with pytest.raises(ConnectorWriteError) as caught:
            connector.write_records(
                [
                    {"reference": "not-delivered-1"},
                    {"reference": "not-delivered-2"},
                ]
            )

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


@pytest.mark.parametrize(
    ("record_count", "sane_attribute"),
    (
        (1, "supports_sane_rowcount"),
        (2, "supports_sane_multi_rowcount"),
    ),
)
def test_database_write_rejects_dialect_without_sane_rowcount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_count: int,
    sane_attribute: str,
) -> None:
    path = tmp_path / f"nonsane-rowcount-{record_count}.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        connector._table()
        connector.capabilities = replace(
            connector.capabilities,
            atomic_batch_write=None,
        )
        monkeypatch.setattr(connector.engine.dialect, sane_attribute, False)
        with pytest.raises(ConnectorWriteError) as caught:
            connector.write_records(
                [{"reference": f"not-delivered-{index}"} for index in range(record_count)]
            )

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


def test_database_scalar_trigger_skip_is_not_reported_as_delivered(tmp_path: Path) -> None:
    path = tmp_path / "scalar-trigger-ignore.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TRIGGER ignore_order
                BEFORE INSERT ON orders
                BEGIN
                    SELECT RAISE(IGNORE);
                END
                """
            )
        )

    with (
        DatabaseConnector(url, "orders") as connector,
        pytest.raises(ConnectorWriteError) as caught,
    ):
        connector.write_records([{"reference": "silently-skipped"}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


def test_atomic_batch_limit_types_are_strictly_positive() -> None:
    for kwargs in (
        {"max_records": 0, "max_wire_bytes": 1},
        {"max_records": True, "max_wire_bytes": 1},
        {"max_records": 1, "max_wire_bytes": 0},
        {"max_records": 1, "max_wire_bytes": False},
    ):
        with pytest.raises(ValueError, match="positive integer"):
            AtomicBatchCapabilities(**kwargs)

    with pytest.raises(ValueError, match="positive integer"):
        BatchWriteItem(
            values={},
            context=DeliveryContext("transfer", "record", "0" * 64, "1" * 64),
            wire_bytes=0,
        )


@pytest.mark.parametrize(
    ("dialect", "transactional", "atomic_batch"),
    (
        (SQLiteDialect_pysqlite(), True, True),
        (PGDialect_psycopg(), True, True),
        (PGDialect_psycopg2(), True, False),
    ),
)
def test_atomic_batch_capability_requires_a_verifiable_dialect_driver(
    monkeypatch: pytest.MonkeyPatch,
    dialect: Dialect,
    transactional: bool,
    atomic_batch: bool,
) -> None:
    class FakeEngine:
        def __init__(self, engine_dialect: Dialect) -> None:
            self.dialect = engine_dialect

        def dispose(self) -> None:
            return None

    monkeypatch.setattr(
        database_module,
        "create_engine",
        lambda *args, **kwargs: FakeEngine(dialect),
    )

    connector = DatabaseConnector("unused", "orders")

    assert connector.capabilities.write_records
    assert connector.capabilities.transactional_write is transactional
    assert (connector.capabilities.atomic_batch_write is not None) is atomic_batch


@pytest.mark.parametrize(
    "sane_attribute",
    ("supports_sane_rowcount", "supports_sane_multi_rowcount"),
)
def test_atomic_batch_capability_requires_sane_rowcount(
    monkeypatch: pytest.MonkeyPatch,
    sane_attribute: str,
) -> None:
    dialect = PGDialect_psycopg()
    monkeypatch.setattr(dialect, sane_attribute, False)

    class FakeEngine:
        def __init__(self) -> None:
            self.dialect = dialect

        def dispose(self) -> None:
            return None

    monkeypatch.setattr(database_module, "create_engine", lambda *args, **kwargs: FakeEngine())

    connector = DatabaseConnector("unused", "orders")

    assert connector.capabilities.transactional_write
    assert connector.capabilities.atomic_batch_write is None


def test_database_atomic_batch_writes_all_rows_in_one_transaction(tmp_path: Path) -> None:
    path = tmp_path / "atomic-batch.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
        Column("quantity", Integer, nullable=False),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        capability = connector.capabilities.atomic_batch_write
        assert capability is not None
        assert capability.max_records == 1_000
        assert capability.max_wire_bytes == 64 * 1024 * 1024
        connector._table()
        begins = 0
        commits = 0

        def count_begin(_connection) -> None:
            nonlocal begins
            begins += 1

        def count_commit(_connection) -> None:
            nonlocal commits
            commits += 1

        from sqlalchemy import event

        event.listen(connector.engine, "begin", count_begin)
        event.listen(connector.engine, "commit", count_commit)
        assert connector.write_batch((_batch_item(1), _batch_item(2))) == 2
        event.remove(connector.engine, "begin", count_begin)
        event.remove(connector.engine, "commit", count_commit)

    assert begins == 1
    assert commits == 1
    with engine.connect() as connection:
        rows = connection.execute(
            select(orders.c.reference, orders.c.quantity).order_by(orders.c.reference)
        ).all()
    assert [tuple(row) for row in rows] == [("order-1", 1), ("order-2", 2)]


@pytest.mark.parametrize(
    "case",
    ("empty", "record_count", "wire_bytes", "duplicate", "unknown_column"),
)
def test_database_atomic_batch_rejects_invalid_batch_before_write(
    tmp_path: Path,
    case: str,
) -> None:
    path = tmp_path / f"invalid-batch-{case}.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
        Column("quantity", Integer, nullable=False),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        capability = connector.capabilities.atomic_batch_write
        assert capability is not None
        first = _batch_item(1)
        if case == "empty":
            items: tuple[BatchWriteItem, ...] = ()
        elif case == "record_count":
            items = tuple(first for _ in range(capability.max_records + 1))
        elif case == "wire_bytes":
            items = (_batch_item(1, wire_bytes=capability.max_wire_bytes + 1),)
        elif case == "duplicate":
            items = (first, first)
        else:
            items = (
                BatchWriteItem(
                    values={"reference": "order-1", "quantity": 1, "unexpected": "value"},
                    context=first.context,
                    wire_bytes=first.wire_bytes,
                ),
            )

        with pytest.raises(ConnectorWriteError) as caught:
            connector.write_batch(items)

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


def test_database_atomic_batch_constraint_error_rolls_back_every_item(tmp_path: Path) -> None:
    path = tmp_path / "atomic-batch-rollback.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
        Column("quantity", Integer, nullable=False),
    )
    metadata.create_all(engine)
    first = _batch_item(1)
    conflicting = BatchWriteItem(
        values={"reference": "order-1", "quantity": 2},
        context=DeliveryContext("transfer-1", "record-2", "2" * 64, "3" * 64),
        wire_bytes=128,
    )

    with (
        DatabaseConnector(url, "orders") as connector,
        pytest.raises(ConnectorWriteError) as caught,
    ):
        connector.write_batch((first, conflicting))

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


def test_database_atomic_batch_silent_trigger_skip_rolls_back_every_item(
    tmp_path: Path,
) -> None:
    path = tmp_path / "atomic-batch-trigger-ignore.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
        Column("quantity", Integer, nullable=False),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TRIGGER ignore_second_order
                BEFORE INSERT ON orders
                WHEN NEW.reference = 'order-2'
                BEGIN
                    SELECT RAISE(IGNORE);
                END
                """
            )
        )

    with (
        DatabaseConnector(url, "orders") as connector,
        pytest.raises(ConnectorWriteError) as caught,
    ):
        connector.write_batch((_batch_item(1), _batch_item(2), _batch_item(3)))

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    with engine.connect() as connection:
        assert connection.execute(select(orders)).all() == []


def test_database_atomic_batch_rowcount_mismatch_with_failed_rollback_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.engine.base import RootTransaction

    path = tmp_path / "atomic-batch-trigger-ignore-rollback-failure.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
        Column("quantity", Integer, nullable=False),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TRIGGER ignore_second_order
                BEFORE INSERT ON orders
                WHEN NEW.reference = 'order-2'
                BEGIN
                    SELECT RAISE(IGNORE);
                END
                """
            )
        )

    with DatabaseConnector(url, "orders") as connector:
        connector._table()

        def fail_rollback(_transaction: RootTransaction) -> None:
            raise OSError("simulated lost rollback acknowledgement")

        monkeypatch.setattr(RootTransaction, "rollback", fail_rollback)
        with pytest.raises(ConnectorWriteError) as caught:
            connector.write_batch((_batch_item(1), _batch_item(2), _batch_item(3)))

    assert caught.value.outcome is WriteOutcome.UNKNOWN


def test_database_atomic_batch_commit_failure_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.engine.base import RootTransaction

    path = tmp_path / "atomic-batch-commit-failure.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("reference", String, nullable=False, unique=True),
        Column("quantity", Integer, nullable=False),
    )
    metadata.create_all(engine)

    with DatabaseConnector(url, "orders") as connector:
        connector._table()

        def fail_commit(_transaction) -> None:
            raise OSError("simulated lost commit acknowledgement")

        monkeypatch.setattr(RootTransaction, "commit", fail_commit)
        with pytest.raises(ConnectorWriteError) as caught:
            connector.write_batch((_batch_item(1), _batch_item(2)))

    assert caught.value.outcome is WriteOutcome.UNKNOWN
