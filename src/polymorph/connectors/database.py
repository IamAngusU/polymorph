from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from threading import Lock

from sqlalchemy import MetaData, Table, create_engine, inspect, select
from sqlalchemy.engine import URL, CursorResult, Engine
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.sql.sqltypes import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Integer,
    LargeBinary,
    Numeric,
    String,
)

from polymorph.classification import classify_field_name, infer_role
from polymorph.errors import ConnectorError, ConnectorWriteError, WriteOutcome
from polymorph.models.schema import (
    FieldDescriptor,
    LookupKeyDescriptor,
    RelationDescriptor,
    SchemaDescriptor,
)
from polymorph.models.types import DataType, FieldRole, Sensitivity
from polymorph.secrets import SecretProvider

from .base import (
    AtomicBatchCapabilities,
    BatchWriteItem,
    ConnectorCapabilities,
    DeliveryContext,
)

_TRANSACTIONAL_DIALECTS = frozenset({"postgresql", "sqlite"})
_VERIFIABLE_ATOMIC_BATCH_DRIVERS = frozenset(
    {
        ("postgresql", "psycopg"),
        ("sqlite", "pysqlite"),
    }
)
DATABASE_ATOMIC_BATCH_MAX_RECORDS = 1_000
DATABASE_ATOMIC_BATCH_MAX_WIRE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class DatabaseEndpoint:
    drivername: str
    database: str
    username: str | None = None
    password_ref: str | None = None
    host: str | None = None
    port: int | None = None
    query: Mapping[str, str] = field(default_factory=dict)

    def sqlalchemy_url(self, provider: SecretProvider | None = None) -> URL:
        password = None
        if self.password_ref is not None:
            if provider is None:
                raise ConnectorError("database credential provider is required")
            password = provider.get(self.password_ref)
        return URL.create(
            self.drivername,
            username=self.username,
            password=password,
            host=self.host,
            port=self.port,
            database=self.database,
            query=dict(self.query),
        )


def _sql_type(value: object) -> DataType:
    if isinstance(value, Integer):
        return DataType.INTEGER
    if isinstance(value, Numeric):
        return DataType.DECIMAL
    if isinstance(value, Boolean):
        return DataType.BOOLEAN
    if isinstance(value, DateTime):
        return DataType.DATETIME
    if isinstance(value, Date):
        return DataType.DATE
    if isinstance(value, LargeBinary):
        return DataType.BINARY
    if isinstance(value, JSON):
        return DataType.JSON
    if isinstance(value, String):
        return DataType.STRING
    return DataType.UNKNOWN


class DatabaseConnector:
    def __init__(
        self,
        url: str | URL | DatabaseEndpoint,
        table: str,
        *,
        schema: str | None = None,
        sensitivity_overrides: Mapping[str, Sensitivity] | None = None,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        resolved_url: str | URL
        if isinstance(url, DatabaseEndpoint):
            resolved_url = url.sqlalchemy_url(secret_provider)
        else:
            resolved_url = url
        self.engine: Engine = create_engine(
            resolved_url,
            future=True,
            hide_parameters=True,
        )
        dialect = self.engine.dialect
        transactional_write = dialect.name in _TRANSACTIONAL_DIALECTS
        verifiable_atomic_batch = (
            dialect.name,
            dialect.driver,
        ) in _VERIFIABLE_ATOMIC_BATCH_DRIVERS and (
            dialect.supports_sane_rowcount and dialect.supports_sane_multi_rowcount
        )
        self.capabilities = ConnectorCapabilities(
            read_schema=True,
            read_records=True,
            write_records=True,
            transactional_write=transactional_write,
            atomic_batch_write=(
                AtomicBatchCapabilities(
                    max_records=DATABASE_ATOMIC_BATCH_MAX_RECORDS,
                    max_wire_bytes=DATABASE_ATOMIC_BATCH_MAX_WIRE_BYTES,
                )
                if verifiable_atomic_batch
                else None
            ),
        )
        self.table_name = table
        self.schema_name = schema
        self.sensitivity_overrides = dict(sensitivity_overrides or {})
        self._reflected_table: Table | None = None
        self._reflection_lock = Lock()
        self._closed = False

    def __enter__(self) -> DatabaseConnector:
        if self._closed:
            raise RuntimeError("database connector is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self.engine.dispose()
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("database connector is closed")

    def _table(self) -> Table:
        self._ensure_open()
        reflected_table = self._reflected_table
        if reflected_table is not None:
            return reflected_table

        with self._reflection_lock:
            self._ensure_open()
            reflected_table = self._reflected_table
            if reflected_table is None:
                metadata = MetaData()
                reflected_table = Table(
                    self.table_name,
                    metadata,
                    schema=self.schema_name,
                    autoload_with=self.engine,
                )
                self._reflected_table = reflected_table
            return reflected_table

    @staticmethod
    def _unique_columns(
        inspector: Inspector,
        table: str,
        schema: str | None,
    ) -> tuple[str, ...]:
        primary_columns = inspector.get_pk_constraint(table, schema=schema).get(
            "constrained_columns"
        )
        unique = (
            {primary_columns[0]}
            if isinstance(primary_columns, (list, tuple))
            and len(primary_columns) == 1
            and isinstance(primary_columns[0], str)
            and primary_columns[0]
            else set()
        )
        for constraint in inspector.get_unique_constraints(table, schema=schema):
            constraint_columns = constraint.get("column_names")
            if (
                isinstance(constraint_columns, (list, tuple))
                and len(constraint_columns) == 1
                and isinstance(constraint_columns[0], str)
                and constraint_columns[0]
            ):
                unique.add(constraint_columns[0])
        for index in inspector.get_indexes(table, schema=schema):
            if not index.get("unique") or "expressions" in index:
                continue
            dialect_options = index.get("dialect_options")
            if dialect_options is not None and (
                not isinstance(dialect_options, Mapping)
                or any(
                    not isinstance(option, str) or option.endswith("_where")
                    for option in dialect_options
                )
            ):
                # Partial/filtered indexes only prove uniqueness for rows matching
                # their predicate, not for the complete lookup domain.
                continue
            index_columns = index.get("column_names")
            if (
                isinstance(index_columns, (list, tuple))
                and len(index_columns) == 1
                and isinstance(index_columns[0], str)
                and index_columns[0]
            ):
                unique.add(index_columns[0])
        return tuple(sorted(unique))

    def inspect_schema(self) -> SchemaDescriptor:
        self._ensure_open()
        inspector = inspect(self.engine)
        reflected_table = self._table()
        generated = {
            column.name
            for column in reflected_table.columns
            if column.server_default is not None
            or column.identity is not None
            or column.computed is not None
            or reflected_table.autoincrement_column is column
        }
        columns = inspector.get_columns(self.table_name, schema=self.schema_name)
        primary = set(
            inspector.get_pk_constraint(self.table_name, schema=self.schema_name).get(
                "constrained_columns"
            )
            or []
        )
        foreign_keys = inspector.get_foreign_keys(self.table_name, schema=self.schema_name)
        foreign_columns = {
            column for fk in foreign_keys for column in fk.get("constrained_columns", [])
        }

        relations: list[RelationDescriptor] = []
        aliases_by_field: dict[str, set[str]] = {}
        for fk in foreign_keys:
            constrained_columns = fk.get("constrained_columns") or []
            referred_columns = fk.get("referred_columns", [])
            referred_table = fk.get("referred_table")
            referred_schema = fk.get("referred_schema") or self.schema_name
            # The runtime resolver deliberately supports only single-column foreign keys.
            # Do not advertise parts of a composite relation as independently executable.
            if not referred_table or len(constrained_columns) != 1 or len(referred_columns) != 1:
                continue
            lookup_keys = self._unique_columns(inspector, str(referred_table), referred_schema)
            lookup_types = {
                column["name"]: _sql_type(column.get("type"))
                for column in inspector.get_columns(str(referred_table), schema=referred_schema)
                if isinstance(column.get("name"), str)
            }
            source = constrained_columns[0]
            target = referred_columns[0]
            alternatives = tuple(item for item in lookup_keys if item != target)
            relations.append(
                RelationDescriptor(
                    source_field_id=source,
                    target_container=str(referred_table),
                    target_field=target,
                    name=fk.get("name"),
                    target_schema=referred_schema,
                    lookup_keys=tuple(
                        LookupKeyDescriptor(
                            name=item,
                            data_type=lookup_types.get(item, DataType.UNKNOWN),
                        )
                        for item in alternatives
                    ),
                )
            )
            aliases = aliases_by_field.setdefault(source, set())
            aliases.update(alternatives)
            aliases.add(f"{referred_table} {target}")

        fields = []
        for column in columns:
            name = column["name"]
            if name in primary:
                role = FieldRole.PRIMARY_KEY
            elif name in foreign_columns:
                role = FieldRole.FOREIGN_KEY
            else:
                role = infer_role(name)
            fields.append(
                FieldDescriptor(
                    id=name,
                    name=name,
                    data_type=_sql_type(column["type"]),
                    nullable=bool(column.get("nullable", True)),
                    destination_generated=name in generated,
                    sensitivity=self.sensitivity_overrides.get(name, classify_field_name(name)),
                    role=role,
                    aliases=tuple(sorted(aliases_by_field.get(name, set()))),
                    container=self.table_name,
                )
            )

        prefix = f"{self.schema_name}." if self.schema_name else ""
        return SchemaDescriptor(
            id=f"db:{prefix}{self.table_name}",
            fields=tuple(fields),
            relations=tuple(relations),
        )

    def iter_records(self) -> Iterable[Mapping[str, object]]:
        self._ensure_open()
        table = self._table()
        with self.engine.connect() as connection:
            for row in connection.execute(select(table)):
                yield dict(row._mapping)

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        self._ensure_open()
        table = self._table()
        rows = [dict(record) for record in records]
        if not rows:
            return 0
        return self._write_rows(table, rows)

    def write_batch(self, items: Sequence[BatchWriteItem]) -> int:
        """Write a bounded batch in exactly one all-or-nothing database transaction.

        Every item retains its own delivery context. The current database connector does not
        provide destination-native idempotency, but keeping the contexts separate prevents a
        caller from accidentally collapsing record identities when that support is added.
        """

        self._ensure_open()
        capability = self.capabilities.atomic_batch_write
        if capability is None:
            raise ConnectorWriteError(
                "database dialect does not guarantee atomic batch writes",
                outcome=WriteOutcome.NOT_COMMITTED,
            )
        try:
            item_count = len(items)
        except TypeError as exc:
            raise ConnectorWriteError(
                "database batch must be a bounded sequence",
                outcome=WriteOutcome.NOT_COMMITTED,
            ) from exc
        if item_count == 0:
            raise ConnectorWriteError(
                "database batch must contain at least one record",
                outcome=WriteOutcome.NOT_COMMITTED,
            )
        if item_count > capability.max_records:
            raise ConnectorWriteError(
                "database batch exceeds the record count limit",
                outcome=WriteOutcome.NOT_COMMITTED,
            )

        rows: list[dict[str, object]] = []
        wire_bytes = 0
        delivery_identities: set[tuple[str, str]] = set()
        idempotency_keys: set[str] = set()
        for item in items:
            if not isinstance(item, BatchWriteItem):
                raise ConnectorWriteError(
                    "database batch contains an invalid item",
                    outcome=WriteOutcome.NOT_COMMITTED,
                )
            wire_bytes += item.wire_bytes
            if wire_bytes > capability.max_wire_bytes:
                raise ConnectorWriteError(
                    "database batch exceeds the wire byte limit",
                    outcome=WriteOutcome.NOT_COMMITTED,
                )
            context = item.context
            identity = (context.transfer_id, context.record_id)
            if identity in delivery_identities or context.idempotency_key in idempotency_keys:
                raise ConnectorWriteError(
                    "database batch contains a duplicate delivery identity",
                    outcome=WriteOutcome.NOT_COMMITTED,
                )
            delivery_identities.add(identity)
            idempotency_keys.add(context.idempotency_key)
            try:
                rows.append(dict(item.values))
            except Exception as exc:
                raise ConnectorWriteError(
                    "database batch contains an invalid record",
                    outcome=WriteOutcome.NOT_COMMITTED,
                ) from exc
        if len(rows) != item_count:
            raise ConnectorWriteError(
                "database batch changed while it was being validated",
                outcome=WriteOutcome.NOT_COMMITTED,
            )

        table = self._table()
        return self._write_rows(table, rows)

    def _write_rows(self, table: Table, rows: list[dict[str, object]]) -> int:
        allowed = set(table.columns.keys())
        for row in rows:
            unknown = set(row) - allowed
            if unknown:
                raise ConnectorWriteError(
                    "record contains columns outside the destination schema",
                    outcome=WriteOutcome.NOT_COMMITTED,
                )

        connection = self.engine.connect()
        transaction = connection.begin()
        expected_count = len(rows)
        is_multirow = expected_count > 1
        try:
            try:
                result = connection.execute(
                    table.insert(),
                    rows if is_multirow else rows[0],
                )
            except Exception as exc:
                try:
                    transaction.rollback()
                except Exception:
                    outcome = WriteOutcome.UNKNOWN
                else:
                    outcome = (
                        WriteOutcome.NOT_COMMITTED
                        if self.capabilities.transactional_write
                        else WriteOutcome.UNKNOWN
                    )
                raise ConnectorWriteError(
                    "database write failed",
                    outcome=outcome,
                ) from exc
            if not self._proves_exact_rowcount(
                result,
                expected_count=expected_count,
                is_multirow=is_multirow,
            ):
                try:
                    transaction.rollback()
                except Exception as exc:
                    raise ConnectorWriteError(
                        "database row count is unproven and rollback outcome is unknown",
                        outcome=WriteOutcome.UNKNOWN,
                    ) from exc
                raise ConnectorWriteError(
                    "database did not prove the exact affected row count",
                    outcome=(
                        WriteOutcome.NOT_COMMITTED
                        if self.capabilities.transactional_write
                        else WriteOutcome.UNKNOWN
                    ),
                )
            try:
                transaction.commit()
            except Exception as exc:
                raise ConnectorWriteError(
                    "database commit outcome is unknown",
                    outcome=WriteOutcome.UNKNOWN,
                ) from exc
        finally:
            connection.close()
        return expected_count

    @staticmethod
    def _proves_exact_rowcount(
        result: CursorResult[object],
        *,
        expected_count: int,
        is_multirow: bool,
    ) -> bool:
        """Accept a write result only when its dialect promises an exact plain-int count."""

        try:
            sane = (
                result.supports_sane_multi_rowcount()
                if is_multirow
                else result.supports_sane_rowcount()
            )
            rowcount = result.rowcount
        except Exception:
            return False
        return sane is True and type(rowcount) is int and rowcount == expected_count

    def resolve_foreign_key(
        self,
        *,
        target_field_id: str,
        match_column: str,
        value: object,
    ) -> object:
        """Resolve a business key to the exact FK value permitted by DB metadata.

        The table and returned column are derived from the real foreign-key constraint.
        Callers can select only a single-column UNIQUE/PK match key on that referenced table.
        """

        self._ensure_open()
        inspector = inspect(self.engine)
        candidates = []
        for fk in inspector.get_foreign_keys(self.table_name, schema=self.schema_name):
            constrained = fk.get("constrained_columns") or []
            referred = fk.get("referred_columns") or []
            if len(constrained) != 1 or len(referred) != 1:
                continue
            if constrained[0] == target_field_id:
                candidates.append(fk)
        if len(candidates) != 1:
            raise ConnectorError("target field does not have one resolvable foreign key")

        fk = candidates[0]
        referred_table = fk.get("referred_table")
        referred_schema = fk.get("referred_schema") or self.schema_name
        referred_columns = fk.get("referred_columns") or []
        if not referred_table or len(referred_columns) != 1:
            raise ConnectorError("foreign key metadata is incomplete")
        return_column = referred_columns[0]

        allowed_match_columns = set(
            self._unique_columns(inspector, str(referred_table), referred_schema)
        )
        if match_column not in allowed_match_columns:
            raise ConnectorError("foreign-key lookup column is not uniquely constrained")

        metadata = MetaData()
        table = Table(
            str(referred_table),
            metadata,
            schema=referred_schema,
            autoload_with=self.engine,
        )
        if match_column not in table.columns or return_column not in table.columns:
            raise ConnectorError("foreign-key lookup references an unknown column")

        statement = select(table.c[return_column]).where(table.c[match_column] == value).limit(2)
        with self.engine.connect() as connection:
            rows = connection.execute(statement).all()
        if len(rows) == 0:
            raise ConnectorError("foreign-key lookup found no matching record")
        if len(rows) > 1:
            raise ConnectorError("foreign-key lookup was not unique")
        return rows[0][0]
