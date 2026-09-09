from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from sqlalchemy import MetaData, Table, create_engine, inspect, select
from sqlalchemy.engine import Engine, URL
from sqlalchemy.sql.sqltypes import Boolean, Date, DateTime, Integer, JSON, LargeBinary, Numeric, String

from polymorph.classification import classify_field_name, infer_role
from polymorph.errors import ConnectorError, ConnectorWriteError, WriteOutcome
from polymorph.models.schema import FieldDescriptor, RelationDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, FieldRole, Sensitivity
from polymorph.secrets import SecretProvider

from .base import ConnectorCapabilities, DeliveryContext


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
    capabilities = ConnectorCapabilities(
        read_schema=True,
        read_records=True,
        write_records=True,
        transactional_write=True,
    )

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
        self.engine: Engine = create_engine(resolved_url, future=True)
        self.table_name = table
        self.schema_name = schema
        self.sensitivity_overrides = dict(sensitivity_overrides or {})

    def _table(self) -> Table:
        metadata = MetaData()
        return Table(self.table_name, metadata, schema=self.schema_name, autoload_with=self.engine)

    @staticmethod
    def _unique_columns(inspector, table: str, schema: str | None) -> tuple[str, ...]:
        unique: set[str] = set(
            inspector.get_pk_constraint(table, schema=schema).get("constrained_columns") or []
        )
        for constraint in inspector.get_unique_constraints(table, schema=schema):
            columns = constraint.get("column_names") or []
            if len(columns) == 1:
                unique.add(columns[0])
        for index in inspector.get_indexes(table, schema=schema):
            columns = index.get("column_names") or []
            if index.get("unique") and len(columns) == 1:
                unique.add(columns[0])
        return tuple(sorted(unique))

    def inspect_schema(self) -> SchemaDescriptor:
        inspector = inspect(self.engine)
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
            referred_columns = fk.get("referred_columns", [])
            referred_table = fk.get("referred_table")
            referred_schema = fk.get("referred_schema") or self.schema_name
            if not referred_table:
                continue
            lookup_keys = self._unique_columns(inspector, str(referred_table), referred_schema)
            for source, target in zip(
                fk.get("constrained_columns", []), referred_columns, strict=False
            ):
                alternatives = tuple(item for item in lookup_keys if item != target)
                relations.append(
                    RelationDescriptor(
                        source_field_id=source,
                        target_container=str(referred_table),
                        target_field=target,
                        name=fk.get("name"),
                        target_schema=referred_schema,
                        lookup_keys=alternatives,
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
                    sensitivity=self.sensitivity_overrides.get(
                        name, classify_field_name(name)
                    ),
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
        table = self._table()
        rows = [dict(record) for record in records]
        if not rows:
            return 0
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
        try:
            try:
                connection.execute(table.insert(), rows)
            except Exception as exc:
                transaction.rollback()
                raise ConnectorWriteError(
                    "database write failed before commit",
                    outcome=WriteOutcome.NOT_COMMITTED,
                ) from exc
            try:
                transaction.commit()
            except Exception as exc:
                raise ConnectorWriteError(
                    "database commit outcome is unknown",
                    outcome=WriteOutcome.UNKNOWN,
                ) from exc
        finally:
            connection.close()
        return len(rows)

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
        return_column = (fk.get("referred_columns") or [None])[0]
        if not referred_table or not return_column:
            raise ConnectorError("foreign key metadata is incomplete")

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

        statement = (
            select(table.c[return_column])
            .where(table.c[match_column] == value)
            .limit(2)
        )
        with self.engine.connect() as connection:
            rows = connection.execute(statement).all()
        if len(rows) == 0:
            raise ConnectorError("foreign-key lookup found no matching record")
        if len(rows) > 1:
            raise ConnectorError("foreign-key lookup was not unique")
        return rows[0][0]
