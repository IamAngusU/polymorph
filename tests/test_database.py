from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, create_engine

from polymorph.connectors.database import DatabaseConnector
from polymorph.models.types import FieldRole


def test_database_introspection_includes_foreign_key(tmp_path):
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
    assert schema.relations[0].target_container == "customers"


def test_database_secret_column_is_classified(tmp_path):
    path = tmp_path / "secret.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    Table("integrations", metadata, Column("id", Integer, primary_key=True), Column("api_token", String))
    metadata.create_all(engine)

    schema = DatabaseConnector(url, "integrations").inspect_schema()
    sensitivity = {field.id: field.sensitivity.value for field in schema.fields}
    assert sensitivity["api_token"] == "secret"


def test_unique_business_key_is_exposed_as_fk_lookup_alias(tmp_path):
    from sqlalchemy import UniqueConstraint

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
    assert relation.lookup_keys == ("external_customer_number",)
