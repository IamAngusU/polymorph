from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, create_engine, select

from polymorph.agents import BlindDestinationAgent, BlindSourceAgent
from polymorph.connectors.database import DatabaseConnector
from polymorph.crypto import RecipientKeyPair
from polymorph.ledger import DeliveryLedger
from polymorph.matching.hybrid import HybridMatcher
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, FieldRole
from polymorph.planning import build_plan
from polymorph.runtime import DeliveryStatus, DestinationRuntime
from polymorph.signing import SigningKeyPair, SourceTrustStore, TrustedSourceKey
from polymorph.spool import SealedSpool


def _setup(
    tmp_path,
    *,
    create_customer: bool,
    source_value="00042",
    source_nullable: bool = False,
    target_nullable: bool = False,
    business_key_nullable: bool = False,
):
    path = tmp_path / "fk.sqlite"
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    metadata = MetaData()
    customers = Table(
        "customers",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "external_customer_number",
            String,
            nullable=business_key_nullable,
            unique=True,
        ),
    )
    orders = Table(
        "orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("customer_id", Integer, ForeignKey("customers.id"), nullable=target_nullable),
    )
    metadata.create_all(engine)
    if create_customer:
        with engine.begin() as connection:
            connection.execute(customers.insert().values(id=7, external_customer_number="00042"))

    connector = DatabaseConnector(url, "orders")
    target = connector.inspect_schema()
    source = SchemaDescriptor(
        "excel:orders",
        (
            FieldDescriptor(
                "c1",
                "Debitor Nr",
                DataType.STRING,
                nullable=source_nullable,
                role=FieldRole.NATURAL_KEY,
            ),
        ),
    )
    decisions = HybridMatcher(
        auto_threshold=0.74,
        minimum_margin=0.05,
        deterministic_auto_floor=0.74,
        deterministic_minimum_margin=0.05,
    ).propose(source, target)
    assert decisions[0].target_field_id == "customer_id"
    plan = build_plan(source, target, decisions)
    assert plan.rules[0].transform == "lookup_foreign_key"
    assert plan.rules[0].parameters["match_column"] == "external_customer_number"

    keys = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "tenant", "excel")])
    transport = BlindSourceAgent(
        tenant="tenant",
        source_connector_id="excel",
        destination_connector_id="orders-db",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=keys.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    ).prepare_record({"c1": source_value}, record_id="row-1", transfer_id="tx-1")

    runtime = DestinationRuntime(
        connector_id="orders-db",
        agent=BlindDestinationAgent(
            keys.private_key,
            expected_tenant="tenant",
            expected_connector_id="orders-db",
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=connector,
        ledger=DeliveryLedger(tmp_path / "ledger.db"),
        spool=SealedSpool(tmp_path / "spool.db"),
        plan=plan,
        target_schema=target,
    )
    return engine, customers, orders, transport, runtime


def test_business_key_is_resolved_to_internal_fk_at_destination(tmp_path):
    engine, _, orders, transport, runtime = _setup(tmp_path, create_customer=True)

    receipt = runtime.deliver(transport)
    assert receipt.status is DeliveryStatus.DELIVERED

    with engine.connect() as connection:
        row = connection.execute(select(orders.c.customer_id)).one()
    assert row[0] == 7


def test_missing_fk_target_can_be_replayed_after_reference_is_created(tmp_path):
    engine, customers, orders, transport, runtime = _setup(tmp_path, create_customer=False)

    first = runtime.deliver(transport)
    assert first.status is DeliveryStatus.QUARANTINED
    assert first.reason_code == "destination_resolution_failed"

    with engine.begin() as connection:
        connection.execute(customers.insert().values(id=7, external_customer_number="00042"))

    replay = runtime.replay(transport.digest())
    assert replay.status is DeliveryStatus.DELIVERED
    with engine.connect() as connection:
        row = connection.execute(select(orders.c.customer_id)).one()
    assert row[0] == 7


def test_fk_resolution_result_is_contract_checked_before_write(tmp_path):
    engine, _, orders, transport, runtime = _setup(tmp_path, create_customer=True)

    def wrong_type_resolver(*, target_field_id, match_column, value):
        return "7"

    runtime.connector.resolve_foreign_key = wrong_type_resolver

    receipt = runtime.deliver(transport)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "destination_contract_failed"
    with engine.connect() as connection:
        assert connection.execute(select(orders.c.customer_id)).all() == []


def test_wrong_typed_business_key_is_not_coerced_by_database_lookup(tmp_path):
    engine, _, orders, transport, runtime = _setup(
        tmp_path,
        create_customer=True,
        source_value=42,
    )

    receipt = runtime.deliver(transport)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "destination_resolution_failed"
    with engine.connect() as connection:
        assert connection.execute(select(orders.c.customer_id)).all() == []


def test_non_null_business_key_cannot_silently_resolve_to_nullable_fk(tmp_path):
    engine, _, orders, transport, runtime = _setup(
        tmp_path,
        create_customer=False,
        target_nullable=True,
    )

    receipt = runtime.deliver(transport)

    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "destination_resolution_failed"
    with engine.connect() as connection:
        assert connection.execute(select(orders.c.customer_id)).all() == []


def test_nullable_fk_value_remains_null_without_business_key_lookup(tmp_path):
    engine, customers, orders, transport, runtime = _setup(
        tmp_path,
        create_customer=False,
        source_value=None,
        source_nullable=True,
        target_nullable=True,
        business_key_nullable=True,
    )
    with engine.begin() as connection:
        connection.execute(
            customers.insert(),
            [
                {"id": 7, "external_customer_number": None},
                {"id": 8, "external_customer_number": None},
            ],
        )

    def must_not_resolve_null(*, target_field_id, match_column, value):
        raise AssertionError("nullable SQL NULL must not enter a business-key lookup")

    runtime.connector.resolve_foreign_key = must_not_resolve_null

    receipt = runtime.deliver(transport)

    assert receipt.status is DeliveryStatus.DELIVERED
    with engine.connect() as connection:
        assert connection.execute(select(orders.c.customer_id)).all() == [(None,)]
