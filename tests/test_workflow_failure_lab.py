from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import polymorph.relay as relay_module
from polymorph.agents import BlindDestinationAgent, BlindSourceAgent, BlindTransportRecord
from polymorph.audit import AuditLog
from polymorph.cli import build_parser
from polymorph.connectors.base import DeliveryContext
from polymorph.connectors.excel import ExcelConnector
from polymorph.connectors.json_file import JsonFileConnector
from polymorph.content import ContentInspector, ContentKind
from polymorph.crypto import RecipientKeyPair
from polymorph.errors import ConnectorError, IntegrityError, PolicyViolation
from polymorph.ledger import DeliveryLedger, DeliveryState
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
from polymorph.outbox import SourceOutbox
from polymorph.recipes import RecipeHealthState, RecipeRunOutcome, RecipeStore
from polymorph.relay import RelayPolicy, RouteBinding, SealedRelayQueue
from polymorph.runtime import AuditWriteStatus, DeliveryStatus, DestinationRuntime
from polymorph.serialization import save_schema
from polymorph.signing import (
    SigningKeyPair,
    SourceTrustStore,
    TrustedSourceKey,
)
from polymorph.spool import SealedSpool

SECRET_MARKER = "failure-lab-secret"


def _route() -> tuple[
    BlindTransportRecord,
    RecipientKeyPair,
    MappingPlan,
    SchemaDescriptor,
    SourceTrustStore,
]:
    source = SchemaDescriptor(
        "lab-source",
        (
            FieldDescriptor(
                "token",
                "API token",
                DataType.STRING,
                nullable=False,
                sensitivity=Sensitivity.SECRET,
            ),
        ),
    )
    target = SchemaDescriptor(
        "lab-target",
        (
            FieldDescriptor(
                "token",
                "API token",
                DataType.STRING,
                nullable=False,
                sensitivity=Sensitivity.SECRET,
            ),
        ),
    )
    plan = MappingPlan(
        "lab-plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("token", "token", "opaque_forward"),),
    )
    recipient = RecipientKeyPair.generate()
    signer = SigningKeyPair.generate()
    trust = SourceTrustStore([TrustedSourceKey(signer.public_bytes(), "lab-tenant", source.id)])
    record = BlindSourceAgent(
        tenant="lab-tenant",
        source_connector_id=source.id,
        destination_connector_id="lab-json",
        source_schema=source,
        target_schema=target,
        plan=plan,
        destination_public_key=recipient.public_bytes(),
        signing_key=signer,
        allow_unauthenticated_recipient_key=True,
    ).prepare_record(
        {"token": SECRET_MARKER},
        record_id="record-1",
        transfer_id="transfer-1",
    )
    return record, recipient, plan, target, trust


def _runtime(
    tmp_path: Path,
    connector: JsonFileConnector,
) -> tuple[BlindTransportRecord, DestinationRuntime, AuditLog, bytes]:
    record, recipient, plan, target, trust = _route()
    audit_signer = SigningKeyPair.generate()
    audit = AuditLog(tmp_path / "audit.db", signer=audit_signer)
    runtime = DestinationRuntime(
        connector_id="lab-json",
        agent=BlindDestinationAgent(
            recipient.private_key,
            expected_tenant="lab-tenant",
            expected_connector_id="lab-json",
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=connector,
        ledger=DeliveryLedger(tmp_path / "delivery-ledger.db"),
        spool=SealedSpool(tmp_path / "sealed-spool.db"),
        plan=plan,
        target_schema=target,
        audit=audit,
        actor_id="failure-lab-destination",
    )
    return record, runtime, audit, audit_signer.public_bytes()


def test_content_extension_conflict_is_rejected_before_excel_parse(
    tmp_path: Path,
) -> None:
    source = tmp_path / "orders.xlsx"
    source.write_text(
        "customer_id,amount\nA-1,10.2\nA-2,11.4\nA-3,9.8\n",
        encoding="utf-8",
    )
    inspection = ContentInspector().inspect(source)
    with pytest.raises(ConnectorError, match="detected delimited_text"):
        ExcelConnector(source).inspect_schema()

    assert inspection.kind is ContentKind.DELIMITED_TEXT
    assert inspection.safe
    assert not tuple(tmp_path.glob("*.db"))
    assert source.stat().st_size > 0


def test_ambiguous_mapping_never_crosses_the_automatic_promotion_gate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "ambiguous.payload"
    source.write_text('[{"Reference":"A-1"}]', encoding="utf-8")
    target_path = tmp_path / "target-schema.json"
    save_schema(
        target_path,
        SchemaDescriptor(
            "target",
            (
                FieldDescriptor("left", "Reference", DataType.STRING, nullable=False),
                FieldDescriptor("right", "Reference", DataType.STRING, nullable=False),
            ),
        ),
    )
    output_plan = tmp_path / "unsafe-plan.json"
    args = build_parser().parse_args(
        [
            "prepare",
            str(source),
            str(target_path),
            "--recipe-store",
            str(tmp_path / "recipes.db"),
            "--output-plan",
            str(output_plan),
        ]
    )
    with pytest.raises(SystemExit) as caught:
        args.func(args)
    payload = json.loads(capsys.readouterr().out)

    decision = payload["decisions"][0]
    assert caught.value.code == 3
    assert payload["ready"] is False
    assert payload["reason"] == "no_auto_approved_mapping_rules"
    assert payload["diagnostic"]["retry_policy"] == "manual_review"
    assert decision["status"] == "review"
    assert decision["margin"] == 0.0
    assert not output_plan.exists()


def test_recipe_circuit_suspends_reuse_and_prepare_builds_a_fresh_version(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "input.payload"
    source.write_text('[{"customer id":"A-1"}]', encoding="utf-8")
    target_path = tmp_path / "target-schema.json"
    save_schema(
        target_path,
        SchemaDescriptor(
            "target",
            (
                FieldDescriptor(
                    "customer_id",
                    "customer id",
                    DataType.STRING,
                    nullable=False,
                ),
            ),
        ),
    )
    store_path = tmp_path / "recipes.db"
    args = build_parser().parse_args(
        [
            "prepare",
            str(source),
            str(target_path),
            "--recipe-store",
            str(store_path),
            "--remember",
        ]
    )
    args.func(args)
    first = json.loads(capsys.readouterr().out)
    store = RecipeStore(store_path)
    old_recipe = store.get(first["recipe_id"])
    assert old_recipe is not None
    for _ in range(3):
        store.record_run(
            old_recipe,
            old_recipe.plan,
            RecipeRunOutcome.REJECTED,
            reason_code="required_target_null",
        )
    suspended = store.health(old_recipe)

    args.func(args)
    adapted = json.loads(capsys.readouterr().out)
    new_recipe = store.get(adapted["recipe_id"])

    assert new_recipe is not None
    assert suspended.state is RecipeHealthState.SUSPENDED
    assert suspended.consecutive_rejections == 3
    assert not suspended.auto_reuse_allowed
    assert adapted["ready"] is True
    assert adapted["route_source"] == "fresh_mapping"
    assert adapted["recipe_id"] != old_recipe.id
    assert adapted["recipe_monitoring"]["adaptation"]["code"] == ("recipe_auto_reuse_suspended")
    assert adapted["recipe_monitoring"]["candidate_health"]["state"] == "suspended"
    assert adapted["recipe_monitoring"]["active_health"]["state"] == "healthy"
    assert new_recipe.version == old_recipe.version + 1


def test_unsigned_ingress_and_tampered_relay_record_never_get_leased(
    tmp_path: Path,
) -> None:
    record, _, plan, _, trust = _route()
    assert record.authentication is not None
    queue = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    "lab-tenant",
                    "lab-source",
                    "lab-json",
                    allowed_plan_digests=frozenset({plan.digest()}),
                    allowed_source_key_ids=frozenset({record.authentication.key_id}),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    unsigned = BlindTransportRecord(record.record_id, record.fields)

    with pytest.raises(IntegrityError, match="no source authentication"):
        queue.enqueue(unsigned)
    queue.enqueue(record)
    with sqlite3.connect(queue.path) as connection:
        row = connection.execute(
            "SELECT wire_json FROM sealed_relay_queue WHERE record_digest = ?",
            (record.digest(),),
        ).fetchone()
        assert row is not None
        wire = json.loads(bytes(row[0]).decode("utf-8"))
        encoded = wire["authentication"]["signature"]
        signature = bytearray(base64.urlsafe_b64decode(encoded))
        signature[0] ^= 1
        wire["authentication"]["signature"] = base64.urlsafe_b64encode(signature).decode("ascii")
        connection.execute(
            "UPDATE sealed_relay_queue SET wire_json = ? WHERE record_digest = ?",
            (
                json.dumps(
                    wire,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8"),
                record.digest(),
            ),
        )

    leased = queue.lease(destination_connector="lab-json", lease_owner="lab-worker")
    dead_letters = queue.list_dead_letters()

    assert leased == ()
    assert queue.depth() == 0
    assert len(dead_letters) == 1
    assert dead_letters[0].reason_code == "relay_source_authentication_failed"
    assert SECRET_MARKER.encode() not in queue.path.read_bytes()


def test_lost_relay_ack_redelivery_is_suppressed_by_the_committed_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record, recipient, plan, target, trust = _route()
    assert record.authentication is not None
    outbox = SourceOutbox(tmp_path / "outbox.db")
    relay = SealedRelayQueue(
        tmp_path / "relay.db",
        RelayPolicy(
            (
                RouteBinding(
                    "lab-tenant",
                    "lab-source",
                    "lab-json",
                    allowed_plan_digests=frozenset({plan.digest()}),
                    allowed_source_key_ids=frozenset({record.authentication.key_id}),
                ),
            ),
            source_trust_store=trust,
        ),
    )
    outbox.stage(record)
    relay.enqueue(outbox.pending()[0].record)
    destination_path = tmp_path / "delivered.json"
    runtime = DestinationRuntime(
        connector_id="lab-json",
        agent=BlindDestinationAgent(
            recipient.private_key,
            expected_tenant="lab-tenant",
            expected_connector_id="lab-json",
            allowed_plan_digests=frozenset({plan.digest()}),
            source_trust_store=trust,
        ),
        connector=JsonFileConnector(destination_path),
        ledger=DeliveryLedger(tmp_path / "delivery-ledger.db"),
        spool=SealedSpool(tmp_path / "sealed-spool.db"),
        plan=plan,
        target_schema=target,
    )
    clock = {"now": datetime.now(UTC)}

    class RelayClock:
        @classmethod
        def now(cls, timezone=None):
            current = clock["now"]
            return current.astimezone(timezone) if timezone else current.replace(tzinfo=None)

    monkeypatch.setattr(relay_module, "datetime", RelayClock)
    first_lease = relay.lease(
        destination_connector="lab-json",
        lease_owner="worker-1",
        lease_for=timedelta(seconds=30),
    )[0]
    first = runtime.deliver(first_lease.record)

    clock["now"] += timedelta(seconds=31)
    second_lease = relay.lease(
        destination_connector="lab-json",
        lease_owner="worker-2",
    )[0]
    repeated = runtime.deliver(second_lease.record)

    records = json.loads(destination_path.read_text(encoding="utf-8"))
    assert first.status is DeliveryStatus.DELIVERED
    assert repeated.status is DeliveryStatus.DUPLICATE
    assert repeated.reason_code is None
    assert runtime.ledger.get(record).state is DeliveryState.COMMITTED
    assert records == [{"token": SECRET_MARKER}]
    relay.ack(
        record.digest(),
        lease_owner="worker-2",
        lease_id=second_lease.lease_id,
    )
    assert outbox.ack(record.digest())
    assert relay.depth() == 0
    assert outbox.depth() == 0
    for path in (outbox.path, relay.path, runtime.ledger.path, runtime.spool.path):
        assert SECRET_MARKER.encode() not in path.read_bytes()


class _CommitThenLoseAckJson(JsonFileConnector):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.write_calls = 0

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        self.write_calls += 1
        super().write_records(records, context=context)
        raise RuntimeError("injected lost acknowledgement after durable file replacement")


def test_unknown_write_outcome_is_quarantined_without_a_blind_second_write(
    tmp_path: Path,
) -> None:
    destination_path = tmp_path / "uncertain.json"
    connector = _CommitThenLoseAckJson(destination_path)
    record, runtime, audit, audit_public_key = _runtime(tmp_path, connector)

    receipt = runtime.deliver(record)
    assert receipt.status is DeliveryStatus.QUARANTINED
    assert receipt.reason_code == "write_outcome_unknown"
    assert receipt.retry_safe is False
    assert receipt.audit_status is AuditWriteStatus.RECORDED
    assert runtime.ledger.get(record).state is DeliveryState.UNCERTAIN
    assert runtime.spool.get(record.digest()) is not None
    with pytest.raises(PolicyViolation, match="uncertain write cannot be replayed"):
        runtime.replay(record.digest())

    records = json.loads(destination_path.read_text(encoding="utf-8"))
    audit_summary = audit.summary(trusted_public_key=audit_public_key)
    assert records == [{"token": SECRET_MARKER}]
    assert connector.write_calls == 1
    assert audit_summary.events == 1
    assert audit_summary.statuses == {"quarantined": 1}
    assert audit_summary.reasons == {"write_outcome_unknown": 1}
    assert audit_summary.signatures_verified
    assert SECRET_MARKER.encode() not in runtime.ledger.path.read_bytes()
    assert SECRET_MARKER.encode() not in runtime.spool.path.read_bytes()
    assert SECRET_MARKER.encode() not in audit.path.read_bytes()
