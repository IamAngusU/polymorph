from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest

import polymorph.audit as audit_module
from polymorph.audit import AuditEvent, AuditLog
from polymorph.errors import IntegrityError


def _event(index: int) -> AuditEvent:
    digest = f"{index:064x}"
    return AuditEvent(
        event_type="delivery",
        actor="test",
        status="delivered",
        tenant="tenant-a",
        connector_id="destination",
        transfer_id=f"transfer-{index}",
        record_id=f"record-{index}",
        record_digest=digest,
        plan_digest="f" * 64,
    )


def test_audit_verify_summary_and_atomic_export_stream_rows(tmp_path, monkeypatch) -> None:
    log = AuditLog(tmp_path / "audit.db")
    log.append_many(_event(index) for index in range(5))
    monkeypatch.setattr(log, "_read_rows", lambda: pytest.fail("full audit read was used"))

    assert log.verify() == 5
    assert log.summary().events == 5
    output = tmp_path / "audit.jsonl"
    assert log.export_jsonl_to(output) == 5
    assert len([json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]) == 5


def test_audit_quota_applies_backpressure_without_deleting_history(tmp_path) -> None:
    log = AuditLog(tmp_path / "audit.db", max_events=1)
    log.append(_event(1))

    with pytest.raises(IntegrityError, match="quota reached"):
        log.append(_event(2))
    assert log.verify() == 1


def test_audit_quota_is_shared_across_writers_without_hot_path_rescans(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "audit.db"
    first = AuditLog(path, max_events=2)
    second = AuditLog(path, max_events=2)
    first.append(_event(1))
    statements: list[str] = []
    real_connect = audit_module.sqlite3.connect

    def tracked_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(audit_module.sqlite3, "connect", tracked_connect)
    second.append(_event(2))
    with pytest.raises(IntegrityError, match="quota reached"):
        first.append(_event(3))

    normalized = [statement.upper() for statement in statements]
    assert not any("COUNT(" in statement or "SUM(" in statement for statement in normalized)
    assert first.verify() == 2


def test_audit_usage_is_backfilled_for_a_legacy_store(tmp_path) -> None:
    path = tmp_path / "audit.db"
    AuditLog(path).append(_event(1))
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER audit_usage_after_insert")
        connection.execute("DROP TRIGGER audit_usage_after_update")
        connection.execute("DROP TRIGGER audit_usage_after_delete")
        connection.execute("DROP TABLE audit_usage")

    migrated = AuditLog(path, max_events=1)
    with pytest.raises(IntegrityError, match="quota reached"):
        migrated.append(_event(2))
    assert migrated.verify() == 1


def test_audit_logical_quota_counts_utf8_bytes(tmp_path) -> None:
    event = AuditEvent(
        event_type="delivery",
        actor="täst",
        status="delivered",
        tenant="tenant-a",
        connector_id="destination",
        transfer_id="transfer-1",
        record_id="record-1",
        record_digest="a" * 64,
        plan_digest="f" * 64,
        timestamp=datetime(2026, 9, 12, tzinfo=UTC),
    )
    encoded = json.dumps(
        event.canonical_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    one_event_bytes = len(encoded) + 128
    log = AuditLog(tmp_path / "audit.db", max_logical_bytes=2 * one_event_bytes - 1)
    log.append(event)

    with pytest.raises(IntegrityError, match="byte quota reached"):
        log.append(event)
