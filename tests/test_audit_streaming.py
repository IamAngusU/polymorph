from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

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
