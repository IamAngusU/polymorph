from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .agents import BlindTransportRecord, ProtocolLimits
from .errors import IntegrityError


@dataclass(frozen=True, slots=True)
class SpoolEntry:
    record_digest: str
    tenant: str
    destination_connector: str
    transfer_id: str
    record_id: str
    plan_digest: str
    reason_code: str
    quarantined_at: str


class SealedSpool:
    """Quarantine storage for opaque transport records.

    Only the already encrypted wire object is persisted. Callers cannot supply arbitrary
    exception text, which prevents accidental persistence of payload-bearing messages.
    """

    def __init__(self, path: str | Path, *, limits: ProtocolLimits | None = None) -> None:
        self.path = Path(path)
        self.limits = limits or ProtocolLimits()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sealed_quarantine (
                    record_digest TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    destination_connector TEXT NOT NULL,
                    transfer_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    wire_json BLOB NOT NULL
                )
                """
            )

    def quarantine(self, record: BlindTransportRecord, reason_code: str) -> SpoolEntry:
        if not reason_code or len(reason_code) > 96 or not reason_code.replace("_", "").isalnum():
            raise ValueError("reason_code must be a short machine-readable identifier")
        wire = record.canonical_wire_bytes()
        if len(wire) > self.limits.max_record_wire_bytes:
            raise ValueError("record exceeds spool wire size limit")
        digest = record.digest()
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sealed_quarantine (
                    record_digest, tenant, destination_connector, transfer_id,
                    record_id, plan_digest, reason_code, quarantined_at, wire_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_digest) DO UPDATE SET
                    reason_code = excluded.reason_code,
                    quarantined_at = excluded.quarantined_at
                """,
                (
                    digest,
                    record.tenant,
                    record.destination_connector,
                    record.transfer_id,
                    record.record_id,
                    record.plan_digest,
                    reason_code,
                    now,
                    wire,
                ),
            )
        return SpoolEntry(
            digest,
            record.tenant,
            record.destination_connector,
            record.transfer_id,
            record.record_id,
            record.plan_digest,
            reason_code,
            now,
        )

    def get(self, record_digest: str) -> BlindTransportRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT wire_json FROM sealed_quarantine WHERE record_digest = ?",
                (record_digest,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(bytes(row["wire_json"]).decode("utf-8"))
        record = BlindTransportRecord.from_wire(payload, limits=self.limits)
        if record.digest() != record_digest:
            raise IntegrityError("sealed spool record digest mismatch")
        return record

    def remove(self, record_digest: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM sealed_quarantine WHERE record_digest = ?",
                (record_digest,),
            )

    def list_entries(self, *, limit: int = 100) -> tuple[SpoolEntry, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT record_digest, tenant, destination_connector, transfer_id,
                       record_id, plan_digest, reason_code, quarantined_at
                FROM sealed_quarantine
                ORDER BY quarantined_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(
            SpoolEntry(
                row["record_digest"],
                row["tenant"],
                row["destination_connector"],
                row["transfer_id"],
                row["record_id"],
                row["plan_digest"],
                row["reason_code"],
                row["quarantined_at"],
            )
            for row in rows
        )
