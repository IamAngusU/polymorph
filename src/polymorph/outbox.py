from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .agents import BlindTransportRecord, ProtocolLimits
from .errors import IntegrityError, ProtocolError, ReplayDetected
from .sqlite_safety import configure_sqlite_durability


@dataclass(frozen=True, slots=True)
class OutboxReceipt:
    record_digest: str
    staged_at: str
    duplicate: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class PendingRecord:
    record: BlindTransportRecord
    wire_bytes: bytes
    staged_at: str

    def __repr__(self) -> str:
        return (
            "PendingRecord("
            f"record_digest={self.record.digest()!r}, staged_at={self.staged_at!r}, <sealed>)"
        )


class SourceOutbox:
    """Durable source-side storage for sealed records awaiting acknowledgement.

    A retry must reuse the exact signed wire bytes staged before the first send. Resealing
    the same logical transfer produces fresh ciphertext and is correctly treated as a replay.
    This store never accepts plaintext records and has no recipient key or decrypt method.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        limits: ProtocolLimits | None = None,
        allow_legacy_unsigned: bool = False,
    ) -> None:
        self.path = Path(path)
        self.limits = limits or ProtocolLimits()
        self.allow_legacy_unsigned = allow_legacy_unsigned
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        configure_sqlite_durability(connection)
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sealed_source_outbox (
                    record_digest TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    source_connector TEXT NOT NULL,
                    destination_connector TEXT NOT NULL,
                    transfer_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    staged_at TEXT NOT NULL,
                    wire_json BLOB NOT NULL,
                    UNIQUE (
                        tenant, source_connector, destination_connector,
                        transfer_id, record_id
                    )
                )
                """
            )

    def stage(self, record: BlindTransportRecord) -> OutboxReceipt:
        wire = record.canonical_wire_bytes()
        if len(wire) > self.limits.max_record_wire_bytes:
            raise ProtocolError("sealed record exceeds source outbox size limit")

        # Parse our own persisted representation before accepting it. Besides enforcing
        # protocol limits this rejects accidentally constructed unsigned v3 records.
        parsed = BlindTransportRecord.from_wire(
            json.loads(wire.decode("utf-8")),
            limits=self.limits,
            allow_legacy_unsigned=self.allow_legacy_unsigned,
        )
        digest = parsed.digest()
        if digest != record.digest():
            raise IntegrityError("sealed source outbox record digest mismatch")

        staged_at = datetime.now(UTC).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            identity = connection.execute(
                """
                SELECT record_digest, staged_at, wire_json
                FROM sealed_source_outbox
                WHERE tenant = ? AND source_connector = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                """,
                (
                    record.tenant,
                    record.source_connector,
                    record.destination_connector,
                    record.transfer_id,
                    record.record_id,
                ),
            ).fetchone()
            if identity is not None:
                existing_wire = bytes(identity["wire_json"])
                if identity["record_digest"] != digest or existing_wire != wire:
                    connection.execute("ROLLBACK")
                    raise ReplayDetected(
                        "source outbox transfer identity was reused with different sealed bytes"
                    )
                connection.execute("COMMIT")
                return OutboxReceipt(digest, str(identity["staged_at"]), duplicate=True)

            connection.execute(
                """
                INSERT INTO sealed_source_outbox (
                    record_digest, tenant, source_connector, destination_connector,
                    transfer_id, record_id, plan_digest, staged_at, wire_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    digest,
                    record.tenant,
                    record.source_connector,
                    record.destination_connector,
                    record.transfer_id,
                    record.record_id,
                    record.plan_digest,
                    staged_at,
                    wire,
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return OutboxReceipt(digest, staged_at)

    def pending(self, *, limit: int = 100) -> tuple[PendingRecord, ...]:
        if not 1 <= limit <= 10_000:
            raise ValueError("outbox limit is outside supported range")
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT record_digest, staged_at, wire_json
                FROM sealed_source_outbox
                ORDER BY staged_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        output: list[PendingRecord] = []
        for row in rows:
            wire = bytes(row["wire_json"])
            record = BlindTransportRecord.from_wire(
                json.loads(wire.decode("utf-8")),
                limits=self.limits,
                allow_legacy_unsigned=self.allow_legacy_unsigned,
            )
            if record.digest() != row["record_digest"]:
                raise IntegrityError("sealed source outbox record digest mismatch")
            if record.canonical_wire_bytes() != wire:
                raise IntegrityError("sealed source outbox wire representation is not canonical")
            output.append(PendingRecord(record, wire, str(row["staged_at"])))
        return tuple(output)

    def ack(self, record_digest: str) -> bool:
        """Remove an acknowledged record, returning whether it was still pending."""

        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "DELETE FROM sealed_source_outbox WHERE record_digest = ?",
                (record_digest,),
            )
            return cursor.rowcount == 1

    def depth(self) -> int:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM sealed_source_outbox"
            ).fetchone()
        return int(row["count"])
