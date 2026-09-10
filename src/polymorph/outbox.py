from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .agents import BlindTransportRecord, ProtocolLimits
from .errors import IntegrityError, ProtocolError, ReplayDetected
from .sqlite_safety import configure_sqlite_durability

MAX_OUTBOX_BATCH_ITEMS = 10_000
DEFAULT_OUTBOX_BATCH_WIRE_BYTES = 64 * 1024 * 1024


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
        allow_legacy_blank_recipient_key_id: bool = False,
        max_batch_wire_bytes: int = DEFAULT_OUTBOX_BATCH_WIRE_BYTES,
    ) -> None:
        if (
            isinstance(max_batch_wire_bytes, bool)
            or not isinstance(max_batch_wire_bytes, int)
            or max_batch_wire_bytes <= 0
        ):
            raise ValueError("source outbox batch wire limit must be a positive integer")
        self.path = Path(path)
        self.limits = limits or ProtocolLimits()
        if max_batch_wire_bytes < self.limits.max_record_wire_bytes:
            raise ValueError("outbox batch wire limit must admit one protocol-sized record")
        self.allow_legacy_unsigned = allow_legacy_unsigned
        self.allow_legacy_blank_recipient_key_id = allow_legacy_blank_recipient_key_id
        self.max_batch_wire_bytes = max_batch_wire_bytes
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
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS source_outbox_pending_order
                ON sealed_source_outbox (staged_at, record_digest)
                """
            )

    def _prepare_stage(
        self, record: BlindTransportRecord
    ) -> tuple[BlindTransportRecord, bytes, str, str]:
        wire = record.canonical_wire_bytes()
        if len(wire) > self.limits.max_record_wire_bytes:
            raise ProtocolError("sealed record exceeds source outbox size limit")

        # Parse our own persisted representation before accepting it. Besides enforcing
        # protocol limits this rejects accidentally constructed unsigned v3 records.
        parsed = BlindTransportRecord.from_wire(
            json.loads(wire.decode("utf-8")),
            limits=self.limits,
            allow_legacy_unsigned=self.allow_legacy_unsigned,
            allow_legacy_blank_recipient_key_id=self.allow_legacy_blank_recipient_key_id,
        )
        digest = parsed.digest()
        if digest != record.digest():
            raise IntegrityError("sealed source outbox record digest mismatch")

        return record, wire, digest, datetime.now(UTC).isoformat()

    def stage(self, record: BlindTransportRecord) -> OutboxReceipt:
        return self.stage_many((record,))[0]

    def stage_many(self, records: Iterable[BlindTransportRecord]) -> tuple[OutboxReceipt, ...]:
        """Validate and durably stage one atomic bounded batch."""

        prepared: list[tuple[BlindTransportRecord, bytes, str, str]] = []
        total_wire_bytes = 0
        for index, record in enumerate(records):
            if index >= MAX_OUTBOX_BATCH_ITEMS:
                raise ValueError("source outbox batch exceeds the record count limit")
            if not isinstance(record, BlindTransportRecord):
                raise TypeError("source outbox batch items must be BlindTransportRecord instances")
            item = self._prepare_stage(record)
            total_wire_bytes += len(item[1])
            if total_wire_bytes > self.max_batch_wire_bytes:
                raise ValueError("source outbox batch exceeds the wire byte limit")
            prepared.append(item)
        if not prepared:
            return ()

        connection = self._connect()
        receipts: list[OutboxReceipt] = []
        postconditions: list[tuple[str, tuple[object, ...]]] = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            for record, wire, digest, staged_at in prepared:
                identity = connection.execute(
                    """
                    SELECT record_digest, tenant, source_connector,
                           destination_connector, transfer_id, record_id,
                           plan_digest, staged_at, wire_json
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
                    raw_wire = identity["wire_json"]
                    if not isinstance(raw_wire, (bytes, bytearray, memoryview)):
                        raise IntegrityError(
                            "sealed source outbox wire representation is not binary"
                        )
                    existing_wire = bytes(raw_wire)
                    if identity["record_digest"] != digest or existing_wire != wire:
                        raise ReplayDetected(
                            "source outbox transfer identity was reused with different sealed bytes"
                        )
                    persisted_staged_at = identity["staged_at"]
                    identity_expected = (
                        digest,
                        record.tenant,
                        record.source_connector,
                        record.destination_connector,
                        record.transfer_id,
                        record.record_id,
                        record.plan_digest,
                        persisted_staged_at,
                        wire,
                    )
                    if tuple(identity) != identity_expected or not isinstance(
                        persisted_staged_at, str
                    ):
                        raise IntegrityError(
                            "sealed source outbox stored metadata does not match sealed record"
                        )
                    postconditions.append((digest, identity_expected))
                    receipts.append(OutboxReceipt(digest, persisted_staged_at, duplicate=True))
                    continue

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
                postconditions.append(
                    (
                        digest,
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
                )
                receipts.append(OutboxReceipt(digest, staged_at))
            for digest, expected_row in postconditions:
                persisted = connection.execute(
                    """
                    SELECT record_digest, tenant, source_connector,
                           destination_connector, transfer_id, record_id,
                           plan_digest, staged_at, wire_json
                    FROM sealed_source_outbox
                    WHERE record_digest = ?
                    """,
                    (digest,),
                ).fetchone()
                if persisted is None or tuple(persisted) != expected_row:
                    raise IntegrityError("sealed source outbox write postcondition failed")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return tuple(receipts)

    def pending(
        self,
        *,
        limit: int = 100,
        max_wire_bytes: int | None = None,
    ) -> tuple[PendingRecord, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise ValueError("outbox limit is outside supported range")
        wire_budget = self.max_batch_wire_bytes if max_wire_bytes is None else max_wire_bytes
        if (
            isinstance(wire_budget, bool)
            or not isinstance(wire_budget, int)
            or not 1 <= wire_budget <= self.max_batch_wire_bytes
        ):
            raise ValueError("outbox pending wire limit is outside supported range")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            selected: list[tuple[str, str, int]] = []
            selected_wire_bytes = 0
            metadata_rows = connection.execute(
                """
                SELECT record_digest, staged_at, LENGTH(wire_json) AS wire_bytes
                FROM sealed_source_outbox
                ORDER BY staged_at ASC, record_digest ASC
                LIMIT ?
                """,
                (limit,),
            )
            for row in metadata_rows:
                wire_size = int(row["wire_bytes"])
                if wire_size > self.limits.max_record_wire_bytes:
                    raise IntegrityError("sealed source outbox record exceeds its wire size limit")
                if selected_wire_bytes + wire_size > wire_budget:
                    if not selected:
                        raise ValueError("next outbox record exceeds the pending wire limit")
                    break
                selected_wire_bytes += wire_size
                selected.append((str(row["record_digest"]), str(row["staged_at"]), wire_size))
            metadata_rows.close()

            output: list[PendingRecord] = []
            for record_digest, staged_at, expected_wire_size in selected:
                stored = connection.execute(
                    """
                    SELECT wire_json
                    FROM sealed_source_outbox
                    WHERE record_digest = ?
                    """,
                    (record_digest,),
                ).fetchone()
                if stored is None:
                    raise IntegrityError("sealed source outbox record disappeared while reading")
                raw_wire = stored["wire_json"]
                if not isinstance(raw_wire, (bytes, bytearray, memoryview)):
                    raise IntegrityError("sealed source outbox wire representation is not binary")
                wire = bytes(raw_wire)
                if len(wire) != expected_wire_size:
                    raise IntegrityError("sealed source outbox wire size changed while reading")
                record = BlindTransportRecord.from_wire(
                    json.loads(wire.decode("utf-8")),
                    limits=self.limits,
                    allow_legacy_unsigned=self.allow_legacy_unsigned,
                    allow_legacy_blank_recipient_key_id=(self.allow_legacy_blank_recipient_key_id),
                )
                if record.digest() != record_digest:
                    raise IntegrityError("sealed source outbox record digest mismatch")
                canonical_wire = record.canonical_wire_bytes()
                if canonical_wire != wire:
                    raise IntegrityError(
                        "sealed source outbox wire representation is not canonical"
                    )
                output.append(PendingRecord(record, canonical_wire, staged_at))
            connection.execute("COMMIT")
            return tuple(output)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def ack(self, record_digest: str) -> bool:
        """Remove an acknowledged record, returning whether it was still pending."""

        return self.ack_many((record_digest,))[0]

    def ack_many(self, record_digests: Iterable[str]) -> tuple[bool, ...]:
        """Atomically remove a bounded batch and report each digest's prior presence."""

        digests: list[str] = []
        for index, record_digest in enumerate(record_digests):
            if index >= MAX_OUTBOX_BATCH_ITEMS:
                raise ValueError(
                    "source outbox acknowledgement batch exceeds the record count limit"
                )
            if not isinstance(record_digest, str):
                raise TypeError("source outbox record digests must be strings")
            if len(record_digest) != 64 or any(
                character not in "0123456789abcdef" for character in record_digest
            ):
                raise ValueError("source outbox record digest must be a lowercase SHA-256 digest")
            digests.append(record_digest)
        if not digests:
            return ()

        connection = self._connect()
        removed: list[bool] = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            for record_digest in digests:
                cursor = connection.execute(
                    "DELETE FROM sealed_source_outbox WHERE record_digest = ?",
                    (record_digest,),
                )
                removed.append(cursor.rowcount == 1)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return tuple(removed)

    def depth(self) -> int:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM sealed_source_outbox"
            ).fetchone()
        return int(row["count"])
