from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .agents import BlindTransportRecord, ProtocolLimits
from .errors import IntegrityError, ProtocolError
from .sqlite_safety import configure_sqlite_durability

MAX_SPOOL_BATCH_ITEMS = 10_000
DEFAULT_SPOOL_BATCH_WIRE_BYTES = 64 * 1024 * 1024
_SQLITE_DIGEST_CHUNK_SIZE = 900


def _decode_spooled_record(
    wire: bytes,
    *,
    limits: ProtocolLimits,
    allow_legacy_unsigned: bool,
    allow_legacy_blank_recipient_key_id: bool,
) -> BlindTransportRecord:
    def reject_constant(value: str) -> object:
        raise ProtocolError(f"non-finite JSON constant is not allowed: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError("duplicate key in spooled transport record")
            result[key] = value
        return result

    if len(wire) > limits.max_record_wire_bytes:
        raise ProtocolError("spooled transport record exceeds the wire size limit")
    try:
        decoded: object = json.loads(
            wire.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("spooled transport record is not valid JSON") from exc
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise ProtocolError("spooled transport record must be a JSON object")
    try:
        return BlindTransportRecord.from_wire(
            cast(dict[str, object], decoded),
            limits=limits,
            allow_legacy_unsigned=allow_legacy_unsigned,
            allow_legacy_blank_recipient_key_id=allow_legacy_blank_recipient_key_id,
        )
    except (
        KeyError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
    ) as exc:
        raise ProtocolError("spooled transport record violates the wire schema") from exc


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

    def __init__(
        self,
        path: str | Path,
        *,
        limits: ProtocolLimits | None = None,
        allow_legacy_unsigned: bool = False,
        allow_legacy_blank_recipient_key_id: bool = False,
        max_batch_wire_bytes: int = DEFAULT_SPOOL_BATCH_WIRE_BYTES,
    ) -> None:
        if (
            isinstance(max_batch_wire_bytes, bool)
            or not isinstance(max_batch_wire_bytes, int)
            or max_batch_wire_bytes <= 0
        ):
            raise ValueError("spool batch wire limit must be a positive integer")
        self.path = Path(path)
        self.limits = limits or ProtocolLimits()
        if max_batch_wire_bytes < self.limits.max_record_wire_bytes:
            raise ValueError("spool batch wire limit must admit one protocol-sized record")
        self.allow_legacy_unsigned = allow_legacy_unsigned
        self.allow_legacy_blank_recipient_key_id = allow_legacy_blank_recipient_key_id
        self.max_batch_wire_bytes = max_batch_wire_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        configure_sqlite_durability(connection)
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
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
        return self.quarantine_many((record,), reason_code=reason_code)[0]

    def quarantine_many(
        self,
        records: Iterable[BlindTransportRecord],
        reason_code: str,
    ) -> tuple[SpoolEntry, ...]:
        """Persist a bounded sealed-record batch in one SQLite transaction."""

        if not isinstance(reason_code, str):
            raise TypeError("reason_code must be a string")
        if not reason_code or len(reason_code) > 96 or not reason_code.replace("_", "").isalnum():
            raise ValueError("reason_code must be a short machine-readable identifier")
        now = datetime.now(UTC).isoformat()
        prepared: list[tuple[SpoolEntry, bytes]] = []
        total_wire_bytes = 0
        for index, record in enumerate(records):
            if index >= MAX_SPOOL_BATCH_ITEMS:
                raise ValueError("spool batch exceeds the record count limit")
            if not isinstance(record, BlindTransportRecord):
                raise TypeError("spool batch items must be BlindTransportRecord instances")
            wire = record.canonical_wire_bytes()
            if len(wire) > self.limits.max_record_wire_bytes:
                raise ValueError("record exceeds spool wire size limit")
            total_wire_bytes += len(wire)
            if total_wire_bytes > self.max_batch_wire_bytes:
                raise ValueError("spool batch exceeds the wire byte limit")
            parsed = BlindTransportRecord.from_wire(
                json.loads(wire.decode("utf-8")),
                limits=self.limits,
                allow_legacy_unsigned=self.allow_legacy_unsigned,
                allow_legacy_blank_recipient_key_id=self.allow_legacy_blank_recipient_key_id,
            )
            digest = record.digest()
            if parsed.digest() != digest or parsed.canonical_wire_bytes() != wire:
                raise IntegrityError("record failed spool canonical validation")
            prepared.append(
                (
                    SpoolEntry(
                        digest,
                        record.tenant,
                        record.destination_connector,
                        record.transfer_id,
                        record.record_id,
                        record.plan_digest,
                        reason_code,
                        now,
                    ),
                    wire,
                )
            )
        if not prepared:
            return ()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for entry, wire in prepared:
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
                        entry.record_digest,
                        entry.tenant,
                        entry.destination_connector,
                        entry.transfer_id,
                        entry.record_id,
                        entry.plan_digest,
                        entry.reason_code,
                        entry.quarantined_at,
                        wire,
                    ),
                )

            expected = {entry.record_digest: (entry, wire) for entry, wire in prepared}
            found: set[str] = set()
            expected_digests = tuple(expected)
            for offset in range(0, len(expected_digests), _SQLITE_DIGEST_CHUNK_SIZE):
                chunk = expected_digests[offset : offset + _SQLITE_DIGEST_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                rows = connection.execute(
                    """
                    SELECT record_digest, tenant, destination_connector, transfer_id,
                           record_id, plan_digest, reason_code, quarantined_at, wire_json
                    FROM sealed_quarantine
                    """
                    f"WHERE record_digest IN ({placeholders})",
                    chunk,
                ).fetchall()
                for row in rows:
                    digest = row["record_digest"]
                    if not isinstance(digest, str) or digest not in expected or digest in found:
                        raise IntegrityError("sealed spool persistence postcondition failed")
                    entry, wire = expected[digest]
                    if (
                        row["tenant"] != entry.tenant
                        or row["destination_connector"] != entry.destination_connector
                        or row["transfer_id"] != entry.transfer_id
                        or row["record_id"] != entry.record_id
                        or row["plan_digest"] != entry.plan_digest
                        or row["reason_code"] != entry.reason_code
                        or row["quarantined_at"] != entry.quarantined_at
                        or type(row["wire_json"]) is not bytes
                        or row["wire_json"] != wire
                    ):
                        raise IntegrityError("sealed spool persistence postcondition failed")
                    found.add(digest)
            if found != set(expected_digests):
                raise IntegrityError("sealed spool persistence postcondition failed")
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        return tuple(entry for entry, _ in prepared)

    def get(self, record_digest: str) -> BlindTransportRecord | None:
        if not isinstance(record_digest, str):
            raise TypeError("spool record digest must be a string")
        if len(record_digest) != 64 or any(
            character not in "0123456789abcdef" for character in record_digest
        ):
            raise ValueError("spool record digest must be a lowercase SHA-256 digest")

        connection = self._connect()
        try:
            # Keep the metadata check and blob fetch in one read transaction. This both
            # rejects oversized persisted values before materializing them and prevents a
            # concurrent database writer from swapping the value between the two reads.
            connection.execute("BEGIN")
            metadata = connection.execute(
                """
                SELECT typeof(wire_json) AS wire_type, length(wire_json) AS wire_bytes
                FROM sealed_quarantine
                WHERE record_digest = ?
                """,
                (record_digest,),
            ).fetchone()
            if metadata is None:
                connection.commit()
                return None
            wire_bytes = metadata["wire_bytes"]
            if metadata["wire_type"] != "blob":
                raise IntegrityError("sealed spool record is not stored as a blob")
            if (
                type(wire_bytes) is not int
                or not 0 < wire_bytes <= self.limits.max_record_wire_bytes
            ):
                raise IntegrityError("sealed spool record has an invalid wire size")

            row = connection.execute(
                "SELECT wire_json FROM sealed_quarantine WHERE record_digest = ?",
                (record_digest,),
            ).fetchone()
            if row is None or type(row["wire_json"]) is not bytes:
                raise IntegrityError("sealed spool record changed while being read")
            wire = row["wire_json"]
            if len(wire) != wire_bytes:
                raise IntegrityError("sealed spool record changed while being read")

            try:
                record = _decode_spooled_record(
                    wire,
                    limits=self.limits,
                    allow_legacy_unsigned=self.allow_legacy_unsigned,
                    allow_legacy_blank_recipient_key_id=self.allow_legacy_blank_recipient_key_id,
                )
            except ProtocolError as exc:
                raise IntegrityError(
                    "sealed spool record is not valid canonical wire data"
                ) from exc
            if record.digest() != record_digest:
                raise IntegrityError("sealed spool record digest mismatch")
            if record.canonical_wire_bytes() != wire:
                raise IntegrityError("sealed spool record is not canonical")
            connection.commit()
            return record
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def remove(self, record_digest: str) -> None:
        self.remove_many((record_digest,))

    def remove_many(self, record_digests: Iterable[str]) -> int:
        """Remove a bounded digest batch atomically and return the number removed."""

        digests: list[str] = []
        for record_digest in record_digests:
            if len(digests) >= MAX_SPOOL_BATCH_ITEMS:
                raise ValueError("spool batch exceeds the record count limit")
            if not isinstance(record_digest, str):
                raise TypeError("spool record digests must be strings")
            if len(record_digest) != 64 or any(
                character not in "0123456789abcdef" for character in record_digest
            ):
                raise ValueError("spool record digest must be a lowercase SHA-256 digest")
            digests.append(record_digest)
        if not digests:
            return 0

        unique_digests = tuple(dict.fromkeys(digests))
        connection = self._connect()
        removed = 0
        try:
            connection.execute("BEGIN IMMEDIATE")
            for offset in range(0, len(unique_digests), _SQLITE_DIGEST_CHUNK_SIZE):
                chunk = unique_digests[offset : offset + _SQLITE_DIGEST_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                cursor = connection.execute(
                    f"DELETE FROM sealed_quarantine WHERE record_digest IN ({placeholders})",
                    chunk,
                )
                removed += cursor.rowcount

            for offset in range(0, len(unique_digests), _SQLITE_DIGEST_CHUNK_SIZE):
                chunk = unique_digests[offset : offset + _SQLITE_DIGEST_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                remaining = connection.execute(
                    "SELECT 1 FROM sealed_quarantine "
                    f"WHERE record_digest IN ({placeholders}) LIMIT 1",
                    chunk,
                ).fetchone()
                if remaining is not None:
                    raise IntegrityError("sealed spool removal postcondition failed")
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        return removed

    def list_entries(self, *, limit: int = 100) -> tuple[SpoolEntry, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise ValueError("spool limit is outside supported range")
        with closing(self._connect()) as connection, connection:
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
