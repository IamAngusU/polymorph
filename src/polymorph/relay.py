from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from .agents import BlindTransportRecord, ProtocolLimits
from .errors import IntegrityError, PolicyViolation, ProtocolError, ReplayDetected, TransferExpired
from .signing import SourceTrustStore
from .sqlite_safety import configure_sqlite_durability

MAX_LEASE_DURATION = timedelta(hours=1)
MAX_DEAD_LETTERS_PER_LEASE = 1_000
_LEASE_ID_BYTES = 32

_DEAD_LETTER_INVALID_WIRE = "relay_wire_invalid"
_DEAD_LETTER_SOURCE_AUTH = "relay_source_authentication_failed"
_DEAD_LETTER_EXPIRED = "relay_transfer_expired"
_DEAD_LETTER_POLICY = "relay_policy_rejected"
_DEAD_LETTER_DIGEST = "relay_digest_mismatch"


@dataclass(frozen=True, slots=True)
class RouteBinding:
    tenant: str
    source_connector: str
    destination_connector: str
    allowed_plan_digests: frozenset[str] = frozenset()
    allowed_source_key_ids: frozenset[str] = frozenset()

    def allows(self, record: BlindTransportRecord) -> bool:
        return (
            record.tenant == self.tenant
            and record.source_connector == self.source_connector
            and record.destination_connector == self.destination_connector
            and (not self.allowed_plan_digests or record.plan_digest in self.allowed_plan_digests)
            and (
                not self.allowed_source_key_ids
                or (
                    record.authentication is not None
                    and record.authentication.key_id in self.allowed_source_key_ids
                )
            )
        )


@dataclass(frozen=True, slots=True)
class RelayPolicy:
    routes: tuple[RouteBinding, ...]
    require_expiry: bool = False
    max_lifetime: timedelta | None = timedelta(hours=24)
    source_trust_store: SourceTrustStore | None = None
    allow_legacy_unsigned: bool = False

    def validate(self, record: BlindTransportRecord, *, now: datetime | None = None) -> None:
        if record.protocol_version == 2:
            if not self.allow_legacy_unsigned:
                raise PolicyViolation("unsigned v2 transport record is not allowed by relay policy")
        else:
            if self.source_trust_store is None:
                raise PolicyViolation("relay policy has no trusted source key registry")
            self.source_trust_store.verify_record(record, now=now)
        if not any(route.allows(record) for route in self.routes):
            raise PolicyViolation("sealed record route is not authorized")
        first = record.fields[0].context
        first.validate_time(now=now)
        if self.require_expiry and first.expires_at is None:
            raise PolicyViolation("sealed record has no authenticated expiry")
        if (
            first.issued_at is not None
            and first.expires_at is not None
            and self.max_lifetime is not None
            and first.expires_at - first.issued_at > self.max_lifetime
        ):
            raise PolicyViolation("sealed record lifetime exceeds relay policy")


@dataclass(frozen=True, slots=True)
class RelayReceipt:
    record_digest: str
    tenant: str
    destination_connector: str
    transfer_id: str
    record_id: str
    plan_digest: str
    accepted_at: str
    duplicate: bool = False


@dataclass(frozen=True, slots=True)
class LeasedRecord:
    record: BlindTransportRecord
    lease_owner: str
    lease_expires_at: str
    lease_id: str


@dataclass(frozen=True, slots=True)
class RelayDeadLetter:
    record_digest: str
    tenant: str
    source_connector: str
    destination_connector: str
    transfer_id: str
    record_id: str
    plan_digest: str
    reason_code: str
    dead_lettered_at: str


def _decode_queued_record(
    wire: bytes,
    *,
    limits: ProtocolLimits,
    allow_legacy_unsigned: bool,
) -> BlindTransportRecord:
    def reject_constant(value: str) -> object:
        raise ProtocolError(f"non-finite JSON constant is not allowed: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError("duplicate key in queued transport record")
            result[key] = value
        return result

    if len(wire) > limits.max_record_wire_bytes:
        raise ProtocolError("queued transport record exceeds the wire size limit")
    try:
        decoded: object = json.loads(
            wire.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("queued transport record is not valid JSON") from exc
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise ProtocolError("queued transport record must be a JSON object")
    try:
        return BlindTransportRecord.from_wire(
            cast(dict[str, object], decoded),
            limits=limits,
            allow_legacy_unsigned=allow_legacy_unsigned,
        )
    except (
        KeyError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
    ) as exc:
        raise ProtocolError("queued transport record violates the wire schema") from exc


class SealedRelayQueue:
    """Persistent queue for ciphertext-only transport records.

    The queue intentionally has no recipient key parameter and no decrypt method. All state
    needed for routing is authenticated metadata already bound into each field envelope.
    """

    def __init__(
        self,
        path: str | Path,
        policy: RelayPolicy,
        *,
        limits: ProtocolLimits | None = None,
    ) -> None:
        self.path = Path(path)
        self.policy = policy
        self.limits = limits or ProtocolLimits()
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
        connection = self._connect()
        try:
            # Schema inspection and migration must be one serialized operation. Without
            # the write lock, parallel workers opening a legacy database can both observe
            # a missing column and race to add it.
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sealed_relay_queue (
                    record_digest TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    source_connector TEXT NOT NULL,
                    destination_connector TEXT NOT NULL,
                    transfer_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    wire_json BLOB NOT NULL,
                    lease_owner TEXT,
                    lease_id TEXT,
                    lease_expires_at TEXT,
                    UNIQUE (tenant, destination_connector, transfer_id, record_id)
                )
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(sealed_relay_queue)")
            }
            if "lease_id" not in columns:
                connection.execute("ALTER TABLE sealed_relay_queue ADD COLUMN lease_id TEXT")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sealed_relay_dead_letter (
                    record_digest TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    source_connector TEXT NOT NULL,
                    destination_connector TEXT NOT NULL,
                    transfer_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    dead_lettered_at TEXT NOT NULL,
                    wire_json BLOB NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS relay_dead_letter_identity
                ON sealed_relay_dead_letter (
                    tenant, destination_connector, transfer_id, record_id
                )
                """
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def enqueue(self, record: BlindTransportRecord) -> RelayReceipt:
        self.policy.validate(record)
        wire = record.canonical_wire_bytes()
        if len(wire) > self.limits.max_record_wire_bytes:
            raise PolicyViolation("sealed record exceeds relay queue size limit")
        digest = record.digest()
        accepted_at = datetime.now(UTC).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            identity = connection.execute(
                """
                SELECT record_digest FROM sealed_relay_queue
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                """,
                (
                    record.tenant,
                    record.destination_connector,
                    record.transfer_id,
                    record.record_id,
                ),
            ).fetchone()
            if identity is not None:
                if identity["record_digest"] != digest:
                    connection.execute("ROLLBACK")
                    raise ReplayDetected(
                        "relay transfer identity was reused with different authenticated content"
                    )
                connection.execute("COMMIT")
                return RelayReceipt(
                    digest,
                    record.tenant,
                    record.destination_connector,
                    record.transfer_id,
                    record.record_id,
                    record.plan_digest,
                    accepted_at,
                    duplicate=True,
                )
            dead_letter_identity = connection.execute(
                """
                SELECT record_digest FROM sealed_relay_dead_letter
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                LIMIT 1
                """,
                (
                    record.tenant,
                    record.destination_connector,
                    record.transfer_id,
                    record.record_id,
                ),
            ).fetchone()
            if dead_letter_identity is not None:
                connection.execute("ROLLBACK")
                raise ReplayDetected("relay transfer identity is permanently dead-lettered")
            connection.execute(
                """
                INSERT INTO sealed_relay_queue (
                    record_digest, tenant, source_connector, destination_connector,
                    transfer_id, record_id, plan_digest, received_at, wire_json
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
                    accepted_at,
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
        return RelayReceipt(
            digest,
            record.tenant,
            record.destination_connector,
            record.transfer_id,
            record.record_id,
            record.plan_digest,
            accepted_at,
        )

    def lease(
        self,
        *,
        destination_connector: str,
        lease_owner: str,
        limit: int = 100,
        lease_for: timedelta = timedelta(minutes=2),
    ) -> tuple[LeasedRecord, ...]:
        if not lease_owner or len(lease_owner) > 128:
            raise ValueError("lease owner is invalid")
        if not 1 <= limit <= 10_000:
            raise ValueError("lease limit is outside supported range")
        if lease_for <= timedelta(0) or lease_for > MAX_LEASE_DURATION:
            raise ValueError("lease duration is outside supported range")
        now = datetime.now(UTC)
        expires = now + lease_for
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            leased: list[LeasedRecord] = []
            scanned = 0
            scan_limit = limit + MAX_DEAD_LETTERS_PER_LEASE
            while len(leased) < limit and scanned < scan_limit:
                row = connection.execute(
                    """
                    SELECT record_digest, tenant, source_connector,
                           destination_connector, transfer_id, record_id,
                           plan_digest, received_at, wire_json
                    FROM sealed_relay_queue
                    WHERE destination_connector = ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    ORDER BY received_at ASC, record_digest ASC
                    LIMIT 1
                    """,
                    (destination_connector, now.isoformat()),
                ).fetchone()
                if row is None:
                    break
                scanned += 1
                raw_wire = row["wire_json"]
                if not isinstance(raw_wire, (bytes, bytearray, memoryview)):
                    self._dead_letter(
                        connection,
                        row,
                        b"",
                        _DEAD_LETTER_INVALID_WIRE,
                        now,
                    )
                    continue
                wire = bytes(raw_wire)
                try:
                    record = _decode_queued_record(
                        wire,
                        limits=self.limits,
                        allow_legacy_unsigned=self.policy.allow_legacy_unsigned,
                    )
                    self.policy.validate(record, now=now)
                except TransferExpired:
                    self._dead_letter(connection, row, wire, _DEAD_LETTER_EXPIRED, now)
                    continue
                except PolicyViolation:
                    self._dead_letter(connection, row, wire, _DEAD_LETTER_POLICY, now)
                    continue
                except IntegrityError:
                    self._dead_letter(connection, row, wire, _DEAD_LETTER_SOURCE_AUTH, now)
                    continue
                except ProtocolError:
                    self._dead_letter(connection, row, wire, _DEAD_LETTER_INVALID_WIRE, now)
                    continue
                if record.digest() != row["record_digest"]:
                    self._dead_letter(connection, row, wire, _DEAD_LETTER_DIGEST, now)
                    continue
                lease_id = secrets.token_urlsafe(_LEASE_ID_BYTES)
                connection.execute(
                    """
                    UPDATE sealed_relay_queue
                    SET lease_owner = ?, lease_id = ?, lease_expires_at = ?
                    WHERE record_digest = ?
                    """,
                    (lease_owner, lease_id, expires.isoformat(), row["record_digest"]),
                )
                leased.append(
                    LeasedRecord(
                        record=record,
                        lease_owner=lease_owner,
                        lease_expires_at=expires.isoformat(),
                        lease_id=lease_id,
                    )
                )
            connection.execute("COMMIT")
            return tuple(leased)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _dead_letter(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        wire: bytes,
        reason_code: str,
        now: datetime,
    ) -> None:
        connection.execute(
            """
            INSERT INTO sealed_relay_dead_letter (
                record_digest, tenant, source_connector, destination_connector,
                transfer_id, record_id, plan_digest, received_at,
                reason_code, dead_lettered_at, wire_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_digest) DO NOTHING
            """,
            (
                row["record_digest"],
                row["tenant"],
                row["source_connector"],
                row["destination_connector"],
                row["transfer_id"],
                row["record_id"],
                row["plan_digest"],
                row["received_at"],
                reason_code,
                now.isoformat(),
                wire,
            ),
        )
        connection.execute(
            "DELETE FROM sealed_relay_queue WHERE record_digest = ?",
            (row["record_digest"],),
        )

    def ack(self, record_digest: str, *, lease_owner: str, lease_id: str) -> None:
        if not lease_id or len(lease_id) > 128:
            raise ValueError("lease id is invalid")
        now = datetime.now(UTC).isoformat()
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                DELETE FROM sealed_relay_queue
                WHERE record_digest = ? AND lease_owner = ? AND lease_id = ?
                  AND lease_expires_at > ?
                """,
                (record_digest, lease_owner, lease_id, now),
            )
            if cursor.rowcount != 1:
                raise IntegrityError("relay acknowledgement does not own the active lease")

    def release(self, record_digest: str, *, lease_owner: str, lease_id: str) -> None:
        if not lease_id or len(lease_id) > 128:
            raise ValueError("lease id is invalid")
        now = datetime.now(UTC).isoformat()
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE sealed_relay_queue
                SET lease_owner = NULL, lease_id = NULL, lease_expires_at = NULL
                WHERE record_digest = ? AND lease_owner = ? AND lease_id = ?
                  AND lease_expires_at > ?
                """,
                (record_digest, lease_owner, lease_id, now),
            )
            if cursor.rowcount != 1:
                raise IntegrityError("relay release does not own the active lease")

    def depth(self, *, destination_connector: str | None = None) -> int:
        with closing(self._connect()) as connection, connection:
            if destination_connector is None:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM sealed_relay_queue"
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM sealed_relay_queue "
                    "WHERE destination_connector = ?",
                    (destination_connector,),
                ).fetchone()
        return int(row["count"])

    def dead_letter_depth(self, *, destination_connector: str | None = None) -> int:
        with closing(self._connect()) as connection, connection:
            if destination_connector is None:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM sealed_relay_dead_letter"
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM sealed_relay_dead_letter "
                    "WHERE destination_connector = ?",
                    (destination_connector,),
                ).fetchone()
        return int(row["count"])

    def list_dead_letters(self, *, limit: int = 100) -> tuple[RelayDeadLetter, ...]:
        if not 1 <= limit <= 10_000:
            raise ValueError("dead-letter limit is outside supported range")
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT record_digest, tenant, source_connector,
                       destination_connector, transfer_id, record_id,
                       plan_digest, reason_code, dead_lettered_at
                FROM sealed_relay_dead_letter
                ORDER BY dead_lettered_at ASC, record_digest ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(
            RelayDeadLetter(
                record_digest=row["record_digest"],
                tenant=row["tenant"],
                source_connector=row["source_connector"],
                destination_connector=row["destination_connector"],
                transfer_id=row["transfer_id"],
                record_id=row["record_id"],
                plan_digest=row["plan_digest"],
                reason_code=row["reason_code"],
                dead_lettered_at=row["dead_lettered_at"],
            )
            for row in rows
        )
