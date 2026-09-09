from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .agents import BlindTransportRecord, ProtocolLimits
from .errors import IntegrityError, PolicyViolation, ReplayDetected


@dataclass(frozen=True, slots=True)
class RouteBinding:
    tenant: str
    source_connector: str
    destination_connector: str
    allowed_plan_digests: frozenset[str] = frozenset()

    def allows(self, record: BlindTransportRecord) -> bool:
        return (
            record.tenant == self.tenant
            and record.source_connector == self.source_connector
            and record.destination_connector == self.destination_connector
            and (
                not self.allowed_plan_digests
                or record.plan_digest in self.allowed_plan_digests
            )
        )


@dataclass(frozen=True, slots=True)
class RelayPolicy:
    routes: tuple[RouteBinding, ...]
    require_expiry: bool = False
    max_lifetime: timedelta | None = timedelta(hours=24)

    def validate(self, record: BlindTransportRecord, *, now: datetime | None = None) -> None:
        if not any(route.allows(record) for route in self.routes):
            raise PolicyViolation("sealed record route is not authorized")
        first = record.fields[0].context
        first.validate_time(now=now)
        if self.require_expiry and first.expires_at is None:
            raise PolicyViolation("sealed record has no authenticated expiry")
        if first.issued_at is not None and first.expires_at is not None and self.max_lifetime is not None:
            if first.expires_at - first.issued_at > self.max_lifetime:
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
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
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
                    lease_expires_at TEXT,
                    UNIQUE (tenant, destination_connector, transfer_id, record_id)
                )
                """
            )

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
        now = datetime.now(UTC)
        expires = now + lease_for
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT record_digest, wire_json FROM sealed_relay_queue
                WHERE destination_connector = ?
                  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                ORDER BY received_at ASC
                LIMIT ?
                """,
                (destination_connector, now.isoformat(), limit),
            ).fetchall()
            leased: list[LeasedRecord] = []
            for row in rows:
                connection.execute(
                    """
                    UPDATE sealed_relay_queue
                    SET lease_owner = ?, lease_expires_at = ?
                    WHERE record_digest = ?
                    """,
                    (lease_owner, expires.isoformat(), row["record_digest"]),
                )
                payload = json.loads(bytes(row["wire_json"]).decode("utf-8"))
                record = BlindTransportRecord.from_wire(payload, limits=self.limits)
                if record.digest() != row["record_digest"]:
                    connection.execute("ROLLBACK")
                    raise IntegrityError("sealed relay queue record digest mismatch")
                leased.append(LeasedRecord(record, lease_owner, expires.isoformat()))
            connection.execute("COMMIT")
            return tuple(leased)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def ack(self, record_digest: str, *, lease_owner: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM sealed_relay_queue
                WHERE record_digest = ? AND lease_owner = ?
                """,
                (record_digest, lease_owner),
            )
            if cursor.rowcount != 1:
                raise IntegrityError("relay acknowledgement does not own the active lease")

    def release(self, record_digest: str, *, lease_owner: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE sealed_relay_queue
                SET lease_owner = NULL, lease_expires_at = NULL
                WHERE record_digest = ? AND lease_owner = ?
                """,
                (record_digest, lease_owner),
            )
            if cursor.rowcount != 1:
                raise IntegrityError("relay release does not own the active lease")

    def depth(self, *, destination_connector: str | None = None) -> int:
        with self._connect() as connection:
            if destination_connector is None:
                row = connection.execute("SELECT COUNT(*) AS count FROM sealed_relay_queue").fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM sealed_relay_queue WHERE destination_connector = ?",
                    (destination_connector,),
                ).fetchone()
        return int(row["count"])
