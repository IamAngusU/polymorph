from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .agents import BlindTransportRecord
from .errors import IntegrityError, ReplayDetected


class DeliveryState(StrEnum):
    CLAIMED = "claimed"
    COMMITTED = "committed"
    UNCERTAIN = "uncertain"
    QUARANTINED = "quarantined"


class ClaimDisposition(StrEnum):
    NEW = "new"
    ALREADY_COMMITTED = "already_committed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class ClaimResult:
    disposition: ClaimDisposition
    state: DeliveryState
    record_digest: str


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    tenant: str
    destination_connector: str
    transfer_id: str
    record_id: str
    record_digest: str
    plan_digest: str
    state: DeliveryState
    created_at: str
    updated_at: str
    reason_code: str | None


class DeliveryLedger:
    """Durable destination-side replay and outcome ledger.

    The ledger stores identifiers and ciphertext digests only. It never receives plaintext
    record values.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
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
                CREATE TABLE IF NOT EXISTS deliveries (
                    tenant TEXT NOT NULL,
                    destination_connector TEXT NOT NULL,
                    transfer_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    record_digest TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    reason_code TEXT,
                    PRIMARY KEY (tenant, destination_connector, transfer_id, record_id)
                )
                """
            )

    @staticmethod
    def _key(record: BlindTransportRecord) -> tuple[str, str, str, str]:
        return (
            record.tenant,
            record.destination_connector,
            record.transfer_id,
            record.record_id,
        )

    def claim(self, record: BlindTransportRecord) -> ClaimResult:
        key = self._key(record)
        digest = record.digest()
        now = datetime.now(UTC).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT record_digest, plan_digest, state
                FROM deliveries
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                """,
                key,
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO deliveries (
                        tenant, destination_connector, transfer_id, record_id,
                        record_digest, plan_digest, state, created_at, updated_at, reason_code
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (*key, digest, record.plan_digest, DeliveryState.CLAIMED.value, now, now),
                )
                connection.execute("COMMIT")
                return ClaimResult(ClaimDisposition.NEW, DeliveryState.CLAIMED, digest)

            if row["record_digest"] != digest or row["plan_digest"] != record.plan_digest:
                connection.execute("ROLLBACK")
                raise ReplayDetected(
                    "transfer identity was reused with different authenticated content"
                )

            state = DeliveryState(row["state"])
            disposition = (
                ClaimDisposition.ALREADY_COMMITTED
                if state is DeliveryState.COMMITTED
                else ClaimDisposition.AMBIGUOUS
            )
            connection.execute("COMMIT")
            return ClaimResult(disposition, state, digest)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _transition(
        self,
        record: BlindTransportRecord,
        state: DeliveryState,
        *,
        reason_code: str | None = None,
        allowed_from: tuple[DeliveryState, ...] = (DeliveryState.CLAIMED,),
    ) -> None:
        key = self._key(record)
        digest = record.digest()
        now = datetime.now(UTC).isoformat()
        placeholders = ",".join("?" for _ in allowed_from)
        params = [
            state.value,
            now,
            reason_code,
            *key,
            digest,
            *(item.value for item in allowed_from),
        ]
        with self._connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE deliveries
                SET state = ?, updated_at = ?, reason_code = ?
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                  AND record_digest = ? AND state IN ({placeholders})
                """,
                params,
            )
            if cursor.rowcount != 1:
                raise IntegrityError("invalid delivery ledger state transition")

    def mark_committed(self, record: BlindTransportRecord) -> None:
        self._transition(record, DeliveryState.COMMITTED)

    def mark_uncertain(self, record: BlindTransportRecord, reason_code: str) -> None:
        self._transition(record, DeliveryState.UNCERTAIN, reason_code=reason_code)

    def mark_quarantined(self, record: BlindTransportRecord, reason_code: str) -> None:
        self._transition(record, DeliveryState.QUARANTINED, reason_code=reason_code)

    def rearm_for_retry(self, record: BlindTransportRecord) -> None:
        self._transition(
            record,
            DeliveryState.CLAIMED,
            reason_code=None,
            allowed_from=(DeliveryState.UNCERTAIN, DeliveryState.QUARANTINED),
        )

    def get(self, record: BlindTransportRecord) -> LedgerEntry | None:
        key = self._key(record)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM deliveries
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                """,
                key,
            ).fetchone()
        if row is None:
            return None
        return LedgerEntry(
            tenant=row["tenant"],
            destination_connector=row["destination_connector"],
            transfer_id=row["transfer_id"],
            record_id=row["record_id"],
            record_digest=row["record_digest"],
            plan_digest=row["plan_digest"],
            state=DeliveryState(row["state"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            reason_code=row["reason_code"],
        )
