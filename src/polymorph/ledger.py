from __future__ import annotations

import os
import secrets
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from .agents import BlindTransportRecord
from .errors import IntegrityError, ReplayDetected
from .sqlite_safety import configure_sqlite_durability


class DeliveryState(StrEnum):
    CLAIMED = "claimed"
    WRITE_STARTED = "write_started"
    COMMITTED = "committed"
    UNCERTAIN = "uncertain"
    QUARANTINED = "quarantined"


class ClaimDisposition(StrEnum):
    NEW = "new"
    RECOVERED = "recovered"
    IN_PROGRESS = "in_progress"
    ALREADY_COMMITTED = "already_committed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class ClaimResult:
    disposition: ClaimDisposition
    state: DeliveryState
    record_digest: str
    claim_token: str | None = None
    claim_expires_at: str | None = None


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
    claim_token: str | None
    claim_expires_at: str | None


DEFAULT_CLAIM_DURATION = timedelta(minutes=5)
MAX_CLAIM_DURATION = timedelta(hours=1)
_CLAIM_TOKEN_BYTES = 32


class DeliveryLedger:
    """Durable destination-side replay and outcome ledger.

    The ledger stores identifiers and ciphertext digests only. It never receives plaintext
    record values.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self._clock = clock or (lambda: datetime.now(UTC))
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
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    PRIMARY KEY (tenant, destination_connector, transfer_id, record_id)
                )
                """
            )
            columns = {
                str(row["name"]) for row in connection.execute("PRAGMA table_info(deliveries)")
            }
            if "claim_token" not in columns:
                connection.execute("ALTER TABLE deliveries ADD COLUMN claim_token TEXT")
            if "claim_expires_at" not in columns:
                connection.execute("ALTER TABLE deliveries ADD COLUMN claim_expires_at TEXT")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("delivery ledger clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    @staticmethod
    def _validate_lease_duration(lease_for: timedelta) -> None:
        if lease_for <= timedelta(0) or lease_for > MAX_CLAIM_DURATION:
            raise ValueError("claim duration is outside supported range")

    @staticmethod
    def _validate_claim_token(claim_token: str) -> None:
        if not claim_token or len(claim_token) > 128:
            raise ValueError("claim token is invalid")

    @staticmethod
    def _parse_expiry(raw: object) -> datetime | None:
        if not isinstance(raw, str) or not raw:
            return None
        try:
            value = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if value.tzinfo is None:
            return None
        return value.astimezone(UTC)

    @staticmethod
    def _key(record: BlindTransportRecord) -> tuple[str, str, str, str]:
        return (
            record.tenant,
            record.destination_connector,
            record.transfer_id,
            record.record_id,
        )

    def claim(
        self,
        record: BlindTransportRecord,
        *,
        lease_for: timedelta = DEFAULT_CLAIM_DURATION,
    ) -> ClaimResult:
        self._validate_lease_duration(lease_for)
        key = self._key(record)
        digest = record.digest()
        now_value = self._now()
        now = now_value.isoformat()
        claim_token = secrets.token_urlsafe(_CLAIM_TOKEN_BYTES)
        claim_expires_at = (now_value + lease_for).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT record_digest, plan_digest, state, claim_token, claim_expires_at
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
                        record_digest, plan_digest, state, created_at, updated_at, reason_code,
                        claim_token, claim_expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        *key,
                        digest,
                        record.plan_digest,
                        DeliveryState.CLAIMED.value,
                        now,
                        now,
                        claim_token,
                        claim_expires_at,
                    ),
                )
                connection.execute("COMMIT")
                return ClaimResult(
                    ClaimDisposition.NEW,
                    DeliveryState.CLAIMED,
                    digest,
                    claim_token,
                    claim_expires_at,
                )

            if row["record_digest"] != digest or row["plan_digest"] != record.plan_digest:
                connection.execute("ROLLBACK")
                raise ReplayDetected(
                    "transfer identity was reused with different authenticated content"
                )

            try:
                state = DeliveryState(row["state"])
            except ValueError as exc:
                connection.execute("ROLLBACK")
                raise IntegrityError("delivery ledger contains an invalid state") from exc

            if state is DeliveryState.COMMITTED:
                connection.execute("COMMIT")
                return ClaimResult(ClaimDisposition.ALREADY_COMMITTED, state, digest)

            if state is DeliveryState.CLAIMED:
                previous_token = row["claim_token"]
                previous_expiry = self._parse_expiry(row["claim_expires_at"])
                if (
                    isinstance(previous_token, str)
                    and previous_token
                    and previous_expiry is not None
                ):
                    if previous_expiry > now_value:
                        connection.execute("COMMIT")
                        return ClaimResult(
                            ClaimDisposition.IN_PROGRESS,
                            state,
                            digest,
                            claim_expires_at=previous_expiry.isoformat(),
                        )
                    cursor = connection.execute(
                        """
                        UPDATE deliveries
                        SET claim_token = ?, claim_expires_at = ?, updated_at = ?,
                            reason_code = NULL
                        WHERE tenant = ? AND destination_connector = ?
                          AND transfer_id = ? AND record_id = ?
                          AND record_digest = ? AND plan_digest = ?
                          AND state = ? AND claim_token = ? AND claim_expires_at = ?
                        """,
                        (
                            claim_token,
                            claim_expires_at,
                            now,
                            *key,
                            digest,
                            record.plan_digest,
                            DeliveryState.CLAIMED.value,
                            previous_token,
                            row["claim_expires_at"],
                        ),
                    )
                    if cursor.rowcount != 1:
                        connection.execute("ROLLBACK")
                        raise IntegrityError("stale delivery claim could not be fenced")
                    connection.execute("COMMIT")
                    return ClaimResult(
                        ClaimDisposition.RECOVERED,
                        DeliveryState.CLAIMED,
                        digest,
                        claim_token,
                        claim_expires_at,
                    )

            # A legacy claim without fencing metadata and every state at or beyond the
            # write boundary are ambiguous. They require idempotency or explicit recovery.
            connection.execute("COMMIT")
            return ClaimResult(ClaimDisposition.AMBIGUOUS, state, digest)
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
        claim_token: str,
        expected_state: DeliveryState,
        reason_code: str | None = None,
        require_unexpired: bool = False,
    ) -> None:
        self._validate_claim_token(claim_token)
        key = self._key(record)
        digest = record.digest()
        now = self._now().isoformat()
        params = [
            state.value,
            now,
            reason_code,
            *key,
            digest,
            record.plan_digest,
            expected_state.value,
            claim_token,
        ]
        expiry_clause = " AND claim_expires_at > ?" if require_unexpired else ""
        if require_unexpired:
            params.append(now)
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                f"""
                UPDATE deliveries
                SET state = ?, updated_at = ?, reason_code = ?
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                  AND record_digest = ? AND plan_digest = ?
                  AND state = ? AND claim_token = ?{expiry_clause}
                """,
                params,
            )
            if cursor.rowcount != 1:
                raise IntegrityError("invalid delivery ledger state transition")

    def start_write(self, record: BlindTransportRecord, claim_token: str) -> None:
        """Cross the write boundary only while owning the active fenced claim."""

        self._transition(
            record,
            DeliveryState.WRITE_STARTED,
            claim_token=claim_token,
            expected_state=DeliveryState.CLAIMED,
            require_unexpired=True,
        )

    def mark_committed(self, record: BlindTransportRecord, claim_token: str) -> None:
        self._transition(
            record,
            DeliveryState.COMMITTED,
            claim_token=claim_token,
            expected_state=DeliveryState.WRITE_STARTED,
        )

    def mark_uncertain(
        self,
        record: BlindTransportRecord,
        reason_code: str,
        claim_token: str,
    ) -> None:
        self._transition(
            record,
            DeliveryState.UNCERTAIN,
            claim_token=claim_token,
            expected_state=DeliveryState.WRITE_STARTED,
            reason_code=reason_code,
        )

    def mark_quarantined(
        self,
        record: BlindTransportRecord,
        reason_code: str,
        claim_token: str,
        *,
        expected_state: DeliveryState = DeliveryState.CLAIMED,
    ) -> None:
        if expected_state not in (DeliveryState.CLAIMED, DeliveryState.WRITE_STARTED):
            raise ValueError("invalid state for delivery quarantine")
        self._transition(
            record,
            DeliveryState.QUARANTINED,
            claim_token=claim_token,
            expected_state=expected_state,
            reason_code=reason_code,
            require_unexpired=expected_state is DeliveryState.CLAIMED,
        )

    def rearm_for_retry(
        self,
        record: BlindTransportRecord,
        *,
        expected_state: DeliveryState,
        lease_for: timedelta = DEFAULT_CLAIM_DURATION,
    ) -> ClaimResult:
        if expected_state not in (
            DeliveryState.CLAIMED,
            DeliveryState.WRITE_STARTED,
            DeliveryState.UNCERTAIN,
            DeliveryState.QUARANTINED,
        ):
            raise ValueError("delivery state cannot be rearmed")
        self._validate_lease_duration(lease_for)
        key = self._key(record)
        digest = record.digest()
        now_value = self._now()
        now = now_value.isoformat()
        claim_token = secrets.token_urlsafe(_CLAIM_TOKEN_BYTES)
        claim_expires_at = (now_value + lease_for).isoformat()
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE deliveries
                SET state = ?, updated_at = ?, reason_code = NULL,
                    claim_token = ?, claim_expires_at = ?
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                  AND record_digest = ? AND plan_digest = ? AND state = ?
                """,
                (
                    DeliveryState.CLAIMED.value,
                    now,
                    claim_token,
                    claim_expires_at,
                    *key,
                    digest,
                    record.plan_digest,
                    expected_state.value,
                ),
            )
            if cursor.rowcount != 1:
                raise IntegrityError("invalid delivery ledger retry transition")
        return ClaimResult(
            ClaimDisposition.RECOVERED,
            DeliveryState.CLAIMED,
            digest,
            claim_token,
            claim_expires_at,
        )

    def get(self, record: BlindTransportRecord) -> LedgerEntry | None:
        key = self._key(record)
        with closing(self._connect()) as connection, connection:
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
            claim_token=row["claim_token"],
            claim_expires_at=row["claim_expires_at"],
        )
