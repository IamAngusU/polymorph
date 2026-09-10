from __future__ import annotations

import os
import secrets
import sqlite3
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import islice
from pathlib import Path

from .agents import BlindTransportRecord
from .connectors.base import MAX_IDEMPOTENCY_CONTRACT_ID_LENGTH
from .errors import IntegrityError, ReplayDetected
from .sqlite_safety import configure_sqlite_durability


class DeliveryState(StrEnum):
    CLAIMED = "claimed"
    WRITE_STARTED = "write_started"
    BATCH_WRITE_STARTED = "batch_write_started"
    REPLAY_CLAIMED = "replay_claimed"
    REPLAY_WRITE_STARTED = "replay_write_started"
    COMMITTED = "committed"
    UNCERTAIN = "uncertain"
    BATCH_UNCERTAIN = "batch_uncertain"
    REPLAY_UNCERTAIN = "replay_uncertain"
    QUARANTINED = "quarantined"
    REPLAY_QUARANTINED = "replay_quarantined"


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
    batch_attempt_id: str | None = None


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
    current_write_batch_attempt_id: str | None = None
    idempotency_contract_id: str | None = None


DEFAULT_CLAIM_DURATION = timedelta(minutes=5)
MAX_CLAIM_DURATION = timedelta(hours=1)
_CLAIM_TOKEN_BYTES = 32
MAX_LEDGER_BATCH_ITEMS = 10_000
_REPLAY_FENCING_MIGRATION = "replay_fencing_v1"


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
        connection = self._connect()
        try:
            # Fence schema inspection and migration together. Concurrent destination
            # workers may start on the same legacy ledger during a rolling restart.
            connection.execute("BEGIN IMMEDIATE")
            deliveries_existed = (
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'deliveries'"
                ).fetchone()
                is not None
            )
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
                    current_write_batch_attempt_id TEXT,
                    idempotency_contract_id TEXT,
                    PRIMARY KEY (tenant, destination_connector, transfer_id, record_id)
                )
                """
            )
            columns = {
                str(row["name"]) for row in connection.execute("PRAGMA table_info(deliveries)")
            }
            had_batch_attempt_column = "current_write_batch_attempt_id" in columns
            if "claim_token" not in columns:
                connection.execute("ALTER TABLE deliveries ADD COLUMN claim_token TEXT")
            if "claim_expires_at" not in columns:
                connection.execute("ALTER TABLE deliveries ADD COLUMN claim_expires_at TEXT")
            if "current_write_batch_attempt_id" not in columns:
                connection.execute(
                    "ALTER TABLE deliveries ADD COLUMN current_write_batch_attempt_id TEXT"
                )
            if "idempotency_contract_id" not in columns:
                connection.execute("ALTER TABLE deliveries ADD COLUMN idempotency_contract_id TEXT")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS polymorph_delivery_ledger_migrations (
                    migration_id TEXT PRIMARY KEY
                )
                """
            )
            replay_fencing_applied = (
                connection.execute(
                    """
                    SELECT 1 FROM polymorph_delivery_ledger_migrations
                    WHERE migration_id = ?
                    """,
                    (_REPLAY_FENCING_MIGRATION,),
                ).fetchone()
                is not None
            )
            if not replay_fencing_applied:
                if deliveries_existed and not had_batch_attempt_column:
                    # v0.3 did not persist replay provenance. Its CLAIMED and QUARANTINED
                    # rows may have originated from a replay of an uncertain write, so
                    # neither state is safe for an automatic retry after upgrading.
                    connection.execute(
                        "UPDATE deliveries SET state = ? WHERE state = ?",
                        (
                            DeliveryState.REPLAY_CLAIMED.value,
                            DeliveryState.CLAIMED.value,
                        ),
                    )
                    connection.execute(
                        "UPDATE deliveries SET state = ? WHERE state = ?",
                        (
                            DeliveryState.REPLAY_QUARANTINED.value,
                            DeliveryState.QUARANTINED.value,
                        ),
                    )
                elif deliveries_existed:
                    # Pre-release batching builds used scalar state names with an attempt
                    # marker. They could also have inherited an unmarked v0.3 replay whose
                    # provenance was already lost. Conservatively fence every pre-existing
                    # claimed or quarantined row exactly once. Repeating this conversion
                    # would misclassify later, known-safe rollback retries.
                    connection.execute(
                        "UPDATE deliveries SET state = ? WHERE state = ?",
                        (
                            DeliveryState.REPLAY_CLAIMED.value,
                            DeliveryState.CLAIMED.value,
                        ),
                    )
                    connection.execute(
                        "UPDATE deliveries SET state = ? WHERE state = ?",
                        (
                            DeliveryState.REPLAY_QUARANTINED.value,
                            DeliveryState.QUARANTINED.value,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE deliveries
                        SET state = ?
                        WHERE state = ? AND current_write_batch_attempt_id IS NOT NULL
                        """,
                        (
                            DeliveryState.BATCH_WRITE_STARTED.value,
                            DeliveryState.WRITE_STARTED.value,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE deliveries
                        SET state = ?
                        WHERE state = ? AND current_write_batch_attempt_id IS NOT NULL
                        """,
                        (
                            DeliveryState.BATCH_UNCERTAIN.value,
                            DeliveryState.UNCERTAIN.value,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO polymorph_delivery_ledger_migrations (migration_id)
                    VALUES (?)
                    """,
                    (_REPLAY_FENCING_MIGRATION,),
                )
            index_row = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'index' AND name = 'idx_deliveries_batch_attempt'
                """
            ).fetchone()
            index_sql = None if index_row is None else index_row["sql"]
            normalized_index_sql = (
                " ".join(index_sql.upper().split()) if isinstance(index_sql, str) else ""
            )
            if "WHERE CURRENT_WRITE_BATCH_ATTEMPT_ID IS NOT NULL" not in normalized_index_sql:
                connection.execute("DROP INDEX IF EXISTS idx_deliveries_batch_attempt")
                connection.execute(
                    """
                    CREATE INDEX idx_deliveries_batch_attempt
                    ON deliveries (current_write_batch_attempt_id)
                    WHERE current_write_batch_attempt_id IS NOT NULL
                    """
                )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

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
    def _validate_batch_attempt_id(batch_attempt_id: str) -> None:
        if len(batch_attempt_id) != 32 or any(
            char not in "0123456789abcdef" for char in batch_attempt_id
        ):
            raise ValueError("batch attempt id must be a lowercase 128-bit hexadecimal identifier")

    @staticmethod
    def _validate_idempotency_contract_id(contract_id: object) -> None:
        if (
            not isinstance(contract_id, str)
            or not contract_id
            or len(contract_id) > MAX_IDEMPOTENCY_CONTRACT_ID_LENGTH
            or not contract_id.isprintable()
            or contract_id != contract_id.strip()
        ):
            raise ValueError("idempotency contract id is invalid")

    @staticmethod
    def _idempotency_contract_from_row(row: sqlite3.Row) -> str | None:
        contract_id = row["idempotency_contract_id"]
        if contract_id is None:
            return None
        if not isinstance(contract_id, str):
            raise IntegrityError("delivery ledger contains an invalid idempotency contract id")
        try:
            DeliveryLedger._validate_idempotency_contract_id(contract_id)
        except ValueError as exc:
            raise IntegrityError(
                "delivery ledger contains an invalid idempotency contract id"
            ) from exc
        return contract_id

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
        return self.claim_many((record,), lease_for=lease_for)[0]

    def claim_many(
        self,
        records: Sequence[BlindTransportRecord],
        *,
        lease_for: timedelta = DEFAULT_CLAIM_DURATION,
    ) -> tuple[ClaimResult, ...]:
        """Claim a bounded delivery group in one all-or-none ledger transaction."""

        self._validate_lease_duration(lease_for)
        materialized = tuple(islice(iter(records), MAX_LEDGER_BATCH_ITEMS + 1))
        if not materialized:
            return ()
        if len(materialized) > MAX_LEDGER_BATCH_ITEMS:
            raise ValueError("delivery ledger batch exceeds the record count limit")
        if not all(isinstance(record, BlindTransportRecord) for record in materialized):
            raise TypeError("delivery ledger batch items must be BlindTransportRecord instances")
        keys = tuple(self._key(record) for record in materialized)
        if len(set(keys)) != len(keys):
            raise ValueError("delivery batch contains a duplicate transfer identity")
        now_value = self._now()
        now = now_value.isoformat()
        claim_expires_at = (now_value + lease_for).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            results: list[ClaimResult] = []
            for record, key in zip(materialized, keys, strict=True):
                digest = record.digest()
                claim_token = secrets.token_urlsafe(_CLAIM_TOKEN_BYTES)
                row = connection.execute(
                    """
                    SELECT record_digest, plan_digest, state, claim_token, claim_expires_at,
                           current_write_batch_attempt_id, idempotency_contract_id
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
                            record_digest, plan_digest, state, created_at, updated_at,
                            reason_code, claim_token, claim_expires_at
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
                    results.append(
                        ClaimResult(
                            ClaimDisposition.NEW,
                            DeliveryState.CLAIMED,
                            digest,
                            claim_token,
                            claim_expires_at,
                        )
                    )
                    continue

                if row["record_digest"] != digest or row["plan_digest"] != record.plan_digest:
                    raise ReplayDetected(
                        "transfer identity was reused with different authenticated content"
                    )

                try:
                    state = DeliveryState(row["state"])
                except ValueError as exc:
                    raise IntegrityError("delivery ledger contains an invalid state") from exc

                batch_attempt_id = row["current_write_batch_attempt_id"]
                if batch_attempt_id is not None:
                    if not isinstance(batch_attempt_id, str):
                        raise IntegrityError("delivery ledger contains an invalid batch attempt id")
                    try:
                        self._validate_batch_attempt_id(batch_attempt_id)
                    except ValueError as exc:
                        raise IntegrityError(
                            "delivery ledger contains an invalid batch attempt id"
                        ) from exc
                if (
                    state
                    in {
                        DeliveryState.BATCH_WRITE_STARTED,
                        DeliveryState.BATCH_UNCERTAIN,
                    }
                    and batch_attempt_id is None
                ):
                    raise IntegrityError("batch delivery state is missing its attempt id")
                self._idempotency_contract_from_row(row)

                if state is DeliveryState.COMMITTED:
                    results.append(
                        ClaimResult(
                            ClaimDisposition.ALREADY_COMMITTED,
                            state,
                            digest,
                            batch_attempt_id=batch_attempt_id,
                        )
                    )
                    continue

                if state in {DeliveryState.CLAIMED, DeliveryState.REPLAY_CLAIMED}:
                    previous_token = row["claim_token"]
                    previous_expiry = self._parse_expiry(row["claim_expires_at"])
                    if (
                        isinstance(previous_token, str)
                        and previous_token
                        and previous_expiry is not None
                        and previous_expiry > now_value
                    ):
                        results.append(
                            ClaimResult(
                                ClaimDisposition.IN_PROGRESS,
                                state,
                                digest,
                                claim_expires_at=previous_expiry.isoformat(),
                                batch_attempt_id=batch_attempt_id,
                            )
                        )
                        continue
                    if state is DeliveryState.REPLAY_CLAIMED:
                        results.append(
                            ClaimResult(
                                ClaimDisposition.AMBIGUOUS,
                                state,
                                digest,
                                batch_attempt_id=batch_attempt_id,
                            )
                        )
                        continue
                    if (
                        isinstance(previous_token, str)
                        and previous_token
                        and previous_expiry is not None
                    ):
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
                            raise IntegrityError("stale delivery claim could not be fenced")
                        results.append(
                            ClaimResult(
                                ClaimDisposition.RECOVERED,
                                DeliveryState.CLAIMED,
                                digest,
                                claim_token,
                                claim_expires_at,
                                batch_attempt_id,
                            )
                        )
                        continue

                # A legacy claim without fencing metadata and every state at or beyond the
                # write boundary are ambiguous. They require idempotency or explicit recovery.
                results.append(
                    ClaimResult(
                        ClaimDisposition.AMBIGUOUS,
                        state,
                        digest,
                        batch_attempt_id=batch_attempt_id,
                    )
                )
            connection.execute("COMMIT")
            return tuple(results)
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
        clear_batch_attempt: bool = False,
        set_idempotency_contract: bool = False,
        idempotency_contract_id: str | None = None,
    ) -> None:
        self._validate_claim_token(claim_token)
        if idempotency_contract_id is not None:
            self._validate_idempotency_contract_id(idempotency_contract_id)
        key = self._key(record)
        digest = record.digest()
        now = self._now().isoformat()
        params: list[object] = [
            state.value,
            now,
            reason_code,
        ]
        update_clause = ", current_write_batch_attempt_id = NULL" if clear_batch_attempt else ""
        if set_idempotency_contract:
            update_clause += ", idempotency_contract_id = ?"
            params.append(idempotency_contract_id)
        params.extend(
            (
                *key,
                digest,
                record.plan_digest,
                expected_state.value,
                claim_token,
            )
        )
        expiry_clause = " AND claim_expires_at > ?" if require_unexpired else ""
        if require_unexpired:
            params.append(now)
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                f"""
                UPDATE deliveries
                SET state = ?, updated_at = ?, reason_code = ?{update_clause}
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                  AND record_digest = ? AND plan_digest = ?
                  AND state = ? AND claim_token = ?{expiry_clause}
                """,
                params,
            )
            if cursor.rowcount != 1:
                raise IntegrityError("invalid delivery ledger state transition")

    def _transition_many(
        self,
        items: Sequence[tuple[BlindTransportRecord, str]],
        state: DeliveryState,
        *,
        expected_state: DeliveryState,
        reason_code: str | None = None,
        require_unexpired: bool = False,
        batch_attempt_id: str | None = None,
        set_idempotency_contract: bool = False,
        idempotency_contract_id: str | None = None,
    ) -> None:
        """Apply fenced transitions atomically across a delivery group."""

        materialized = tuple(islice(iter(items), MAX_LEDGER_BATCH_ITEMS + 1))
        if not materialized:
            return
        if len(materialized) > MAX_LEDGER_BATCH_ITEMS:
            raise ValueError("delivery ledger batch exceeds the record count limit")
        keys = tuple(self._key(record) for record, _ in materialized)
        if len(set(keys)) != len(keys):
            raise ValueError("delivery batch contains a duplicate transfer identity")
        for _, claim_token in materialized:
            self._validate_claim_token(claim_token)
        if batch_attempt_id is not None:
            self._validate_batch_attempt_id(batch_attempt_id)
        if idempotency_contract_id is not None:
            self._validate_idempotency_contract_id(idempotency_contract_id)

        now = self._now().isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for record, claim_token in materialized:
                params: list[object] = [
                    state.value,
                    now,
                    reason_code,
                ]
                batch_clause = ""
                if batch_attempt_id is not None:
                    batch_clause = ", current_write_batch_attempt_id = ?"
                    params.append(batch_attempt_id)
                if set_idempotency_contract:
                    batch_clause += ", idempotency_contract_id = ?"
                    params.append(idempotency_contract_id)
                params.extend(
                    (
                        *self._key(record),
                        record.digest(),
                        record.plan_digest,
                        expected_state.value,
                        claim_token,
                    )
                )
                expiry_clause = " AND claim_expires_at > ?" if require_unexpired else ""
                if require_unexpired:
                    params.append(now)
                cursor = connection.execute(
                    f"""
                    UPDATE deliveries
                    SET state = ?, updated_at = ?, reason_code = ?{batch_clause}
                    WHERE tenant = ? AND destination_connector = ?
                      AND transfer_id = ? AND record_id = ?
                      AND record_digest = ? AND plan_digest = ?
                      AND state = ? AND claim_token = ?{expiry_clause}
                    """,
                    params,
                )
                if cursor.rowcount != 1:
                    raise IntegrityError("invalid delivery ledger batch state transition")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def start_write(
        self,
        record: BlindTransportRecord,
        claim_token: str,
        *,
        idempotency_contract_id: str | None = None,
    ) -> None:
        """Cross the write boundary only while owning the active fenced claim."""

        self._transition(
            record,
            DeliveryState.WRITE_STARTED,
            claim_token=claim_token,
            expected_state=DeliveryState.CLAIMED,
            require_unexpired=True,
            clear_batch_attempt=True,
            set_idempotency_contract=True,
            idempotency_contract_id=idempotency_contract_id,
        )

    def start_replay_write(self, record: BlindTransportRecord, claim_token: str) -> None:
        """Cross a scalar replay write boundary without losing replay provenance."""

        self._transition(
            record,
            DeliveryState.REPLAY_WRITE_STARTED,
            claim_token=claim_token,
            expected_state=DeliveryState.REPLAY_CLAIMED,
            require_unexpired=True,
        )

    def start_write_many(
        self,
        items: Sequence[tuple[BlindTransportRecord, str]],
        *,
        idempotency_contract_id: str | None = None,
    ) -> str:
        """Cross one atomic batch write boundary while every claim is still fenced."""

        batch_attempt_id = secrets.token_hex(16)
        self._transition_many(
            items,
            DeliveryState.BATCH_WRITE_STARTED,
            expected_state=DeliveryState.CLAIMED,
            require_unexpired=True,
            batch_attempt_id=batch_attempt_id,
            set_idempotency_contract=True,
            idempotency_contract_id=idempotency_contract_id,
        )
        return batch_attempt_id

    def mark_committed(self, record: BlindTransportRecord, claim_token: str) -> None:
        self._transition(
            record,
            DeliveryState.COMMITTED,
            claim_token=claim_token,
            expected_state=DeliveryState.WRITE_STARTED,
        )

    def mark_replay_committed(self, record: BlindTransportRecord, claim_token: str) -> None:
        self._transition(
            record,
            DeliveryState.COMMITTED,
            claim_token=claim_token,
            expected_state=DeliveryState.REPLAY_WRITE_STARTED,
        )

    def mark_committed_many(
        self,
        items: Sequence[tuple[BlindTransportRecord, str]],
    ) -> None:
        self._transition_many(
            items,
            DeliveryState.COMMITTED,
            expected_state=DeliveryState.BATCH_WRITE_STARTED,
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

    def mark_replay_uncertain(
        self,
        record: BlindTransportRecord,
        reason_code: str,
        claim_token: str,
    ) -> None:
        self._transition(
            record,
            DeliveryState.REPLAY_UNCERTAIN,
            claim_token=claim_token,
            expected_state=DeliveryState.REPLAY_WRITE_STARTED,
            reason_code=reason_code,
        )

    def mark_uncertain_many(
        self,
        items: Sequence[tuple[BlindTransportRecord, str]],
        reason_code: str,
    ) -> None:
        self._transition_many(
            items,
            DeliveryState.BATCH_UNCERTAIN,
            expected_state=DeliveryState.BATCH_WRITE_STARTED,
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
        if expected_state not in (
            DeliveryState.CLAIMED,
            DeliveryState.WRITE_STARTED,
            DeliveryState.REPLAY_CLAIMED,
            DeliveryState.REPLAY_WRITE_STARTED,
        ):
            raise ValueError("invalid state for delivery quarantine")
        target_state = (
            DeliveryState.REPLAY_QUARANTINED
            if expected_state in {DeliveryState.REPLAY_CLAIMED, DeliveryState.REPLAY_WRITE_STARTED}
            else DeliveryState.QUARANTINED
        )
        self._transition(
            record,
            target_state,
            claim_token=claim_token,
            expected_state=expected_state,
            reason_code=reason_code,
            require_unexpired=expected_state
            in {DeliveryState.CLAIMED, DeliveryState.REPLAY_CLAIMED},
        )

    def mark_quarantined_many(
        self,
        items: Sequence[tuple[BlindTransportRecord, str]],
        reason_code: str,
        *,
        expected_state: DeliveryState = DeliveryState.CLAIMED,
    ) -> None:
        if expected_state not in (
            DeliveryState.CLAIMED,
            DeliveryState.BATCH_WRITE_STARTED,
        ):
            raise ValueError("invalid state for delivery quarantine")
        self._transition_many(
            items,
            DeliveryState.QUARANTINED,
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
            DeliveryState.BATCH_WRITE_STARTED,
            DeliveryState.UNCERTAIN,
            DeliveryState.BATCH_UNCERTAIN,
            DeliveryState.QUARANTINED,
            DeliveryState.REPLAY_CLAIMED,
            DeliveryState.REPLAY_WRITE_STARTED,
            DeliveryState.REPLAY_UNCERTAIN,
            DeliveryState.REPLAY_QUARANTINED,
        ):
            raise ValueError("delivery state cannot be rearmed")
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
                SELECT record_digest, plan_digest, state, claim_token, claim_expires_at,
                       current_write_batch_attempt_id, idempotency_contract_id
                FROM deliveries
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                """,
                key,
            ).fetchone()
            if (
                row is None
                or row["record_digest"] != digest
                or row["plan_digest"] != record.plan_digest
                or row["state"] != expected_state.value
            ):
                raise IntegrityError("invalid delivery ledger retry transition")

            previous_token = row["claim_token"]
            previous_expiry_raw = row["claim_expires_at"]
            previous_expiry = self._parse_expiry(previous_expiry_raw)
            if (
                expected_state in {DeliveryState.CLAIMED, DeliveryState.REPLAY_CLAIMED}
                and isinstance(previous_token, str)
                and previous_token
                and previous_expiry is not None
                and previous_expiry > now_value
            ):
                raise IntegrityError("active delivery claim cannot be rearmed")

            batch_attempt_id = row["current_write_batch_attempt_id"]
            if batch_attempt_id is not None:
                if not isinstance(batch_attempt_id, str):
                    raise IntegrityError("delivery ledger contains an invalid batch attempt id")
                try:
                    self._validate_batch_attempt_id(batch_attempt_id)
                except ValueError as exc:
                    raise IntegrityError(
                        "delivery ledger contains an invalid batch attempt id"
                    ) from exc
            elif expected_state in {
                DeliveryState.BATCH_WRITE_STARTED,
                DeliveryState.BATCH_UNCERTAIN,
            }:
                raise IntegrityError("batch delivery state is missing its attempt id")
            self._idempotency_contract_from_row(row)

            target_state = (
                DeliveryState.CLAIMED
                if expected_state is DeliveryState.QUARANTINED
                else DeliveryState.REPLAY_CLAIMED
            )
            cursor = connection.execute(
                """
                UPDATE deliveries
                SET state = ?, updated_at = ?, claim_token = ?, claim_expires_at = ?
                WHERE tenant = ? AND destination_connector = ?
                  AND transfer_id = ? AND record_id = ?
                  AND record_digest = ? AND plan_digest = ? AND state = ?
                  AND claim_token IS ? AND claim_expires_at IS ?
                  AND current_write_batch_attempt_id IS ?
                """,
                (
                    target_state.value,
                    now,
                    claim_token,
                    claim_expires_at,
                    *key,
                    digest,
                    record.plan_digest,
                    expected_state.value,
                    previous_token,
                    previous_expiry_raw,
                    batch_attempt_id,
                ),
            )
            if cursor.rowcount != 1:
                raise IntegrityError("invalid delivery ledger retry transition")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return ClaimResult(
            ClaimDisposition.RECOVERED,
            target_state,
            digest,
            claim_token,
            claim_expires_at,
            batch_attempt_id,
        )

    @staticmethod
    def _entry_from_row(row: sqlite3.Row) -> LedgerEntry:
        batch_attempt = row["current_write_batch_attempt_id"]
        if batch_attempt is not None:
            if not isinstance(batch_attempt, str):
                raise IntegrityError("delivery ledger contains an invalid batch attempt id")
            try:
                DeliveryLedger._validate_batch_attempt_id(batch_attempt)
            except ValueError as exc:
                raise IntegrityError(
                    "delivery ledger contains an invalid batch attempt id"
                ) from exc
        try:
            state = DeliveryState(row["state"])
        except ValueError as exc:
            raise IntegrityError("delivery ledger contains an invalid state") from exc
        if (
            state
            in {
                DeliveryState.BATCH_WRITE_STARTED,
                DeliveryState.BATCH_UNCERTAIN,
            }
            and batch_attempt is None
        ):
            raise IntegrityError("batch delivery state is missing its attempt id")
        idempotency_contract_id = DeliveryLedger._idempotency_contract_from_row(row)
        return LedgerEntry(
            tenant=row["tenant"],
            destination_connector=row["destination_connector"],
            transfer_id=row["transfer_id"],
            record_id=row["record_id"],
            record_digest=row["record_digest"],
            plan_digest=row["plan_digest"],
            state=state,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            reason_code=row["reason_code"],
            claim_token=row["claim_token"],
            claim_expires_at=row["claim_expires_at"],
            current_write_batch_attempt_id=batch_attempt,
            idempotency_contract_id=idempotency_contract_id,
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
        return self._entry_from_row(row)

    def get_batch_attempt(self, batch_attempt_id: str) -> tuple[LedgerEntry, ...]:
        """Return the bounded durable membership of one atomic destination attempt."""

        self._validate_batch_attempt_id(batch_attempt_id)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM deliveries
                WHERE current_write_batch_attempt_id = ?
                ORDER BY record_digest
                LIMIT ?
                """,
                (batch_attempt_id, MAX_LEDGER_BATCH_ITEMS + 1),
            ).fetchall()
        if len(rows) > MAX_LEDGER_BATCH_ITEMS:
            raise IntegrityError("delivery ledger batch membership exceeds its limit")
        return tuple(self._entry_from_row(row) for row in rows)
