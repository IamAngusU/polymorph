from __future__ import annotations

import json
import os
import secrets
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from .agents import BlindTransportRecord, ProtocolLimits
from .errors import IntegrityError, PolicyViolation, ProtocolError, ReplayDetected, TransferExpired
from .signing import SourceTrustStore, SourceTrustVerificationSession
from .sqlite_safety import configure_sqlite_durability

MAX_LEASE_DURATION = timedelta(hours=1)
MAX_DEAD_LETTERS_PER_LEASE = 1_000
MAX_RELAY_BATCH_ITEMS = 10_000
DEFAULT_RELAY_BATCH_WIRE_BYTES = 64 * 1024 * 1024
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
    allow_legacy_blank_recipient_key_id: bool = False

    def validate(self, record: BlindTransportRecord, *, now: datetime | None = None) -> None:
        self._validate(record, now=now, source_verification=None)

    @contextmanager
    def _verification_session(self) -> Iterator[SourceTrustVerificationSession | None]:
        if self.source_trust_store is None:
            yield None
            return
        with self.source_trust_store.verification_session() as source_verification:
            yield source_verification

    def _validate(
        self,
        record: BlindTransportRecord,
        *,
        now: datetime | None,
        source_verification: SourceTrustVerificationSession | None,
    ) -> None:
        if (
            record.protocol_version == 3
            and not record.fields[0].context.recipient_key_id
            and not self.allow_legacy_blank_recipient_key_id
        ):
            raise PolicyViolation("v3 transport record has no authenticated recipient key id")
        if record.protocol_version == 2:
            if not self.allow_legacy_unsigned:
                raise PolicyViolation("unsigned v2 transport record is not allowed by relay policy")
        else:
            if self.source_trust_store is None:
                raise PolicyViolation("relay policy has no trusted source key registry")
            if source_verification is None:
                self.source_trust_store.verify_record(record, now=now)
            else:
                source_verification.verify_record(record, now=now)
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
    allow_legacy_blank_recipient_key_id: bool,
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
        max_batch_wire_bytes: int = DEFAULT_RELAY_BATCH_WIRE_BYTES,
    ) -> None:
        if (
            isinstance(max_batch_wire_bytes, bool)
            or not isinstance(max_batch_wire_bytes, int)
            or max_batch_wire_bytes <= 0
        ):
            raise ValueError("relay batch wire limit must be a positive integer")
        self.path = Path(path)
        self.policy = policy
        self.limits = limits or ProtocolLimits()
        if max_batch_wire_bytes < self.limits.max_record_wire_bytes:
            raise ValueError("relay batch wire limit must admit one protocol-sized record")
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
                CREATE INDEX IF NOT EXISTS relay_available_order
                ON sealed_relay_queue (
                    destination_connector, received_at, record_digest, lease_expires_at
                )
                """
            )
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

    def _prepare_enqueue(
        self, record: BlindTransportRecord
    ) -> tuple[BlindTransportRecord, bytes, str]:
        wire = record.canonical_wire_bytes()
        if len(wire) > self.limits.max_record_wire_bytes:
            raise PolicyViolation("sealed record exceeds relay queue size limit")
        return record, wire, record.digest()

    def enqueue(self, record: BlindTransportRecord) -> RelayReceipt:
        return self.enqueue_many((record,))[0]

    def enqueue_many(self, records: Iterable[BlindTransportRecord]) -> tuple[RelayReceipt, ...]:
        """Validate and enqueue one atomic bounded batch of sealed records."""

        prepared: list[tuple[BlindTransportRecord, bytes, str]] = []
        total_wire_bytes = 0
        for index, record in enumerate(records):
            if index >= MAX_RELAY_BATCH_ITEMS:
                raise ValueError("relay enqueue batch exceeds the record count limit")
            if not isinstance(record, BlindTransportRecord):
                raise TypeError("relay enqueue batch items must be BlindTransportRecord instances")
            item = self._prepare_enqueue(record)
            total_wire_bytes += len(item[1])
            if total_wire_bytes > self.max_batch_wire_bytes:
                raise ValueError("relay enqueue batch exceeds the wire byte limit")
            prepared.append(item)
        if not prepared:
            return ()

        with self.policy._verification_session() as source_verification:
            authorized: list[tuple[BlindTransportRecord, bytes, str, str]] = []
            for record, wire, digest in prepared:
                self.policy._validate(
                    record,
                    now=None,
                    source_verification=source_verification,
                )
                authorized.append((record, wire, digest, datetime.now(UTC).isoformat()))
            return self._enqueue_prepared(authorized)

    def _enqueue_prepared(
        self,
        prepared: list[tuple[BlindTransportRecord, bytes, str, str]],
    ) -> tuple[RelayReceipt, ...]:
        """Commit records while the caller keeps their source verification session open."""

        connection = self._connect()
        receipts: list[RelayReceipt] = []
        postconditions: list[tuple[str, tuple[object, ...]]] = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            for record, wire, digest, accepted_at in prepared:
                identity = connection.execute(
                    """
                    SELECT record_digest, tenant, source_connector,
                           destination_connector, transfer_id, record_id,
                           plan_digest, received_at, wire_json,
                           lease_owner, lease_id, lease_expires_at
                    FROM sealed_relay_queue
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
                        raise ReplayDetected(
                            "relay transfer identity was reused with different "
                            "authenticated content"
                        )
                    raw_wire = identity["wire_json"]
                    if not isinstance(raw_wire, (bytes, bytearray, memoryview)):
                        raise IntegrityError("relay queue wire representation is not binary")
                    persisted_accepted_at = identity["received_at"]
                    expected = (
                        digest,
                        record.tenant,
                        record.source_connector,
                        record.destination_connector,
                        record.transfer_id,
                        record.record_id,
                        record.plan_digest,
                        persisted_accepted_at,
                        wire,
                        identity["lease_owner"],
                        identity["lease_id"],
                        identity["lease_expires_at"],
                    )
                    if (
                        tuple(identity) != expected
                        or bytes(raw_wire) != wire
                        or not isinstance(persisted_accepted_at, str)
                    ):
                        raise IntegrityError(
                            "relay queue stored metadata does not match authenticated record"
                        )
                    postconditions.append((digest, expected))
                    receipts.append(
                        RelayReceipt(
                            digest,
                            record.tenant,
                            record.destination_connector,
                            record.transfer_id,
                            record.record_id,
                            record.plan_digest,
                            persisted_accepted_at,
                            duplicate=True,
                        )
                    )
                    continue
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
                            accepted_at,
                            wire,
                            None,
                            None,
                            None,
                        ),
                    )
                )
                receipts.append(
                    RelayReceipt(
                        digest,
                        record.tenant,
                        record.destination_connector,
                        record.transfer_id,
                        record.record_id,
                        record.plan_digest,
                        accepted_at,
                    )
                )
            self._assert_queue_postconditions(connection, postconditions)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return tuple(receipts)

    @staticmethod
    def _assert_queue_postconditions(
        connection: sqlite3.Connection,
        postconditions: Iterable[tuple[str, tuple[object, ...]]],
    ) -> None:
        for digest, expected in postconditions:
            persisted = connection.execute(
                """
                SELECT record_digest, tenant, source_connector,
                       destination_connector, transfer_id, record_id,
                       plan_digest, received_at, wire_json,
                       lease_owner, lease_id, lease_expires_at
                FROM sealed_relay_queue
                WHERE record_digest = ?
                """,
                (digest,),
            ).fetchone()
            if persisted is None or tuple(persisted) != expected:
                raise IntegrityError("relay queue write postcondition failed")

    def lease(
        self,
        *,
        destination_connector: str,
        lease_owner: str,
        limit: int = 100,
        lease_for: timedelta = timedelta(minutes=2),
        max_wire_bytes: int | None = None,
    ) -> tuple[LeasedRecord, ...]:
        if not lease_owner or len(lease_owner) > 128:
            raise ValueError("lease owner is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise ValueError("lease limit is outside supported range")
        if lease_for <= timedelta(0) or lease_for > MAX_LEASE_DURATION:
            raise ValueError("lease duration is outside supported range")
        wire_budget = self.max_batch_wire_bytes if max_wire_bytes is None else max_wire_bytes
        if (
            isinstance(wire_budget, bool)
            or not isinstance(wire_budget, int)
            or not 1 <= wire_budget <= self.max_batch_wire_bytes
        ):
            raise ValueError("relay lease wire limit is outside supported range")
        now = datetime.now(UTC)
        expires = now + lease_for
        session_stack = ExitStack()
        connection: sqlite3.Connection | None = None
        try:
            source_verification = session_stack.enter_context(self.policy._verification_session())
            connection = session_stack.enter_context(closing(self._connect()))
            connection.execute("BEGIN IMMEDIATE")
            scan_limit = limit + MAX_DEAD_LETTERS_PER_LEASE
            rows = connection.execute(
                """
                SELECT record_digest, tenant, source_connector,
                       destination_connector, transfer_id, record_id,
                       plan_digest, received_at, LENGTH(wire_json) AS wire_bytes
                FROM sealed_relay_queue
                WHERE destination_connector = ?
                  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                ORDER BY received_at ASC, record_digest ASC
                LIMIT ?
                """,
                (destination_connector, now.isoformat(), scan_limit),
            )
            leased: list[LeasedRecord] = []
            lease_updates: list[tuple[str, str, str, str]] = []
            oversized_dead_letters: list[sqlite3.Row] = []
            decoded_dead_letters: list[tuple[sqlite3.Row, bytes, str]] = []
            consumed_wire_bytes = 0
            dead_letters = 0
            budget_blocked = False
            for row in rows:
                if len(leased) >= limit:
                    break
                wire_size = int(row["wire_bytes"])
                if wire_size > self.limits.max_record_wire_bytes:
                    if dead_letters >= MAX_DEAD_LETTERS_PER_LEASE:
                        break
                    oversized_dead_letters.append(row)
                    dead_letters += 1
                    continue
                if consumed_wire_bytes + wire_size > wire_budget:
                    budget_blocked = True
                    break
                consumed_wire_bytes += wire_size
                stored = connection.execute(
                    """
                    SELECT wire_json
                    FROM sealed_relay_queue
                    WHERE record_digest = ?
                    """,
                    (row["record_digest"],),
                ).fetchone()
                if stored is None:
                    raise IntegrityError("relay queue record disappeared while being leased")
                raw_wire = stored["wire_json"]
                if not isinstance(raw_wire, (bytes, bytearray, memoryview)):
                    failure_code = _DEAD_LETTER_INVALID_WIRE
                    wire = b""
                else:
                    wire = bytes(raw_wire)
                    if len(wire) != wire_size:
                        raise IntegrityError("relay queue wire size changed while being leased")
                    failure_code = None
                record: BlindTransportRecord | None = None
                if failure_code is None:
                    try:
                        record = _decode_queued_record(
                            wire,
                            limits=self.limits,
                            allow_legacy_unsigned=self.policy.allow_legacy_unsigned,
                            allow_legacy_blank_recipient_key_id=(
                                self.policy.allow_legacy_blank_recipient_key_id
                            ),
                        )
                        self.policy._validate(
                            record,
                            now=now,
                            source_verification=source_verification,
                        )
                    except TransferExpired:
                        failure_code = _DEAD_LETTER_EXPIRED
                    except PolicyViolation:
                        failure_code = _DEAD_LETTER_POLICY
                    except IntegrityError:
                        failure_code = _DEAD_LETTER_SOURCE_AUTH
                    except ProtocolError:
                        failure_code = _DEAD_LETTER_INVALID_WIRE
                if failure_code is not None:
                    if dead_letters >= MAX_DEAD_LETTERS_PER_LEASE:
                        break
                    decoded_dead_letters.append((row, wire, failure_code))
                    dead_letters += 1
                    continue
                assert record is not None
                if record.digest() != row["record_digest"]:
                    if dead_letters >= MAX_DEAD_LETTERS_PER_LEASE:
                        break
                    decoded_dead_letters.append((row, wire, _DEAD_LETTER_DIGEST))
                    dead_letters += 1
                    continue
                lease_id = secrets.token_urlsafe(_LEASE_ID_BYTES)
                lease_updates.append(
                    (lease_owner, lease_id, expires.isoformat(), row["record_digest"])
                )
                leased.append(
                    LeasedRecord(
                        record=record,
                        lease_owner=lease_owner,
                        lease_expires_at=expires.isoformat(),
                        lease_id=lease_id,
                    )
                )
            rows.close()
            dead_letter_postconditions: list[tuple[str, tuple[object, ...]]] = []
            for row in oversized_dead_letters:
                dead_letter_postconditions.append(self._dead_letter_oversized(connection, row, now))
            for row, wire, failure_code in decoded_dead_letters:
                dead_letter_postconditions.append(
                    self._dead_letter(connection, row, wire, failure_code, now)
                )
            if lease_updates:
                cursor = connection.executemany(
                    """
                    UPDATE sealed_relay_queue
                    SET lease_owner = ?, lease_id = ?, lease_expires_at = ?
                    WHERE record_digest = ?
                    """,
                    lease_updates,
                )
                if cursor.rowcount != len(lease_updates):
                    raise IntegrityError("relay lease batch changed while being fenced")
            self._assert_dead_letter_postconditions(connection, dead_letter_postconditions)
            connection.execute("COMMIT")
            if budget_blocked and not leased:
                raise ValueError("next relay record exceeds the lease wire limit")
            return tuple(leased)
        except Exception:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            session_stack.close()

    @staticmethod
    def _dead_letter_oversized(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        now: datetime,
    ) -> tuple[str, tuple[object, ...]]:
        postcondition = SealedRelayQueue._prepare_dead_letter_postcondition(
            connection,
            row,
            wire=b"",
            reason_code=_DEAD_LETTER_INVALID_WIRE,
            dead_lettered_at=now.isoformat(),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO sealed_relay_dead_letter (
                record_digest, tenant, source_connector, destination_connector,
                transfer_id, record_id, plan_digest, received_at,
                reason_code, dead_lettered_at, wire_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                _DEAD_LETTER_INVALID_WIRE,
                now.isoformat(),
                b"",
            ),
        )
        connection.execute(
            "DELETE FROM sealed_relay_queue WHERE record_digest = ?",
            (row["record_digest"],),
        )
        return postcondition

    @staticmethod
    def _dead_letter(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        wire: bytes,
        reason_code: str,
        now: datetime,
    ) -> tuple[str, tuple[object, ...]]:
        postcondition = SealedRelayQueue._prepare_dead_letter_postcondition(
            connection,
            row,
            wire=wire,
            reason_code=reason_code,
            dead_lettered_at=now.isoformat(),
        )
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
        return postcondition

    @staticmethod
    def _prepare_dead_letter_postcondition(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        wire: bytes,
        reason_code: str,
        dead_lettered_at: str,
    ) -> tuple[str, tuple[object, ...]]:
        digest = row["record_digest"]
        if not isinstance(digest, str):
            raise IntegrityError("relay dead-letter record digest is not text")
        attempted = (
            digest,
            row["tenant"],
            row["source_connector"],
            row["destination_connector"],
            row["transfer_id"],
            row["record_id"],
            row["plan_digest"],
            row["received_at"],
            reason_code,
            dead_lettered_at,
            wire,
        )
        existing = connection.execute(
            """
            SELECT record_digest, tenant, source_connector,
                   destination_connector, transfer_id, record_id,
                   plan_digest, received_at, reason_code,
                   dead_lettered_at, wire_json
            FROM sealed_relay_dead_letter
            WHERE record_digest = ?
            """,
            (digest,),
        ).fetchone()
        if existing is None:
            return digest, attempted

        existing_dead_lettered_at = existing["dead_lettered_at"]
        expected = (*attempted[:9], existing_dead_lettered_at, wire)
        if not isinstance(existing_dead_lettered_at, str) or tuple(existing) != expected:
            raise IntegrityError("relay dead-letter conflict does not match expected record")
        return digest, expected

    @staticmethod
    def _assert_dead_letter_postconditions(
        connection: sqlite3.Connection,
        postconditions: Iterable[tuple[str, tuple[object, ...]]],
    ) -> None:
        for digest, expected in postconditions:
            persisted = connection.execute(
                """
                SELECT record_digest, tenant, source_connector,
                       destination_connector, transfer_id, record_id,
                       plan_digest, received_at, reason_code,
                       dead_lettered_at, wire_json
                FROM sealed_relay_dead_letter
                WHERE record_digest = ?
                """,
                (digest,),
            ).fetchone()
            remaining = connection.execute(
                "SELECT 1 FROM sealed_relay_queue WHERE record_digest = ?",
                (digest,),
            ).fetchone()
            if persisted is None or tuple(persisted) != expected or remaining is not None:
                raise IntegrityError("relay dead-letter transition postcondition failed")

    def ack(self, record_digest: str, *, lease_owner: str, lease_id: str) -> None:
        self.ack_many(((record_digest, lease_id),), lease_owner=lease_owner)

    def ack_many(
        self,
        acknowledgements: Iterable[tuple[str, str]],
        *,
        lease_owner: str,
    ) -> None:
        """Atomically acknowledge digest/lease-id pairs owned by one worker."""

        if (
            not isinstance(lease_owner, str)
            or not lease_owner
            or len(lease_owner) > 128
            or not lease_owner.isprintable()
        ):
            raise ValueError("lease owner is invalid")
        batch: list[tuple[str, str]] = []
        for index, acknowledgement in enumerate(acknowledgements):
            if index >= MAX_RELAY_BATCH_ITEMS:
                raise ValueError("relay acknowledgement batch exceeds the record count limit")
            if not isinstance(acknowledgement, tuple) or len(acknowledgement) != 2:
                raise TypeError("relay acknowledgements must be digest/lease-id tuples")
            record_digest, lease_id = acknowledgement
            if not isinstance(record_digest, str):
                raise TypeError("relay acknowledgement digests must be strings")
            if len(record_digest) != 64 or any(
                character not in "0123456789abcdef" for character in record_digest
            ):
                raise ValueError("relay acknowledgement digest must be a lowercase SHA-256 digest")
            if not isinstance(lease_id, str):
                raise TypeError("relay acknowledgement lease ids must be strings")
            if not lease_id or len(lease_id) > 128 or not lease_id.isprintable():
                raise ValueError("lease id is invalid")
            batch.append((record_digest, lease_id))
        if not batch:
            return

        now = datetime.now(UTC).isoformat()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.executemany(
                """
                DELETE FROM sealed_relay_queue
                WHERE record_digest = ? AND lease_owner = ? AND lease_id = ?
                  AND lease_expires_at > ?
                """,
                ((record_digest, lease_owner, lease_id, now) for record_digest, lease_id in batch),
            )
            if cursor.rowcount != len(batch):
                raise IntegrityError("relay acknowledgement does not own the active lease")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

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
