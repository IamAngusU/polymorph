from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .errors import IntegrityError
from .filesystem import atomic_text_writer
from .signing import SigningKeyPair, verify_ed25519
from .sqlite_safety import configure_sqlite_durability

MAX_AUDIT_BATCH_EVENTS = 10_000
MAX_AUDIT_EVENT_BYTES = 16 * 1024
MAX_AUDIT_BATCH_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_AUDIT_EVENTS = 1_000_000
DEFAULT_MAX_AUDIT_LOGICAL_BYTES = 2 * 1024 * 1024 * 1024
AUDIT_READ_BATCH_ROWS = 1024


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    actor: str
    status: str
    tenant: str
    connector_id: str
    transfer_id: str
    record_id: str
    record_digest: str
    plan_digest: str
    reason_code: str | None = None
    timestamp: datetime | None = None
    batch_attempt_id: str | None = None

    def canonical_dict(self) -> dict[str, object]:
        machine_fields = {
            "event_type": (self.event_type, 64),
            "status": (self.status, 64),
        }
        for label, (value, maximum) in machine_fields.items():
            if (
                not isinstance(value, str)
                or not value
                or len(value) > maximum
                or not value.replace("_", "").isalnum()
            ):
                raise ValueError(f"audit {label} must be a short machine-readable identifier")
        metadata_fields = {
            "actor": (self.actor, 128),
            "tenant": (self.tenant, 128),
            "connector_id": (self.connector_id, 128),
            "transfer_id": (self.transfer_id, 256),
            "record_id": (self.record_id, 256),
        }
        for label, (value, maximum) in metadata_fields.items():
            if (
                not isinstance(value, str)
                or not value
                or len(value) > maximum
                or not value.isprintable()
            ):
                raise ValueError(f"audit {label} must be bounded printable metadata")
        for label, value in {
            "record_digest": self.record_digest,
            "plan_digest": self.plan_digest,
        }.items():
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in value)
            ):
                raise ValueError(f"audit {label} must be a SHA-256 hex digest")
        timestamp = self.timestamp or datetime.now(UTC)
        if not isinstance(timestamp, datetime):
            raise ValueError("audit timestamp must be a datetime")
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        else:
            timestamp = timestamp.astimezone(UTC)
        if self.reason_code is not None and (
            not isinstance(self.reason_code, str)
            or not self.reason_code
            or len(self.reason_code) > 96
            or not self.reason_code.replace("_", "").isalnum()
        ):
            raise ValueError("audit reason_code must be machine-readable")
        if self.batch_attempt_id is not None and (
            not isinstance(self.batch_attempt_id, str)
            or len(self.batch_attempt_id) != 32
            or any(char not in "0123456789abcdef" for char in self.batch_attempt_id)
        ):
            raise ValueError("audit batch_attempt_id must be a lowercase 128-bit identifier")
        payload: dict[str, object] = {
            "actor": self.actor,
            "connector_id": self.connector_id,
            "event_type": self.event_type,
            "plan_digest": self.plan_digest,
            "reason_code": self.reason_code,
            "record_digest": self.record_digest,
            "record_id": self.record_id,
            "status": self.status,
            "tenant": self.tenant,
            "timestamp": timestamp.isoformat(),
            "transfer_id": self.transfer_id,
        }
        if self.batch_attempt_id is not None:
            payload["batch_attempt_id"] = self.batch_attempt_id
        return payload


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    event: dict[str, object]
    previous_hash: str
    event_hash: str
    signature: bytes | None


@dataclass(frozen=True, slots=True)
class AuditSummary:
    events: int
    event_types: dict[str, int]
    statuses: dict[str, int]
    reasons: dict[str, int]
    signature_fields_present: int
    signature_fields_absent: int
    signatures_verified: bool
    first_timestamp: str | None
    last_timestamp: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "events": self.events,
            "event_types": self.event_types,
            "statuses": self.statuses,
            "reasons": self.reasons,
            "signature_fields_present": self.signature_fields_present,
            "signature_fields_absent": self.signature_fields_absent,
            "signatures_verified": self.signatures_verified,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
        }


class AuditLog:
    """Tamper-evident metadata audit trail with optional Ed25519 signatures.

    The API accepts a bounded event structure instead of arbitrary dictionaries. This reduces
    accidental payload logging, but callers must still treat every supplied identifier as
    potentially sensitive metadata.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        signer: SigningKeyPair | None = None,
        create: bool = True,
        max_events: int = DEFAULT_MAX_AUDIT_EVENTS,
        max_logical_bytes: int = DEFAULT_MAX_AUDIT_LOGICAL_BYTES,
    ) -> None:
        for name, value in (("max_events", max_events), ("max_logical_bytes", max_logical_bytes)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"audit {name} must be a positive integer")
        self.path = Path(path)
        self.signer = signer
        self.max_events = max_events
        self.max_logical_bytes = max_logical_bytes
        self._read_only = not create
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        else:
            if not self.path.is_file():
                raise IntegrityError("audit store does not exist")
            self._validate_existing_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._read_only:
            database = f"{self.path.resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(
                database,
                timeout=10.0,
                isolation_level=None,
                uri=True,
            )
        else:
            connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        if not self._read_only:
            configure_sqlite_durability(connection)
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    signature BLOB
                )
                """
            )

    def _validate_existing_schema(self) -> None:
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute("PRAGMA table_info(audit_events)").fetchall()
        except sqlite3.DatabaseError as exc:
            raise IntegrityError("audit store is not a valid SQLite database") from exc
        required = {
            "sequence",
            "event_json",
            "previous_hash",
            "event_hash",
            "signature",
        }
        columns = {str(row["name"]) for row in rows}
        if not required.issubset(columns):
            raise IntegrityError("audit store schema is missing or incompatible")

    @staticmethod
    def _hash(previous_hash: str, event: dict[str, object]) -> str:
        encoded = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(previous_hash.encode("ascii") + b"\x00" + encoded).hexdigest()

    def append(self, event: AuditEvent) -> AuditRecord:
        return self.append_many((event,))[0]

    def append_many(self, events: Iterable[AuditEvent]) -> tuple[AuditRecord, ...]:
        """Append a bounded event batch in one hash-chain transaction."""

        if self._read_only:
            raise IntegrityError("cannot append to a read-only audit store")
        prepared: list[tuple[dict[str, object], str]] = []
        total_encoded_bytes = 0
        for index, event in enumerate(events):
            if index >= MAX_AUDIT_BATCH_EVENTS:
                raise ValueError("audit batch exceeds the event count limit")
            if not isinstance(event, AuditEvent):
                raise TypeError("audit batch items must be AuditEvent instances")
            payload = event.canonical_dict()
            encoded = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            encoded_size = len(encoded.encode("utf-8"))
            if encoded_size > MAX_AUDIT_EVENT_BYTES:
                raise ValueError("audit event exceeds the encoded size limit")
            total_encoded_bytes += encoded_size
            if total_encoded_bytes > MAX_AUDIT_BATCH_BYTES:
                raise ValueError("audit batch exceeds the encoded size limit")
            prepared.append((payload, encoded))
        if not prepared:
            return ()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            usage = connection.execute(
                """
                SELECT COUNT(*) AS event_count,
                       COALESCE(SUM(LENGTH(CAST(event_json AS BLOB)) + LENGTH(previous_hash) +
                                    LENGTH(event_hash) + COALESCE(LENGTH(signature), 0)), 0)
                           AS logical_bytes
                FROM audit_events
                """
            ).fetchone()
            assert usage is not None
            signature_bytes = 64 if self.signer is not None else 0
            additional_bytes = sum(
                len(encoded.encode("utf-8")) + 128 + signature_bytes for _, encoded in prepared
            )
            if int(usage["event_count"]) + len(prepared) > self.max_events:
                raise IntegrityError("audit event quota reached; archive before retrying")
            if int(usage["logical_bytes"]) + additional_bytes > self.max_logical_bytes:
                raise IntegrityError("audit byte quota reached; archive before retrying")
            initial_sequence = int(previous["sequence"]) if previous is not None else 0
            previous_hash = previous["event_hash"] if previous is not None else "0" * 64
            expected_rows: list[tuple[int, str, str, str, bytes | None]] = []
            for payload, encoded in prepared:
                event_hash = self._hash(previous_hash, payload)
                signature = self.signer.sign(bytes.fromhex(event_hash)) if self.signer else None
                connection.execute(
                    """
                    INSERT INTO audit_events (event_json, previous_hash, event_hash, signature)
                    VALUES (?, ?, ?, ?)
                    """,
                    (encoded, previous_hash, event_hash, signature),
                )
                expected_rows.append(
                    (
                        initial_sequence + len(expected_rows) + 1,
                        encoded,
                        previous_hash,
                        event_hash,
                        signature,
                    )
                )
                previous_hash = event_hash

            stored_rows = connection.execute(
                """
                SELECT sequence, event_json, previous_hash, event_hash, signature
                FROM audit_events
                WHERE sequence > ?
                ORDER BY sequence
                """,
                (initial_sequence,),
            ).fetchall()
            actual_rows = [
                (
                    int(row["sequence"]),
                    str(row["event_json"]),
                    str(row["previous_hash"]),
                    str(row["event_hash"]),
                    bytes(row["signature"]) if row["signature"] is not None else None,
                )
                for row in stored_rows
            ]
            if actual_rows != expected_rows:
                raise IntegrityError("audit append postcondition failed")

            records = [
                AuditRecord(
                    sequence,
                    payload,
                    previous_hash,
                    event_hash,
                    signature,
                )
                for (payload, _), (
                    sequence,
                    _,
                    previous_hash,
                    event_hash,
                    signature,
                ) in zip(prepared, expected_rows, strict=True)
            ]
            connection.execute("COMMIT")
            return tuple(records)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _read_rows(self) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                "SELECT sequence, event_json, previous_hash, event_hash, signature "
                "FROM audit_events ORDER BY sequence"
            ).fetchall()
        return rows

    @staticmethod
    def _iter_rows(connection: sqlite3.Connection) -> Iterator[sqlite3.Row]:
        cursor = connection.execute(
            "SELECT sequence, event_json, previous_hash, event_hash, signature "
            "FROM audit_events ORDER BY sequence"
        )
        while rows := cursor.fetchmany(AUDIT_READ_BATCH_ROWS):
            yield from rows

    def _verified_rows(
        self,
        rows: Iterable[sqlite3.Row],
        *,
        trusted_public_key: bytes | None = None,
    ) -> Iterator[tuple[sqlite3.Row, dict[str, object]]]:
        previous_hash = "0" * 64
        expected_sequence = 1
        for row in rows:
            if int(row["sequence"]) != expected_sequence:
                raise IntegrityError("audit sequence contains a gap")
            try:
                event = json.loads(row["event_json"])
            except (json.JSONDecodeError, TypeError) as exc:
                raise IntegrityError("audit event JSON is invalid") from exc
            if not isinstance(event, dict):
                raise IntegrityError("audit event JSON is not an object")
            if row["previous_hash"] != previous_hash:
                raise IntegrityError("audit hash chain is broken")
            expected_hash = self._hash(previous_hash, event)
            if row["event_hash"] != expected_hash:
                raise IntegrityError("audit event hash mismatch")
            signature = row["signature"]
            if trusted_public_key is not None:
                if signature is None:
                    raise IntegrityError("signed audit verification found an unsigned event")
                verify_ed25519(trusted_public_key, bytes.fromhex(expected_hash), bytes(signature))
            yield row, event
            previous_hash = expected_hash
            expected_sequence += 1

    def _verify_rows(
        self,
        rows: Iterable[sqlite3.Row],
        *,
        trusted_public_key: bytes | None = None,
    ) -> int:
        return sum(1 for _ in self._verified_rows(rows, trusted_public_key=trusted_public_key))

    def verify(self, *, trusted_public_key: bytes | None = None) -> int:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            return self._verify_rows(
                self._iter_rows(connection),
                trusted_public_key=trusted_public_key,
            )

    def summary(self, *, trusted_public_key: bytes | None = None) -> AuditSummary:
        """Verify the chain, then aggregate metadata without exposing event identifiers."""

        event_types: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        reasons: Counter[str] = Counter()
        first_timestamp: str | None = None
        last_timestamp: str | None = None
        signature_fields_present = 0
        count = 0
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            for row, event in self._verified_rows(
                self._iter_rows(connection), trusted_public_key=trusted_public_key
            ):
                count += 1
                event_types[str(event.get("event_type", "unknown"))] += 1
                statuses[str(event.get("status", "unknown"))] += 1
                reason = event.get("reason_code")
                if reason is not None:
                    reasons[str(reason)] += 1
                timestamp = event.get("timestamp")
                if isinstance(timestamp, str):
                    first_timestamp = first_timestamp or timestamp
                    last_timestamp = timestamp
                if row["signature"] is not None:
                    signature_fields_present += 1
        return AuditSummary(
            events=count,
            event_types=dict(sorted(event_types.items())),
            statuses=dict(sorted(statuses.items())),
            reasons=dict(sorted(reasons.items())),
            signature_fields_present=signature_fields_present,
            signature_fields_absent=count - signature_fields_present,
            signatures_verified=trusted_public_key is not None,
            first_timestamp=first_timestamp,
            last_timestamp=last_timestamp,
        )

    @staticmethod
    def _jsonl_line(row: sqlite3.Row, event: dict[str, object]) -> str:
        return json.dumps(
            {
                "sequence": row["sequence"],
                "event": event,
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
                "signature": (
                    base64.urlsafe_b64encode(bytes(row["signature"])).decode("ascii")
                    if row["signature"] is not None
                    else None
                ),
            },
            sort_keys=True,
            ensure_ascii=False,
        )

    def export_jsonl_to(
        self,
        path: str | Path,
        *,
        trusted_public_key: bytes | None = None,
    ) -> int:
        """Verify and atomically stream the complete chain to a JSONL file."""

        count = 0
        with (
            closing(self._connect()) as connection,
            connection,
            atomic_text_writer(path, encoding="utf-8", private=True) as output,
        ):
            connection.execute("BEGIN")
            for row, event in self._verified_rows(
                self._iter_rows(connection), trusted_public_key=trusted_public_key
            ):
                output.write(self._jsonl_line(row, event))
                output.write("\n")
                count += 1
        return count

    def export_jsonl(self) -> str:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            lines = [
                self._jsonl_line(row, event)
                for row, event in self._verified_rows(self._iter_rows(connection))
            ]
            return "\n".join(lines) + ("\n" if lines else "")
