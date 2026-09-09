from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .errors import IntegrityError
from .signing import SigningKeyPair, verify_ed25519


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

    def canonical_dict(self) -> dict[str, object]:
        timestamp = self.timestamp or datetime.now(UTC)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        else:
            timestamp = timestamp.astimezone(UTC)
        if self.reason_code is not None:
            if (
                not self.reason_code
                or len(self.reason_code) > 96
                or not self.reason_code.replace("_", "").isalnum()
            ):
                raise ValueError("audit reason_code must be machine-readable")
        return {
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


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    event: dict[str, object]
    previous_hash: str
    event_hash: str
    signature: bytes | None


class AuditLog:
    """Tamper-evident metadata audit trail with optional Ed25519 signatures.

    The API intentionally accepts a fixed event structure instead of arbitrary dictionaries,
    preventing callers from casually placing payload values in the audit store.
    """

    def __init__(self, path: str | Path, *, signer: SigningKeyPair | None = None) -> None:
        self.path = Path(path)
        self.signer = signer
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
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    signature BLOB
                )
                """
            )

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
        payload = event.canonical_dict()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous is not None else "0" * 64
            event_hash = self._hash(previous_hash, payload)
            signature = self.signer.sign(bytes.fromhex(event_hash)) if self.signer else None
            cursor = connection.execute(
                """
                INSERT INTO audit_events (event_json, previous_hash, event_hash, signature)
                VALUES (?, ?, ?, ?)
                """,
                (
                    json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    previous_hash,
                    event_hash,
                    signature,
                ),
            )
            sequence = int(cursor.lastrowid)
            connection.execute("COMMIT")
            return AuditRecord(sequence, payload, previous_hash, event_hash, signature)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def verify(self, *, trusted_public_key: bytes | None = None) -> int:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, event_json, previous_hash, event_hash, signature FROM audit_events ORDER BY sequence"
            ).fetchall()

        previous_hash = "0" * 64
        expected_sequence = 1
        for row in rows:
            if int(row["sequence"]) != expected_sequence:
                raise IntegrityError("audit sequence contains a gap")
            event = json.loads(row["event_json"])
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
            previous_hash = expected_hash
            expected_sequence += 1
        return len(rows)

    def export_jsonl(self) -> str:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT sequence, event_json, previous_hash, event_hash, signature FROM audit_events ORDER BY sequence"
            ).fetchall()
        lines = []
        for row in rows:
            lines.append(
                json.dumps(
                    {
                        "sequence": row["sequence"],
                        "event": json.loads(row["event_json"]),
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
            )
        return "\n".join(lines) + ("\n" if lines else "")
