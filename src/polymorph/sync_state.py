from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .errors import PolymorphError
from .sqlite_safety import configure_sqlite_durability

SYNC_STATE_SCHEMA_VERSION = 1
MAX_CURSOR_BYTES = 64 * 1024
MAX_CURSOR_NODES = 4096
MAX_CURSOR_DEPTH = 12


class SyncStateError(PolymorphError):
    """Raised when durable recurring-run state cannot be advanced safely."""


class CheckpointConflict(SyncStateError):
    """Raised when another run advanced the same route first."""


class RunLeaseBusy(SyncStateError):
    """Raised when a non-expired run already owns a route lease."""


def _bounded_identifier(name: str, value: str) -> str:
    if not value or len(value) > 256:
        raise SyncStateError(f"{name} must contain 1..256 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SyncStateError(f"{name} contains control characters")
    return value


def _validate_cursor(value: object, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_CURSOR_NODES or depth > MAX_CURSOR_DEPTH:
        raise SyncStateError("sync cursor exceeds the structural safety limit")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > MAX_CURSOR_BYTES:
            raise SyncStateError("sync cursor string exceeds the local safety limit")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SyncStateError("sync cursor contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_cursor(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise SyncStateError("sync cursor object keys must be bounded strings")
            _validate_cursor(item, depth=depth + 1, counter=counter)
        return
    raise SyncStateError("sync cursor contains an unsupported JSON value")


def _cursor_json(cursor: object) -> str:
    _validate_cursor(cursor)
    try:
        rendered = json.dumps(
            cursor,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise SyncStateError("sync cursor is not canonical JSON") from exc
    if len(rendered.encode("utf-8")) > MAX_CURSOR_BYTES:
        raise SyncStateError("sync cursor exceeds the local byte limit")
    return rendered


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CommitReceipt:
    """Minimal proof required before a recurring cursor may advance."""

    run_id: str
    committed_records: int
    completed_at: str
    outcome: str = "completed"

    def __post_init__(self) -> None:
        _bounded_identifier("run_id", self.run_id)
        if self.outcome != "completed":
            raise SyncStateError("only a completed write can create a commit receipt")
        if self.committed_records < 0:
            raise SyncStateError("committed record count cannot be negative")
        try:
            parsed = datetime.fromisoformat(self.completed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SyncStateError("commit receipt timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise SyncStateError("commit receipt timestamp must include a timezone")

    @property
    def sha256(self) -> str:
        payload = {
            "committed_records": self.committed_records,
            "completed_at": self.completed_at,
            "outcome": self.outcome,
            "run_id": self.run_id,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def from_result(cls, result: object, *, run_id: str | None = None) -> CommitReceipt:
        serializer = getattr(result, "as_dict", None)
        if not callable(serializer):
            serializer = getattr(result, "to_dict", None)
        if callable(serializer):
            payload = serializer()
        elif isinstance(result, Mapping):
            payload = result
        else:
            raise SyncStateError("write result does not expose structured evidence")
        if not isinstance(payload, Mapping):
            raise SyncStateError("write result evidence is malformed")
        status = payload.get("status") or payload.get("outcome")
        status_text = getattr(status, "value", status)
        if str(status_text).casefold() != "completed":
            raise SyncStateError("checkpoint cannot advance from a non-completed write")
        records = payload.get("records_written", payload.get("committed_records", 0))
        if not isinstance(records, int):
            raise SyncStateError("write result record count is malformed")
        candidate_run_id = run_id if run_id is not None else payload.get("run_id")
        if not isinstance(candidate_run_id, str) or not candidate_run_id:
            raise SyncStateError("write result has no stable run id for checkpoint identity")
        return cls(
            run_id=candidate_run_id,
            committed_records=records,
            completed_at=_utc_now(),
        )


@dataclass(frozen=True, slots=True)
class SyncCheckpoint:
    route_id: str
    generation: int
    cursor: object
    committed_records: int
    run_id: str
    updated_at: str
    receipt_sha256: str

    def to_dict(self, *, include_cursor: bool = False) -> dict[str, object]:
        cursor_encoded = _cursor_json(self.cursor).encode("utf-8")
        result: dict[str, object] = {
            "committed_records": self.committed_records,
            "cursor_bytes": len(cursor_encoded),
            "cursor_sha256": hashlib.sha256(cursor_encoded).hexdigest(),
            "generation": self.generation,
            "receipt_sha256": self.receipt_sha256,
            "route_id": self.route_id,
            "run_id": self.run_id,
            "updated_at": self.updated_at,
        }
        if include_cursor:
            result["cursor"] = self.cursor
        return result


@dataclass(frozen=True, slots=True)
class RunLease:
    route_id: str
    token: str
    expires_at_epoch: float


@dataclass(frozen=True, slots=True)
class SchedulePolicy:
    interval_seconds: int
    deterministic_jitter_seconds: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.interval_seconds <= 31 * 24 * 60 * 60:
            raise SyncStateError("schedule interval must be between one second and 31 days")
        if not 0 <= self.deterministic_jitter_seconds < self.interval_seconds:
            raise SyncStateError("schedule jitter must be smaller than the interval")

    def next_due(self, route_id: str, last_completed_at: datetime) -> datetime:
        _bounded_identifier("route_id", route_id)
        if last_completed_at.tzinfo is None:
            raise SyncStateError("last completion time must include a timezone")
        jitter = 0
        if self.deterministic_jitter_seconds:
            digest = hashlib.sha256(route_id.encode("utf-8")).digest()
            jitter = int.from_bytes(digest[:8], "big") % (self.deterministic_jitter_seconds + 1)
        return last_completed_at + timedelta(seconds=self.interval_seconds + jitter)


class SyncStateStore:
    """Durable local checkpoints and fenced run leases for one trusted host."""

    def __init__(self, path: str | Path) -> None:
        expanded = Path(path).expanduser()
        if not expanded.is_absolute():
            expanded = Path.cwd() / expanded
        self.path = Path(os.path.abspath(expanded))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._reject_unsafe_existing_path()
        self._initialize()

    def _reject_unsafe_existing_path(self) -> None:
        if not self.path.exists() and not self.path.is_symlink():
            return
        metadata = self.path.lstat()
        if self.path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise SyncStateError("sync state path must be a regular non-symlink file")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        try:
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 10000")
            configure_sqlite_durability(connection)
        except Exception:
            connection.close()
            raise
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, SYNC_STATE_SCHEMA_VERSION}:
                raise SyncStateError("sync state database has an unsupported schema version")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    route_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL CHECK (generation > 0),
                    cursor_json TEXT NOT NULL,
                    committed_records INTEGER NOT NULL CHECK (committed_records >= 0),
                    run_id TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS checkpoints_run_id ON checkpoints(run_id);
                CREATE TABLE IF NOT EXISTS run_leases (
                    route_id TEXT PRIMARY KEY,
                    token TEXT NOT NULL,
                    expires_at_epoch REAL NOT NULL,
                    acquired_at TEXT NOT NULL
                );
                """
            )
            connection.execute(f"PRAGMA user_version = {SYNC_STATE_SCHEMA_VERSION}")
        self._reject_unsafe_existing_path()

    @staticmethod
    def _checkpoint(row: sqlite3.Row | tuple[object, ...]) -> SyncCheckpoint:
        return SyncCheckpoint(
            route_id=str(row[0]),
            generation=int(str(row[1])),
            cursor=json.loads(str(row[2])),
            committed_records=int(str(row[3])),
            run_id=str(row[4]),
            updated_at=str(row[5]),
            receipt_sha256=str(row[6]),
        )

    def get(self, route_id: str) -> SyncCheckpoint | None:
        key = _bounded_identifier("route_id", route_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT route_id, generation, cursor_json, committed_records, run_id, "
                "updated_at, receipt_sha256 FROM checkpoints WHERE route_id = ?",
                (key,),
            ).fetchone()
        return None if row is None else self._checkpoint(row)

    def list(self, *, limit: int = 1000) -> tuple[SyncCheckpoint, ...]:
        if not 1 <= limit <= 10_000:
            raise SyncStateError("checkpoint list limit must be between 1 and 10,000")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT route_id, generation, cursor_json, committed_records, run_id, "
                "updated_at, receipt_sha256 FROM checkpoints ORDER BY route_id LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(self._checkpoint(row) for row in rows)

    def advance(
        self,
        route_id: str,
        *,
        expected_generation: int,
        next_cursor: object,
        receipt: CommitReceipt,
    ) -> SyncCheckpoint:
        key = _bounded_identifier("route_id", route_id)
        if expected_generation < 0:
            raise SyncStateError("expected checkpoint generation cannot be negative")
        cursor_json = _cursor_json(next_cursor)
        updated_at = _utc_now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT route_id, generation, cursor_json, committed_records, run_id, "
                "updated_at, receipt_sha256 FROM checkpoints WHERE route_id = ?",
                (key,),
            ).fetchone()
            if row is not None and str(row[4]) == receipt.run_id:
                existing = self._checkpoint(row)
                if (
                    existing.receipt_sha256 != receipt.sha256
                    or _cursor_json(existing.cursor) != cursor_json
                ):
                    raise CheckpointConflict(
                        "run id was already used with different checkpoint evidence"
                    )
                connection.commit()
                return existing
            current_generation = 0 if row is None else int(row[1])
            if current_generation != expected_generation:
                raise CheckpointConflict("checkpoint generation changed before commit")
            total = (0 if row is None else int(row[3])) + receipt.committed_records
            generation = current_generation + 1
            connection.execute(
                "INSERT INTO checkpoints(route_id, generation, cursor_json, committed_records, "
                "run_id, updated_at, receipt_sha256) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(route_id) DO UPDATE SET generation=excluded.generation, "
                "cursor_json=excluded.cursor_json, committed_records=excluded.committed_records, "
                "run_id=excluded.run_id, updated_at=excluded.updated_at, "
                "receipt_sha256=excluded.receipt_sha256",
                (
                    key,
                    generation,
                    cursor_json,
                    total,
                    receipt.run_id,
                    updated_at,
                    receipt.sha256,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        checkpoint = self.get(key)
        if checkpoint is None:
            raise SyncStateError("checkpoint commit was not observable")
        return checkpoint

    def claim(self, route_id: str, *, ttl_seconds: float = 900.0) -> RunLease:
        key = _bounded_identifier("route_id", route_id)
        if not math.isfinite(ttl_seconds) or not 1 <= ttl_seconds <= 24 * 60 * 60:
            raise SyncStateError("run lease TTL must be between one second and 24 hours")
        now = time.time()
        token = uuid.uuid4().hex
        expires = now + ttl_seconds
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT token, expires_at_epoch FROM run_leases WHERE route_id = ?", (key,)
            ).fetchone()
            if row is not None and float(row[1]) > now:
                raise RunLeaseBusy("another run holds the route lease")
            connection.execute(
                "INSERT INTO run_leases(route_id, token, expires_at_epoch, acquired_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(route_id) DO UPDATE SET token=excluded.token, "
                "expires_at_epoch=excluded.expires_at_epoch, acquired_at=excluded.acquired_at",
                (key, token, expires, _utc_now()),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return RunLease(key, token, expires)

    def renew(self, lease: RunLease, *, ttl_seconds: float = 900.0) -> RunLease:
        if not math.isfinite(ttl_seconds) or not 1 <= ttl_seconds <= 24 * 60 * 60:
            raise SyncStateError("run lease TTL must be between one second and 24 hours")
        expires = time.time() + ttl_seconds
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "UPDATE run_leases SET expires_at_epoch = ? WHERE route_id = ? AND token = ?",
                (expires, lease.route_id, lease.token),
            )
            if cursor.rowcount != 1:
                raise CheckpointConflict("run lease was lost before renewal")
        return RunLease(lease.route_id, lease.token, expires)

    def release(self, lease: RunLease) -> None:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "DELETE FROM run_leases WHERE route_id = ? AND token = ?",
                (lease.route_id, lease.token),
            )
            if cursor.rowcount != 1:
                raise CheckpointConflict("run lease was lost before release")

    @contextmanager
    def hold(self, route_id: str, *, ttl_seconds: float = 900.0) -> Iterator[RunLease]:
        lease = self.claim(route_id, ttl_seconds=ttl_seconds)
        try:
            yield lease
        finally:
            self.release(lease)


def _inspect(args: argparse.Namespace) -> int:
    store = SyncStateStore(args.database)
    checkpoints = (
        tuple(filter(None, (store.get(args.route),)))
        if args.route
        else store.list(limit=args.limit)
    )
    print(
        json.dumps(
            {
                "checkpoints": [
                    item.to_dict(include_cursor=args.show_cursor) for item in checkpoints
                ],
                "database": str(store.path),
                "privacy": (
                    "cursor_visible_by_explicit_request"
                    if args.show_cursor
                    else "cursor_redacted_digest_only"
                ),
                "schema": "polymorph.sync-state-inspection",
                "version": 1,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect durable local recurring-run checkpoints without advancing them."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("database")
    inspect.add_argument("--route")
    inspect.add_argument("--limit", type=int, default=1000)
    inspect.add_argument("--show-cursor", action="store_true")
    inspect.set_defaults(func=_inspect)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
