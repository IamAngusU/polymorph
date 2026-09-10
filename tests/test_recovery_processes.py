from __future__ import annotations

import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path


def _run_contending_processes(
    tmp_path: Path,
    database: Path,
    child_operation: str,
    *,
    workers: int = 12,
) -> None:
    gate = tmp_path / "process-start.gate"
    script = f"""
import sys
import time
from pathlib import Path

gate = Path(sys.argv[1])
deadline = time.monotonic() + 30
while not gate.exists():
    if time.monotonic() >= deadline:
        raise TimeoutError("parent process did not release the startup gate")
    time.sleep(0.005)
{child_operation}
"""
    processes: list[subprocess.Popen[str]] = []
    failures: list[str] = []
    try:
        for _ in range(workers):
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-c", script, str(gate), str(database)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        gate.touch()
        for process in processes:
            try:
                stdout, stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                failures.append(f"timeout stdout={stdout!r} stderr={stderr!r}")
                continue
            if process.returncode:
                failures.append(f"exit={process.returncode} stdout={stdout!r} stderr={stderr!r}")
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()
    assert failures == []


def test_process_startup_migrates_legacy_relay_once(tmp_path: Path) -> None:
    path = tmp_path / "legacy-relay.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE sealed_relay_queue (
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
        connection.execute(
            """
            INSERT INTO sealed_relay_queue VALUES (
                'digest', 'tenant', 'source', 'destination', 'transfer', 'record',
                'plan', '2026-09-10T00:00:00+00:00', X'7B7D', NULL, NULL
            )
            """
        )

    _run_contending_processes(
        tmp_path,
        path,
        (
            "from polymorph.relay import RelayPolicy, SealedRelayQueue\n"
            "SealedRelayQueue(Path(sys.argv[2]), RelayPolicy(()))"
        ),
    )

    with closing(sqlite3.connect(path)) as connection:
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(sealed_relay_queue)")
        }
        rows = connection.execute("SELECT record_digest FROM sealed_relay_queue").fetchall()
    assert "lease_id" in columns
    assert rows == [("digest",)]


def test_process_startup_migrates_legacy_delivery_ledger_once(tmp_path: Path) -> None:
    path = tmp_path / "legacy-ledger.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE deliveries (
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
        connection.execute(
            """
            INSERT INTO deliveries VALUES (
                'tenant', 'destination', 'transfer', 'record', 'digest', 'plan',
                'committed', '2026-09-10T00:00:00+00:00',
                '2026-09-10T00:00:00+00:00', NULL
            )
            """
        )

    _run_contending_processes(
        tmp_path,
        path,
        ("from polymorph.ledger import DeliveryLedger\nDeliveryLedger(Path(sys.argv[2]))"),
    )

    with closing(sqlite3.connect(path)) as connection:
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(deliveries)")}
        rows = connection.execute(
            "SELECT state, claim_token, claim_expires_at FROM deliveries"
        ).fetchall()
    assert {"claim_token", "claim_expires_at"} <= columns
    assert rows == [("committed", None, None)]
