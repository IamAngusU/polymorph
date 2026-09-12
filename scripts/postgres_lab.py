"""Run an explicit real PostgreSQL connector write and rollback lab."""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, func, select

from polymorph.connectors.database import DatabaseConnector
from polymorph.errors import ConnectorWriteError


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url-env", default="POLYMORPH_TEST_POSTGRES_URL")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    url = os.environ.get(args.url_env)
    if not url:
        payload = {
            "schema": "polymorph.postgres-lab",
            "version": 1,
            "status": "blocked",
            "reason": f"environment variable {args.url_env} is not set",
            "uploaded": False,
        }
        encoded = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 3

    table_name = f"polymorph_lab_{uuid.uuid4().hex[:12]}"
    engine = create_engine(url, future=True, hide_parameters=True)
    if engine.dialect.name != "postgresql":
        raise SystemExit("the configured lab URL is not PostgreSQL")
    metadata = MetaData()
    table = Table(
        table_name,
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("external_id", String(64), nullable=False, unique=True),
        Column("amount_minor", Integer, nullable=False),
    )
    started = time.perf_counter()
    rollback_proven = False
    try:
        metadata.create_all(engine)
        with DatabaseConnector(url, table_name) as connector:
            schema = connector.inspect_schema()
            written = connector.write_records(
                [
                    {"external_id": "evidence-a", "amount_minor": 1250},
                    {"external_id": "evidence-b", "amount_minor": 9900},
                ]
            )
            with suppress(ConnectorWriteError):
                connector.write_records(
                    [
                        {"external_id": "evidence-c", "amount_minor": 1},
                        {"external_id": "evidence-a", "amount_minor": 2},
                    ]
                )
            with engine.connect() as connection:
                count = int(
                    connection.execute(select(func.count()).select_from(table)).scalar_one()
                )
                server_version = connection.dialect.server_version_info
            rollback_proven = count == 2
        payload = {
            "schema": "polymorph.postgres-lab",
            "version": 1,
            "status": "passed" if written == 2 and rollback_proven else "failed",
            "timestamp": _now(),
            "duration_seconds": round(time.perf_counter() - started, 6),
            "dialect": engine.dialect.name,
            "driver": engine.dialect.driver,
            "server_version": list(server_version or ()),
            "schema_fields": len(schema.fields),
            "rows_written": written,
            "rows_after_forced_unique_violation": count,
            "transaction_rollback_proven": rollback_proven,
            "url_recorded": False,
            "uploaded": False,
        }
    finally:
        metadata.drop_all(engine, checkfirst=True)
        engine.dispose()
    encoded = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if payload["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
